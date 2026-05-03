use anyhow::{Context, Result};

use crate::compression::{CompressionLevel, Compressor};
use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::core::{Cipher, CipherAlgorithm};
use crate::encoding::Encoding;
use crate::padding::{BlockSize, Pkcs7Padding};
use crate::secret::SecretBytes;
use crate::types::{Processing, Task, TaskResult};

pub struct Pipeline {
    cipher: Cipher,
    encoder: Encoding,
    compressor: Compressor,
    padding: Pkcs7Padding,
    processing: Processing,
}

impl Pipeline {
    pub fn new(key: &SecretBytes, processing: Processing) -> Result<Self> {
        let cipher = Cipher::new(key).context("failed to initialize cipher")?;
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS).context("failed to initialize encoder")?;
        let compressor = Compressor::new(CompressionLevel::Fast).context("failed to initialize compressor")?;
        let padding = Pkcs7Padding::new(BlockSize::B128).context("failed to initialize padding")?;

        Ok(Self { cipher, encoder, compressor, padding, processing })
    }

    pub fn process(&self, task: &Task) -> Result<TaskResult> {
        match self.processing {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    fn encrypt_pipeline(&self, task: &Task) -> Result<TaskResult> {
        self.compressor
            .compress(&task.data)
            .and_then(|data| self.padding.pad(&data))
            .and_then(|data| self.cipher.encrypt(&CipherAlgorithm::Aes256Gcm, &data))
            .and_then(|data| self.cipher.encrypt(&CipherAlgorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.encoder.encode(&data))
            .map(|data| {
                let size = task.data.len();
                TaskResult::new(task.index, data, size)
            })
    }

    fn decrypt_pipeline(&self, task: &Task) -> Result<TaskResult> {
        self.encoder
            .decode(&task.data)
            .and_then(|data| self.cipher.decrypt(&CipherAlgorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.cipher.decrypt(&CipherAlgorithm::Aes256Gcm, &data))
            .and_then(|data| self.padding.unpad(&data))
            .and_then(|data| self.compressor.decompress(&data))
            .map(|data| {
                let size = data.len();
                TaskResult::new(task.index, data, size)
            })
    }
}
