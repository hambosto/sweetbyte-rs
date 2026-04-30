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
        let data = self.compressor.compress(&task.data).context("failed to compress data")?;
        let data = self.padding.pad(&data).context("failed to pad data")?;
        let data = self.cipher.encrypt(&CipherAlgorithm::Aes256Gcm, &data).context("failed to encrypt with AES-256-GCM")?;
        let data = self.cipher.encrypt(&CipherAlgorithm::ChaCha20Poly1305, &data).context("failed to encrypt with ChaCha20Poly1305")?;
        let encoded_data = self.encoder.encode(&data).context("failed to encode data")?;

        let size = task.data.len();
        Ok(TaskResult::new(task.index, encoded_data, size))
    }

    fn decrypt_pipeline(&self, task: &Task) -> Result<TaskResult> {
        let data = self.encoder.decode(&task.data).context("failed to decode data")?;
        let data = self.cipher.decrypt(&CipherAlgorithm::ChaCha20Poly1305, &data).context("failed to decrypt with ChaCha20Poly1305")?;
        let data = self.cipher.decrypt(&CipherAlgorithm::Aes256Gcm, &data).context("failed to decrypt with AES-256-GCM")?;
        let data = self.padding.unpad(&data).context("failed to unpad data")?;
        let data = self.compressor.decompress(&data).context("failed to decompress data")?;

        let size = data.len();
        Ok(TaskResult::new(task.index, data, size))
    }
}
