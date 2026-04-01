use anyhow::Result;

use crate::cipher::{Cipher, CipherAlgorithm};
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;
use crate::padding::{BlockSize, Pkcs7Padding};
use crate::secret::SecretBytes;
use crate::types::{Processing, Task, TaskResult};

pub struct Pipeline {
    cipher: Cipher,
    encoder: Encoding,
    compressor: Compressor,
    padding: Pkcs7Padding,
    mode: Processing,
}

impl Pipeline {
    pub fn new(key: &SecretBytes, mode: Processing) -> Result<Self> {
        let cipher = Cipher::new(key)?;
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;
        let compressor = Compressor::new(CompressionLevel::Fast)?;
        let padding = Pkcs7Padding::new(BlockSize::B128)?;

        Ok(Self { cipher, encoder, compressor, padding, mode })
    }

    pub fn process(&self, task: &Task) -> TaskResult {
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    fn encrypt_pipeline(&self, task: &Task) -> TaskResult {
        let result = self
            .compressor
            .compress(&task.data)
            .and_then(|data| self.padding.pad(&data))
            .and_then(|data| self.cipher.encrypt(&CipherAlgorithm::Aes256Gcm, &data))
            .and_then(|data| self.cipher.encrypt(&CipherAlgorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.encoder.encode(&data));

        match result {
            Ok(encoded_data) => {
                let size = task.data.len();
                TaskResult::ok(task.index, encoded_data, size)
            }
            Err(error) => TaskResult::err(task.index, &error),
        }
    }

    fn decrypt_pipeline(&self, task: &Task) -> TaskResult {
        let result = self
            .encoder
            .decode(&task.data)
            .and_then(|data| self.cipher.decrypt(&CipherAlgorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.cipher.decrypt(&CipherAlgorithm::Aes256Gcm, &data))
            .and_then(|data| self.padding.unpad(&data))
            .and_then(|data| Compressor::decompress(&data));

        match result {
            Ok(data) => {
                let size = data.len();
                TaskResult::ok(task.index, data, size)
            }
            Err(error) => TaskResult::err(task.index, &error),
        }
    }
}
