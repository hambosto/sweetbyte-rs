use anyhow::Result;

use crate::cipher::{Cipher, CipherAlgorithm};
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;
use crate::padding::{BlockSize, Pkcs7Padding};
use crate::secret::SecretBytes;
use crate::types::{ProcessorMode, Task, TaskResult};

pub struct Pipeline {
    cipher: Cipher,
    encoder: Encoding,
    compressor: Compressor,
    padding: Pkcs7Padding,
    mode: ProcessorMode,
}

impl Pipeline {
    pub fn new(key: &SecretBytes, mode: ProcessorMode) -> Result<Self> {
        let cipher = Cipher::new(key)?;
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;
        let compressor = Compressor::new(CompressionLevel::Fast)?;
        let padding = Pkcs7Padding::new(BlockSize::B128)?;

        Ok(Self { cipher, encoder, compressor, padding, mode })
    }

    pub fn process(&self, task: &Task) -> Result<TaskResult> {
        match self.mode {
            ProcessorMode::Encryption => self.encrypt_pipeline(task),
            ProcessorMode::Decryption => self.decrypt_pipeline(task),
        }
    }

    fn encrypt_pipeline(&self, task: &Task) -> Result<TaskResult> {
        let encoded_data = self
            .compressor
            .compress(&task.data)
            .and_then(|data| self.padding.pad(&data))
            .and_then(|data| self.cipher.encrypt(&CipherAlgorithm::Aes256Gcm, &data))
            .and_then(|data| self.cipher.encrypt(&CipherAlgorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.encoder.encode(&data))?;

        let size = task.data.len();
        Ok(TaskResult::new(task.index, encoded_data, size))
    }

    fn decrypt_pipeline(&self, task: &Task) -> Result<TaskResult> {
        let data = self
            .encoder
            .decode(&task.data)
            .and_then(|data| self.cipher.decrypt(&CipherAlgorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.cipher.decrypt(&CipherAlgorithm::Aes256Gcm, &data))
            .and_then(|data| self.padding.unpad(&data))
            .and_then(|data| Compressor::decompress(&data))?;

        let size = data.len();
        Ok(TaskResult::new(task.index, data, size))
    }
}
