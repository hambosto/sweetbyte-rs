use anyhow::{Context, Result};

use crate::cipher::{Cipher, CipherAlgorithm};
use crate::compression::{CompressionLevel, Compressor};
use crate::encoding::Encoding;
use crate::padding::{BlockSize, Pkcs7Padding};
use crate::secret::Secret;
use crate::types::{Processing, Task, TaskResult};

pub(super) struct Pipeline {
    cipher: Cipher,
    encoder: Encoding,
    compressor: Compressor,
    padding: Pkcs7Padding,
    processing: Processing,
}

impl Pipeline {
    pub(super) fn new(
        primary_key: &Secret, secondary_key: &Secret, processing: Processing, compression_level: CompressionLevel, block_size: BlockSize, original_count: usize, recovery_count: usize,
    ) -> Result<Self> {
        let cipher = Cipher::new(primary_key, secondary_key).context("failed to initialize cipher")?;
        let encoder = Encoding::new(original_count, recovery_count).context("failed to initialize encoder")?;
        let compressor = Compressor::new(compression_level).context("failed to initialize compressor")?;
        let padding = Pkcs7Padding::new(block_size).context("failed to initialize padding")?;

        Ok(Self { cipher, encoder, compressor, padding, processing })
    }

    #[inline]
    pub(super) fn process(&self, task: &Task) -> Result<TaskResult> {
        match self.processing {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    #[inline]
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

    #[inline]
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
