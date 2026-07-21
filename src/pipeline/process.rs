use anyhow::{Context, Result};

use super::types::{Processing, Task, TaskResult};
use crate::cipher::{Algorithm, Cipher};
use crate::compression::Compression;
use crate::config::{BLOCK_SIZE, COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::encoding::Encoding;
use crate::padding::Pkcs7Padding;
use crate::secret::Secret;

pub(super) struct Process {
    cipher: Cipher,
    encoder: Encoding,
    compressor: Compression,
    padding: Pkcs7Padding,
    processing: Processing,
}

impl Process {
    pub(super) fn new(primary_key: &Secret, secondary_key: &Secret, processing: Processing) -> Result<Self> {
        let cipher = Cipher::new(primary_key, secondary_key).context("failed to initialize cipher")?;
        let encoder = Encoding::new(ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to initialize encoder")?;
        let compressor = Compression::new(COMPRESSION_LEVEL).context("failed to initialize compressor")?;
        let padding = Pkcs7Padding::new(BLOCK_SIZE).context("failed to initialize padding")?;

        Ok(Self { cipher, encoder, compressor, padding, processing })
    }

    #[inline]
    pub(super) fn process(&self, task: &Task) -> Result<TaskResult> {
        match self.processing {
            Processing::Encryption => self.encrypt(task),
            Processing::Decryption => self.decrypt(task),
        }
    }

    #[inline]
    fn encrypt(&self, task: &Task) -> Result<TaskResult> {
        self.compressor
            .compress(&task.data)
            .and_then(|data| self.padding.pad(&data))
            .and_then(|data| self.cipher.encrypt(&Algorithm::Aes256Gcm, &data))
            .and_then(|data| self.cipher.encrypt(&Algorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.encoder.encode(&data))
            .map(|data| {
                let size = task.data.len();
                TaskResult::new(task.index, data, size)
            })
    }

    #[inline]
    fn decrypt(&self, task: &Task) -> Result<TaskResult> {
        self.encoder
            .decode(&task.data)
            .and_then(|data| self.cipher.decrypt(&Algorithm::ChaCha20Poly1305, &data))
            .and_then(|data| self.cipher.decrypt(&Algorithm::Aes256Gcm, &data))
            .and_then(|data| self.padding.unpad(&data))
            .and_then(|data| self.compressor.decompress(&data))
            .map(|data| {
                let size = data.len();
                TaskResult::new(task.index, data, size)
            })
    }
}
