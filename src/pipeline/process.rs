use anyhow::{Context, Result};

use crate::config::{BLOCK_SIZE, COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::{Operation, Secret, Task, TaskResult};
use crate::crypto::{Aes256Gcm, Cipher, XChaCha20Poly1305};
use crate::transform::{Compression, Encoding, Pkcs7Padding};

pub(super) struct Process {
    primary_cipher: Cipher<Aes256Gcm>,
    secondary_cipher: Cipher<XChaCha20Poly1305>,
    encoder: Encoding,
    compressor: Compression,
    padding: Pkcs7Padding,
    operation: Operation,
}

impl Process {
    pub(super) fn new(primary_key: &Secret, secondary_key: &Secret, operation: Operation) -> Result<Self> {
        let primary_cipher = Cipher::<Aes256Gcm>::new(primary_key).context("failed to initialize primary cipher")?;
        let secondary_cipher = Cipher::<XChaCha20Poly1305>::new(secondary_key).context("failed to initialize secondary cipher")?;
        let encoder = Encoding::new(ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to initialize encoder")?;
        let compressor = Compression::new(COMPRESSION_LEVEL).context("failed to initialize compressor")?;
        let padding = Pkcs7Padding::new(BLOCK_SIZE).context("failed to initialize padding")?;

        Ok(Self { primary_cipher, secondary_cipher, encoder, compressor, padding, operation })
    }

    pub(super) fn process(&self, task: &Task) -> Result<TaskResult> {
        match self.operation {
            Operation::Encryption => self.encrypt(task),
            Operation::Decryption => self.decrypt(task),
        }
    }

    fn encrypt(&self, task: &Task) -> Result<TaskResult> {
        self.compressor
            .compress(&task.data)
            .and_then(|data| self.padding.pad(&data))
            .and_then(|data| self.primary_cipher.encrypt(&data))
            .and_then(|data| self.secondary_cipher.encrypt(&data))
            .and_then(|data| self.encoder.encode(&data))
            .map(|data| {
                let size = task.data.len();
                TaskResult::new(task.index, data, size)
            })
    }

    fn decrypt(&self, task: &Task) -> Result<TaskResult> {
        self.encoder
            .decode(&task.data)
            .and_then(|data| self.secondary_cipher.decrypt(&data))
            .and_then(|data| self.primary_cipher.decrypt(&data))
            .and_then(|data| self.padding.unpad(&data))
            .and_then(|data| self.compressor.decompress(&data))
            .map(|data| {
                let size = data.len();
                TaskResult::new(task.index, data, size)
            })
    }
}
