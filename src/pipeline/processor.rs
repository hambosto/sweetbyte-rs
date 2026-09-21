use anyhow::{Context, Result};

use crate::config::{BLOCK_SIZE, COMPRESSION_LEVEL, ORIGINAL_COUNT, RECOVERY_COUNT};
use crate::core::{Operation, Secret, Task, TaskResult};
use crate::crypto::{Aes256Gcm, Cipher, XChaCha20Poly1305};
use crate::transform::{Compression, Encoding, Padding};

pub(super) struct Processor {
    primary_cipher: Cipher<Aes256Gcm>,
    secondary_cipher: Cipher<XChaCha20Poly1305>,
    encoder: Encoding,
    compressor: Compression,
    padding: Padding,
    operation: Operation,
}

impl Processor {
    pub(super) fn new(primary_key: &Secret, secondary_key: &Secret, operation: Operation) -> Result<Self> {
        let primary_cipher = Cipher::<Aes256Gcm>::new(primary_key).context("failed to init AES cipher")?;
        let secondary_cipher = Cipher::<XChaCha20Poly1305>::new(secondary_key).context("failed to init XChaCha cipher")?;
        let encoder = Encoding::new(ORIGINAL_COUNT, RECOVERY_COUNT).context("failed to init erasure encoder")?;
        let compressor = Compression::new(COMPRESSION_LEVEL).context("failed to init zstd compressor")?;
        let padding = Padding::new(BLOCK_SIZE).context("failed to init PKCS7 padding")?;

        Ok(Self { primary_cipher, secondary_cipher, encoder, compressor, padding, operation })
    }

    pub(super) fn transform(&self, task: &Task) -> Result<TaskResult> {
        match self.operation {
            Operation::Encryption => self.encrypt(task),
            Operation::Decryption => self.decrypt(task),
        }
    }

    fn encrypt(&self, task: &Task) -> Result<TaskResult> {
        self.compressor
            .compress(&task.data)
            .and_then(|compressed| self.padding.pad(&compressed))
            .and_then(|padded| self.primary_cipher.encrypt(&padded))
            .and_then(|primary| self.secondary_cipher.encrypt(&primary))
            .and_then(|secondary| self.encoder.encode(&secondary))
            .map(|encoded| {
                let size = task.data.len();
                TaskResult::new(task.index, encoded, size)
            })
    }

    fn decrypt(&self, task: &Task) -> Result<TaskResult> {
        self.encoder
            .decode(&task.data)
            .and_then(|decoded| self.secondary_cipher.decrypt(&decoded))
            .and_then(|secondary| self.primary_cipher.decrypt(&secondary))
            .and_then(|primary| self.padding.unpad(&primary))
            .and_then(|unpadded| self.compressor.decompress(&unpadded))
            .map(|decompressed| {
                let size = decompressed.len();
                TaskResult::new(task.index, decompressed, size)
            })
    }
}
