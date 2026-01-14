use anyhow::Result;

use crate::cipher::Cipher;
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{ARGON_KEY_LEN, BLOCK_SIZE, DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::ReedSolomonEncoder;
use crate::padding::Padding;
use crate::types::{Processing, Task, TaskResult};

pub struct DataProcessor {
    cipher: Cipher,
    encoder: ReedSolomonEncoder,
    compressor: Compressor,
    padding: Padding,
    mode: Processing,
}

impl DataProcessor {
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let cipher = Cipher::new(key)?;
        let encoder = ReedSolomonEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let compressor = Compressor::new(CompressionLevel::Fast);
        let padding = Padding::new(BLOCK_SIZE)?;

        Ok(Self {
            cipher,
            encoder,
            compressor,
            padding,
            mode,
        })
    }

    pub fn process(&self, task: Task) -> TaskResult {
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    fn encrypt_pipeline(&self, task: Task) -> TaskResult {
        let input_size = task.data.len();

        let compressed = match self.compressor.compress(&task.data) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        let padded = match self.padding.pad(&compressed) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        let aes_encrypted = match self.cipher.encrypt_aes(&padded) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        let chacha_encrypted = match self.cipher.encrypt_chacha(&aes_encrypted) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        let encoded = match self.encoder.encode(&chacha_encrypted) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        TaskResult::success(task.index, encoded, input_size)
    }

    fn decrypt_pipeline(&self, task: Task) -> TaskResult {
        let decoded = match self.encoder.decode(&task.data) {
            Ok(data) => data,
            Err(e) => {
                return TaskResult::failure(task.index, e.context("Reed-Solomon decoding failed"));
            }
        };

        let chacha_decrypted = match self.cipher.decrypt_chacha(&decoded) {
            Ok(data) => data,
            Err(e) => {
                return TaskResult::failure(task.index, e.context("ChaCha decryption failed"));
            }
        };

        let aes_decrypted = match self.cipher.decrypt_aes(&chacha_decrypted) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e.context("AES decryption failed")),
        };

        let unpadded = match self.padding.unpad(&aes_decrypted) {
            Ok(data) => data,
            Err(e) => {
                return TaskResult::failure(task.index, e.context("padding validation failed"));
            }
        };

        let decompressed = match self.compressor.decompress(&unpadded) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e.context("decompression failed")),
        };

        let output_size = decompressed.len();
        TaskResult::success(task.index, decompressed, output_size)
    }
}
