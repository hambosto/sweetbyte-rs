//! Data processing pipeline for encryption/decryption.

use anyhow::Result;

use crate::compression::{CompressionLevel, Compressor};
use crate::config::ARGON_KEY_LEN;
use crate::crypto::Cipher;
use crate::encoding::ReedSolomon;
use crate::padding::Padding;
use crate::types::{Processing, Task, TaskResult};

/// Processes data chunks through the encryption/decryption pipeline.
pub struct DataProcessor {
    cipher: Cipher,
    encoder: ReedSolomon,
    compressor: Compressor,
    padding: Padding,
    mode: Processing,
}

impl DataProcessor {
    /// Creates a new data processor.
    ///
    /// # Arguments
    /// * `key` - The 64-byte derived key
    /// * `mode` - The processing mode
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let cipher = Cipher::new(key)?;
        let encoder = ReedSolomon::default();
        let compressor = Compressor::new(CompressionLevel::Fast);
        let padding = Padding::default();

        Ok(Self {
            cipher,
            encoder,
            compressor,
            padding,
            mode,
        })
    }

    /// Processes a single task.
    pub fn process(&self, task: Task) -> TaskResult {
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    fn encrypt_pipeline(&self, task: Task) -> TaskResult {
        let input_size = task.data.len();

        // 1. Compress
        let compressed = match self.compressor.compress(&task.data) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        // 2. Pad
        let padded = match self.padding.pad(&compressed) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        // 3. Encrypt with AES
        let aes_encrypted = match self.cipher.encrypt_aes(&padded) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        // 4. Encrypt with ChaCha
        let chacha_encrypted = match self.cipher.encrypt_chacha(&aes_encrypted) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        // 5. Reed-Solomon encode
        let encoded = match self.encoder.encode(&chacha_encrypted) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e),
        };

        TaskResult::success(task.index, encoded, input_size)
    }

    fn decrypt_pipeline(&self, task: Task) -> TaskResult {
        // 1. Reed-Solomon decode
        let decoded = match self.encoder.decode(&task.data) {
            Ok(data) => data,
            Err(e) => {
                return TaskResult::failure(task.index, e.context("Reed-Solomon decoding failed"));
            }
        };

        // 2. Decrypt ChaCha
        let chacha_decrypted = match self.cipher.decrypt_chacha(&decoded) {
            Ok(data) => data,
            Err(e) => {
                return TaskResult::failure(task.index, e.context("ChaCha decryption failed"));
            }
        };

        // 3. Decrypt AES
        let aes_decrypted = match self.cipher.decrypt_aes(&chacha_decrypted) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e.context("AES decryption failed")),
        };

        // 4. Unpad
        let unpadded = match self.padding.unpad(&aes_decrypted) {
            Ok(data) => data,
            Err(e) => {
                return TaskResult::failure(task.index, e.context("padding validation failed"));
            }
        };

        // 5. Decompress
        let decompressed = match self.compressor.decompress(&unpadded) {
            Ok(data) => data,
            Err(e) => return TaskResult::failure(task.index, e.context("decompression failed")),
        };

        let output_size = decompressed.len();
        TaskResult::success(task.index, decompressed, output_size)
    }
}
