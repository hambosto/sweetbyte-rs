//! Processing pipeline for encryption and decryption.
//!
//! Implements the complete transformation pipeline for each data chunk.
//! Each chunk is processed independently for parallel execution.
//!
//! # Encryption Pipeline
//!
//! 1. Compress data (zlib, fast level)
//! 2. Apply PKCS7 padding
//! 3. Encrypt with AES-256-GCM
//! 4. Encrypt with XChaCha20-Poly1305
//! 5. Apply Reed-Solomon error correction
//!
//! # Decryption Pipeline
//!
//! 1. Decode Reed-Solomon (recover from corruption)
//! 2. Decrypt XChaCha20-Poly1305
//! 3. Decrypt AES-256-GCM
//! 4. Remove PKCS7 padding
//! 5. Decompress data

use anyhow::Result;

use crate::cipher::{Algorithm, Cipher};
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{ARGON_KEY_LEN, BLOCK_SIZE, DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;
use crate::padding::Padding;
use crate::types::{Processing, Task, TaskResult};

/// Processing pipeline for a single chunk.
///
/// Contains all components needed to encrypt or decrypt a data chunk.
/// Shared via Arc for thread-safe concurrent access.
pub struct Pipeline {
    /// Dual-cipher for encryption/decryption.
    cipher: Cipher,

    /// Reed-Solomon encoder/decoder.
    encoder: Encoding,

    /// Zlib compressor.
    compressor: Compressor,

    /// PKCS7 padding handler.
    padding: Padding,

    /// Current processing mode.
    mode: Processing,
}

impl Pipeline {
    /// Creates a new pipeline with the given key and mode.
    ///
    /// # Arguments
    ///
    /// * `key` - The 64-byte derived cryptographic key.
    /// * `mode` - Encryption or decryption mode.
    ///
    /// # Errors
    ///
    /// Returns an error if any component fails to initialize.
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let cipher = Cipher::new(key)?;
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;
        let compressor = Compressor::new(CompressionLevel::Fast)?;
        let padding = Padding::new(BLOCK_SIZE)?;

        Ok(Self { cipher, encoder, compressor, padding, mode })
    }

    /// Processes a task through the appropriate pipeline.
    ///
    /// # Arguments
    ///
    /// * `task` - The task containing data to process.
    ///
    /// # Returns
    ///
    /// The processing result with transformed data or error.
    #[inline]
    pub fn process(&self, task: &Task) -> TaskResult {
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    /// Executes the encryption pipeline on a task.
    fn encrypt_pipeline(&self, task: &Task) -> TaskResult {
        let input_size = task.data.len();

        // Step 1: Compress data
        let compressed_data = match self.compressor.compress(&task.data) {
            Ok(compressed) => compressed,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 2: Apply PKCS7 padding
        let padded_data = match self.padding.pad(&compressed_data) {
            Ok(padded) => padded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 3: First encryption layer - AES-256-GCM
        let aes_encrypted = match self.cipher.encrypt::<Algorithm::Aes256Gcm>(&padded_data) {
            Ok(aes_encrypted) => aes_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 4: Second encryption layer - XChaCha20-Poly1305
        let chacha_encrypted = match self.cipher.encrypt::<Algorithm::XChaCha20Poly1305>(&aes_encrypted) {
            Ok(chacha_encrypted) => chacha_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 5: Apply Reed-Solomon error correction
        let encoded_data = match self.encoder.encode(&chacha_encrypted) {
            Ok(encoded) => encoded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        TaskResult::ok(task.index, encoded_data, input_size)
    }

    /// Executes the decryption pipeline on a task.
    fn decrypt_pipeline(&self, task: &Task) -> TaskResult {
        // Step 1: Decode Reed-Solomon (with error correction)
        let decoded_data = match self.encoder.decode(&task.data) {
            Ok(decoded) => decoded,
            Err(e) => return TaskResult::err(task.index, &e.context("failed to decode data")),
        };

        // Step 2: First decryption layer - XChaCha20-Poly1305
        let chacha_decrypted = match self.cipher.decrypt::<Algorithm::XChaCha20Poly1305>(&decoded_data) {
            Ok(chacha_decrypted) => chacha_decrypted,
            Err(e) => return TaskResult::err(task.index, &e.context("chacha20poly1305 decryption failed")),
        };

        // Step 3: Second decryption layer - AES-256-GCM
        let aes_decrypted = match self.cipher.decrypt::<Algorithm::Aes256Gcm>(&chacha_decrypted) {
            Ok(aes_decrypted) => aes_decrypted,
            Err(e) => return TaskResult::err(task.index, &e.context("aes256gcm decryption failed")),
        };

        // Step 4: Remove PKCS7 padding
        let unpadded_data = match self.padding.unpad(&aes_decrypted) {
            Ok(unpadded) => unpadded,
            Err(e) => return TaskResult::err(task.index, &e.context("padding validation failed")),
        };

        // Step 5: Decompress data
        let decompressed_data = match Compressor::decompress(&unpadded_data) {
            Ok(decompressed) => decompressed,
            Err(e) => return TaskResult::err(task.index, &e.context("decompression failed")),
        };

        let output_size = decompressed_data.len();
        TaskResult::ok(task.index, decompressed_data, output_size)
    }
}
