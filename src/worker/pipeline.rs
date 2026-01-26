//! Cryptographic processing pipeline.
//!
//! This module defines the `Pipeline` struct, which encapsulates the sequence of operations
//! performed on each data chunk. It serves as the "engine" driven by the executor.
//!
//! # Processing Chain
//!
//! ## Encryption
//! 1. **Compress**: Zlib compression (if enabled).
//! 2. **Pad**: PKCS#7 padding to align with block size.
//! 3. **Encrypt (Layer 1)**: AES-256-GCM.
//! 4. **Encrypt (Layer 2)**: XChaCha20-Poly1305.
//! 5. **Encode**: Reed-Solomon erasure coding.
//!
//! ## Decryption
//! 1. **Decode**: Reed-Solomon error correction/reconstruction.
//! 2. **Decrypt (Layer 2)**: XChaCha20-Poly1305.
//! 3. **Decrypt (Layer 1)**: AES-256-GCM.
//! 4. **Unpad**: Remove PKCS#7 padding.
//! 5. **Decompress**: Zlib decompression.

use anyhow::Result;

use crate::cipher::{Aes256Gcm, Cipher, XChaCha20Poly1305};
use crate::compression::{CompressionLevel, Compressor};
use crate::config::{ARGON_KEY_LEN, BLOCK_SIZE, DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;
use crate::padding::Padding;
use crate::types::{Processing, Task, TaskResult};

/// The unified processing engine for a single chunk of data.
///
/// This struct holds the initialized cryptographic contexts and transformation tools
/// required to process a `Task`. It is thread-safe (via `Sync`) and designed to be
/// shared across multiple executor threads.
pub struct Pipeline {
    /// The dual-algorithm cipher context.
    cipher: Cipher,

    /// Reed-Solomon encoder/decoder.
    encoder: Encoding,

    /// Zlib compressor/decompressor.
    compressor: Compressor,

    /// PKCS#7 padding utility.
    padding: Padding,

    /// The current operation mode (Encrypt vs Decrypt).
    mode: Processing,
}

impl Pipeline {
    /// Creates a new processing pipeline.
    ///
    /// # Arguments
    ///
    /// * `key` - The master derived key.
    /// * `mode` - Whether we are encrypting or decrypting.
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        // Initialize cryptographic primitives.
        let cipher = Cipher::new(key)?;

        // Initialize error correction.
        // We use the global shard configuration.
        let encoder = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Initialize compression.
        // Currently hardcoded to Fast for performance balance.
        let compressor = Compressor::new(CompressionLevel::Fast)?;

        // Initialize padding.
        // Must match the cipher's block requirement (typically 128 bytes in our config).
        let padding = Padding::new(BLOCK_SIZE)?;

        Ok(Self { cipher, encoder, compressor, padding, mode })
    }

    /// Processes a single task (data chunk) according to the pipeline mode.
    ///
    /// # Returns
    ///
    /// A `TaskResult` containing either the processed data or an error.
    #[inline]
    pub fn process(&self, task: &Task) -> TaskResult {
        // Dispatch to the specific pipeline method based on mode.
        // This keeps the high-level flow clear.
        match self.mode {
            Processing::Encryption => self.encrypt_pipeline(task),
            Processing::Decryption => self.decrypt_pipeline(task),
        }
    }

    /// Executes the encryption steps: Compress -> Pad -> AES -> ChaCha -> Encode.
    fn encrypt_pipeline(&self, task: &Task) -> TaskResult {
        let input_size = task.data.len();

        // Step 1: Compress the raw data.
        // This reduces the amount of data to encrypt and write, and increases entropy.
        let compressed_data = match self.compressor.compress(&task.data) {
            Ok(compressed) => compressed,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 2: Apply PKCS#7 padding.
        // This ensures the data length is a multiple of the block size, required for
        // some block cipher modes and good practice generally.
        let padded_data = match self.padding.pad(&compressed_data) {
            Ok(padded) => padded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 3: Encrypt with AES-256-GCM (Inner Layer).
        let aes_encrypted = match self.cipher.encrypt::<Aes256Gcm>(&padded_data) {
            Ok(aes_encrypted) => aes_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 4: Encrypt with XChaCha20-Poly1305 (Outer Layer).
        // This provides defense-in-depth. Defeating encryption requires breaking BOTH algorithms.
        let chacha_encrypted = match self.cipher.encrypt::<XChaCha20Poly1305>(&aes_encrypted) {
            Ok(chacha_encrypted) => chacha_encrypted,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Step 5: Encode with Reed-Solomon.
        // This adds redundancy to survive data corruption.
        let encoded_data = match self.encoder.encode(&chacha_encrypted) {
            Ok(encoded) => encoded,
            Err(e) => return TaskResult::err(task.index, &e),
        };

        // Return successful result.
        // Note: size here tracks input size for progress reporting.
        TaskResult::ok(task.index, encoded_data, input_size)
    }

    /// Executes the decryption steps: Decode -> ChaCha -> AES -> Unpad -> Decompress.
    fn decrypt_pipeline(&self, task: &Task) -> TaskResult {
        // Step 1: Decode Reed-Solomon blocks.
        // This attempts to reconstruct the data if corruption occurred.
        let decoded_data = match self.encoder.decode(&task.data) {
            Ok(decoded) => decoded,
            Err(e) => return TaskResult::err(task.index, &e.context("failed to decode data")),
        };

        // Step 2: Decrypt XChaCha20-Poly1305 (Outer Layer).
        // If authentication fails here, it means the outer layer was tampered with beyond RS repair.
        let chacha_decrypted = match self.cipher.decrypt::<XChaCha20Poly1305>(&decoded_data) {
            Ok(chacha_decrypted) => chacha_decrypted,
            Err(e) => return TaskResult::err(task.index, &e.context("chacha20poly1305 decryption failed")),
        };

        // Step 3: Decrypt AES-256-GCM (Inner Layer).
        let aes_decrypted = match self.cipher.decrypt::<Aes256Gcm>(&chacha_decrypted) {
            Ok(aes_decrypted) => aes_decrypted,
            Err(e) => {
                return TaskResult::err(task.index, &e.context("aes256gcm decryption failed"));
            }
        };

        // Step 4: Remove Padding.
        // Checks PKCS#7 invariants.
        let unpadded_data = match self.padding.unpad(&aes_decrypted) {
            Ok(unpadded) => unpadded,
            Err(e) => return TaskResult::err(task.index, &e.context("padding validation failed")),
        };

        // Step 5: Decompress Zlib data.
        let decompressed_data = match Compressor::decompress(&unpadded_data) {
            Ok(decompressed) => decompressed,
            Err(e) => return TaskResult::err(task.index, &e.context("decompression failed")),
        };

        // Calculate size of recovered data.
        let output_size = decompressed_data.len();

        TaskResult::ok(task.index, decompressed_data, output_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_roundtrip() {
        // Setup valid keys.
        let key = [0u8; ARGON_KEY_LEN];
        let pipeline_enc = Pipeline::new(&key, Processing::Encryption).unwrap();
        let pipeline_dec = Pipeline::new(&key, Processing::Decryption).unwrap();

        let data = b"Hello, secure world!";
        let task = Task { data: data.to_vec(), index: 0 };

        // Run forward pipeline.
        let encrypted = pipeline_enc.process(&task);
        assert!(encrypted.error.is_none());
        assert_ne!(encrypted.data, data);

        // Run reverse pipeline.
        let task_dec = Task { data: encrypted.data, index: 0 };
        let decrypted = pipeline_dec.process(&task_dec);
        assert!(decrypted.error.is_none());

        // Check integrity.
        assert_eq!(decrypted.data, data);
    }
}
