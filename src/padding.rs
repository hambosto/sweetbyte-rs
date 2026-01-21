//! PKCS7 padding for block ciphers.
//!
//! Implements PKCS#7 padding scheme required for block cipher encryption.
//! Padding ensures that plaintext length is a multiple of the block size,
//! which is a requirement for AES and similar ciphers.
//!
//! # PKCS7 Scheme
//!
//! For a block size of N bytes:
//! - If data length is already a multiple of N, add N bytes of padding (all N)
//! - Otherwise, add K bytes where K = N - (data_length % N), all set to K
//!
//! This scheme allows unambiguous removal of padding during decryption.

use anyhow::{Result, anyhow, ensure};

/// PKCS7 padding handler.
///
/// Provides methods to add and remove padding according to the PKCS#7 specification.
/// Used in the encryption/decryption pipeline to ensure block-aligned data.
pub struct Padding {
    /// The block size in bytes (e.g., 16 for AES, 128 for internal use).
    block_size: usize,
}

impl Padding {
    /// Creates a new padding handler for the specified block size.
    ///
    /// # Arguments
    ///
    /// * `block_size` - The block size in bytes (must be > 0).
    ///
    /// # Errors
    ///
    /// Returns an error if block_size is 0.
    pub fn new(block_size: usize) -> Result<Self> {
        ensure!(block_size > 0, "block size must be greater than 0");
        Ok(Self { block_size })
    }

    /// Adds PKCS7 padding to the data.
    ///
    /// Extends the data to be a multiple of the block size.
    ///
    /// PKCS7 padding rule:
    /// - Let N = block_size, L = data length
    /// - If L % N == 0: add N bytes of 0xN (special case for exact blocks)
    /// - Otherwise: add K bytes where K = N - (L % N), all set to K
    ///
    /// Example with block_size=16:
    /// - 15 bytes → add 1 byte of 0x01
    /// - 16 bytes → add 16 bytes of 0x10
    /// - 17 bytes → add 15 bytes of 0x0F
    ///
    /// # Arguments
    ///
    /// * `data` - The data to pad.
    ///
    /// # Errors
    ///
    /// Returns an error if data is empty.
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Calculate padding length: N - (len % N), where N = block_size.
        // If len is already multiple of N, this gives N (adds full block of padding).
        let padding_len = self.block_size - (data.len() % self.block_size);

        // Create padding bytes: repeat the padding_len value.
        // For example, if padding_len=5, creates [5, 5, 5, 5, 5].
        let padded = data.iter().copied().chain(std::iter::repeat_n(padding_len as u8, padding_len)).collect();

        Ok(padded)
    }

    /// Removes PKCS7 padding from the data.
    ///
    /// Validates that padding is well-formed and returns the original data.
    ///
    /// Validation steps:
    /// 1. Last byte indicates padding length K (1 to block_size)
    /// 2. Data must be at least K bytes long
    /// 3. All K padding bytes must equal K
    ///
    /// The padding length check prevents padding oracle attacks by rejecting
    /// invalid padding early.
    ///
    /// # Arguments
    ///
    /// * `data` - The padded data to unpad.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Data is empty
    /// - Padding length is 0 or exceeds block size
    /// - Data is shorter than indicated padding length
    /// - Padding bytes don't match expected value
    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Extract the last byte which indicates padding length.
        // This is the PKCS7 "padding length indicator".
        let padding_len = data.last().copied().ok_or_else(|| anyhow!("cannot unpad empty data"))?;

        // Validate padding length is within valid range.
        // Must be at least 1 and at most block_size (inclusive).
        // This prevents malformed padding from passing validation.
        ensure!(padding_len > 0 && padding_len <= self.block_size as u8, "invalid padding length: {padding_len}");

        let padding_len = padding_len as usize;

        // Ensure data is long enough to contain the padding.
        // The content must be at least as long as the padding length.
        ensure!(data.len() >= padding_len, "data too short for padding length");

        // Split into content and padding sections.
        // Content is everything except the last K bytes.
        let (content, padding_bytes) = data.split_at(data.len() - padding_len);

        // Validate all padding bytes match the expected value.
        // If any byte differs, the padding is malformed/tampered.
        ensure!(padding_bytes.iter().all(|&b| b == padding_len as u8), "invalid PKCS#7 padding bytes");

        Ok(content.to_vec())
    }
}
