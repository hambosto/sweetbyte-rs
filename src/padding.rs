//! PKCS#7 padding implementation.
//!
//! This module provides padding functionality to align data to block boundaries.
//! SweetByte uses PKCS#7 (RFC 5652) padding, which is the standard for AES and other block ciphers.
//!
//! # Mechanism
//!
//! If the data length is not a multiple of the block size, $N$ bytes are added,
//! where each byte has the value $N$. This guarantees that the last byte of the
//! padded data always indicates the number of padding bytes to remove.
//!
//! If data is already a multiple of the block size, a full block of padding is added.
//! This ensures ambiguity-free unpadding.

use anyhow::{Result, anyhow, ensure};

/// A utility for adding and removing PKCS#7 padding.
pub struct Padding {
    /// The block size alignment (e.g., 16 for AES-128, though typically 128 bytes in our config).
    block_size: usize,
}

impl Padding {
    /// Creates a new Padding utility for the specified block size.
    ///
    /// # Arguments
    ///
    /// * `block_size` - The block alignment size in bytes. Must be between 1 and 255.
    ///
    /// # Errors
    ///
    /// Returns an error if the block size is invalid (0 or > 255).
    pub fn new(block_size: usize) -> Result<Self> {
        ensure!(block_size > 0, "block size must be greater than 0");
        // PKCS#7 represents padding length as a byte, so max padding is 255 bytes.
        ensure!(block_size <= 255, "block size must be <= 255 for PKCS#7");
        Ok(Self { block_size })
    }

    /// Adds PKCS#7 padding to the data.
    ///
    /// # Returns
    ///
    /// A new vector containing the original data plus padding.
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Calculate how many bytes we need to add to reach the next block boundary.
        // Result is in range [1, block_size].
        let padding_len = self.block_size - (data.len() % self.block_size);

        // Extend the data with `padding_len` copies of the byte value `padding_len`.
        // e.g., if we need 3 bytes, append [0x03, 0x03, 0x03].
        let padded = data.iter().copied().chain(std::iter::repeat_n(padding_len as u8, padding_len)).collect();

        Ok(padded)
    }

    /// Removes PKCS#7 padding from the data.
    ///
    /// # Returns
    ///
    /// A new vector containing the data without padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the padding is invalid (wrong values or length).
    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Read the last byte to determine the expected padding length.
        let padding_len = data.last().copied().ok_or_else(|| anyhow!("cannot unpad empty data"))?;

        // Validation: padding length must be valid (1 <= len <= block_size).
        ensure!(padding_len > 0 && padding_len <= self.block_size as u8, "invalid padding length: {padding_len}");
        let padding_len = padding_len as usize;

        // Validation: data must be at least as long as the padding.
        ensure!(data.len() >= padding_len, "data too short for padding length");

        // Split data into content and padding.
        let (content, padding_bytes) = data.split_at(data.len() - padding_len);

        // Validation: verify ALL padding bytes have the correct value.
        // This check is crucial to prevent padding oracle attacks (though less relevant
        // here due to authenticated encryption, we still validate strictly).
        ensure!(padding_bytes.iter().all(|&b| b == padding_len as u8), "invalid PKCS#7 padding bytes");

        Ok(content.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_new() {
        assert!(Padding::new(16).is_ok());
        assert!(Padding::new(0).is_err());
        assert!(Padding::new(255).is_ok());
        assert!(Padding::new(256).is_err());
    }

    #[test]
    fn test_pad_exact_block_size() {
        let padding = Padding::new(8).unwrap();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let padded = padding.pad(&data).unwrap();

        // If exact multiple, adds full block of padding.
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[8..], &[8, 8, 8, 8, 8, 8, 8, 8]);
    }

    #[test]
    fn test_pad_partial_block() {
        let padding = Padding::new(8).unwrap();
        let data = vec![1, 2, 3, 4, 5]; // 5 bytes
        let padded = padding.pad(&data).unwrap();

        // Needs 3 bytes to reach 8. Padding value is 3.
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[5..], &[3, 3, 3]);
    }

    #[test]
    fn test_unpad_valid() {
        let padding = Padding::new(8).unwrap();
        let data = vec![1, 2, 3, 4, 5, 3, 3, 3];
        let unpadded = padding.unpad(&data).unwrap();
        assert_eq!(unpadded, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_unpad_invalid_padding_value() {
        let padding = Padding::new(8).unwrap();
        // Last byte says 2, but second to last is 3. Invalid.
        let data = vec![1, 2, 3, 4, 5, 3, 3, 2];
        assert!(padding.unpad(&data).is_err());
    }

    #[test]
    fn test_unpad_invalid_length() {
        let padding = Padding::new(8).unwrap();
        // Last byte says 9, but block size is 8.
        let data = vec![1, 2, 3, 9];
        assert!(padding.unpad(&data).is_err());
    }

    #[test]
    fn test_unpad_short_data() {
        let padding = Padding::new(8).unwrap();
        // Last byte says 5, but total length is 1.
        let data = vec![5];
        assert!(padding.unpad(&data).is_err());
    }
}
