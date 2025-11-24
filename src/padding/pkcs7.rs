//! PKCS#7 padding implementation for block cipher operations.
//!
//! This module provides functionality to add and remove padding from data to ensure
//! it aligns with block cipher requirements. The padding scheme follows PKCS#7 standard,
//! where the padding value indicates the number of padding bytes added.

use anyhow::{Result, anyhow};

/// Default block size for padding operations (128 bits / 16 bytes for AES).
/// This is the standard block size for AES encryption algorithms.
pub const BLOCK_SIZE: usize = 16;

/// PKCS#7 padding manager for block cipher operations.
///
/// This struct handles adding and removing padding to data to ensure it aligns
/// with the specified block size. The padding scheme follows PKCS#7 standard.
pub struct Pkcs7Padding {
    /// The block size in bytes that data should be padded to.
    /// Must be between 1 and 255 to fit in a single byte.
    block_size: usize,
}

impl Pkcs7Padding {
    /// Creates a new `Pkcs7Padding` instance with the specified block size.
    ///
    /// # Arguments
    ///
    /// * `block_size` - The block size in bytes (must be between 1 and 255)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Pkcs7Padding)` if the block size is valid, or an error if the block size
    /// is 0 or greater than 255.
    ///
    /// # Errors
    ///
    /// Returns an error if `block_size` is 0 or greater than 255, as these values
    /// cannot be represented in the PKCS#7 padding scheme.
    pub fn new(block_size: usize) -> Result<Self> {
        // Validate block size is within PKCS#7 limits (1-255)
        if block_size == 0 || block_size > 255 {
            return Err(anyhow!(
                "block size must be between 1 and 255, got {}",
                block_size
            ));
        }
        Ok(Self { block_size })
    }

    /// Pads the input data using PKCS#7 padding scheme.
    ///
    /// The data is padded to align with the block size. The padding value indicates
    /// the number of padding bytes added. For example, if 3 bytes of padding are needed,
    /// three bytes with value `0x03` are appended.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be padded
    ///
    /// # Returns
    ///
    /// Returns a new `Vec<u8>` containing the original data followed by padding bytes.
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Calculate how many padding bytes are needed to reach the next block boundary
        let padding = self.block_size - (data.len() % self.block_size);

        // Pre-allocate the exact size needed for efficiency
        let mut padded_data = Vec::with_capacity(data.len() + padding);

        // Copy the original data
        padded_data.extend_from_slice(data);

        // Append padding bytes, each with value equal to the number of padding bytes
        // This follows PKCS#7 standard where the padding value indicates padding length
        padded_data.extend(std::iter::repeat_n(padding as u8, padding));

        Ok(padded_data)
    }

    /// Removes PKCS#7 padding from the input data.
    ///
    /// The last byte of the data indicates how many padding bytes to remove.
    /// This reverses the operation performed by `pad()`.
    ///
    /// # Arguments
    ///
    /// * `data` - The padded data
    ///
    /// # Returns
    ///
    /// Returns a new `Vec<u8>` containing the original data without padding.
    ///
    /// # Note
    ///
    /// This function assumes the data is properly padded. Invalid padding may result
    /// in incorrect data or panics. Consider adding validation in production code.
    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let length = data.len();

        // Read the last byte which indicates the number of padding bytes
        let unpadded_data = data[length - 1] as usize;

        // Return the data without the padding bytes
        Ok(data[..length - unpadded_data].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad() {
        let padding = Pkcs7Padding::new(16).unwrap();
        let data = b"Hello, World!";

        let padded = padding.pad(data).unwrap();
        assert_eq!(padded.len() % 16, 0);

        let unpadded = padding.unpad(&padded).unwrap();
        assert_eq!(data.as_slice(), unpadded.as_slice());
    }
}
