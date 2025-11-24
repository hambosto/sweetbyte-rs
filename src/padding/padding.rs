//! PKCS#7 padding implementation for block cipher operations.
//!
//! This module provides functionality to add and remove padding from data to ensure
//! it aligns with block cipher requirements. The padding scheme follows PKCS#7 standard,
//! where the padding value indicates the number of padding bytes added.

use anyhow::{anyhow, Result};

/// Default block size for padding operations (128 bits / 16 bytes for AES).
///
/// This is the standard block size for AES encryption algorithms.
pub const DEFAULT_PADDING_BLOCK_SIZE: usize = 16;

/// PKCS#7 padding manager for block cipher operations.
///
/// This struct handles adding and removing padding to data to ensure it aligns
/// with the specified block size. The padding scheme follows PKCS#7 standard.
///
/// # Examples
///
/// ```
/// use sweetbyte_rs::padding::Padding;
///
/// let padding = Padding::new(16).unwrap();
/// let data = b"Hello, World!";
///
/// // Pad the data to align with block size
/// let padded = padding.pad(data).unwrap();
/// assert_eq!(padded.len() % 16, 0);
///
/// // Unpad to get original data back
/// let original = padding.unpad(&padded).unwrap();
/// assert_eq!(data, original.as_slice());
/// ```
pub struct Padding {
    /// The block size in bytes that data should be padded to.
    /// Must be between 1 and 255 to fit in a single byte.
    block_size: usize,
}

impl Padding {
    /// Creates a new `Padding` instance with the specified block size.
    ///
    /// # Arguments
    ///
    /// * `block_size` - The block size in bytes (must be between 1 and 255)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Padding)` if the block size is valid, or an error if the block size
    /// is 0 or greater than 255.
    ///
    /// # Errors
    ///
    /// Returns an error if `block_size` is 0 or greater than 255, as these values
    /// cannot be represented in the PKCS#7 padding scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::padding::Padding;
    ///
    /// // Valid block size
    /// let padding = Padding::new(16).unwrap();
    ///
    /// // Invalid block size (too large)
    /// assert!(Padding::new(256).is_err());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::padding::Padding;
    ///
    /// let padding = Padding::new(16).unwrap();
    /// let data = b"Hello";  // 5 bytes
    ///
    /// let padded = padding.pad(data).unwrap();
    /// // Result: [H, e, l, l, o, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11]
    /// assert_eq!(padded.len(), 16);  // Padded to next block boundary
    /// ```
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Calculate how many padding bytes are needed to reach the next block boundary
        let padding = self.block_size - (data.len() % self.block_size);

        // Pre-allocate the exact size needed for efficiency
        let mut padded_data = Vec::with_capacity(data.len() + padding);

        // Copy the original data
        padded_data.extend_from_slice(data);

        // Append padding bytes, each with value equal to the number of padding bytes
        // This follows PKCS#7 standard where the padding value indicates padding length
        padded_data.extend(std::iter::repeat(padding as u8).take(padding));

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
    ///
    /// # Examples
    ///
    /// ```
    /// use sweetbyte_rs::padding::Padding;
    ///
    /// let padding = Padding::new(16).unwrap();
    /// let data = b"Hello";
    ///
    /// let padded = padding.pad(data).unwrap();
    /// let original = padding.unpad(&padded).unwrap();
    ///
    /// assert_eq!(data, original.as_slice());
    /// ```
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
        let padding = Padding::new(16).unwrap();
        let data = b"Hello, World!";

        let padded = padding.pad(data).unwrap();
        assert_eq!(padded.len() % 16, 0);

        let unpadded = padding.unpad(&padded).unwrap();
        assert_eq!(data.as_slice(), unpadded.as_slice());
    }
}
