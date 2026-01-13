//! PKCS7 padding implementation.

use anyhow::{Result, bail};

use crate::config::BLOCK_SIZE;

/// Maximum allowed block size for PKCS7 padding.
pub const MAX_BLOCK_SIZE: u8 = 255;

/// PKCS7 padding handler.
pub struct Padding {
    block_size: u8,
}

impl Padding {
    /// Creates a new padding handler with the given block size.
    ///
    /// # Arguments
    /// * `block_size` - The block size (1-255)
    pub fn new(block_size: u8) -> Result<Self> {
        if block_size == 0 {
            bail!("block size must be between 1 and 255");
        }

        Ok(Self { block_size })
    }

    /// Pads data to the block size using PKCS7.
    ///
    /// # Arguments
    /// * `data` - The data to pad
    ///
    /// # Returns
    /// The padded data
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        let padding_len = self.block_size - (data.len() % self.block_size as usize) as u8;
        let mut padded = Vec::with_capacity(data.len() + padding_len as usize);
        padded.extend_from_slice(data);
        padded.extend(std::iter::repeat_n(padding_len, padding_len as usize));
        padded
    }

    /// Removes PKCS7 padding from data.
    ///
    /// # Arguments
    /// * `data` - The padded data
    ///
    /// # Returns
    /// The unpadded data
    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let padding_len = *data.last().unwrap() as usize;

        if padding_len == 0 || padding_len > self.block_size as usize {
            bail!("invalid padding length");
        }

        if padding_len > data.len() {
            bail!("padding length exceeds data length");
        }

        // Verify all padding bytes are correct
        let padding_start = data.len() - padding_len;
        for byte in &data[padding_start..] {
            if *byte != padding_len as u8 {
                bail!("invalid padding bytes");
            }
        }

        Ok(data[..padding_start].to_vec())
    }
}

impl Default for Padding {
    fn default() -> Self {
        Self::new(BLOCK_SIZE).expect("valid default block size")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad() {
        let padding = Padding::default();
        let data = b"Hello, World!";

        let padded = padding.pad(data);
        assert_eq!(padded.len() % BLOCK_SIZE as usize, 0);

        let unpadded = padding.unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_exact_block() {
        let padding = Padding::new(16).unwrap();
        let data = vec![0u8; 16]; // Exactly one block

        let padded = padding.pad(&data);
        // Should add a full block of padding
        assert_eq!(padded.len(), 32);

        let unpadded = padding.unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_empty() {
        let padding = Padding::new(16).unwrap();
        let data = b"";

        let padded = padding.pad(data);
        assert_eq!(padded.len(), 16);
        assert!(padded.iter().all(|&b| b == 16));

        let unpadded = padding.unpad(&padded).unwrap();
        assert!(unpadded.is_empty());
    }

    #[test]
    fn test_unpad_empty() {
        let padding = Padding::default();
        assert!(padding.unpad(&[]).is_err());
    }

    #[test]
    fn test_unpad_invalid_padding() {
        let padding = Padding::new(16).unwrap();
        // Invalid padding byte (0)
        let invalid = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0];
        assert!(padding.unpad(&invalid).is_err());
    }

    #[test]
    fn test_invalid_block_size() {
        assert!(Padding::new(0).is_err());
    }
}
