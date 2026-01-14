use anyhow::{Result, bail};

use crate::config::BLOCK_SIZE;

pub const MAX_BLOCK_SIZE: usize = 255;

pub struct Padding {
    block_size: usize,
}

impl Padding {
    pub fn new(block_size: usize) -> Result<Padding> {
        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            bail!("block size must be between 1 and 255, got {}", block_size);
        }
        Ok(Padding { block_size })
    }

    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let padding_len = self.block_size - (data.len() % self.block_size);
        let mut padded_data = data.to_vec();
        padded_data.extend(vec![padding_len as u8; padding_len]);
        Ok(padded_data)
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let data_len = data.len();
        let padding_len = data[data_len - 1] as usize;
        Ok(data[..data_len - padding_len].to_vec())
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

        let padded = padding.pad(data).unwrap();
        assert_eq!(padded.len() % BLOCK_SIZE, 0);

        let unpadded = padding.unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_exact_block() {
        let padding = Padding::new(16).unwrap();
        let data = vec![0u8; 16];
        let padded = padding.pad(&data).unwrap();

        assert_eq!(padded.len(), 32);
        let unpadded = padding.unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_empty() {
        let padding = Padding::new(16).unwrap();
        let data = b"";

        assert!(padding.pad(data).is_err());
    }

    #[test]
    fn test_unpad_empty() {
        let padding = Padding::default();
        assert!(padding.unpad(&[]).is_err());
    }

    #[test]
    fn test_unpad_invalid_padding() {
        let padding = Padding::new(16).unwrap();
        let valid = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1];
        let unpadded = padding.unpad(&valid).unwrap();
        assert_eq!(unpadded.len(), 15);
    }

    #[test]
    fn test_invalid_block_size() {
        assert!(Padding::new(0).is_err());
    }
}
