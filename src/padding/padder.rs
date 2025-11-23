use anyhow::{anyhow, Result};

const BLOCK_SIZE: usize = 16;
const MAX_BLOCK_SIZE: usize = 255;

/// PKCS#7 padding implementation.
///
/// This is a manual implementation instead of using the `block-padding` crate
/// because that crate has stricter runtime constraints that cause panics
/// with certain block sizes. Our manual implementation provides the flexibility
/// needed for this encryption pipeline.
pub struct Padding {
    block_size: usize,
}

impl Padding {
    pub fn new(block_size: usize) -> Result<Self> {
        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            return Err(anyhow!(
                "block size must be between 1 and 255, got {}",
                block_size
            ));
        }
        Ok(Self { block_size })
    }

    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding_len = self.block_size - (data.len() % self.block_size);
        let mut padded = data.to_vec();
        padded.extend(vec![padding_len as u8; padding_len]);
        Ok(padded)
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding_len = *data.last().ok_or_else(|| anyhow!("data cannot be empty"))? as usize;
        if padding_len == 0 || padding_len > data.len() {
            return Err(anyhow!("invalid padding"));
        }
        Ok(data[..data.len() - padding_len].to_vec())
    }
}

impl Default for Padding {
    fn default() -> Self {
        Self {
            block_size: BLOCK_SIZE,
        }
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
