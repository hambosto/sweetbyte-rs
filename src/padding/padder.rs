use anyhow::{anyhow, Result};

const BLOCK_SIZE: usize = 16;
const MAX_BLOCK_SIZE: usize = 255;

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
        let len = data.len();
        let padding_len = self.block_size - (len % self.block_size);
        let mut padded = Vec::with_capacity(len + padding_len);
        padded.extend_from_slice(data);
        padded.resize(len + padding_len, padding_len as u8);
        Ok(padded)
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("data cannot be empty"));
        }

        let len = data.len();
        let padding_len = data[len - 1] as usize;

        if padding_len == 0 || padding_len > self.block_size || padding_len > len {
            return Err(anyhow!("invalid padding"));
        }

        // Verify all padding bytes
        for i in 0..padding_len {
            if data[len - 1 - i] != padding_len as u8 {
                return Err(anyhow!("invalid padding"));
            }
        }

        Ok(data[..len - padding_len].to_vec())
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
