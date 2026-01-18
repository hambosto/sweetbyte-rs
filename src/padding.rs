use anyhow::{Result, anyhow, bail};

pub const MAX_BLOCK_SIZE: usize = 255;

pub struct Padding {
    block_size: usize,
}

impl Padding {
    pub fn new(block_size: usize) -> Result<Self> {
        (block_size > 0 && block_size <= MAX_BLOCK_SIZE)
            .then_some(Self { block_size })
            .ok_or_else(|| anyhow!("block size must be between 1 and 255, got {}", block_size))
    }

    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let padding_len = self.block_size - (data.len() % self.block_size);
        let mut padded_data = Vec::with_capacity(data.len() + padding_len);
        padded_data.extend_from_slice(data);
        padded_data.extend(std::iter::repeat_n(padding_len as u8, padding_len));
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
