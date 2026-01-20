use anyhow::{Result, anyhow, ensure};

pub struct Padding {
    block_size: usize,
}

impl Padding {
    pub fn new(block_size: usize) -> Result<Self> {
        ensure!(block_size > 0, "block size must be greater than 0");
        Ok(Self { block_size })
    }

    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");
        let padding_len = self.block_size - (data.len() % self.block_size);
        let padded = data.iter().copied().chain(std::iter::repeat_n(padding_len as u8, padding_len)).collect();

        Ok(padded)
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding_len = data.last().copied().ok_or_else(|| anyhow!("cannot unpad empty data"))?;
        ensure!(padding_len > 0 && padding_len <= self.block_size as u8, "invalid padding length: {padding_len}");

        let padding_len = padding_len as usize;
        ensure!(data.len() >= padding_len, "data too short for padding length");

        let (content, padding_bytes) = data.split_at(data.len() - padding_len);
        ensure!(padding_bytes.iter().all(|&b| b == padding_len as u8), "invalid PKCS#7 padding bytes");

        Ok(content.to_vec())
    }
}
