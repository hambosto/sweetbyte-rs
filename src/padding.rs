use anyhow::Result;

pub struct Padding {
    block_size: usize,
}

impl Padding {
    pub fn new(block_size: usize) -> Result<Self> {
        if block_size == 0 {
            anyhow::bail!("zero block size");
        }

        if block_size > 255 {
            anyhow::bail!("block size > 255");
        }

        Ok(Self { block_size })
    }

    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty data");
        }

        let padding_len = self.block_size - (data.len() % self.block_size);
        let padded = data.iter().copied().chain(std::iter::repeat_n(padding_len as u8, padding_len)).collect();

        Ok(padded)
    }

    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding_len = data.last().copied().ok_or_else(|| anyhow::anyhow!("empty data"))?;

        if !(padding_len > 0 && padding_len <= self.block_size as u8) {
            anyhow::bail!("invalid padding: {padding_len}");
        }
        let padding_len = padding_len as usize;

        if data.len() < padding_len {
            anyhow::bail!("data shorter than padding");
        }

        let (content, padding_bytes) = data.split_at(data.len() - padding_len);

        if !padding_bytes.iter().all(|&b| b == padding_len as u8) {
            anyhow::bail!("invalid padding bytes");
        }

        Ok(Vec::from(content))
    }
}
