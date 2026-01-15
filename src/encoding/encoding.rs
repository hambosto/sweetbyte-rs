use anyhow::{Result, anyhow, bail};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::shards::Shards;

pub const MAX_DATA_LEN: usize = 1 << 30;

pub struct Encoding {
    encoder: ReedSolomon,
    shards: Shards,
}

impl Encoding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = ReedSolomon::new(data_shards, parity_shards).map_err(|e| anyhow!("failed to create Reed-Solomon encoder: {:?}", e))?;

        Ok(Self { encoder, shards: Shards::new(data_shards, parity_shards) })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("input data cannot be empty");
        }

        if data.len() > MAX_DATA_LEN {
            bail!("data size {} exceeds maximum {} bytes", data.len(), MAX_DATA_LEN);
        }

        let mut shards = self.shards.split(data);
        self.encoder.encode(&mut shards).map_err(|e| anyhow!("Reed-Solomon encoding failed: {:?}", e))?;
        Ok(self.shards.combine(&shards))
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let total_shards = DATA_SHARDS + PARITY_SHARDS;

        if encoded.is_empty() {
            bail!("encoded data cannot be empty");
        }

        if !encoded.len().is_multiple_of(total_shards) {
            bail!("encoded data length {} not divisible by total shards {}", encoded.len(), total_shards);
        }

        let mut shards: Vec<Option<Vec<u8>>> = self.shards.split_encoded(encoded).into_iter().map(Some).collect();
        self.encoder.reconstruct(&mut shards).map_err(|e| anyhow::anyhow!("Reed-Solomon reconstruction failed: {:?}", e))?;

        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();
        self.shards.extract(&reconstructed)
    }
}

impl Default for Encoding {
    fn default() -> Self {
        Self::new(DATA_SHARDS, PARITY_SHARDS).expect("valid default parameters")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let rs = Encoding::default();
        let data = b"Hello, World! This is some test data for Reed-Solomon.";
        let encoded = rs.encode(data).unwrap();
        let decoded = rs.decode(&encoded).unwrap();
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_encode_empty() {
        let rs = Encoding::default();
        assert!(rs.encode(b"").is_err());
    }

    #[test]
    fn test_decode_empty() {
        let rs = Encoding::default();
        assert!(rs.decode(&[]).is_err());
    }

    #[test]
    fn test_decode_invalid_length() {
        let rs = Encoding::default();
        assert!(rs.decode(&[0u8; 15]).is_err());
    }
}
