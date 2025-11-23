use anyhow::{anyhow, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

use super::shards::Shards;

const MAX_DATA_LEN: usize = 1 << 30;
pub const DATA_SHARDS: usize = 4;
pub const PARITY_SHARDS: usize = 10;

pub struct Encoding {
    data_shards: usize,
    parity_shards: usize,
    encoder: ReedSolomon,
    shards: Shards,
}

impl Encoding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 {
            return Err(anyhow!("data shards must be positive"));
        }
        if parity_shards == 0 {
            return Err(anyhow!("parity shards must be positive"));
        }
        if data_shards + parity_shards > 255 {
            return Err(anyhow!("total shards cannot exceed 255"));
        }

        let encoder = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow!("failed to create reed-solomon encoder: {}", e))?;

        Ok(Self {
            data_shards,
            parity_shards,
            encoder,
            shards: Shards::new(data_shards, parity_shards),
        })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("input data cannot be empty"));
        }
        if data.len() > MAX_DATA_LEN {
            return Err(anyhow!(
                "data size {} exceeds maximum {} bytes",
                data.len(),
                MAX_DATA_LEN
            ));
        }

        let mut shards = self.shards.split(data);

        self.encoder
            .encode(&mut shards)
            .map_err(|e| anyhow!("encoding failed: {}", e))?;

        Ok(self.shards.combine(&shards))
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;

        if encoded.is_empty() {
            return Err(anyhow!("encoded data cannot be empty"));
        }
        if encoded.len() % total_shards != 0 {
            return Err(anyhow!(
                "encoded data length {} not divisible by total shards {}",
                encoded.len(),
                total_shards
            ));
        }

        let shards = self.shards.split_encoded(encoded);
        // Convert to Option<Vec<u8>> for reconstruction
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        self.encoder
            .reconstruct(&mut shard_options)
            .map_err(|e| anyhow!("reconstruction failed: {}", e))?;

        // Convert back to Vec<Vec<u8>>
        let decoded_shards: Vec<Vec<u8>> = shard_options
            .into_iter()
            .map(|s| s.unwrap_or_default())
            .collect();

        self.shards.extract(&decoded_shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let enc = Encoding::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
        let data = b"Hello, World! This is a test of Reed-Solomon encoding.";

        let encoded = enc.encode(data).unwrap();
        let decoded = enc.decode(&encoded).unwrap();

        // Reed-Solomon encoding may add padding to align with shard size
        assert!(decoded.len() >= data.len());
        assert_eq!(data.as_slice(), &decoded[..data.len()]);
    }
}
