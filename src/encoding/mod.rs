use anyhow::{Result, anyhow, bail};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::config::TOTAL_SHARDS;
use crate::encoding::shards::Shards;

mod shards;

pub struct Encoding {
    encoder: ReedSolomon,
    shards: Shards,
}

impl Encoding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(Self { encoder: ReedSolomon::new(data_shards, parity_shards).map_err(|e| anyhow!("failed to create reed-solomon encoder: {}", e))?, shards: Shards::new(data_shards, parity_shards) })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("input data cannot be empty");
        }

        let mut shards = self.shards.split(data, false);
        self.encoder.encode(&mut shards).map_err(|e| anyhow!("reed-solomon encoding failed: {}", e))?;
        Ok(self.shards.combine(&shards))
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.is_empty() {
            bail!("encoded data cannot be empty");
        }
        if !encoded.len().is_multiple_of(TOTAL_SHARDS) {
            bail!("encoded data length {} not divisible by total shards {}", encoded.len(), TOTAL_SHARDS);
        }

        let mut shards: Vec<Option<Vec<u8>>> = self.shards.split(encoded, true).into_iter().map(Some).collect();
        self.encoder.reconstruct(&mut shards).map_err(|e| anyhow!("reed-solomon reconstruction failed: {}", e))?;

        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();
        self.shards.extract(&reconstructed)
    }
}
