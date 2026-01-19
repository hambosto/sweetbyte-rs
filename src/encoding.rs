use anyhow::{Result, bail};
use reed_solomon_erasure::galois_8::ReedSolomon;

pub struct Encoding {
    encoder: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl Encoding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = ReedSolomon::new(data_shards, parity_shards)?;
        Ok(Self { encoder, data_shards, parity_shards })
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("input data cannot be empty");
        }

        let mut shards = self.split(data, false);
        self.encoder.encode(&mut shards)?;
        Ok(self.combine(&shards))
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.is_empty() {
            bail!("encoded data cannot be empty");
        }

        let mut shards: Vec<Option<Vec<u8>>> = self.split(encoded, true).into_iter().map(Some).collect();
        self.encoder.reconstruct(&mut shards)?;

        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();
        Ok(self.extract(&reconstructed))
    }

    fn split(&self, data: &[u8], exact: bool) -> Vec<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;
        let shard_size = if exact { data.len() / total_shards } else { data.len().div_ceil(self.data_shards) };
        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0u8; shard_size]).collect();
        for (idx, chunk) in data.chunks(shard_size).enumerate() {
            if idx < self.data_shards {
                shards[idx][..chunk.len()].copy_from_slice(chunk);
            }
        }

        shards
    }

    fn combine(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        let mut result = Vec::with_capacity(shards.iter().map(|s| s.len()).sum());
        for shard in shards {
            result.extend_from_slice(shard);
        }

        result
    }

    fn extract(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        let mut result = Vec::with_capacity(shards.iter().take(self.data_shards).map(|s| s.len()).sum());
        for shard in shards.iter().take(self.data_shards) {
            result.extend_from_slice(shard);
        }

        result
    }
}
