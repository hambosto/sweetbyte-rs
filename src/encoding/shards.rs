use anyhow::{Result, bail};

pub struct Shards {
    data_shards: usize,
    parity_shards: usize,
}

impl Shards {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self { data_shards, parity_shards }
    }

    pub fn split(&self, data: &[u8], exact: bool) -> Vec<Vec<u8>> {
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

    pub fn combine(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        let mut result = Vec::with_capacity(shards.iter().map(|s| s.len()).sum());
        for shard in shards {
            result.extend_from_slice(shard);
        }
        result
    }

    pub fn extract(&self, shards: &[Vec<u8>]) -> Result<Vec<u8>> {
        if shards.len() < self.data_shards {
            bail!("insufficient shards, have {} but need at least {} data shards", shards.len(), self.data_shards);
        }

        let mut result = Vec::with_capacity(shards.iter().take(self.data_shards).map(|s| s.len()).sum());
        for shard in shards.iter().take(self.data_shards) {
            result.extend_from_slice(shard);
        }
        Ok(result)
    }
}
