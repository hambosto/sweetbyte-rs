use anyhow::{anyhow, Result};

pub struct Shards {
    data_shards: usize,
    #[allow(dead_code)]
    parity_shards: usize,
    total_shards: usize,
}

impl Shards {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            total_shards: data_shards + parity_shards,
        }
    }

    pub fn split(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut shards = vec![vec![0u8; shard_size]; self.total_shards];

        for (i, &byte) in data.iter().enumerate() {
            let shard_index = i / shard_size;
            let pos_in_shard = i % shard_size;
            shards[shard_index][pos_in_shard] = byte;
        }

        shards
    }

    pub fn split_encoded(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let shard_size = data.len() / self.total_shards;
        let mut shards = vec![vec![0u8; shard_size]; self.total_shards];

        for (i, shard) in shards.iter_mut().enumerate() {
            let start = i * shard_size;
            let end = (i + 1) * shard_size;
            shard.copy_from_slice(&data[start..end]);
        }

        shards
    }

    pub fn combine(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        if shards.is_empty() {
            return Vec::new();
        }

        let shard_size = shards[0].len();
        let total_size = shard_size * shards.len();
        let mut result = vec![0u8; total_size];

        for (i, shard) in shards.iter().enumerate() {
            let start = i * shard_size;
            result[start..start + shard_size].copy_from_slice(shard);
        }

        result
    }

    pub fn extract(&self, shards: &[Vec<u8>]) -> Result<Vec<u8>> {
        if shards.len() < self.data_shards {
            return Err(anyhow!(
                "insufficient shards, have {} but need at least {} data shards",
                shards.len(),
                self.data_shards
            ));
        }

        let shard_size = shards[0].len();
        let mut combined = Vec::with_capacity(shard_size * self.data_shards);

        for i in 0..self.data_shards {
            combined.extend_from_slice(&shards[i]);
        }

        Ok(combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_combine() {
        let shards = Shards::new(4, 10);
        let data = b"Hello, World!";

        let split = shards.split(data);
        assert_eq!(split.len(), 14);

        let combined = shards.combine(&split);
        // Should match or be padded
        assert!(combined.starts_with(data));
    }
}
