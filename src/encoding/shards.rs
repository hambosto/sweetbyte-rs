use anyhow::{Result, bail};

use crate::config::{DATA_SHARDS, PARITY_SHARDS};

pub struct Shards {
    data_shards: usize,
    total_shards: usize,
}

impl Shards {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self { data_shards, total_shards: data_shards + parity_shards }
    }

    pub fn split(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let shard_size = data.len().div_ceil(self.data_shards);
        let mut shards: Vec<Vec<u8>> = (0..self.total_shards).map(|_| vec![0u8; shard_size]).collect();

        for (i, byte) in data.iter().enumerate() {
            let shard_index = i / shard_size;
            let pos_in_shard = i % shard_size;
            if shard_index < self.data_shards {
                shards[shard_index][pos_in_shard] = *byte;
            }
        }

        shards
    }

    pub fn split_encoded(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let shard_size = data.len() / self.total_shards;
        let mut shards = Vec::with_capacity(self.total_shards);

        for i in 0..self.total_shards {
            let start = i * shard_size;
            let end = start + shard_size;
            shards.push(data[start..end].to_vec());
        }

        shards
    }

    pub fn combine(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        if shards.is_empty() {
            return Vec::new();
        }

        let shard_size = shards[0].len();
        let total_size = shard_size * shards.len();
        let mut result = Vec::with_capacity(total_size);

        for shard in shards {
            result.extend_from_slice(shard);
        }

        result
    }

    pub fn extract(&self, shards: &[Vec<u8>]) -> Result<Vec<u8>> {
        if shards.len() < self.data_shards {
            bail!("insufficient shards, have {} but need at least {} data shards", shards.len(), self.data_shards);
        }

        let shard_size = shards[0].len();
        let mut combined = Vec::with_capacity(shard_size * self.data_shards);

        for shard in shards.iter().take(self.data_shards) {
            combined.extend_from_slice(shard);
        }

        Ok(combined)
    }
}

impl Default for Shards {
    fn default() -> Self {
        Self::new(DATA_SHARDS, PARITY_SHARDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TOTAL_SHARDS;

    #[test]
    fn test_split_and_extract() {
        let shards_handler = Shards::new(DATA_SHARDS, PARITY_SHARDS);
        let data = b"Hello, World! This is a test.";

        let shards = shards_handler.split(data);
        assert_eq!(shards.len(), TOTAL_SHARDS);

        let shard_size = shards[0].len();
        for shard in &shards {
            assert_eq!(shard.len(), shard_size);
        }
    }

    #[test]
    fn test_combine() {
        let shards_handler = Shards::new(4, 10);
        let shards: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4], vec![5, 6], vec![7, 8]];

        let combined = shards_handler.combine(&shards);
        assert_eq!(combined, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_split_encoded_roundtrip() {
        let shards_handler = Shards::new(4, 10);

        let encoded: Vec<u8> = (0..56).collect();

        let shards = shards_handler.split_encoded(&encoded);
        assert_eq!(shards.len(), 14);
        assert_eq!(shards[0].len(), 4);

        let recombined = shards_handler.combine(&shards);
        assert_eq!(recombined, encoded);
    }
}
