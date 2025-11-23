//! Shard management for Reed-Solomon encoding/decoding.
//!
//! This module handles splitting data into shards for erasure coding
//! and combining/extracting shards back into original data.

use anyhow::{anyhow, Result};

/// Manages data and parity shards for Reed-Solomon encoding.
///
/// Shards are fixed-size chunks of data used for error correction.
/// Data is split across multiple shards, with parity shards providing redundancy.
pub struct Shards {
    /// Number of data shards (minimum required for reconstruction)
    data_shards: usize,
    /// Total number of shards (data + parity)
    total_shards: usize,
}

impl Shards {
    /// Creates a new shard manager.
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards
    /// * `parity_shards` - Number of parity shards for redundancy
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            total_shards: data_shards + parity_shards,
        }
    }

    /// Splits data into shards for encoding.
    ///
    /// Data is distributed across shards in round-robin fashion.
    /// Remaining shards are zero-filled for parity generation.
    pub fn split(&self, data: &[u8]) -> Vec<Vec<u8>> {
        // Calculate shard size (rounded up to fit all data)
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut shards = vec![vec![0u8; shard_size]; self.total_shards];

        // Distribute data bytes across shards
        data.iter()
            .enumerate()
            .for_each(|(i, &byte)| shards[i / shard_size][i % shard_size] = byte);

        shards
    }

    /// Splits already-encoded data into shards for decoding.
    ///
    /// Used when reading encoded data from storage.
    pub fn split_encoded(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let shard_size = data.len() / self.total_shards;
        data.chunks(shard_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Combines shards back into continuous data.
    ///
    /// Flattens all shards into a single byte vector.
    pub fn combine(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        shards.iter().flatten().copied().collect()
    }

    /// Extracts original data from decoded shards.
    ///
    /// Only uses the first `data_shards` shards, discarding parity.
    pub fn extract(&self, shards: &[Vec<u8>]) -> Result<Vec<u8>> {
        if shards.len() < self.data_shards {
            return Err(anyhow!(
                "insufficient shards: have {}, need {}",
                shards.len(),
                self.data_shards
            ));
        }

        // Take only data shards and flatten into original data
        Ok(shards[..self.data_shards]
            .iter()
            .flatten()
            .copied()
            .collect())
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
        assert!(combined.starts_with(data));
    }
}
