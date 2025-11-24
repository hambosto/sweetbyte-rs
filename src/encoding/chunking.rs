//! Data chunking and manipulation utilities.
//!
//! This module handles splitting data into shards for erasure coding
//! and combining/extracting shards back into original data.

use anyhow::{Result, anyhow};

/// Splits data into shards for encoding.
///
/// Data is distributed across shards in round-robin fashion.
/// Remaining shards are zero-filled for parity generation.
pub fn split_data(data: &[u8], data_shards: usize, total_shards: usize) -> Vec<Vec<u8>> {
    // Calculate shard size (rounded up to fit all data)
    let shard_size = data.len().div_ceil(data_shards);
    let mut shards = vec![vec![0u8; shard_size]; total_shards];

    // Distribute data bytes across shards
    data.iter()
        .enumerate()
        .for_each(|(i, &byte)| shards[i / shard_size][i % shard_size] = byte);

    shards
}

/// Splits already-encoded data into shards for decoding.
///
/// Used when reading encoded data from storage.
pub fn split_encoded(data: &[u8], total_shards: usize) -> Vec<Vec<u8>> {
    let shard_size = data.len() / total_shards;
    data.chunks(shard_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Combines shards back into continuous data.
///
/// Flattens all shards into a single byte vector.
pub fn combine_shards(shards: &[Vec<u8>]) -> Vec<u8> {
    shards.iter().flatten().copied().collect()
}

/// Extracts original data from decoded shards.
///
/// Only uses the first `data_shards` shards, discarding parity.
pub fn extract_data(shards: &[Vec<u8>], data_shards: usize) -> Result<Vec<u8>> {
    if shards.len() < data_shards {
        return Err(anyhow!(
            "insufficient shards: have {}, need {}",
            shards.len(),
            data_shards
        ));
    }

    // Take only data shards and flatten into original data
    Ok(shards[..data_shards].iter().flatten().copied().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_combine() {
        let data = b"Hello, World!";
        let data_shards = 4;
        let total_shards = 14;

        let split = split_data(data, data_shards, total_shards);
        assert_eq!(split.len(), total_shards);

        let combined = combine_shards(&split);
        assert!(combined.starts_with(data));
    }
}
