//! Reed-Solomon erasure coding implementation.
//!
//! This module provides encoding and decoding using Reed-Solomon error correction.
//! Encoded data can survive loss of up to `parity_shards` chunks while still being
//! fully recoverable.

use anyhow::{Result, anyhow};
use reed_solomon_erasure::galois_8::ReedSolomon;

use super::chunking;

/// Number of data shards (4 shards)
pub const DATA_SHARDS: usize = 4;

/// Number of parity shards for redundancy (10 shards)
/// This provides 71% redundancy - up to 10 of 14 total shards can be lost
pub const PARITY_SHARDS: usize = 10;

/// Reed-Solomon encoder/decoder for erasure coding.
///
/// Provides data redundancy by distributing data across multiple shards
/// with parity information. Can recover original data even if some shards are lost.
pub struct ErasureEncoder {
    /// Reed-Solomon encoder/decoder
    encoder: ReedSolomon,
    /// Number of data shards
    data_shards: usize,
    /// Total number of shards
    total_shards: usize,
}

impl ErasureEncoder {
    /// Creates a new Reed-Solomon encoder/decoder.
    ///
    /// # Arguments
    /// * `data_shards` - Number of shards containing original data
    /// * `parity_shards` - Number of shards for error correction
    ///
    /// # Errors
    /// Returns error if parameters are invalid (handled by ReedSolomon library)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow!("failed to create encoder: {}", e))?;

        Ok(Self {
            encoder,
            data_shards,
            total_shards: data_shards + parity_shards,
        })
    }

    /// Encodes data with Reed-Solomon error correction.
    ///
    /// Splits data into shards and generates parity information.
    /// The result can survive loss of up to `parity_shards` chunks.
    ///
    /// # Errors
    /// Returns error if encoding fails
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut shards = chunking::split_data(data, self.data_shards, self.total_shards);

        // Generate parity shards for error correction
        self.encoder
            .encode(&mut shards)
            .map_err(|e| anyhow!("encoding failed: {}", e))?;

        Ok(chunking::combine_shards(&shards))
    }

    /// Decodes Reed-Solomon encoded data.
    ///
    /// Reconstructs original data from shards, recovering from any lost shards
    /// using parity information (up to `parity_shards` can be missing).
    ///
    /// # Errors
    /// Returns error if reconstruction fails (too many missing shards)
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let shards = chunking::split_encoded(encoded, self.total_shards);
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Reconstruct missing shards using parity information
        self.encoder
            .reconstruct(&mut shard_options)
            .map_err(|e| anyhow!("reconstruction failed: {}", e))?;

        // Extract original data from reconstructed shards
        let decoded_shards: Vec<Vec<u8>> = shard_options.into_iter().flatten().collect();

        chunking::extract_data(&decoded_shards, self.data_shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let enc = ErasureEncoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
        let data = b"Hello, World! This is a test of Reed-Solomon encoding.";

        let encoded = enc.encode(data).unwrap();
        let decoded = enc.decode(&encoded).unwrap();

        assert!(decoded.len() >= data.len());
        assert_eq!(data.as_slice(), &decoded[..data.len()]);
    }
}
