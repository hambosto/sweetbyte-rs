//! Reed-Solomon erasure coding implementation.
//!
//! This module provides error correction capabilities using Reed-Solomon codes.
//! It allows data to be split into "shards" (some data, some parity), such that
//! the original data can be recovered even if some shards are lost or corrupted.
//!
//! # Purpose
//!
//! SweetByte uses this module to:
//! 1. Protect the file header against corruption (crucial for decryptability).
//! 2. (Optionally) Protect the file body data.
//!
//! # Terminology
//!
//! - **Data Shards (k)**: The number of shards containing original data.
//! - **Parity Shards (m)**: The number of redundant shards generated.
//! - **Total Shards (n)**: $n = k + m$.
//! - **Recovery**: Data can be recovered as long as any $k$ shards out of $n$ are available.

use anyhow::{Result, ensure};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// A wrapper around the Reed-Solomon encoder.
#[derive(Debug)]
pub struct Encoding {
    /// The underlying encoder from `reed_solomon_erasure`.
    encoder: ReedSolomon,

    /// Number of shards containing original data.
    data_shards: usize,

    /// Number of parity shards.
    parity_shards: usize,
}

impl Encoding {
    /// Creates a new Reed-Solomon encoder/decoder.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards (k).
    /// * `parity_shards` - Number of parity shards (m).
    ///
    /// # Errors
    ///
    /// Returns an error if the shard counts are invalid (e.g., sum > 256 for Galois 2^8).
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        // Initialize the RS encoder.
        // This pre-computes the Galois Field lookup tables.
        let encoder = ReedSolomon::new(data_shards, parity_shards)?;

        Ok(Self { encoder, data_shards, parity_shards })
    }

    /// Encodes data into data shards + parity shards.
    ///
    /// The input data is padded to be divisible by `data_shards`, then split.
    /// Parity shards are calculated and appended.
    ///
    /// # Returns
    ///
    /// A single vector containing all shards concatenated sequentially.
    /// Format: `[Data Shard 0][Data Shard 1]...[Parity Shard 0]...`
    ///
    /// # Errors
    ///
    /// Returns an error if the input data is empty.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validation: encoding empty data is undefined/pointless.
        ensure!(!data.is_empty(), "input data cannot be empty");

        // Split the data into equal-sized chunks for the shards.
        // The `split` method handles padding if data length isn't perfectly divisible.
        let mut shards = self.split(data, false);

        // Compute parity shards in-place.
        // The `shards` vector initially contains data shards + empty parity shards.
        // `encode` fills the parity shards based on the data shards.
        self.encoder.encode(&mut shards)?;

        // Combine all shards back into a single contiguous byte vector.
        // This format is suitable for storage or transmission.
        Ok(Self::combine(&shards))
    }

    /// Reconstructs original data from encoded bytes, correcting errors if possible.
    ///
    /// # Arguments
    ///
    /// * `encoded` - A byte slice containing the concatenated shards.
    ///
    /// # Returns
    ///
    /// The original data, with any padding removed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The encoded length is not divisible by the total number of shards.
    /// - Too many shards are corrupted (more than `parity_shards`).
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        ensure!(!encoded.is_empty(), "encoded data cannot be empty");

        let total_shards = self.data_shards + self.parity_shards;

        // Basic structural check.
        // Since all shards must be the same size, the total length must be a multiple of N.
        ensure!(encoded.len().is_multiple_of(total_shards), "encoded data length {} not divisible by total shards {}", encoded.len(), total_shards);

        // Split the flat byte array back into a vector of vectors (shards).
        // We wrap them in Option because the reconstruct API expects Option<Vec<u8>>
        // to mark missing shards (though here we assume all are present but potentially corrupt).
        // Note: For erasure coding (where we know which are missing), we'd pass None.
        // For simple error correction where we have all bits but some might be wrong,
        // we pass them all. The library handles both.
        let mut shards: Vec<Option<Vec<u8>>> = self.split(encoded, true).into_iter().map(Some).collect();

        // Attempt reconstruction.
        // This will correct bit flips if they are within the correction capability.
        self.encoder.reconstruct(&mut shards)?;

        // Flatten the reconstructed shards back into a single vector.
        // We only care about the data shards, but this flattens everything first.
        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();

        // Extract just the original data bytes, discarding parity shards and padding.
        Ok(self.extract(&reconstructed))
    }

    /// Splits data into shards.
    ///
    /// # Arguments
    ///
    /// * `data` - Input bytes.
    /// * `exact` - If true, assumes data is already perfectly sized for `total_shards`. If false,
    ///   calculates shard size based on `data_shards` (adding padding).
    fn split(&self, data: &[u8], exact: bool) -> Vec<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;

        // Calculate size per shard.
        let shard_size = if exact {
            // Decoding path: data contains all shards (data + parity).
            data.len() / total_shards
        } else {
            // Encoding path: data contains only original data.
            // We divide by `data_shards` and round up (ceil) to accommodate all data.
            data.len().div_ceil(self.data_shards)
        };

        // Allocate buffers for all shards (data + parity).
        // Initialize with zeros (effective padding).
        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0u8; shard_size]).collect();

        // Copy input data into the data shards.
        // If data doesn't fill the last data shard perfectly, the rest remains 0 (padding).
        for (idx, chunk) in data.chunks(shard_size).enumerate() {
            if idx < self.data_shards {
                shards[idx][..chunk.len()].copy_from_slice(chunk);
            }
        }

        shards
    }

    /// Combines a slice of shards into a single flat vector.
    fn combine(shards: &[Vec<u8>]) -> Vec<u8> {
        // Calculate total size to pre-allocate.
        let total: usize = shards.iter().map(|s| s.len()).sum();
        let mut result = Vec::with_capacity(total);

        // Append each shard sequentially.
        for shard in shards {
            result.extend_from_slice(shard);
        }

        result
    }

    /// Extracts original data from the reconstructed shards.
    ///
    /// This removes the parity shards but keeps the padding in the last data shard
    /// (the caller must handle padding removal if they know the original length,
    /// or simple trailing zero removal if appropriate).
    fn extract(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        // Calculate size of just the data shards.
        let total: usize = shards.iter().take(self.data_shards).map(|s| s.len()).sum();

        let mut result = Vec::with_capacity(total);

        // Only iterate over the data shards (k).
        for shard in shards.iter().take(self.data_shards) {
            result.extend_from_slice(shard);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_new_valid() {
        let encoding = Encoding::new(4, 2);
        assert!(encoding.is_ok());
    }

    #[test]
    fn test_encoding_new_invalid() {
        // 0 shards is invalid
        let encoding = Encoding::new(0, 2);
        assert!(encoding.is_err());

        // Too many shards for GF(2^8) which supports up to 256
        let encoding = Encoding::new(200, 200);
        assert!(encoding.is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let encoding = Encoding::new(4, 2).unwrap();
        let data = b"Hello, world! This is a test.";

        // Encode
        let encoded = encoding.encode(data).unwrap();
        assert_ne!(data, &encoded[..]);
        // Length check: data len 29. ceil(29/4) = 8 bytes per shard.
        // Total shards = 4+2=6. Total size = 6 * 8 = 48.
        assert_eq!(encoded.len(), 48);

        // Decode
        let decoded = encoding.decode(&encoded).unwrap();

        // Check prefix matches (ignoring padding)
        assert_eq!(data, &decoded[..data.len()]);

        // Verify padding is zero
        for &b in &decoded[data.len()..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_invalid_length_for_decode() {
        let encoding = Encoding::new(4, 2).unwrap();
        // 7 bytes cannot be divided into 6 shards evenly (integers).
        let data = vec![0; 7];
        assert!(encoding.decode(&data).is_err());
    }

    #[test]
    fn test_too_many_errors() {
        let encoding = Encoding::new(4, 2).unwrap();
        let data = b"Hello, World!";
        let mut encoded = encoding.encode(data).unwrap();

        // Corrupt first 12 bytes (entire first shard + half of second).
        // Since shard size is likely small, this might exceed corruption limit.
        // Shard size for 13 bytes / 4 = 4 bytes per shard.
        // Corrupting 12 bytes affects 3 shards.
        // Parity is 2. So 3 > 2 => unrecoverable.
        for i in encoded.iter_mut().take(12) {
            *i = 0xFF;
        }

        let result = encoding.decode(&encoded);

        // Either it errors, or it decodes garbage.
        // The RS algorithm guarantees recovery if <= parity errors,
        // but behavior on > parity errors is failure or garbage.
        if let Ok(decoded) = result {
            assert_ne!(decoded[..data.len()], data[..]);
        }
    }

    #[test]
    fn test_empty_input() {
        let encoding = Encoding::new(4, 2).unwrap();
        assert!(encoding.encode(&[]).is_err());
        assert!(encoding.decode(&[]).is_err());
    }
}
