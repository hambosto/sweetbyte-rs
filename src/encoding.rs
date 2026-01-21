//! Reed-Solomon error correction encoding.
//!
//! Implements erasure coding to add redundancy to encrypted data.
//! This allows recovery from partial data corruption, making encrypted
//! files resilient to bit rot, transmission errors, and media degradation.
//!
//! # Configuration
//!
//! SweetByte uses 4 data shards and 10 parity shards, providing
//! redundancy that allows recovery even if up to 10 shards are corrupted
//! or missing. The overhead ratio is 10/4 = 2.5x.
//!
//! # How It Works
//!
//! 1. **Encoding**: Data is split into N data shards, then M parity shards
//!    are computed algebraically. Total shards = N + M.
//! 2. **Decoding**: If some shards are corrupted/missing, the decoder uses
//!    the remaining good shards to reconstruct the original data.

use anyhow::{Result, ensure};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Reed-Solomon error correction encoder/decoder.
///
/// Provides encode and decode operations using Galois Field 256 (GF(256)).
/// Used to add redundancy to ciphertext and recover from corrupted data.
pub struct Encoding {
    /// The underlying Reed-Solomon encoder.
    encoder: ReedSolomon,

    /// Number of data shards (original data pieces).
    data_shards: usize,

    /// Number of parity shards (redundancy pieces).
    parity_shards: usize,
}

impl Encoding {
    /// Creates a new encoder with the specified shard counts.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards (must be >= 1).
    /// * `parity_shards` - Number of parity shards (must be >= 1).
    ///
    /// # Errors
    ///
    /// Returns an error if the Reed-Solomon encoder cannot be created
    /// with the specified shard counts.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = ReedSolomon::new(data_shards, parity_shards)?;
        Ok(Self { encoder, data_shards, parity_shards })
    }

    /// Encodes data by adding Reed-Solomon parity.
    ///
    /// Splits data into shards, computes parity, and returns combined output.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encode.
    ///
    /// # Errors
    ///
    /// Returns an error if data is empty or encoding fails.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "input data cannot be empty");

        // Split data into shards with space for parity
        let mut shards = self.split(data, false);

        // Compute parity shards from data shards
        self.encoder.encode(&mut shards)?;

        // Combine all shards into single output
        Ok(Self::combine(&shards))
    }

    /// Decodes data by reconstructing from possibly corrupted shards.
    ///
    /// Reconstructs missing/corrupted shards using available data
    /// and parity shards, then extracts the original data.
    ///
    /// The reconstruction process:
    /// 1. Split encoded data into individual shards
    /// 2. Mark shards as `Option<T>` (None for missing/corrupted)
    /// 3. Reed-Solomon reconstruct() fills in missing shards algebraically
    /// 4. Extract only the original data shards (discard parity)
    ///
    /// # Arguments
    ///
    /// * `encoded` - The encoded data (data + parity shards).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Data is empty
    /// - Length is not divisible by total shard count
    /// - Reconstruction fails (too many corrupted shards)
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        ensure!(!encoded.is_empty(), "encoded data cannot be empty");

        let total_shards = self.data_shards + self.parity_shards;

        // Verify encoded data size matches expected shard layout.
        // Each shard has equal size, so total must divide evenly.
        ensure!(encoded.len().is_multiple_of(total_shards), "encoded data length {} not divisible by total shards {}", encoded.len(), total_shards);

        // Split into individual shards.
        // Option<Vec<u8>> represents: Some(data) = good shard, None = corrupted/missing.
        // This allows reconstruct() to know which shards need recovery.
        let mut shards: Vec<Option<Vec<u8>>> = self.split(encoded, true).into_iter().map(Some).collect();

        // Reed-Solomon reconstruction:
        // Uses remaining good shards to algebraically recover corrupted ones.
        // Can recover up to parity_shards corrupted/missing shards.
        self.encoder.reconstruct(&mut shards)?;

        // Flatten Option<Vec<u8>> to Vec<Vec<u8>>, discarding None entries.
        // All shards should be Some at this point if reconstruction succeeded.
        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();

        // Extract original data by taking only first N shards (data_shards count).
        // Parity shards were only for error correction, not original data.
        Ok(self.extract(&reconstructed))
    }

    /// Splits data into fixed-size shards.
    ///
    /// The shard size calculation differs between encoding and decoding:
    /// - **Encoding**: Use ceil division so last shard isn't oversized
    /// - **Decoding**: Use exact division since encoded size is known
    ///
    /// # Arguments
    ///
    /// * `data` - The data to split.
    /// * `exact` - If true, shard size is data_len / total_shards.
    ///   If false, shard size is ceil(data_len / data_shards).
    ///
    /// # Returns
    ///
    /// A vector of shards (total = data_shards + parity_shards).
    fn split(&self, data: &[u8], exact: bool) -> Vec<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;

        // Calculate shard size based on mode:
        // - exact=false (encoding): ceil division ensures last data shard isn't oversized
        // - exact=true (decoding): exact division since we know the total encoded size
        let shard_size = if exact { data.len() / total_shards } else { data.len().div_ceil(self.data_shards) };

        // Pre-allocate all shard buffers with the calculated size.
        // This creates (data_shards + parity_shards) buffers, all same size.
        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0u8; shard_size]).collect();

        // Distribute input data across the first N shards (data_shards only).
        // Each chunk goes into its corresponding shard; remaining shards stay zeroed
        // and will be filled with parity during encoding.
        for (idx, chunk) in data.chunks(shard_size).enumerate() {
            if idx < self.data_shards {
                // Copy chunk into shard, preserving exact byte count
                shards[idx][..chunk.len()].copy_from_slice(chunk);
            }
        }

        shards
    }

    /// Combines multiple shards into a single byte vector.
    ///
    /// Used during encoding to flatten shards back into contiguous data
    /// after parity computation. The result is: data_shard_0 + data_shard_1 + ...
    ///
    /// # Arguments
    ///
    /// * `shards` - The shards to combine (all same size).
    ///
    /// # Returns
    ///
    /// Concatenated data from all shards.
    fn combine(shards: &[Vec<u8>]) -> Vec<u8> {
        // Calculate total capacity for single allocation (avoid reallocations)
        let total: usize = shards.iter().map(|s| s.len()).sum();
        let mut result = Vec::with_capacity(total);

        // Concatenate all shards in order. Each shard contributes its full contents.
        for shard in shards {
            result.extend_from_slice(shard);
        }

        result
    }

    /// Extracts data shards from reconstructed shards.
    ///
    /// Returns only the original data shards, excluding parity.
    /// After reconstruction, we have all shards but only need the first N.
    ///
    /// # Arguments
    ///
    /// * `shards` - All shards (data + parity).
    ///
    /// # Returns
    ///
    /// Concatenated data from data shards only.
    fn extract(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        // Calculate capacity based on first N shards only (data_shards count)
        let total: usize = shards.iter().take(self.data_shards).map(|s| s.len()).sum();
        let mut result = Vec::with_capacity(total);

        // Concatenate only the data shards (first N shards), skip parity.
        for shard in shards.iter().take(self.data_shards) {
            result.extend_from_slice(shard);
        }

        result
    }
}
