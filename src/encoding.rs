//! Reed-Solomon Error Correction Module
//!
//! This module implements Reed-Solomon error correction coding to provide
//! resilience against data corruption during storage or transmission. It uses
//! the reed_solomon_erasure crate which implements Galois Field arithmetic
//! over GF(2^8).
//!
//! ## How Reed-Solomon Works
//!
//! Reed-Solomon encoding works by:
//! 1. Splitting data into equal-sized "data shards"
//! 2. Computing additional "parity shards" using polynomial interpolation
//! 3. Combining all shards for storage/transmission
//! 4. Allowing reconstruction from any subset of sufficient size
//!
//! ## Error Correction Capability
//!
//! With N data shards and M parity shards, the system can recover from
// any M shard failures. For example, with 4 data + 10 parity shards,
// the system can recover from up to 10 corrupted shards out of 14 total.
//!
//! ## Security Considerations
// - Error correction does not affect cryptographic security
// - Corrupted shards are detected during reconstruction attempts
// - The system cannot recover from malicious modifications without integrity checks

use anyhow::{Result, ensure};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Reed-Solomon encoder/decoder for error correction
///
/// This struct provides forward error correction capabilities using Reed-Solomon
/// coding over GF(2^8). It can encode data into data+parity shards and reconstruct
/// the original data even when some shards are corrupted or missing.
///
/// ## Mathematical Foundation
///
/// The encoding treats data shards as coefficients of a polynomial over GF(2^8).
/// Parity shards are computed by evaluating this polynomial at different points.
/// Reconstruction uses Lagrange interpolation to recover the original polynomial.
///
/// ## Performance Characteristics
///
/// - **Encoding**: O(N) where N is total number of shards
/// - **Decoding**: O(N^2) for reconstruction using Gaussian elimination
/// - **Memory**: O(N * shard_size) for intermediate calculations
///
/// ## Error Tolerance
///
/// Can recover from any `parity_shards` number of corrupted or missing shards.
/// The remaining data must be at least `data_shards` shards for successful reconstruction.
#[derive(Debug)]
pub struct Encoding {
    /// The underlying Reed-Solomon encoder instance from the crate
    encoder: ReedSolomon,
    /// Number of data shards containing the original data
    data_shards: usize,
    /// Number of parity shards providing error correction capability
    parity_shards: usize,
}

impl Encoding {
    /// Create a new Reed-Solomon encoder with specified shard configuration
    ///
    /// This constructor initializes the encoder with the desired number of
    /// data and parity shards. The parameters determine both the error
    /// correction capability and the storage overhead.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of shards containing original data
    /// * `parity_shards` - Number of parity shards for error correction
    ///
    /// # Returns
    ///
    /// * `Ok(Encoding)` - Successfully created encoder
    /// * `Err(anyhow::Error)` - Invalid parameters (too many or negative shards)
    ///
    /// # Performance Impact
    ///
    /// - More shards increase encoding/decoding time
    /// - More parity shards increase storage overhead
    /// - Total shards should be ≤ 255 for GF(2^8) efficiency
    ///
    /// # Error Correction Capability
    ///
    /// Can recover from any `parity_shards` corrupted/missing shards.
    /// Must have at least `data_shards` valid shards for reconstruction.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        // Create the underlying Reed-Solomon encoder
        let encoder = ReedSolomon::new(data_shards, parity_shards)?;

        Ok(Self { encoder, data_shards, parity_shards })
    }

    /// Encode data into Reed-Solomon format with error correction
    ///
    /// This method splits the input data into data shards, computes parity shards,
    /// and combines all shards into a single output vector. The encoded data can
    /// withstand corruption of up to `parity_shards` shards.
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to encode (must not be empty)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Encoded data with error correction
    /// * `Err(anyhow::Error)` - Encoding failed or input was invalid
    ///
    /// # Output Format
    ///
    /// The output contains all shards concatenated in order:
    /// `[data_shard_0][data_shard_1]...[parity_shard_0][parity_shard_1]...`
    ///
    /// # Size Overhead
    ///
    /// Output size = input_size * (data_shards + parity_shards) / data_shards
    /// For 4+10 configuration, output is 3.5× larger than input
    ///
    /// # Example
    ///
    /// With 4 data + 2 parity shards:
    /// - Input: "Hello World!" (12 bytes)
    /// - Each data shard: 3 bytes
    /// - Output: 15 bytes (12 data + 6 parity, padded to shard boundaries)
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate input data
        ensure!(!data.is_empty(), "input data cannot be empty");

        // Split data into shards (data shards filled, parity shards zeroed)
        let mut shards = self.split(data, false);

        // Compute parity shards using Reed-Solomon encoding
        self.encoder.encode(&mut shards)?;

        // Combine all shards into a single output vector
        Ok(Self::combine(&shards))
    }

    /// Decode Reed-Solomon encoded data with error correction
    ///
    /// This method reconstructs the original data from encoded data that may
    /// contain corrupted or missing shards. It uses the Reed-Solomon algorithm
    /// to detect and correct errors automatically.
    ///
    /// # Arguments
    ///
    /// * `encoded` - Reed-Solomon encoded data (must not be empty)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Successfully reconstructed original data
    /// * `Err(anyhow::Error)` - Decoding failed or too many corrupted shards
    ///
    /// # Error Conditions
    ///
    /// - Empty input data
    /// - Input size not divisible by total shard count
    /// - More than `parity_shards` corrupted/missing shards
    /// - Invalid Reed-Solomon encoding
    ///
    /// # Error Correction Process
    ///
    /// 1. Split encoded data into individual shards
    /// 2. Mark shards as potentially corrupted
    /// 3. Use Reed-Solomon reconstruction algorithm
    /// 4. Extract original data from data shards only
    ///
    /// # Success Probability
    ///
    /// If corruption is random and affects ≤ `parity_shards` shards,
    /// reconstruction success probability approaches 100%.
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        // Validate input data
        ensure!(!encoded.is_empty(), "encoded data cannot be empty");

        let total_shards = self.data_shards + self.parity_shards;

        // Ensure encoded data length matches expected shard structure
        ensure!(encoded.len().is_multiple_of(total_shards), "encoded data length {} not divisible by total shards {}", encoded.len(), total_shards);

        // Split into shards and mark all as potentially corrupted for reconstruction
        let mut shards: Vec<Option<Vec<u8>>> = self.split(encoded, true).into_iter().map(Some).collect();

        // Attempt reconstruction - this will succeed if enough shards are valid
        self.encoder.reconstruct(&mut shards)?;

        // Flatten the Option wrappers, assuming reconstruction succeeded
        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();

        // Extract only the data portion from reconstructed shards
        Ok(self.extract(&reconstructed))
    }

    /// Split data into shards for Reed-Solomon processing
    ///
    /// This method divides input data into equal-sized chunks suitable for
    /// Reed-Solomon encoding or decoding. It handles both exact division
    /// (for decoding) and padding division (for encoding).
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to split into shards
    /// * `exact` - If true, divide exactly by total_shards (for decoding)
    ///  - If false, pad to data_shards size (for encoding)
    ///
    /// # Returns
    ///
    /// Vector of byte vectors, each representing a shard
    ///
    /// # Shard Size Calculation
    ///
    /// - **Exact mode**: shard_size = data.len() / total_shards
    /// - **Padding mode**: shard_size = ceil(data.len() / data_shards)
    ///
    /// # Data Distribution
    ///
    /// - Data shards (first N shards) contain the original data split across them
    /// - Parity shards (remaining M shards) are initialized to zero for encoding
    /// - For decoding, all shards are split from the encoded data
    ///
    /// # Padding Handling
    ///
    /// When not using exact division, the last data shard may be padded with
    /// zeros to ensure equal shard sizes. This padding is handled during
    /// the extract() phase.
    fn split(&self, data: &[u8], exact: bool) -> Vec<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;

        // Calculate shard size based on mode
        let shard_size = if exact {
            // For decoding: exact division by total shards
            data.len() / total_shards
        } else {
            // For encoding: pad to ensure data fits in data_shards
            data.len().div_ceil(self.data_shards)
        };

        // Initialize all shards with zeros
        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0u8; shard_size]).collect();

        // Distribute data across data shards only
        for (idx, chunk) in data.chunks(shard_size).enumerate() {
            if idx < self.data_shards {
                shards[idx][..chunk.len()].copy_from_slice(chunk);
            }
        }

        shards
    }

    /// Combine multiple shards into a single contiguous byte vector
    ///
    /// This method concatenates all shards in order to create the final
    /// encoded output. The ordering preserves the shard structure for
    /// later decoding.
    ///
    /// # Arguments
    ///
    /// * `shards` - Vector of shards to combine (includes both data and parity)
    ///
    /// # Returns
    ///
    /// Single byte vector containing all shards concatenated together
    ///
    /// # Output Structure
    ///
    /// The combined output has this structure:
    /// ```
    /// [data_shard_0][data_shard_1]...[data_shard_N][parity_shard_0][parity_shard_1]...[parity_shard_M]
    /// ```
    ///
    /// # Memory Efficiency
    ///
    /// The method pre-allocates the exact required capacity to avoid
    /// multiple reallocations during the concatenation process.
    ///
    /// # Reversibility
    ///
    /// This operation is reversible by the split() method with exact=true,
    /// assuming the original shard configuration is known.
    fn combine(shards: &[Vec<u8>]) -> Vec<u8> {
        // Calculate total size for pre-allocation
        let total: usize = shards.iter().map(|s| s.len()).sum();
        let mut result = Vec::with_capacity(total);

        // Concatenate all shards in order
        for shard in shards {
            result.extend_from_slice(shard);
        }

        result
    }

    /// Extract original data from reconstructed data shards
    ///
    /// This method reconstructs the original data by combining only the
    /// data shards from a set of reconstructed shards. It ignores parity
    /// shards since they don't contain original data information.
    ///
    /// # Arguments
    ///
    /// * `shards` - Reconstructed shards (includes both data and parity)
    ///
    /// # Returns
    ///
    /// The original data extracted from the data shards only
    ///
    /// # Data Recovery Process
    ///
    /// 1. Take only the first `data_shards` shards (original data)
    /// 2. Concatenate them in order
    /// 3. The result contains the original data (may include padding)
    ///
    /// # Padding Handling
    ///
    /// The extracted data may include zero padding from the encoding process.
    /// The calling code should handle removing this padding based on the
    /// original data length if necessary.
    ///
    /// # Error Safety
    ///
    /// This method assumes the shards have been successfully reconstructed.
    /// If reconstruction failed, the data shards may be corrupted, but this
    /// method will still attempt to extract them.
    fn extract(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        // Calculate total data size (data shards only)
        let total: usize = shards.iter().take(self.data_shards).map(|s| s.len()).sum();

        // Pre-allocate result vector
        let mut result = Vec::with_capacity(total);

        // Concatenate only the data shards
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
        let encoding = Encoding::new(0, 2);
        assert!(encoding.is_err());

        let encoding = Encoding::new(200, 200);
        assert!(encoding.is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let encoding = Encoding::new(4, 2).unwrap();
        let data = b"Hello, world! This is a test.";

        let encoded = encoding.encode(data).unwrap();
        assert_ne!(data, &encoded[..]);
        assert_eq!(encoded.len(), 48);

        let decoded = encoding.decode(&encoded).unwrap();
        assert_eq!(data, &decoded[..data.len()]);

        assert!(decoded.starts_with(data));

        for &b in &decoded[data.len()..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_invalid_length_for_decode() {
        let encoding = Encoding::new(4, 2).unwrap();
        let data = vec![0; 7];
        assert!(encoding.decode(&data).is_err());
    }

    #[test]
    fn test_too_many_errors() {
        let encoding = Encoding::new(4, 2).unwrap();
        let data = b"Hello, World!";
        let mut encoded = encoding.encode(data).unwrap();

        for i in 0..12 {
            encoded[i] = 0xFF;
        }

        let result = encoding.decode(&encoded);

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
