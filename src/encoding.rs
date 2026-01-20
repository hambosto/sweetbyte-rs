use anyhow::{Result, ensure};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Reed-Solomon erasure coding handler for error correction.
///
/// Provides encode and decode operations using Reed-Solomon codes over
/// GF(256). This enables recovery from data corruption by generating
/// parity shards that can reconstruct missing data shards.
pub struct Encoding {
    /// The Reed-Solomon encoder/decoder instance.
    encoder: ReedSolomon,
    /// Number of data shards for encoding.
    data_shards: usize,
    /// Number of parity shards for error correction.
    parity_shards: usize,
}

/// Maximum data length in bytes (1 GB).
const MAX_DATA_LEN: usize = 1 << 30;

impl Encoding {
    /// Creates a new Encoding instance with the specified shard configuration.
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards to create.
    /// * `parity_shards` - Number of parity shards for error correction.
    ///
    /// # Returns
    /// A new Encoding instance.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = ReedSolomon::new(data_shards, parity_shards)?;
        Ok(Self { encoder, data_shards, parity_shards })
    }

    /// Encodes data using Reed-Solomon erasure coding.
    ///
    /// Splits the data into data shards and generates parity shards.
    /// The output is the concatenation of all shards.
    ///
    /// # Arguments
    /// * `data` - The data to encode (must not be empty, must not exceed MAX_DATA_LEN).
    ///
    /// # Returns
    /// The encoded data (data shards + parity shards), or an error.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "input data cannot be empty");
        ensure!(data.len() <= MAX_DATA_LEN, "data size {} exceeds maximum {} bytes", data.len(), MAX_DATA_LEN);

        // Split data into shards.
        let mut shards = self.split(data, false);
        // Generate parity shards.
        self.encoder.encode(&mut shards)?;
        // Combine all shards into a single output.
        Ok(Self::combine(&shards))
    }

    /// Decodes and reconstructs data using Reed-Solomon erasure coding.
    ///
    /// Splits the encoded data into shards and attempts to reconstruct
    /// any missing data shards using the parity shards.
    ///
    /// # Arguments
    /// * `encoded` - The encoded data to decode (must not be empty).
    ///
    /// # Returns
    /// The original data, or an error if reconstruction fails.
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        ensure!(!encoded.is_empty(), "encoded data cannot be empty");

        let total_shards = self.data_shards + self.parity_shards;
        // Verify the encoded data length is divisible by total shards.
        ensure!(encoded.len().is_multiple_of(total_shards), "encoded data length {} not divisible by total shards {}", encoded.len(), total_shards);

        // Split encoded data into shards.
        let mut shards: Vec<Option<Vec<u8>>> = self.split(encoded, true).into_iter().map(Some).collect();
        // Reconstruct any missing shards using parity.
        self.encoder.reconstruct(&mut shards)?;

        // Flatten the Option<Vec<u8>> into Vec<Vec<u8>>.
        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();
        // Extract only the data shards.
        Ok(self.extract(&reconstructed))
    }

    /// Splits data into equal-sized shards.
    ///
    /// # Arguments
    /// * `data` - The data to split.
    /// * `exact` - If true, shard size is data_len / total_shards; otherwise, uses ceiling
    ///   division.
    ///
    /// # Returns
    /// A vector of shards, initialized with zeros.
    fn split(&self, data: &[u8], exact: bool) -> Vec<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;
        // Calculate shard size based on exact flag.
        let shard_size = if exact { data.len() / total_shards } else { data.len().div_ceil(self.data_shards) };

        // Create empty shards.
        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0u8; shard_size]).collect();

        // Copy data chunks into data shards.
        for (idx, chunk) in data.chunks(shard_size).enumerate() {
            if idx < self.data_shards {
                shards[idx][..chunk.len()].copy_from_slice(chunk);
            }
        }

        shards
    }

    /// Combines all shards into a single byte vector.
    ///
    /// # Arguments
    /// * `shards` - The shards to combine.
    ///
    /// # Returns
    /// The concatenated data from all shards.
    fn combine(shards: &[Vec<u8>]) -> Vec<u8> {
        shards.iter().flatten().copied().collect()
    }

    /// Extracts only the data shards from a collection of shards.
    ///
    /// # Arguments
    /// * `shards` - The shards to extract from.
    ///
    /// # Returns
    /// The concatenated data from data shards only.
    fn extract(&self, shards: &[Vec<u8>]) -> Vec<u8> {
        shards.iter().take(self.data_shards).flatten().copied().collect()
    }
}
