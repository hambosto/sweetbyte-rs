//! Reed-Solomon error correction encoding.

use anyhow::{Context, Result, bail};
use reed_solomon_erasure::galois_8::ReedSolomon as RsEncoder;

use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::shards::Shards;

/// Maximum data length for encoding (1 GB).
pub const MAX_DATA_LEN: usize = 1 << 30;

/// Reed-Solomon encoder for error correction.
pub struct ReedSolomon {
    encoder: RsEncoder,
    shards: Shards,
}

impl ReedSolomon {
    /// Creates a new Reed-Solomon encoder.
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards
    /// * `parity_shards` - Number of parity shards
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = RsEncoder::new(data_shards, parity_shards)
            .context("failed to create Reed-Solomon encoder")?;

        Ok(Self {
            encoder,
            shards: Shards::new(data_shards, parity_shards),
        })
    }

    /// Encodes data with Reed-Solomon error correction.
    ///
    /// # Arguments
    /// * `data` - The data to encode
    ///
    /// # Returns
    /// The encoded data with parity shards appended
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("input data cannot be empty");
        }

        if data.len() > MAX_DATA_LEN {
            bail!(
                "data size {} exceeds maximum {} bytes",
                data.len(),
                MAX_DATA_LEN
            );
        }

        let mut shards = self.shards.split(data);

        self.encoder
            .encode(&mut shards)
            .context("Reed-Solomon encoding failed")?;

        Ok(self.shards.combine(&shards))
    }

    /// Decodes Reed-Solomon encoded data.
    ///
    /// Can recover from up to `parity_shards` missing or corrupted shards.
    ///
    /// # Arguments
    /// * `encoded` - The encoded data
    ///
    /// # Returns
    /// The original data
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let total_shards = DATA_SHARDS + PARITY_SHARDS;

        if encoded.is_empty() {
            bail!("encoded data cannot be empty");
        }

        if !encoded.len().is_multiple_of(total_shards) {
            bail!(
                "encoded data length {} not divisible by total shards {}",
                encoded.len(),
                total_shards
            );
        }

        let mut shards: Vec<Option<Vec<u8>>> = self
            .shards
            .split_encoded(encoded)
            .into_iter()
            .map(Some)
            .collect();

        self.encoder
            .reconstruct(&mut shards)
            .context("Reed-Solomon reconstruction failed")?;

        // Extract data from reconstructed shards
        let reconstructed: Vec<Vec<u8>> = shards.into_iter().flatten().collect();

        self.shards.extract(&reconstructed)
    }
}

impl Default for ReedSolomon {
    fn default() -> Self {
        Self::new(DATA_SHARDS, PARITY_SHARDS).expect("valid default parameters")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let rs = ReedSolomon::default();
        let data = b"Hello, World! This is some test data for Reed-Solomon.";

        let encoded = rs.encode(data).unwrap();
        let decoded = rs.decode(&encoded).unwrap();

        // Decoded data may have padding, so check prefix
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_encode_empty() {
        let rs = ReedSolomon::default();
        assert!(rs.encode(b"").is_err());
    }

    #[test]
    fn test_decode_empty() {
        let rs = ReedSolomon::default();
        assert!(rs.decode(&[]).is_err());
    }

    #[test]
    fn test_decode_invalid_length() {
        let rs = ReedSolomon::default();
        // Not divisible by total shards
        assert!(rs.decode(&[0u8; 15]).is_err());
    }
}
