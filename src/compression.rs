//! Data compression using DEFLATE (zlib).
//!
//! This module handles the compression and decompression of data blocks using the Zlib algorithm.
//! Compression is applied *before* encryption to reduce file size and increase entropy.
//!
//! # Security Note
//!
//! Compressing data before encryption can theoretically leak information about the plaintext
//! content (CRIME/BREACH attacks) if the attacker can control parts of the plaintext and observe
//! output size. However, for general file encryption (data-at-rest), this is generally considered
//! safe and beneficial.

use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

/// Specifies the compression effort level.
///
/// Higher levels define better compression ratios but slower processing speeds.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression (store only).
    None,

    /// Fastest compression (lowest ratio).
    #[default]
    Fast,

    /// Balanced compression (level 6).
    Default,

    /// Best compression (highest ratio, slowest).
    Best,
}

impl CompressionLevel {
    /// Validates internal integer representation.
    #[inline]
    pub fn is_valid(self) -> bool {
        let value = match self {
            Self::None => 0,
            Self::Fast => 1,
            Self::Default => 6,
            Self::Best => 9,
        };
        value <= 9
    }
}

impl From<CompressionLevel> for Compression {
    /// Converts the enum to the `flate2` native `Compression` struct.
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => Self::none(),
            CompressionLevel::Fast => Self::fast(),
            CompressionLevel::Default => Self::default(),
            CompressionLevel::Best => Self::best(),
        }
    }
}

/// A wrapper for Zlib compression operations.
pub struct Compressor {
    /// The configured compression level.
    level: Compression,
}

impl Compressor {
    /// Creates a new compressor with the specified level.
    ///
    /// # Errors
    ///
    /// Returns an error if the level is invalid (though the enum prevents this).
    #[inline]
    pub fn new(level: CompressionLevel) -> Result<Self> {
        ensure!(level.is_valid(), "invalid compression level");
        Ok(Self { level: level.into() })
    }

    /// Compresses a byte slice using Zlib.
    ///
    /// # Returns
    ///
    /// The compressed data as a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Zlib encoder fails.
    #[inline]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Initialize Zlib encoder with a growing vector buffer.
        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);

        // Write all data to the encoder.
        encoder.write_all(data).context("compression failed")?;

        // Finish the stream and retrieve the buffer.
        encoder.finish().context("compression finalization failed")
    }

    /// Decompresses a Zlib-compressed byte slice.
    ///
    /// # Returns
    ///
    /// The original decompressed data.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is not valid Zlib format or is corrupted.
    #[inline]
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Initialize Zlib decoder.
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        // Read the full decoded stream into the vector.
        // This handles growing the vector automatically.
        decoder.read_to_end(&mut decompressed).context("failed to decompress data")?;

        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_level_validity() {
        assert!(CompressionLevel::None.is_valid());
        assert!(CompressionLevel::Fast.is_valid());
        assert!(CompressionLevel::Default.is_valid());
        assert!(CompressionLevel::Best.is_valid());
    }

    #[test]
    fn test_compression_level_into() {
        let level: Compression = CompressionLevel::Fast.into();
        // Check that conversion works (compile-time check mainly)
        let _ = level;
    }

    #[test]
    fn test_compressor_new() {
        let compressor = Compressor::new(CompressionLevel::Fast);
        assert!(compressor.is_ok());
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, world! This is a test string for compression.";
        let compressor = Compressor::new(CompressionLevel::Default).unwrap();

        let compressed = compressor.compress(data).unwrap();

        // Compressed data should generally look different.
        // For very short strings, zlib overhead might make it larger, but it shouldn't match.
        assert_ne!(data, &compressed[..]);

        let decompressed = Compressor::decompress(&compressed).unwrap();
        assert_eq!(data, &decompressed[..]);
    }

    #[test]
    fn test_compress_empty() {
        let compressor = Compressor::new(CompressionLevel::Default).unwrap();
        let result = compressor.compress(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_empty() {
        let result = Compressor::decompress(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_invalid_data() {
        let invalid_data = b"This is not zlib data";
        let result = Compressor::decompress(invalid_data);
        assert!(result.is_err());
    }
}
