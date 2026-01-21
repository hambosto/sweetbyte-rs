//! Zlib compression and decompression.
//!
//! Provides [`Compressor`] for compressing data before encryption
//! and decompress function for restoring compressed data.
//!
//! # Compression Levels
//!
//! - `None`: No compression, passes data through unchanged
//! - `Fast`: Level 1 - fastest compression, least compact
//! - `Default`: Level 6 - balanced speed and compression ratio
//! - `Best`: Level 9 - slowest compression, most compact
//!
//! SweetByte uses the `Fast` level for minimal overhead in the pipeline.

use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

/// Available compression levels.
///
/// Controls the trade-off between compression speed and ratio.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression - data passes through unchanged.
    None,

    /// Fastest compression (level 1).
    #[default]
    Fast,

    /// Default compression (level 6).
    Default,

    /// Best compression (level 9).
    Best,
}

impl CompressionLevel {
    /// Validates that the compression level is within valid range (0-9).
    ///
    /// Each level maps to a valid zlib compression level.
    #[inline]
    pub fn is_valid(&self) -> bool {
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
    /// Converts a [`CompressionLevel`] to flate2's [`Compression`].
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => Self::none(),
            CompressionLevel::Fast => Self::fast(),
            CompressionLevel::Default => Self::default(),
            CompressionLevel::Best => Self::best(),
        }
    }
}

/// Zlib compressor with configurable compression level.
///
/// Used in the encryption pipeline to compress data before encryption.
/// Reduces encrypted file size, especially for compressible content.
pub struct Compressor {
    /// The configured compression level.
    level: Compression,
}

impl Compressor {
    /// Creates a new compressor with the specified level.
    ///
    /// # Arguments
    ///
    /// * `level` - The compression level to use.
    ///
    /// # Errors
    ///
    /// Returns an error if the compression level is invalid.
    #[inline]
    pub fn new(level: CompressionLevel) -> Result<Self> {
        ensure!(level.is_valid(), "invalid compression level");
        Ok(Self { level: level.into() })
    }

    /// Compresses the input data using zlib.
    ///
    /// Compression is applied before encryption to reduce file size.
    /// This is especially effective on text files, executables, and other
    /// compressible content. Encrypted data is not compressible.
    ///
    /// The zlib format includes a header and checksum (Adler-32) for integrity.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to compress.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is empty or compression fails.
    #[inline]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Create encoder with configured compression level.
        // The encoder writes to a Vec, which grows as needed.
        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);

        // Write all data to the encoder.
        // This may return short writes if the internal buffer fills.
        encoder.write_all(data).context("compression failed")?;

        // Finish() finalizes the compressed data and returns the result.
        // This must be called to get valid zlib output.
        // The Adler-32 checksum is computed automatically.
        encoder.finish().context("compression finalization failed")
    }

    /// Decompresses zlib-compressed data.
    ///
    /// Used in the decryption pipeline to restore compressed data.
    /// This is a standalone function since decompression doesn't require
    /// configuration state.
    ///
    /// The decompressor reads from the compressed data and produces
    /// the original uncompressed content.
    ///
    /// # Arguments
    ///
    /// * `data` - The compressed data to decompress.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is empty or decompression fails
    /// (e.g., corrupted or non-compressed data).
    #[inline]
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Create decoder from compressed data.
        // The decoder reads the zlib header to determine parameters.
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        // Read all decompressed data.
        // This loops until the decoder has produced all output.
        decoder.read_to_end(&mut decompressed).context("failed to decompress data")?;

        Ok(decompressed)
    }
}
