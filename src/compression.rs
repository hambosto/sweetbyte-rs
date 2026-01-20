use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

/// Compression level options for the zlib compression algorithm.
///
/// These levels control the trade-off between compression speed and ratio.
#[derive(Default)]
pub enum CompressionLevel {
    /// No compression (passthrough).
    None,
    /// Fast compression with lower ratio (default).
    #[default]
    Fast,
    /// Balanced compression speed and ratio.
    Default,
    /// Best compression ratio, slowest speed.
    Best,
}

impl From<CompressionLevel> for Compression {
    /// Converts a CompressionLevel to the flate2 Compression type.
    ///
    /// # Arguments
    /// * `level` - The compression level to convert.
    ///
    /// # Returns
    /// The corresponding flate2 Compression value.
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => Self::none(),
            CompressionLevel::Fast => Self::fast(),
            CompressionLevel::Default => Self::default(),
            CompressionLevel::Best => Self::best(),
        }
    }
}

/// Zlib compression handler.
///
/// Provides compression and decompression using the zlib format
/// (DEFLATE algorithm with zlib wrapper).
pub struct Compressor {
    /// The compression level to use.
    level: Compression,
}

impl Compressor {
    /// Creates a new Compressor with the specified compression level.
    ///
    /// # Arguments
    /// * `level` - The compression level to use.
    ///
    /// # Returns
    /// A new Compressor instance.
    #[inline]
    pub fn new(level: CompressionLevel) -> Self {
        Self { level: level.into() }
    }

    /// Compresses data using zlib compression.
    ///
    /// # Arguments
    /// * `data` - The data to compress (must not be empty).
    ///
    /// # Returns
    /// The compressed data, or an error if compression fails.
    #[inline]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Create a zlib encoder with the configured compression level.
        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);
        // Write all data to the encoder.
        encoder.write_all(data).context("compression failed")?;
        // Finalize and return the compressed data.
        encoder.finish().context("compression finalization failed")
    }

    /// Decompresses zlib-compressed data.
    ///
    /// # Arguments
    /// * `data` - The compressed data to decompress (must not be empty).
    ///
    /// # Returns
    /// The decompressed data, or an error if decompression fails.
    #[inline]
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Pre-allocate output buffer (2x input size as initial capacity).
        let mut decompressed = Vec::with_capacity(data.len() * 2);
        // Create a zlib decoder and read all decompressed data.
        ZlibDecoder::new(data).read_to_end(&mut decompressed).context("decompression failed")?;

        Ok(decompressed)
    }
}
