//! Zlib compression and decompression.

use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
use flate2::Compression as FlateCompression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

/// Compression level options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionLevel {
    /// No compression
    None,
    /// Fast compression
    #[default]
    Fast,
    /// Default compression
    Default,
    /// Best compression
    Best,
}

impl From<CompressionLevel> for FlateCompression {
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => FlateCompression::none(),
            CompressionLevel::Fast => FlateCompression::fast(),
            CompressionLevel::Default => FlateCompression::default(),
            CompressionLevel::Best => FlateCompression::best(),
        }
    }
}

/// Zlib compressor/decompressor.
pub struct Compressor {
    level: FlateCompression,
}

impl Compressor {
    /// Creates a new compressor with the given level.
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            level: level.into(),
        }
    }

    /// Compresses data using Zlib.
    ///
    /// # Arguments
    /// * `data` - The data to compress
    ///
    /// # Returns
    /// The compressed data
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);
        encoder.write_all(data).context("compression failed")?;

        encoder.finish().context("compression finalization failed")
    }

    /// Decompresses Zlib-compressed data.
    ///
    /// # Arguments
    /// * `data` - The compressed data
    ///
    /// # Returns
    /// The decompressed data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        decoder
            .read_to_end(&mut decompressed)
            .context("decompression failed")?;

        Ok(decompressed)
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new(CompressionLevel::Fast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let compressor = Compressor::default();
        let data = b"Hello, World! This is some test data for compression.";

        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_empty() {
        let compressor = Compressor::default();
        assert!(compressor.compress(b"").is_err());
    }

    #[test]
    fn test_decompress_empty() {
        let compressor = Compressor::default();
        assert!(compressor.decompress(&[]).is_err());
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        for level in [
            CompressionLevel::None,
            CompressionLevel::Fast,
            CompressionLevel::Default,
            CompressionLevel::Best,
        ] {
            let compressor = Compressor::new(level);
            let compressed = compressor.compress(data).unwrap();
            let decompressed = compressor.decompress(&compressed).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    #[test]
    fn test_compression_actually_compresses() {
        let compressor = Compressor::new(CompressionLevel::Best);
        // Highly compressible data
        let data: Vec<u8> = vec![b'a'; 10000];

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());
    }
}
