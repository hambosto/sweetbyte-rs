use anyhow::{Result, anyhow};
use flate2::{read::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};

use super::Level;

/// A ZLIB compression handler.
///
/// This struct provides stateless compression and decompression operations
/// using the configured compression level.
#[derive(Debug, Clone)]
pub struct Compression {
    level: flate2::Compression,
}

impl Compression {
    /// Creates a new Compression instance with the specified level.
    ///
    /// # Arguments
    ///
    /// * `level` - The compression level to use
    pub fn new(level: impl Into<flate2::Compression>) -> Self {
        Self {
            level: level.into(),
        }
    }

    /// Compresses the given data using ZLIB compression.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to compress
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input data is empty
    /// - Compression fails
    /// - Finalization fails
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("cannot compress empty data"));
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);
        encoder
            .write_all(data)
            .map_err(|e| anyhow!("failed to compress data: {}", e))?;

        encoder
            .finish()
            .map_err(|e| anyhow!("failed to finalize compression: {}", e))
    }

    /// Decompresses ZLIB-compressed data.
    ///
    /// # Arguments
    ///
    /// * `data` - The compressed data to decompress
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input data is empty
    /// - Decompression fails (corrupted data, wrong format, etc.)
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("cannot decompress empty data"));
        }

        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| anyhow!("failed to decompress data: {}", e))?;

        Ok(decompressed)
    }
}

impl Default for Compression {
    fn default() -> Self {
        Self::new(Level::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let comp = Compression::new(Level::BestSpeed);
        // Use larger, repetitive data to ensure compression actually reduces size
        let data = b"Hello, World! This is a test. ".repeat(10);

        let compressed = comp.compress(&data).unwrap();
        let decompressed = comp.decompress(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_slice());
        assert!(compressed.len() < data.len()); // Should be compressed
    }

    #[test]
    fn test_compress_empty_data() {
        let comp = Compression::new(Level::BestSpeed);
        let result = comp.compress(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_decompress_empty_data() {
        let comp = Compression::new(Level::BestSpeed);
        let result = comp.decompress(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_different_compression_levels() {
        let data = b"Hello, World! This is a test. ".repeat(100);

        for level in [
            Level::NoCompression,
            Level::BestSpeed,
            Level::DefaultCompression,
            Level::BestCompression,
        ] {
            let comp = Compression::new(level);
            let compressed = comp.compress(&data).unwrap();
            let decompressed = comp.decompress(&compressed).unwrap();
            assert_eq!(data.as_slice(), decompressed.as_slice());
        }
    }

    #[test]
    fn test_compression_default() {
        let comp = Compression::default();
        let data = b"Hello, World! This is a test. ".repeat(10);
        let compressed = comp.compress(&data).unwrap();
        let decompressed = comp.decompress(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compression_with_flate2_level() {
        // Test that new() accepts flate2::Compression directly
        let comp = Compression::new(flate2::Compression::fast());
        let data = b"Hello, World! This is a test. ".repeat(10);
        let compressed = comp.compress(&data).unwrap();
        let decompressed = comp.decompress(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}
