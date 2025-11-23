use anyhow::{anyhow, Result};
use flate2::{read::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};

use super::Level;

pub struct Compression {
    level: flate2::Compression,
}

impl Compression {
    pub fn new(level: Level) -> Result<Self> {
        Ok(Self {
            level: level.to_flate2(),
        })
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("data cannot be empty"));
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);
        encoder
            .write_all(data)
            .map_err(|e| anyhow!("failed to compress data: {}", e))?;

        encoder
            .finish()
            .map_err(|e| anyhow!("failed to finalize compression: {}", e))
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("data cannot be empty"));
        }

        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| anyhow!("failed to decompress data: {}", e))?;

        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let comp = Compression::new(Level::BestSpeed).unwrap();
        // Use larger, repetitive data to ensure compression actually reduces size
        let data = b"Hello, World! This is a test. Hello, World! This is a test. Hello, World! This is a test. Hello, World! This is a test.";

        let compressed = comp.compress(data).unwrap();
        let decompressed = comp.decompress(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_slice());
        assert!(compressed.len() < data.len()); // Should be compressed
    }
}
