use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

#[derive(Default)]
pub enum CompressionLevel {
    None,

    #[default]
    Fast,

    Default,

    Best,
}

impl From<CompressionLevel> for Compression {
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => Self::none(),
            CompressionLevel::Fast => Self::fast(),
            CompressionLevel::Default => Self::default(),
            CompressionLevel::Best => Self::best(),
        }
    }
}

pub struct Compressor {
    level: Compression,
}

impl Compressor {
    #[inline]
    pub fn new(level: CompressionLevel) -> Self {
        Self { level: level.into() }
    }

    #[inline]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);

        encoder.write_all(data).context("compression failed")?;

        encoder.finish().context("compression finalization failed")
    }

    #[inline]
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        let mut decompressed = Vec::new();

        ZlibDecoder::new(data).read_to_end(&mut decompressed).context("decompression failed")?;

        Ok(decompressed)
    }
}
