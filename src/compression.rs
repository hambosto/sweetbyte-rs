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

impl CompressionLevel {
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
    pub fn new(level: CompressionLevel) -> Result<Self> {
        ensure!(level.is_valid(), "invalid compression level");
        Ok(Self { level: level.into() })
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

        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();

        decoder.read_to_end(&mut decompressed).context("failed to decompress data")?;

        Ok(decompressed)
    }
}
