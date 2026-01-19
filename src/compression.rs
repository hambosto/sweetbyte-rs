use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
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
            CompressionLevel::None => Compression::none(),
            CompressionLevel::Fast => Compression::fast(),
            CompressionLevel::Default => Compression::default(),
            CompressionLevel::Best => Compression::best(),
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
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), self.level);
        encoder.write_all(data).context("compression failed")?;
        encoder.finish().context("compression finalization failed")
    }

    #[inline]
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let mut decompressed = Vec::with_capacity(data.len() * 2);
        ZlibDecoder::new(data).read_to_end(&mut decompressed).context("decompression failed")?;

        Ok(decompressed)
    }
}
