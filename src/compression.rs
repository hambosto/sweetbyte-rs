use anyhow::{Context, Result};

use crate::validation::NonEmptyBytes;

#[derive(Default)]
pub enum CompressionLevel {
    Fast,
    #[default]
    Default,
    Good,
    Best,
}

impl CompressionLevel {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Fast | Self::Default | Self::Good | Self::Best)
    }
}

impl From<CompressionLevel> for i32 {
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 3,
            CompressionLevel::Good => 9,
            CompressionLevel::Best => 22,
        }
    }
}

pub struct Compressor {
    level: i32,
}

impl Compressor {
    pub fn new(level: CompressionLevel) -> Result<Self> {
        if !level.is_valid() {
            anyhow::bail!("invalid compression level: must be Fast, Default, Good, or Best");
        }

        Ok(Self { level: i32::from(level) })
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        zstd::stream::encode_all(data.as_ref().as_slice(), self.level).context("failed to compress")
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        zstd::stream::decode_all(data.as_ref().as_slice()).context("failed to decompress")
    }
}
