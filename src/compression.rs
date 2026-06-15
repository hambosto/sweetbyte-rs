use anyhow::{Context, Result};

use crate::validation::NonEmptyBytes;

#[non_exhaustive]
#[derive(Default)]
pub(crate) enum CompressionLevel {
    Fast,
    #[default]
    Default,
    Good,
    Best,
}

impl CompressionLevel {
    #[inline]
    pub(crate) fn is_valid(&self) -> bool {
        matches!(self, Self::Fast | Self::Default | Self::Good | Self::Best)
    }
}

impl From<CompressionLevel> for i32 {
    #[inline]
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 3,
            CompressionLevel::Good => 9,
            CompressionLevel::Best => 22,
        }
    }
}

pub(crate) struct Compressor {
    level: i32,
}

impl Compressor {
    pub(crate) fn new(level: CompressionLevel) -> Result<Self> {
        if !level.is_valid() {
            anyhow::bail!("invalid compression level: must be Fast, Default, Good, or Best");
        }

        Ok(Self { level: i32::from(level) })
    }

    pub(crate) fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        zstd::stream::encode_all(data.as_ref().as_slice(), self.level).context("failed to compress")
    }

    pub(crate) fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        zstd::stream::decode_all(data.as_ref().as_slice()).context("failed to decompress")
    }
}
