use anyhow::{Context, Error, Result};

use crate::validation::NonEmptyBytes;

#[non_exhaustive]
#[derive(Clone, Copy, Default)]
pub(crate) enum CompressionLevel {
    Fast,
    #[default]
    Default,
    Good,
    Best,
}

impl TryFrom<i32> for CompressionLevel {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CompressionLevel::Fast),
            3 => Ok(CompressionLevel::Default),
            9 => Ok(CompressionLevel::Good),
            22 => Ok(CompressionLevel::Best),
            _ => Err(anyhow::anyhow!("invalid compression level: {}. must be 1, 3, 9, or 22.", value)),
        }
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

pub(crate) struct Compressor {
    level: CompressionLevel,
}

impl Compressor {
    pub(crate) fn new(level: CompressionLevel) -> Result<Self> {
        Ok(Self { level })
    }

    pub(crate) fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        zstd::stream::encode_all(data.as_ref().as_slice(), self.level.into()).context("failed to compress")
    }

    pub(crate) fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let data = NonEmptyBytes::try_new(data.to_vec()).context("data must not be empty")?;

        zstd::stream::decode_all(data.as_ref().as_slice()).context("failed to decompress")
    }
}
