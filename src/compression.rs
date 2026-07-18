use anyhow::{Context, Error, Result};

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
            _ => Err(anyhow::anyhow!("invalid compression level: {value}. must be 1, 3, 9, or 22.")),
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

pub(crate) struct Compression {
    level: CompressionLevel,
}

impl Compression {
    pub(crate) fn new(level: CompressionLevel) -> Result<Self> {
        let zstd_level: i32 = level.into();
        let supported_range = zstd::compression_level_range();
        if !supported_range.contains(&zstd_level) {
            anyhow::bail!("compression level {zstd_level} out of range: valid range is {} to {}", supported_range.start(), supported_range.end());
        }

        Ok(Self { level })
    }

    pub(crate) fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("data must not be empty");
        }

        zstd::stream::encode_all(data, self.level.into()).context("failed to compress")
    }

    pub(crate) fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("data must not be empty");
        }

        zstd::stream::decode_all(data).context("failed to decompress")
    }
}
