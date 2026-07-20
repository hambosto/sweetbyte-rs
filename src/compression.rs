use anyhow::{Context, Result};

pub(crate) struct Compression {
    level: i32,
}

impl Compression {
    pub(crate) fn new(level: i32) -> Result<Self> {
        let supported_range = zstd::compression_level_range();
        if !supported_range.contains(&level) {
            anyhow::bail!("compression level {level} out of range: valid range is {} to {}", supported_range.start(), supported_range.end());
        }

        Ok(Self { level })
    }

    pub(crate) fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("data must not be empty");
        }

        zstd::stream::encode_all(data, self.level).context("failed to compress")
    }

    pub(crate) fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("data must not be empty");
        }

        zstd::stream::decode_all(data).context("failed to decompress")
    }
}
