use anyhow::{Context, Result};

pub(crate) struct Compression {
    level: i32,
}

impl Compression {
    pub(crate) fn new(level: i32) -> Result<Self> {
        let supported_range = zstd::compression_level_range();
        if !supported_range.contains(&level) {
            anyhow::bail!("invalid compression level");
        }

        Ok(Self { level })
    }

    pub(crate) fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty input data");
        }

        zstd::stream::encode_all(data, self.level).context("failed to compress data")
    }

    #[expect(clippy::unused_self, reason = "consistent API with compress")]
    pub(crate) fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty input data");
        }

        zstd::stream::decode_all(data).context("failed to decompress data")
    }
}
