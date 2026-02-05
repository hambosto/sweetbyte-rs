use anyhow::Result;

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
            anyhow::bail!("invalid compression level");
        }

        Ok(Self { level: i32::from(level) })
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("cannot compress empty data");
        }

        zstd::stream::encode_all(data, self.level).map_err(|error| anyhow::anyhow!("compression failed: {error}"))
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("cannot decompress empty data");
        }

        zstd::stream::decode_all(data).map_err(|error| anyhow::anyhow!("decompression failed: {error}"))
    }
}
