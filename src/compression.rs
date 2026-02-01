use anyhow::Result;
use zstd::DEFAULT_COMPRESSION_LEVEL;

#[derive(Default, Clone, Copy)]
pub enum CompressionLevel {
    None,
    #[default]
    Fast,
    Default,
    Best,
}

impl CompressionLevel {
    pub fn is_valid(self) -> bool {
        let value = match self {
            Self::None => 0,
            Self::Fast => 1,
            Self::Default => 3,
            Self::Best => 19,
        };
        value <= 19
    }
}

impl From<CompressionLevel> for i32 {
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::None => 0,
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => DEFAULT_COMPRESSION_LEVEL,
            CompressionLevel::Best => 19,
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

        Ok(Self { level: level.into() })
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty data");
        }

        zstd::stream::encode_all(data, self.level).map_err(|error| anyhow::anyhow!("compression failed: {error}"))
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty data");
        }

        zstd::stream::decode_all(data).map_err(|error| anyhow::anyhow!("decompression failed: {error}"))
    }
}
