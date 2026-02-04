use anyhow::Result;

#[derive(Default, Clone, Copy)]
pub enum CompressionLevel {
    Fast,
    #[default]
    Default,
    Good,
    Best,
}

impl CompressionLevel {
    pub fn value(self) -> i32 {
        match self {
            Self::Fast => 1,
            Self::Default => 3,
            Self::Good => 9,
            Self::Best => 22,
        }
    }

    pub fn is_valid(self) -> bool {
        let value = self.value();
        (1..=22).contains(&value)
    }
}

impl From<CompressionLevel> for i32 {
    fn from(level: CompressionLevel) -> Self {
        level.value()
    }
}

pub struct Compressor {
    level: i32,
}

impl Compressor {
    pub fn new(level: CompressionLevel) -> Result<Self> {
        if !level.is_valid() {
            anyhow::bail!("invalid compression level: {}", level.value());
        }

        Ok(Self { level: level.into() })
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
