use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::compression::{CompressionLevel, Compressor};
use crate::encoding::Encoding;
use crate::secret::Secret;

#[serde_with::serde_as]
#[derive(Serialize, Deserialize)]
struct SectionList {
    #[serde_as(as = "Base64")]
    salt: Vec<u8>,
    #[serde_as(as = "Base64")]
    params: Vec<u8>,
    #[serde_as(as = "Base64")]
    metadata: Vec<u8>,
    #[serde_as(as = "Base64")]
    mac: Vec<u8>,
}

pub struct Header {
    pub salt: Secret,
    pub params: Secret,
    pub metadata: Secret,
    pub mac: Secret,
}

pub struct Section {
    compressor: Compressor,
    encoder: Encoding,
}

impl Section {
    pub fn new(compression_level: CompressionLevel, original_count: usize, recovery_count: usize) -> Result<Self> {
        let compressor = Compressor::new(compression_level).context("failed to initialize compressor")?;
        let encoder = Encoding::new(original_count, recovery_count).context("failed to initialize encoder")?;

        Ok(Self { compressor, encoder })
    }

    pub fn pack(&self, salt: &[u8], params: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let encoded_section = SectionList {
            salt: self.encoder.encode(salt).context("failed to encode salt")?,
            params: self.encoder.encode(params).context("failed to encode params")?,
            metadata: self.encoder.encode(metadata).context("failed to encode metadata")?,
            mac: self.encoder.encode(mac).context("failed to encode mac")?,
        };

        let serialized_section = postcard::to_allocvec(&encoded_section).context("failed to serialize section")?;
        let compressed_section = self.compressor.compress(&serialized_section).context("failed to compress section")?;
        let compressed_length = u32::try_from(compressed_section.len()).context("section too large")?;

        let mut result = compressed_length.to_le_bytes().to_vec();
        result.extend_from_slice(&compressed_section);

        Ok(result)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Header> {
        let buffer_size = reader.read_u32_le().await.context("failed to read section length")?;

        let mut buffer = vec![0u8; buffer_size as usize];
        reader.read_exact(&mut buffer).await.context("failed to read section")?;

        let decompressed_section = self.compressor.decompress(&buffer).context("failed to decompress section")?;
        let encoded_section: SectionList = postcard::from_bytes(&decompressed_section).context("failed to deserialize section")?;

        Ok(Header {
            salt: Secret::new(self.encoder.decode(&encoded_section.salt).context("failed to decode salt")?),
            params: Secret::new(self.encoder.decode(&encoded_section.params).context("failed to decode params")?),
            metadata: Secret::new(self.encoder.decode(&encoded_section.metadata).context("failed to decode metadata")?),
            mac: Secret::new(self.encoder.decode(&encoded_section.mac).context("failed to decode mac")?),
        })
    }
}
