use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::compression::{CompressionLevel, Compressor};
use crate::encoding::Encoding;
use crate::secret::SecretBytes;

#[serde_with::serde_as]
#[derive(Serialize, Deserialize)]
struct EncodedSection {
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
    pub salt: SecretBytes,
    pub params: SecretBytes,
    pub metadata: SecretBytes,
    pub mac: SecretBytes,
}

pub struct SectionEncoder {
    compressor: Compressor,
    encoder: Encoding,
}

impl SectionEncoder {
    pub fn new(original_count: usize, recovery_count: usize) -> Result<Self> {
        let compressor = Compressor::new(CompressionLevel::Fast).context("failed to initialize compressor")?;
        let encoder = Encoding::new(original_count, recovery_count).context("failed to initialize encoder")?;

        Ok(Self { compressor, encoder })
    }

    pub fn encode(&self, salt: &[u8], params: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let encoded_section = EncodedSection {
            salt: self.encoder.encode(salt).context("failed to encode salt")?,
            params: self.encoder.encode(params).context("failed to encode params")?,
            metadata: self.encoder.encode(metadata).context("failed to encode metadata")?,
            mac: self.encoder.encode(mac).context("failed to encode mac")?,
        };

        let serialized = postcard::to_allocvec(&encoded_section).context("failed to serialize section")?;
        let compressed = self.compressor.compress(&serialized).context("failed to compress section")?;

        let compressed_len = u32::try_from(compressed.len()).context("section too large")?;
        let mut result = compressed_len.to_le_bytes().to_vec();
        result.extend_from_slice(&compressed);

        Ok(result)
    }

    pub async fn decode<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Header> {
        let buffer_len = reader.read_u32_le().await.context("failed to read section length")?;

        let mut buffer = vec![0u8; buffer_len as usize];
        reader.read_exact(&mut buffer).await.context("failed to read section")?;

        let decompressed = self.compressor.decompress(&buffer).context("failed to decompress section")?;
        let encoded_section: EncodedSection = postcard::from_bytes(&decompressed).context("failed to deserialize section")?;

        Ok(Header {
            salt: SecretBytes::new(self.encoder.decode(&encoded_section.salt).context("failed to decode salt")?),
            params: SecretBytes::new(self.encoder.decode(&encoded_section.params).context("failed to decode params")?),
            metadata: SecretBytes::new(self.encoder.decode(&encoded_section.metadata).context("failed to decode metadata")?),
            mac: SecretBytes::new(self.encoder.decode(&encoded_section.mac).context("failed to decode mac")?),
        })
    }
}
