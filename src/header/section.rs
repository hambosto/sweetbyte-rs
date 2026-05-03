use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::encoding::Encoding;
use crate::secret::SecretBytes;

#[derive(Serialize, Deserialize)]
struct EncodedSection {
    salt: Vec<u8>,
    params: Vec<u8>,
    metadata: Vec<u8>,
    mac: Vec<u8>,
}

pub struct Header {
    pub salt: SecretBytes,
    pub params: Vec<u8>,
    pub metadata: Vec<u8>,
    pub mac: SecretBytes,
}

pub struct SectionEncoder {
    encoder: Encoding,
}

impl SectionEncoder {
    pub fn new(data: usize, parity: usize) -> Result<Self> {
        Ok(Self { encoder: Encoding::new(data, parity)? })
    }

    pub fn encode(&self, salt: &[u8], params: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let encoded_section = EncodedSection {
            salt: self.encoder.encode(salt).context("failed to encode salt")?,
            params: self.encoder.encode(params).context("failed to encode params")?,
            metadata: self.encoder.encode(metadata).context("failed to encode metadata")?,
            mac: self.encoder.encode(mac).context("failed to encode mac")?,
        };

        let serialized = postcard::to_allocvec(&encoded_section).context("failed to serialize section")?;
        let serialized_len = u32::try_from(serialized.len()).context("section too large")?;

        let mut result = serialized_len.to_le_bytes().to_vec();
        result.extend_from_slice(&serialized);

        Ok(result)
    }

    pub async fn decode<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Header> {
        let serialized_len = reader.read_u32_le().await.context("failed to read section length")?;

        let mut serialized = vec![0u8; serialized_len as usize];
        reader.read_exact(&mut serialized).await.context("failed to read section")?;

        let encoded_section: EncodedSection = postcard::from_bytes(&serialized).context("failed to deserialize section")?;

        Ok(Header {
            salt: SecretBytes::new(self.encoder.decode(&encoded_section.salt).context("failed to decode salt")?),
            params: self.encoder.decode(&encoded_section.params).context("failed to decode params")?,
            metadata: self.encoder.decode(&encoded_section.metadata).context("failed to decode metadata")?,
            mac: SecretBytes::new(self.encoder.decode(&encoded_section.mac).context("failed to decode mac")?),
        })
    }
}
