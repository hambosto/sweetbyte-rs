use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::config::MAX_SECTION_SIZE;
use crate::core::Secret;
use crate::transform::{Compression, Encoding};

const PREFIX_LEN: usize = 4;

#[derive(Serialize, Deserialize)]
struct SectionList {
    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    params: Vec<u8>,
    #[serde(with = "serde_bytes")]
    metadata: Vec<u8>,
    #[serde(with = "serde_bytes")]
    mac: Vec<u8>,
}

pub(super) struct SectionData {
    pub(super) salt: Secret,
    pub(super) params: Secret,
    pub(super) metadata: Secret,
    pub(super) mac: Secret,
}

pub(super) struct Section {
    compressor: Compression,
    encoder: Encoding,
}

impl Section {
    pub(super) fn new(compression_level: i32, original_count: usize, recovery_count: usize) -> Result<Self> {
        let compressor = Compression::new(compression_level).context("failed to init header compressor")?;
        let encoder = Encoding::new(original_count, recovery_count).context("failed to init header encoder")?;

        Ok(Self { compressor, encoder })
    }

    pub(super) fn pack(&self, salt: &[u8], params: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let encoded_section = SectionList {
            salt: self.encoder.encode(salt).context("failed to encode header salt")?,
            params: self.encoder.encode(params).context("failed to encode header params")?,
            metadata: self.encoder.encode(metadata).context("failed to encode header metadata")?,
            mac: self.encoder.encode(mac).context("failed to encode header tag")?,
        };

        let serialized_section = postcard::to_allocvec(&encoded_section).context("failed to serialize header")?;
        let compressed_section = self.compressor.compress(&serialized_section).context("failed to compress header")?;
        let compressed_length = u32::try_from(compressed_section.len()).context("header length overflow")?;
        if compressed_length > MAX_SECTION_SIZE {
            anyhow::bail!("header exceeds limit");
        }

        let capacity = PREFIX_LEN.checked_add(compressed_section.len()).context("header length overflow")?;
        let mut packed_section = Vec::with_capacity(capacity);
        packed_section.extend_from_slice(&compressed_length.to_le_bytes());
        packed_section.extend_from_slice(&compressed_section);

        Ok(packed_section)
    }

    pub(super) async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<SectionData> {
        let compressed_length = reader.read_u32_le().await.context("failed to read header length")?;
        if compressed_length > MAX_SECTION_SIZE {
            anyhow::bail!("header exceeds limit");
        }

        let mut compressed_section = vec![u8::MIN; compressed_length as usize];
        reader.read_exact(&mut compressed_section).await.context("failed to read header data")?;

        let decompressed_section = self.compressor.decompress(&compressed_section).context("failed to decompress header")?;
        let encoded_section: SectionList = postcard::from_bytes(&decompressed_section).context("failed to parse header")?;

        Ok(SectionData {
            salt: Secret::new(self.encoder.decode(&encoded_section.salt).context("failed to decode header salt")?),
            params: Secret::new(self.encoder.decode(&encoded_section.params).context("failed to decode header params")?),
            metadata: Secret::new(self.encoder.decode(&encoded_section.metadata).context("failed to decode header metadata")?),
            mac: Secret::new(self.encoder.decode(&encoded_section.mac).context("failed to decode header tag")?),
        })
    }
}
