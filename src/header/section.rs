use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};
use wincode::{SchemaRead, SchemaWrite};

use crate::encoding::Encoding;
use crate::secret::SecretBytes;

const SECTION_COUNT: usize = 4;

pub struct DecodedSections {
    pub salt: SecretBytes,
    pub parameter: Vec<u8>,
    pub metadata: Vec<u8>,
    pub mac: SecretBytes,
}

#[derive(SchemaRead, SchemaWrite)]
struct SectionsLength {
    lengths: [u32; SECTION_COUNT],
}

impl SectionsLength {
    const SIZE: usize = std::mem::size_of::<Self>();

    fn total_bytes(&self) -> usize {
        self.lengths.iter().map(|&n| n as usize).sum()
    }
}

pub struct SectionShield {
    encoder: Encoding,
}

impl SectionShield {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(Self { encoder: Encoding::new(data_shards, parity_shards)? })
    }

    pub fn pack(&self, salt: &[u8], parameter: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let sections = [salt, parameter, metadata, mac];

        for (idx, data) in sections.iter().enumerate() {
            if data.is_empty() {
                anyhow::bail!("section {idx} is empty");
            }
        }

        let mut encoded_sections = Vec::with_capacity(SECTION_COUNT);
        let mut lengths = [0u32; SECTION_COUNT];

        for (idx, &section) in sections.iter().enumerate() {
            let encoded = self.encoder.encode(section).context("encode section")?;
            lengths[idx] = u32::try_from(encoded.len())?;
            encoded_sections.push(encoded);
        }

        let sections_length = SectionsLength { lengths };
        let mut result = Vec::with_capacity(SectionsLength::SIZE + sections_length.total_bytes());

        result.extend_from_slice(&wincode::serialize(&sections_length)?);
        for section in &encoded_sections {
            result.extend_from_slice(section);
        }

        Ok(result)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<DecodedSections> {
        let mut buffer = [0u8; SectionsLength::SIZE];
        reader.read_exact(&mut buffer).await.context("failed to read sections length")?;

        let header: SectionsLength = wincode::deserialize(&buffer).context("failed to deserialize sections length")?;
        let decoded_sections = self.read_sections(reader, &header).await?;

        Ok(decoded_sections)
    }

    async fn read_sections<R: AsyncRead + Unpin>(&self, reader: &mut R, header: &SectionsLength) -> Result<DecodedSections> {
        let [salt, parameter, metadata, mac] = header.lengths;

        Ok(DecodedSections {
            salt: SecretBytes::from_slice(&self.read_and_decode(reader, salt, 0).await?),
            parameter: self.read_and_decode(reader, parameter, 1).await?,
            metadata: self.read_and_decode(reader, metadata, 2).await?,
            mac: SecretBytes::from_slice(&self.read_and_decode(reader, mac, 3).await?),
        })
    }

    async fn read_and_decode<R: AsyncRead + Unpin>(&self, reader: &mut R, size: u32, section_idx: usize) -> Result<Vec<u8>> {
        if size == 0 {
            anyhow::bail!("section {section_idx} is empty");
        }

        let mut buffer = vec![0u8; size as usize];
        reader
            .read_exact(&mut buffer)
            .await
            .with_context(|| format!("failed to read section {} ({} bytes)", section_idx, size as usize))?;

        self.encoder.decode(&buffer).with_context(|| format!("failed to decode section {section_idx}"))
    }
}
