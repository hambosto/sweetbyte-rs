use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt};
use wincode::{SchemaRead, SchemaWrite};

use crate::encoding::Encoding;

pub struct DecodedSections {
    pub salt: Vec<u8>,
    pub parameter: Vec<u8>,
    pub metadata: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(SchemaRead, SchemaWrite)]
struct LengthsHeader {
    salt_len: u32,
    parameter_len: u32,
    metadata_len: u32,
    mac_len: u32,
}

impl LengthsHeader {
    const SIZE: usize = 16;

    fn from_array(arr: [u32; 4]) -> Self {
        Self { salt_len: arr[0], parameter_len: arr[1], metadata_len: arr[2], mac_len: arr[3] }
    }

    fn as_array(&self) -> [u32; 4] {
        [self.salt_len, self.parameter_len, self.metadata_len, self.mac_len]
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

        let mut encoded_sections: [Vec<u8>; 4] = Default::default();
        let mut lengths = [0u32; 4];
        for (idx, &data) in sections.iter().enumerate() {
            encoded_sections[idx] = self.encoder.encode(data).context("encode section")?;
            lengths[idx] = encoded_sections[idx].len() as u32;
        }

        let lengths_header = LengthsHeader::from_array(lengths);
        let total_len = LengthsHeader::SIZE + encoded_sections.iter().map(|s| s.len()).sum::<usize>();
        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(&wincode::serialize(&lengths_header)?);

        for section in &encoded_sections {
            result.extend_from_slice(section);
        }

        Ok(result)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<DecodedSections> {
        let mut buffer = [0u8; LengthsHeader::SIZE];
        reader.read_exact(&mut buffer).await.context("failed to read lengths header")?;

        let lengths_header: LengthsHeader = wincode::deserialize(&buffer).context("failed to deserialize lengths header")?;
        let decoded_sections = self.read_sections(reader, &lengths_header).await?;

        Ok(decoded_sections)
    }

    async fn read_sections<R: AsyncRead + Unpin>(&self, reader: &mut R, header: &LengthsHeader) -> Result<DecodedSections> {
        let lengths = header.as_array();

        let mut sections: [Vec<u8>; 4] = Default::default();
        for (idx, &length) in lengths.iter().enumerate() {
            sections[idx] = self.read_and_decode(reader, length, idx).await?;
        }

        Ok(DecodedSections { salt: std::mem::take(&mut sections[0]), parameter: std::mem::take(&mut sections[1]), metadata: std::mem::take(&mut sections[2]), mac: std::mem::take(&mut sections[3]) })
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
