use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::MAGIC_BYTES;
use crate::encoding::Encoding;

pub struct DecodedSections {
    pub magic: Vec<u8>,
    pub salt: Vec<u8>,
    pub header_data: Vec<u8>,
    pub metadata: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Serialize, Deserialize, SchemaRead, SchemaWrite)]
struct LengthsHeader {
    magic_len: u32,
    salt_len: u32,
    header_data_len: u32,
    metadata_len: u32,
    mac_len: u32,
}

impl LengthsHeader {
    const SIZE: usize = 20;

    fn as_array(&self) -> [u32; 5] {
        [self.magic_len, self.salt_len, self.header_data_len, self.metadata_len, self.mac_len]
    }
}

pub struct SectionShield {
    encoder: Encoding,
}

impl SectionShield {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(Self { encoder: Encoding::new(data_shards, parity_shards)? })
    }

    pub fn pack(&self, magic: &[u8], salt: &[u8], header_data: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        let raw_sections = [magic, salt, header_data, metadata, mac];
        let sections: Vec<Vec<u8>> = raw_sections.iter().map(|&data| self.encode_non_empty(data)).collect::<Result<Vec<Vec<u8>>>>()?;

        let length_sections: Vec<Vec<u8>> = sections
            .iter()
            .map(|section| self.encode_non_empty(&(section.len() as u32).to_be_bytes()))
            .collect::<Result<Vec<Vec<u8>>>>()?;

        let lengths_header = LengthsHeader {
            magic_len: length_sections[0].len() as u32,
            salt_len: length_sections[1].len() as u32,
            header_data_len: length_sections[2].len() as u32,
            metadata_len: length_sections[3].len() as u32,
            mac_len: length_sections[4].len() as u32,
        };

        let mut result = wincode::serialize(&lengths_header)?;
        for section in length_sections.iter().chain(sections.iter()) {
            result.extend_from_slice(section);
        }

        Ok(result)
    }

    fn encode_non_empty(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty data");
        }

        self.encoder.encode(data)
    }

    fn decode_non_empty(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty encoded section");
        }

        self.encoder.decode(data)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<DecodedSections> {
        let mut buffer = [0u8; LengthsHeader::SIZE];
        reader.read_exact(&mut buffer).await.context("read")?;

        let lengths_header: LengthsHeader = wincode::deserialize(&buffer).context("deserialize lengths header")?;
        let section_lengths = self.read_and_decode_lengths(reader, &lengths_header).await?;
        let sections = self.read_and_decode_sections(reader, &section_lengths).await?;

        Ok(sections)
    }

    async fn read_and_decode_lengths<R: AsyncRead + Unpin>(&self, reader: &mut R, header: &LengthsHeader) -> Result<[u32; 5]> {
        let mut decoded_lengths = Vec::with_capacity(5);

        for &size in header.as_array().iter() {
            let mut buffer = vec![0u8; size as usize];
            reader.read_exact(&mut buffer).await.context("read length section")?;

            let decoded = self.decode_non_empty(&buffer)?;
            if decoded.len() < 4 {
                anyhow::bail!("invalid length prefix");
            }

            let length = u32::from_be_bytes(decoded[..4].try_into().context("convert length")?);
            decoded_lengths.push(length);
        }

        decoded_lengths.try_into().map_err(|error| anyhow::anyhow!("convert length array: {error:?}"))
    }

    async fn read_and_decode_sections<R: AsyncRead + Unpin>(&self, reader: &mut R, section_lengths: &[u32; 5]) -> Result<DecodedSections> {
        let magic = self.read_and_decode(reader, section_lengths[0], "magic").await?;

        if magic != MAGIC_BYTES.to_be_bytes() {
            anyhow::bail!("invalid magic bytes");
        }

        Ok(DecodedSections {
            magic,
            salt: self.read_and_decode(reader, section_lengths[1], "salt").await?,
            header_data: self.read_and_decode(reader, section_lengths[2], "header data").await?,
            metadata: self.read_and_decode(reader, section_lengths[3], "metadata").await?,
            mac: self.read_and_decode(reader, section_lengths[4], "mac").await?,
        })
    }

    async fn read_and_decode<R: AsyncRead + Unpin>(&self, reader: &mut R, size: u32, _name: &str) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size as usize];
        reader.read_exact(&mut buffer).await.context("read")?;

        self.decode_non_empty(&buffer)
    }
}
