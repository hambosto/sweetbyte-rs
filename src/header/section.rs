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
    const SIZE: usize = std::mem::size_of::<Self>();

    const fn as_array(&self) -> [u32; 4] {
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
        let raw_sections = [salt, parameter, metadata, mac];

        let encoded_sections = raw_sections.iter().map(|&data| self.encode_non_empty(data)).collect::<Result<Vec<Vec<u8>>>>()?;

        let encoded_lengths = encoded_sections.iter().map(|section| self.encode_length(section.len())).collect::<Result<Vec<Vec<u8>>>>()?;

        let lengths_header = LengthsHeader {
            salt_len: encoded_lengths[0].len() as u32,
            parameter_len: encoded_lengths[1].len() as u32,
            metadata_len: encoded_lengths[2].len() as u32,
            mac_len: encoded_lengths[3].len() as u32,
        };

        let mut result = wincode::serialize(&lengths_header)?;
        for section in encoded_lengths.iter().chain(&encoded_sections) {
            result.extend_from_slice(section);
        }

        Ok(result)
    }

    pub async fn unpack<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<DecodedSections> {
        let lengths_header = self.read_header(reader).await?;

        let section_lengths = self.read_and_decode_lengths(reader, &lengths_header).await?;

        self.read_and_decode_sections(reader, &section_lengths).await
    }

    fn encode_non_empty(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty data");
        }
        self.encoder.encode(data)
    }

    fn encode_length(&self, length: usize) -> Result<Vec<u8>> {
        self.encode_non_empty(&(length as u32).to_be_bytes())
    }

    fn decode_non_empty(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("empty encoded section");
        }
        self.encoder.decode(data)
    }

    fn decode_length(&self, encoded: &[u8]) -> Result<u32> {
        let decoded = self.decode_non_empty(encoded)?;
        if decoded.len() < 4 {
            anyhow::bail!("invalid length prefix");
        }

        Ok(u32::from_be_bytes(decoded[..4].try_into().context("convert length bytes")?))
    }

    async fn read_header<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<LengthsHeader> {
        let mut buffer = [0u8; LengthsHeader::SIZE];
        reader.read_exact(&mut buffer).await.context("read lengths header")?;

        wincode::deserialize(&buffer).context("deserialize lengths header")
    }

    async fn read_and_decode_lengths<R: AsyncRead + Unpin>(&self, reader: &mut R, header: &LengthsHeader) -> Result<[u32; 4]> {
        let mut decoded_lengths = [0u32; 4];

        for (idx, &encoded_size) in header.as_array().iter().enumerate() {
            let encoded = self.read_bytes(reader, encoded_size as usize).await?;
            decoded_lengths[idx] = self.decode_length(&encoded)?;
        }

        Ok(decoded_lengths)
    }

    async fn read_and_decode_sections<R: AsyncRead + Unpin>(&self, reader: &mut R, section_lengths: &[u32; 4]) -> Result<DecodedSections> {
        Ok(DecodedSections {
            salt: self.read_and_decode(reader, section_lengths[0]).await?,
            parameter: self.read_and_decode(reader, section_lengths[1]).await?,
            metadata: self.read_and_decode(reader, section_lengths[2]).await?,
            mac: self.read_and_decode(reader, section_lengths[3]).await?,
        })
    }

    async fn read_and_decode<R: AsyncRead + Unpin>(&self, reader: &mut R, size: u32) -> Result<Vec<u8>> {
        let encoded = self.read_bytes(reader, size as usize).await?;
        self.decode_non_empty(&encoded)
    }

    async fn read_bytes<R: AsyncRead + Unpin>(&self, reader: &mut R, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        reader.read_exact(&mut buffer).await.context("read bytes")?;
        Ok(buffer)
    }
}
