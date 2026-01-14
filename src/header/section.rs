use anyhow::{Result, bail};
use byteorder::{BigEndian, ByteOrder};

use crate::config::{DATA_SHARDS, PARITY_SHARDS};
use crate::encoding::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Magic,
    Salt,
    HeaderData,
    Mac,
}

pub const SECTION_ORDER: [SectionType; 4] = [
    SectionType::Magic,
    SectionType::Salt,
    SectionType::HeaderData,
    SectionType::Mac,
];

#[derive(Debug)]
pub struct EncodedSection {
    pub data: Vec<u8>,
    pub length: u32,
}

pub struct SectionEncoder {
    rs: Encoding,
}

impl SectionEncoder {
    pub fn new() -> Result<Self> {
        let rs = Encoding::new(DATA_SHARDS, PARITY_SHARDS)?;
        Ok(Self { rs })
    }

    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        if data.is_empty() {
            bail!("data cannot be empty");
        }

        let encoded = self.rs.encode(data)?;
        let length = encoded.len() as u32;

        Ok(EncodedSection {
            data: encoded,
            length,
        })
    }

    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        if section.data.is_empty() {
            bail!("invalid encoded section");
        }

        self.rs.decode(&section.data)
    }

    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        let mut bytes = [0u8; 4];
        BigEndian::write_u32(&mut bytes, length);
        self.encode_section(&bytes)
    }

    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;
        if decoded.len() < 4 {
            bail!("invalid length prefix size");
        }

        Ok(BigEndian::read_u32(&decoded[..4]))
    }
}

impl Default for SectionEncoder {
    fn default() -> Self {
        Self::new().expect("valid default parameters")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_section() {
        let encoder = SectionEncoder::default();
        let data = b"Hello, World!";

        let encoded = encoder.encode_section(data).unwrap();
        let decoded = encoder.decode_section(&encoded).unwrap();

        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_encode_decode_length() {
        let encoder = SectionEncoder::default();
        let length = 12345u32;

        let encoded = encoder.encode_length(length).unwrap();
        let decoded = encoder.decode_length(&encoded).unwrap();

        assert_eq!(decoded, length);
    }

    #[test]
    fn test_encode_empty() {
        let encoder = SectionEncoder::default();
        assert!(encoder.encode_section(&[]).is_err());
    }
}
