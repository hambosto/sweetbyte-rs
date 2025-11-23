use crate::encoding::Encoding;
use crate::utils::UintType;
use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Magic,
    Salt,
    HeaderData,
    MAC,
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionType::Magic => write!(f, "magic"),
            SectionType::Salt => write!(f, "salt"),
            SectionType::HeaderData => write!(f, "header_data"),
            SectionType::MAC => write!(f, "mac"),
        }
    }
}

pub const SECTION_ORDER: [SectionType; 4] = [
    SectionType::Magic,
    SectionType::Salt,
    SectionType::HeaderData,
    SectionType::MAC,
];

pub struct EncodedSection {
    pub data: Vec<u8>,
    pub length: u32,
}

pub struct SectionEncoder {
    encoder: Encoding,
}

impl SectionEncoder {
    pub fn new() -> Result<Self> {
        let encoder = Encoding::new(crate::encoding::DATA_SHARDS, crate::encoding::PARITY_SHARDS)?;
        Ok(Self { encoder })
    }

    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        if data.is_empty() {
            return Err(anyhow!("data cannot be empty"));
        }

        let encoded = self.encoder.encode(data)?;
        let encoded_len = encoded.len();

        if encoded_len > u32::MAX as usize {
            return Err(anyhow!(
                "encoded data length {} exceeds maximum allowed size for u32",
                encoded_len
            ));
        }

        Ok(EncodedSection {
            data: encoded,
            length: encoded_len as u32,
        })
    }

    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        if section.data.is_empty() {
            return Err(anyhow!("invalid encoded section"));
        }

        self.encoder.decode(&section.data)
    }

    pub fn encode_length_prefix(&self, length: u32) -> Result<EncodedSection> {
        let length_bytes = length.to_bytes();
        self.encode_section(&length_bytes)
    }

    pub fn decode_length_prefix(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;

        if decoded.len() < 4 {
            return Err(anyhow!("invalid length prefix size"));
        }

        Ok(u32::from_bytes(&decoded[..4]))
    }
}

pub fn verify_magic(magic: &[u8]) -> bool {
    if magic.len() < 4 {
        return false;
    }
    let expected = 0xCAFEBABEu32.to_bytes();
    magic[..4] == expected[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_encode_decode() {
        let encoder = SectionEncoder::new().unwrap();
        let data = b"test data";

        let encoded = encoder.encode_section(data).unwrap();
        let decoded = encoder.decode_section(&encoded).unwrap();

        // Reed-Solomon encoding may add padding
        assert!(decoded.len() >= data.len());
        assert_eq!(data.as_slice(), &decoded[..data.len()]);
    }

    #[test]
    fn test_verify_magic() {
        let magic = 0xCAFEBABEu32.to_bytes();
        assert!(verify_magic(&magic));

        let wrong = vec![0u8; 4];
        assert!(!verify_magic(&wrong));
    }
}
