use anyhow::{Result, ensure};

use crate::config::{ARGON_SALT_LEN, HEADER_DATA_SIZE, MAGIC_BYTES};
use crate::header::mac::Mac;
use crate::header::section::{EncodedSection, SectionEncoder, SectionType};

pub struct Serializer<'a> {
    encoder: &'a SectionEncoder,
}

impl<'a> Serializer<'a> {
    #[inline]
    #[must_use]
    pub const fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    pub fn serialize(&self, version: u16, flags: u32, original_size: u64, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        ensure!(salt.len() == ARGON_SALT_LEN, "invalid salt size: expected {}, got {}", ARGON_SALT_LEN, salt.len());
        ensure!(!key.is_empty(), "key cannot be empty");

        let magic = MAGIC_BYTES.to_be_bytes();
        let header_data = Self::serialize_header_data(version, flags, original_size);
        let mac = Mac::new(key)?.compute(&[&magic, salt, &header_data])?;

        let raw_sections: [&[u8]; 4] = [&magic, salt, &header_data, &mac];
        let sections = self.encode_all_sections(&raw_sections)?;
        let length_sections = self.encode_length_prefixes(&sections)?;
        let lengths_header = Self::build_lengths_header(&length_sections);

        Ok(Self::assemble(&lengths_header, &length_sections, &sections))
    }

    fn encode_all_sections(&self, raw: &[&[u8]; 4]) -> Result<[EncodedSection; 4]> {
        SectionType::ALL
            .iter()
            .map(|st| self.encoder.encode_section(raw[st.index()]))
            .collect::<Result<Vec<EncodedSection>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    fn encode_length_prefixes(&self, sections: &[EncodedSection; 4]) -> Result<[EncodedSection; 4]> {
        SectionType::ALL
            .iter()
            .map(|st| self.encoder.encode_length(sections[st.index()].length_u32()))
            .collect::<Result<Vec<EncodedSection>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    fn build_lengths_header(length_sections: &[EncodedSection; 4]) -> [u8; 16] {
        let mut header = [0u8; 16];
        for (i, section) in length_sections.iter().enumerate() {
            let offset = i * 4;
            header[offset..offset + 4].copy_from_slice(&section.length_u32().to_be_bytes());
        }
        header
    }

    fn assemble(lengths_header: &[u8], length_sections: &[EncodedSection; 4], data_sections: &[EncodedSection; 4]) -> Vec<u8> {
        let total_size = lengths_header.len() + length_sections.iter().map(|s| s.len()).sum::<usize>() + data_sections.iter().map(|s| s.len()).sum::<usize>();

        let mut result = Vec::with_capacity(total_size);
        result.extend_from_slice(lengths_header);

        for section in length_sections {
            result.extend_from_slice(section.data());
        }
        for section in data_sections {
            result.extend_from_slice(section.data());
        }

        result
    }

    #[inline]
    fn serialize_header_data(version: u16, flags: u32, original_size: u64) -> [u8; HEADER_DATA_SIZE] {
        let mut data = [0u8; HEADER_DATA_SIZE];
        data[0..2].copy_from_slice(&version.to_be_bytes());
        data[2..6].copy_from_slice(&flags.to_be_bytes());
        data[6..14].copy_from_slice(&original_size.to_be_bytes());
        data
    }
}
