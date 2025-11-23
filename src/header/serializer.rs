use crate::utils::UintType;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

use super::header::{Header, MAGIC_BYTES};
use super::mac;
use super::section::{EncodedSection, SectionEncoder, SectionType, SECTION_ORDER};

pub struct Serializer<'a> {
    header: &'a Header,
    encoder: SectionEncoder,
}

impl<'a> Serializer<'a> {
    pub fn new(header: &'a Header) -> Result<Self> {
        let encoder = SectionEncoder::new()?;
        Ok(Self { header, encoder })
    }

    pub fn marshal(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.validate_inputs(salt, key)?;

        let magic = MAGIC_BYTES.to_bytes();
        let header_data = self.header.serialize();

        let mac = mac::compute_mac(key, &[&magic, salt, &header_data])?;

        let sections = self.encode_sections(&magic, salt, &header_data, &mac)?;
        let length_sections = self.encode_length_prefixes(&sections)?;
        let lengths_header = self.build_lengths_header(&length_sections);

        Ok(self.assemble_encoded_header(lengths_header, length_sections, sections))
    }

    fn validate_inputs(&self, salt: &[u8], key: &[u8]) -> Result<()> {
        self.header.validate()?;
        if salt.len() != crate::crypto::ARGON_SALT_LEN {
            return Err(anyhow!(
                "invalid salt size: expected {}, got {}",
                crate::crypto::ARGON_SALT_LEN,
                salt.len()
            ));
        }
        if key.is_empty() {
            return Err(anyhow!("key cannot be empty"));
        }
        Ok(())
    }

    fn encode_sections(
        &self,
        magic: &[u8],
        salt: &[u8],
        header_data: &[u8],
        mac: &[u8],
    ) -> Result<HashMap<SectionType, EncodedSection>> {
        let mut sections = HashMap::new();

        sections.insert(SectionType::Magic, self.encoder.encode_section(magic)?);
        sections.insert(SectionType::Salt, self.encoder.encode_section(salt)?);
        sections.insert(
            SectionType::HeaderData,
            self.encoder.encode_section(header_data)?,
        );
        sections.insert(SectionType::MAC, self.encoder.encode_section(mac)?);

        Ok(sections)
    }

    fn encode_length_prefixes(
        &self,
        sections: &HashMap<SectionType, EncodedSection>,
    ) -> Result<HashMap<SectionType, EncodedSection>> {
        let mut length_sections = HashMap::new();

        for (section_type, section) in sections.iter() {
            length_sections.insert(
                *section_type,
                self.encoder.encode_length_prefix(section.length)?,
            );
        }

        Ok(length_sections)
    }

    fn build_lengths_header(
        &self,
        length_sections: &HashMap<SectionType, EncodedSection>,
    ) -> Vec<u8> {
        let mut lengths_header = Vec::with_capacity(16);

        for section_type in &SECTION_ORDER {
            let sec = length_sections.get(section_type).expect(&format!(
                "missing encoded length section for {:?}",
                section_type
            ));
            lengths_header.extend_from_slice(&sec.length.to_bytes());
        }

        lengths_header
    }

    fn assemble_encoded_header(
        &self,
        lengths_header: Vec<u8>,
        length_sections: HashMap<SectionType, EncodedSection>,
        sections: HashMap<SectionType, EncodedSection>,
    ) -> Vec<u8> {
        let mut result = lengths_header;

        // Append encoded length prefixes
        for section_type in &SECTION_ORDER {
            let sec = length_sections.get(section_type).expect(&format!(
                "missing encoded length prefix for {:?}",
                section_type
            ));
            result.extend_from_slice(&sec.data);
        }

        // Append encoded data sections
        for section_type in &SECTION_ORDER {
            let sec = sections
                .get(section_type)
                .expect(&format!("missing encoded section for {:?}", section_type));
            result.extend_from_slice(&sec.data);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn test_marshal() {
        let mut header = Header::new().unwrap();
        header.set_original_size(12345);
        header.set_protected(true);

        let salt = crypto::get_random_bytes(crypto::ARGON_SALT_LEN).unwrap();
        let key = vec![0u8; 64];

        let serializer = Serializer::new(&header).unwrap();
        let marshalled = serializer.marshal(&salt, &key).unwrap();

        // Should have lengths header (16) + encoded sections
        assert!(marshalled.len() > 16);
    }
}
