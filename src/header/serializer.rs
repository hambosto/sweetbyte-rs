use anyhow::{Result, anyhow, bail};

use crate::config::{ARGON_SALT_LEN, HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use crate::header::Header;
use crate::header::mac::Mac;
use crate::header::section::{EncodedSection, SECTION_ORDER, SectionEncoder, SectionType};

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

        let magic = MAGIC_BYTES.to_be_bytes();
        let header_data = self.serialize_header_data();
        let mac = Mac::compute_bytes(key, &[&magic, salt, &header_data])?;

        let sections = self.encode_sections(&magic, salt, &header_data, &mac)?;
        let length_sections = self.encode_length_prefixes(&sections)?;

        let lengths_header = self.build_lengths_header(&length_sections)?;
        self.assemble_header(&lengths_header, &length_sections, &sections)
    }

    fn validate_inputs(&self, salt: &[u8], key: &[u8]) -> Result<()> {
        self.header.validate()?;

        if salt.len() != ARGON_SALT_LEN {
            bail!("invalid salt size: expected {}, got {}", ARGON_SALT_LEN, salt.len());
        }

        if key.is_empty() {
            bail!("key cannot be empty");
        }

        Ok(())
    }

    fn encode_sections(&self, magic: &[u8], salt: &[u8], header_data: &[u8], mac: &[u8]) -> Result<[(SectionType, EncodedSection); 4]> {
        Ok([
            (SectionType::Magic, self.encoder.encode_section(magic)?),
            (SectionType::Salt, self.encoder.encode_section(salt)?),
            (SectionType::HeaderData, self.encoder.encode_section(header_data)?),
            (SectionType::Mac, self.encoder.encode_section(mac)?),
        ])
    }

    fn encode_length_prefixes(&self, sections: &[(SectionType, EncodedSection); 4]) -> Result<[(SectionType, EncodedSection); 4]> {
        Ok([
            (SectionType::Magic, self.encoder.encode_length(sections[0].1.length())?),
            (SectionType::Salt, self.encoder.encode_length(sections[1].1.length())?),
            (SectionType::HeaderData, self.encoder.encode_length(sections[2].1.length())?),
            (SectionType::Mac, self.encoder.encode_length(sections[3].1.length())?),
        ])
    }

    fn build_lengths_header(&self, length_sections: &[(SectionType, EncodedSection); 4]) -> Result<[u8; 16]> {
        let mut header = [0u8; 16];

        for (i, section_type) in SECTION_ORDER.iter().enumerate() {
            let section = length_sections.iter().find(|(t, _)| t == section_type).ok_or_else(|| anyhow!("section must exist"))?;
            let bytes = section.1.length().to_be_bytes();
            header[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        Ok(header)
    }

    fn assemble_header(&self, lengths_header: &[u8], length_sections: &[(SectionType, EncodedSection); 4], sections: &[(SectionType, EncodedSection); 4]) -> Result<Vec<u8>> {
        let total_size = lengths_header.len() + length_sections.iter().map(|(_, s)| s.data().len()).sum::<usize>() + sections.iter().map(|(_, s)| s.data().len()).sum::<usize>();

        let mut result = Vec::with_capacity(total_size);
        result.extend_from_slice(lengths_header);

        for section_list in [length_sections, sections] {
            for section_type in SECTION_ORDER {
                let section = section_list.iter().find(|(t, _)| *t == section_type).ok_or_else(|| anyhow!("section must exist"))?;
                result.extend_from_slice(section.1.data());
            }
        }

        Ok(result)
    }

    #[inline]
    fn serialize_header_data(&self) -> [u8; HEADER_DATA_SIZE] {
        let mut data = [0u8; HEADER_DATA_SIZE];
        data[0..2].copy_from_slice(&self.header.version().to_be_bytes());
        data[2..6].copy_from_slice(&self.header.flags().to_be_bytes());
        data[6..14].copy_from_slice(&self.header.original_size().to_be_bytes());
        data
    }
}

#[inline]
#[must_use]
pub fn magic_bytes() -> [u8; MAGIC_SIZE] {
    MAGIC_BYTES.to_be_bytes()
}
