use crate::utils::UintType;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::Read;

use super::header::{Header, HEADER_DATA_SIZE, MAGIC_SIZE};
use super::section::{verify_magic, EncodedSection, SectionEncoder, SectionType, SECTION_ORDER};

pub struct Deserializer<'a> {
    header: &'a mut Header,
    encoder: SectionEncoder,
}

impl<'a> Deserializer<'a> {
    pub fn new(header: &'a mut Header) -> Result<Self> {
        let encoder = SectionEncoder::new()?;
        Ok(Self { header, encoder })
    }

    pub fn unmarshal(&mut self, r: &mut dyn Read) -> Result<()> {
        let length_sizes = self.read_length_sizes(r)?;
        let section_lengths = self.read_and_decode_lengths(r, &length_sizes)?;
        let decoded_sections = self.read_and_decode_data(r, &section_lengths)?;

        self.header.set_decoded_sections(decoded_sections.clone());

        // Verify magic bytes
        let magic = decoded_sections
            .get(&SectionType::Magic)
            .ok_or_else(|| anyhow!("invalid or missing magic section"))?;

        if magic.len() < MAGIC_SIZE {
            return Err(anyhow!("magic section too short"));
        }

        if !verify_magic(&magic[..MAGIC_SIZE]) {
            return Err(anyhow!("invalid magic bytes"));
        }

        // Deserialize header data
        let header_data = decoded_sections
            .get(&SectionType::HeaderData)
            .ok_or_else(|| anyhow!("invalid or missing header data section"))?;

        if header_data.len() < HEADER_DATA_SIZE {
            return Err(anyhow!("header data section too short"));
        }

        self.header.deserialize(&header_data[..HEADER_DATA_SIZE])?;
        self.header.validate()?;

        Ok(())
    }

    fn read_length_sizes(&self, r: &mut dyn Read) -> Result<HashMap<SectionType, u32>> {
        let mut lengths_header = [0u8; 16];
        r.read_exact(&mut lengths_header)
            .map_err(|e| anyhow!("failed to read lengths header: {}", e))?;

        let mut length_sizes = HashMap::new();
        length_sizes.insert(SectionType::Magic, u32::from_bytes(&lengths_header[0..4]));
        length_sizes.insert(SectionType::Salt, u32::from_bytes(&lengths_header[4..8]));
        length_sizes.insert(
            SectionType::HeaderData,
            u32::from_bytes(&lengths_header[8..12]),
        );
        length_sizes.insert(SectionType::MAC, u32::from_bytes(&lengths_header[12..16]));

        Ok(length_sizes)
    }

    fn read_and_decode_lengths(
        &self,
        r: &mut dyn Read,
        length_sizes: &HashMap<SectionType, u32>,
    ) -> Result<HashMap<SectionType, u32>> {
        let mut section_lengths = HashMap::new();

        for section_type in &SECTION_ORDER {
            let encoded_length = length_sizes
                .get(section_type)
                .ok_or_else(|| anyhow!("missing length size for {:?}", section_type))?;

            let mut encoded_data = vec![0u8; *encoded_length as usize];
            r.read_exact(&mut encoded_data).map_err(|e| {
                anyhow!(
                    "failed to read encoded length for {:?}: {}",
                    section_type,
                    e
                )
            })?;

            let section = EncodedSection {
                data: encoded_data,
                length: *encoded_length,
            };

            let length = self.encoder.decode_length_prefix(&section)?;
            section_lengths.insert(*section_type, length);
        }

        Ok(section_lengths)
    }

    fn read_and_decode_data(
        &self,
        r: &mut dyn Read,
        section_lengths: &HashMap<SectionType, u32>,
    ) -> Result<HashMap<SectionType, Vec<u8>>> {
        let mut decoded_sections = HashMap::new();

        for section_type in &SECTION_ORDER {
            let length = section_lengths
                .get(section_type)
                .ok_or_else(|| anyhow!("missing section length for {:?}", section_type))?;

            let mut encoded_data = vec![0u8; *length as usize];
            r.read_exact(&mut encoded_data)
                .map_err(|e| anyhow!("failed to read encoded {:?}: {}", section_type, e))?;

            let section = EncodedSection {
                data: encoded_data,
                length: *length,
            };

            let decoded = self.encoder.decode_section(&section)?;
            decoded_sections.insert(*section_type, decoded);
        }

        Ok(decoded_sections)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::header::serializer::Serializer;
    use std::io::Cursor;

    #[test]
    fn test_unmarshal() {
        let mut header = Header::new().unwrap();
        header.set_original_size(12345);
        header.set_protected(true);

        let salt = crypto::get_random_bytes(crypto::ARGON_SALT_LEN).unwrap();
        let key = vec![0u8; 64];

        // Serialize
        let serializer = Serializer::new(&header).unwrap();
        let marshalled = serializer.marshal(&salt, &key).unwrap();

        // Deserialize
        let mut header2 = Header::new().unwrap();
        let mut cursor = Cursor::new(marshalled);
        header2.unmarshal(&mut cursor).unwrap();

        assert_eq!(header.version, header2.version);
        assert_eq!(header.flags, header2.flags);
        assert_eq!(header.original_size, header2.original_size);
    }
}
