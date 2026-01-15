use std::io::Read;

use anyhow::{Context, Result, bail};
use hashbrown::HashMap;

use crate::config::{HEADER_DATA_SIZE, MAGIC_SIZE};
use crate::header::Header;
use crate::header::mac::verify_magic;
use crate::header::section::{EncodedSection, SECTION_ORDER, SectionEncoder, SectionType};
use crate::header::serializer::magic_bytes;

pub struct Deserializer<'a> {
    header: &'a mut Header,
    encoder: SectionEncoder,
}

impl<'a> Deserializer<'a> {
    pub fn new(header: &'a mut Header) -> Result<Self> {
        let encoder = SectionEncoder::new()?;
        Ok(Self { header, encoder })
    }

    pub fn unmarshal<R: Read>(&mut self, mut reader: R) -> Result<()> {
        let length_sizes = self.read_length_sizes(&mut reader)?;
        let section_lengths = self.read_and_decode_lengths(&mut reader, &length_sizes)?;
        let decoded_sections = self.read_and_decode_data(&mut reader, &section_lengths)?;
        self.header.decoded_sections = Some(decoded_sections);

        let magic = self.header.get_section(SectionType::Magic, MAGIC_SIZE)?;
        if !verify_magic(magic, &magic_bytes()) {
            bail!("invalid magic bytes");
        }

        let header_data: Vec<u8> = self.header.get_section(SectionType::HeaderData, HEADER_DATA_SIZE)?.to_vec();
        self.deserialize_header_data(&header_data)?;
        self.header.validate()?;

        Ok(())
    }

    fn read_length_sizes<R: Read>(&self, reader: &mut R) -> Result<HashMap<SectionType, u32>> {
        let mut lengths_header = [0u8; 16];
        reader.read_exact(&mut lengths_header).context("failed to read lengths header")?;

        let mut sizes = HashMap::new();
        sizes.insert(SectionType::Magic, u32::from_be_bytes([lengths_header[0], lengths_header[1], lengths_header[2], lengths_header[3]]));
        sizes.insert(SectionType::Salt, u32::from_be_bytes([lengths_header[4], lengths_header[5], lengths_header[6], lengths_header[7]]));
        sizes.insert(SectionType::HeaderData, u32::from_be_bytes([lengths_header[8], lengths_header[9], lengths_header[10], lengths_header[11]]));
        sizes.insert(SectionType::Mac, u32::from_be_bytes([lengths_header[12], lengths_header[13], lengths_header[14], lengths_header[15]]));

        Ok(sizes)
    }

    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &HashMap<SectionType, u32>) -> Result<HashMap<SectionType, u32>> {
        let mut section_lengths = HashMap::new();

        for section_type in SECTION_ORDER {
            let size = *length_sizes.get(&section_type).context("missing length size")?;

            let mut encoded_length = vec![0u8; size as usize];
            reader
                .read_exact(&mut encoded_length)
                .with_context(|| format!("failed to read encoded length for {:?}", section_type))?;

            let section = EncodedSection { data: encoded_length, length: size };
            let length = self.encoder.decode_length(&section)?;
            section_lengths.insert(section_type, length);
        }

        Ok(section_lengths)
    }

    fn read_and_decode_data<R: Read>(&self, reader: &mut R, section_lengths: &HashMap<SectionType, u32>) -> Result<HashMap<SectionType, Vec<u8>>> {
        let mut decoded_sections = HashMap::new();

        for section_type in SECTION_ORDER {
            let length = *section_lengths.get(&section_type).context("missing section length")?;

            let mut encoded_data = vec![0u8; length as usize];
            reader.read_exact(&mut encoded_data).with_context(|| format!("failed to read encoded {:?}", section_type))?;

            let section = EncodedSection { data: encoded_data, length };
            let decoded = self.encoder.decode_section(&section)?;
            decoded_sections.insert(section_type, decoded);
        }

        Ok(decoded_sections)
    }

    fn deserialize_header_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < HEADER_DATA_SIZE {
            bail!("invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());
        }

        self.header.version = u16::from_be_bytes([data[0], data[1]]);
        self.header.flags = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        self.header.original_size = u64::from_be_bytes([data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13]]);
        Ok(())
    }
}
