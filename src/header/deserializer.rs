use std::collections::HashMap;
use std::io::Read;

use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ByteOrder};

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
        sizes.insert(SectionType::Magic, BigEndian::read_u32(&lengths_header[0..4]));
        sizes.insert(SectionType::Salt, BigEndian::read_u32(&lengths_header[4..8]));
        sizes.insert(SectionType::HeaderData, BigEndian::read_u32(&lengths_header[8..12]));
        sizes.insert(SectionType::Mac, BigEndian::read_u32(&lengths_header[12..16]));

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

        self.header.version = BigEndian::read_u16(&data[0..2]);
        self.header.flags = BigEndian::read_u32(&data[2..6]);
        self.header.original_size = BigEndian::read_u64(&data[6..14]);
        Ok(())
    }
}
