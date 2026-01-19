use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use crate::header::Header;
use crate::header::mac::Mac;
use crate::header::section::{EncodedSection, SECTION_ORDER, SectionEncoder, SectionType, Sections};

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
        let sections = self.read_and_decode_data(&mut reader, &section_lengths)?;
        self.header.set_sections(sections);

        let magic = self.header.get_section(SectionType::Magic, MAGIC_SIZE)?;
        ensure!(Mac::verify_magic(magic, &MAGIC_BYTES.to_be_bytes()), "invalid magic bytes");

        let header_data = self.header.get_section(SectionType::HeaderData, HEADER_DATA_SIZE)?.to_vec();
        self.deserialize_header_data(&header_data)?;
        self.header.validate()?;

        Ok(())
    }

    fn read_length_sizes<R: Read>(&self, reader: &mut R) -> Result<[(SectionType, u32); 4]> {
        let header = self.read_exact::<16, R>(reader).context("failed to read lengths header")?;

        Ok([
            (SectionType::Magic, u32::from_be_bytes(header[0..4].try_into().context("slice has incorrect length for u32 conversion")?)),
            (SectionType::Salt, u32::from_be_bytes(header[4..8].try_into().context("slice has incorrect length for u32 conversion")?)),
            (SectionType::HeaderData, u32::from_be_bytes(header[8..12].try_into().context("slice has incorrect length for u32 conversion")?)),
            (SectionType::Mac, u32::from_be_bytes(header[12..16].try_into().context("slice has incorrect length for u32 conversion")?)),
        ])
    }

    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[(SectionType, u32); 4]) -> Result<[(SectionType, u32); 4]> {
        let mut result = [(SectionType::Magic, 0u32); 4];

        for (i, section_type) in SECTION_ORDER.iter().enumerate() {
            let size = length_sizes.iter().find(|(t, _)| t == section_type).map(|(_, s)| *s).context("missing length size")?;

            let mut encoded_length = vec![0u8; size as usize];
            reader.read_exact(&mut encoded_length).with_context(|| format!("failed to read encoded length for {}", section_type))?;

            let section = EncodedSection::new(encoded_length, size);
            let length = self.encoder.decode_length(&section)?;
            result[i] = (*section_type, length);
        }

        Ok(result)
    }

    fn read_and_decode_data<R: Read>(&self, reader: &mut R, section_lengths: &[(SectionType, u32); 4]) -> Result<Sections> {
        let mut sections = Sections::new();

        for section_type in SECTION_ORDER {
            let length = section_lengths.iter().find(|(t, _)| *t == section_type).map(|(_, l)| *l).context("missing section length")?;

            let mut encoded_data = vec![0u8; length as usize];
            reader.read_exact(&mut encoded_data).with_context(|| format!("failed to read encoded {}", section_type))?;

            let section = EncodedSection::new(encoded_data, length);
            let decoded = self.encoder.decode_section(&section)?;
            sections.set(section_type, decoded);
        }

        Ok(sections)
    }

    fn deserialize_header_data(&mut self, data: &[u8]) -> Result<()> {
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        self.header
            .set_version(u16::from_be_bytes(data[0..2].try_into().context("slice has incorrect length for u16 conversion")?));
        self.header
            .set_flags(u32::from_be_bytes(data[2..6].try_into().context("slice has incorrect length for u32 conversion")?));
        self.header
            .set_original_size(u64::from_be_bytes(data[6..14].try_into().context("slice has incorrect length for u64 conversion")?));

        Ok(())
    }

    fn read_exact<const N: usize, R: Read>(&self, reader: &mut R) -> Result<[u8; N]> {
        let mut buffer = [0u8; N];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}
