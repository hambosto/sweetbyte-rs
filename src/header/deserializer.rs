use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use crate::header::section::{EncodedSection, LengthCheck, SECTION_COUNT, SectionEncoder, SectionType, Sections, SectionsBuilder};

/// Intermediate structure containing parsed header data.
///
/// Holds the deserialized header metadata before constructing the full Header.
#[derive(Debug)]
pub struct ParsedHeaderData {
    /// The file format version.
    version: u16,
    /// The flags value.
    flags: u32,
    /// The original file size.
    original_size: u64,
    /// The deserialized sections.
    sections: Sections,
}

impl ParsedHeaderData {
    /// Creates a new ParsedHeaderData instance.
    ///
    /// # Arguments
    /// * `version` - The file format version.
    /// * `flags` - The flags value.
    /// * `original_size` - The original file size.
    /// * `sections` - The deserialized sections.
    ///
    /// # Returns
    /// A new ParsedHeaderData instance.
    #[inline]
    pub(crate) fn new(version: u16, flags: u32, original_size: u64, sections: Sections) -> Self {
        Self { version, flags, original_size, sections }
    }

    /// Returns the file format version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns the flags value.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the original file size.
    #[inline]
    #[must_use]
    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Consumes this instance and returns the sections.
    ///
    /// # Returns
    /// The sections stored in this instance.
    #[inline]
    pub fn into_sections(self) -> Sections {
        self.sections
    }
}

/// Deserializes header sections from a byte stream.
///
/// Handles the complete deserialization process including:
/// - Reading and decoding section lengths
/// - Reading and decoding section data
/// - Validating magic bytes
/// - Parsing header metadata
pub struct Deserializer<'a> {
    /// Reference to the section encoder for decoding.
    encoder: &'a SectionEncoder,
}

impl<'a> Deserializer<'a> {
    /// Creates a new Deserializer with the given encoder.
    ///
    /// # Arguments
    /// * `encoder` - The section encoder to use.
    ///
    /// # Returns
    /// A new Deserializer instance.
    #[inline]
    #[must_use]
    pub fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    /// Deserializes header data from a reader.
    ///
    /// # Arguments
    /// * `reader` - The reader positioned at the start of the header.
    ///
    /// # Returns
    /// ParsedHeaderData on success, or an error if deserialization fails.
    pub fn deserialize<R: Read>(&self, mut reader: R) -> Result<ParsedHeaderData> {
        // Read the 16-byte lengths header.
        let length_sizes = Self::read_lengths_header(&mut reader)?;
        // Read and decode the encoded lengths to get actual section sizes.
        let section_lengths = self.read_and_decode_lengths(&mut reader, &length_sizes)?;

        // Read and decode all sections.
        let sections = self.read_and_decode_sections(&mut reader, &section_lengths)?;

        // Extract and validate magic bytes.
        let magic = sections.get_len(SectionType::Magic, LengthCheck::Exact(MAGIC_SIZE))?;
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes");

        // Parse header metadata from the HeaderData section.
        let header_data = sections.get(SectionType::HeaderData).ok_or_else(|| anyhow::anyhow!("HeaderData section not found"))?;
        let (version, flags, original_size) = Self::parse_header_data(header_data)?;

        Ok(ParsedHeaderData::new(version, flags, original_size, sections))
    }

    /// Reads the 16-byte lengths header.
    ///
    /// Each section length is stored as a big-endian u32.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from.
    ///
    /// # Returns
    /// Array of encoded section lengths.
    fn read_lengths_header<R: Read>(reader: &mut R) -> Result<[u32; SECTION_COUNT]> {
        let header = Self::read_exact::<16, R>(reader).context("failed to read lengths header")?;

        // Parse each length as big-endian u32.
        Ok([
            u32::from_be_bytes(header[0..4].try_into().context("magic length conversion")?),
            u32::from_be_bytes(header[4..8].try_into().context("salt length conversion")?),
            u32::from_be_bytes(header[8..12].try_into().context("header data length conversion")?),
            u32::from_be_bytes(header[12..16].try_into().context("mac length conversion")?),
        ])
    }

    /// Reads and decodes the encoded section lengths.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from.
    /// * `length_sizes` - The sizes of the encoded length sections.
    ///
    /// # Returns
    /// Array of decoded actual section lengths.
    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[u32; SECTION_COUNT]) -> Result<[u32; SECTION_COUNT]> {
        let mut result = [0u32; SECTION_COUNT];

        // For each section type, read and decode its length.
        for (i, &size) in length_sizes.iter().enumerate() {
            let section_type = SectionType::ALL[i];

            // Read the encoded length section.
            let mut encoded = vec![0u8; size as usize];
            reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded length for {section_type}"))?;

            // Decode the length using Reed-Solomon.
            let section = EncodedSection::new(encoded);
            result[i] = self.encoder.decode_length(&section)?;
        }

        Ok(result)
    }

    /// Reads and decodes all data sections.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from.
    /// * `section_lengths` - The lengths of each section.
    ///
    /// # Returns
    /// The deserialized Sections instance.
    fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; SECTION_COUNT]) -> Result<Sections> {
        // Read magic section first.
        let magic = self.read_section(reader, SectionType::Magic, section_lengths[0])?;
        let mut builder = SectionsBuilder::with_magic(magic);

        // Read remaining sections.
        for (section_type, &length) in SectionType::ALL[1..].iter().zip(&section_lengths[1..]) {
            let decoded = self.read_section(reader, *section_type, length)?;
            builder.set(*section_type, decoded);
        }

        builder.build()
    }

    /// Reads and decodes a single section.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from.
    /// * `section_type` - The type of section being read.
    /// * `length` - The length of the encoded section.
    ///
    /// # Returns
    /// The decoded section data.
    fn read_section<R: Read>(&self, reader: &mut R, section_type: SectionType, length: u32) -> Result<Vec<u8>> {
        // Read the encoded section.
        let mut encoded = vec![0u8; length as usize];
        reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded {section_type}"))?;

        // Decode the section using Reed-Solomon.
        let section = EncodedSection::new(encoded);
        self.encoder.decode_section(&section)
    }

    /// Parses header metadata from the HeaderData section.
    ///
    /// # Arguments
    /// * `data` - The raw header data bytes.
    ///
    /// # Returns
    /// Tuple of (version, flags, original_size).
    fn parse_header_data(data: &[u8]) -> Result<(u16, u32, u64)> {
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        // Parse version as big-endian u16.
        let version = u16::from_be_bytes(data[0..2].try_into().context("version conversion")?);
        // Parse flags as big-endian u32.
        let flags = u32::from_be_bytes(data[2..6].try_into().context("flags conversion")?);
        // Parse original size as big-endian u64.
        let original_size = u64::from_be_bytes(data[6..14].try_into().context("original size conversion")?);

        Ok((version, flags, original_size))
    }

    /// Reads exactly N bytes from the reader.
    ///
    /// # Type Parameters
    /// * `N` - The number of bytes to read.
    /// * `R` - The reader type.
    ///
    /// # Arguments
    /// * `reader` - The reader to read from.
    ///
    /// # Returns
    /// Array of N bytes.
    fn read_exact<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N]> {
        let mut buffer = [0u8; N];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}
