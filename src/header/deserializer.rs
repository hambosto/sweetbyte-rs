//! Header deserialization for secure file format.
//!
//! Reads and validates the binary header format, recovering from
//! partial corruption using Reed-Solomon error correction.
//!
//! # Deserialization Process
//!
//! 1. Read the 16-byte lengths header (encoded sizes of each section)
//! 2. Read and decode the length prefixes for each section
//! 3. Read and decode each data section (Magic, Salt, HeaderData, MAC)
//! 4. Verify magic bytes match expected value
//! 5. Parse header metadata (version, flags, original size)

use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{HEADER_DATA_SIZE, MAGIC_BYTES, MAGIC_SIZE};
use crate::header::section::{EncodedSection, SectionEncoder, SectionType, Sections, SectionsBuilder};

/// Intermediate structure holding deserialized header data.
///
/// Contains parsed metadata and the deserialized sections.
pub struct ParsedHeaderData {
    /// File format version.
    version: u16,

    /// Processing flags.
    flags: u32,

    /// Original file size.
    original_size: u64,

    /// Deserialized header sections.
    sections: Sections,
}

impl ParsedHeaderData {
    /// Creates a new ParsedHeaderData instance.
    #[inline]
    pub(crate) const fn new(version: u16, flags: u32, original_size: u64, sections: Sections) -> Self {
        Self { version, flags, original_size, sections }
    }

    /// Returns the file format version.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the processing flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the original file size.
    #[inline]
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Consumes self and returns the sections.
    #[inline]
    pub fn into_sections(self) -> Sections {
        self.sections
    }
}

/// Deserializes header data from a reader.
pub struct Deserializer<'a> {
    /// Reference to the section encoder for Reed-Solomon decoding.
    encoder: &'a SectionEncoder,
}

impl<'a> Deserializer<'a> {
    /// Creates a new deserializer with the given section encoder.
    #[inline]
    #[must_use]
    pub const fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    /// Deserializes header data from a reader.
    ///
    /// # Type Parameters
    ///
    /// * `R` - A readable type implementing [`Read`].
    ///
    /// # Arguments
    ///
    /// * `reader` - The reader positioned at the start of the header.
    ///
    /// # Returns
    ///
    /// Parsed header data including metadata and sections.
    ///
    /// # Errors
    ///
    /// Returns an error if reading, decoding, or validation fails.
    pub fn deserialize<R: Read>(&self, mut reader: R) -> Result<ParsedHeaderData> {
        // Read the 16-byte lengths header
        let length_sizes = Self::read_lengths_header(&mut reader)?;

        // Read and decode the actual lengths of each section
        let section_lengths = self.read_and_decode_lengths(&mut reader, &length_sizes)?;

        // Read and decode each data section
        let sections = self.read_and_decode_sections(&mut reader, &section_lengths)?;

        // Verify magic bytes
        let magic = sections.get_with_min_len(SectionType::Magic, MAGIC_SIZE)?;
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes: expected {:?}, got {:?}", MAGIC_BYTES.to_be_bytes(), magic);

        // Get header metadata section
        let header_data = sections.get(SectionType::HeaderData).ok_or_else(|| anyhow::anyhow!("HeaderData section not found"))?;

        // Parse version, flags, and original size
        let (version, flags, original_size) = Self::parse_header_data(header_data)?;

        Ok(ParsedHeaderData::new(version, flags, original_size, sections))
    }

    /// Reads the 16-byte lengths header.
    ///
    /// This header tells us how large each Reed-Solomon encoded section is.
    /// Without this, we wouldn't know how many bytes to read for each section.
    ///
    /// Contains the encoded sizes (in bytes) of each section's Reed-Solomon encoding.
    /// Each size is a big-endian u32: \[magic_len\]\[salt_len\]\[header_data_len\]\[mac_len\]
    fn read_lengths_header<R: Read>(reader: &mut R) -> Result<[u32; 4]> {
        // Read exactly 16 bytes for the lengths header.
        let header = Self::read_exact::<16, R>(reader).context("failed to read lengths header")?;

        // Parse 4 big-endian u32 values, one for each section.
        // try_into() ensures we get exactly 4 bytes for each u32.
        // context() provides helpful error messages if conversion fails.
        Ok([
            u32::from_be_bytes(header[0..4].try_into().context("magic length conversion")?),
            u32::from_be_bytes(header[4..8].try_into().context("salt length conversion")?),
            u32::from_be_bytes(header[8..12].try_into().context("header data length conversion")?),
            u32::from_be_bytes(header[12..16].try_into().context("mac length conversion")?),
        ])
    }

    /// Reads and decodes the length prefixes for each section.
    ///
    /// The lengths tell us how many bytes to read for each data section.
    /// Each length is itself Reed-Solomon encoded for corruption recovery.
    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[u32; 4]) -> Result<[u32; 4]> {
        // Process each section type with its corresponding encoded length size.
        SectionType::ALL
            .iter()
            .zip(length_sizes)
            .map(|(section_type, &size)| {
                // Read the Reed-Solomon encoded length.
                // The size tells us how many bytes the encoded length occupies.
                let mut encoded = vec![0u8; size as usize];
                reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded length for {section_type}"))?;

                // Wrap in EncodedSection for Reed-Solomon decoding.
                let section = EncodedSection::new(encoded);
                // Decode will recover from corruption if present.
                self.encoder.decode_length(&section)
            })
            .collect::<Result<Vec<u32>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    /// Reads and decodes all data sections.
    ///
    /// The magic section is read first because it serves as a quick validation
    /// check - if the magic bytes don't match, the file is not a SweetByte file.
    fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; 4]) -> Result<Sections> {
        // Read magic section first for early validation.
        let magic = self.read_section(reader, SectionType::Magic, section_lengths[0])?;
        let mut builder = SectionsBuilder::with_magic(magic);

        // Read remaining sections (Salt, HeaderData, Mac) in order.
        // zip() pairs section types with their corresponding lengths.
        for (&section_type, &length) in SectionType::ALL[1..].iter().zip(&section_lengths[1..]) {
            let decoded = self.read_section(reader, section_type, length)?;
            builder.set(section_type, decoded);
        }

        // Build the final Sections struct, validating all sections are present.
        builder.build()
    }

    /// Reads and decodes a single section.
    ///
    /// Reads the encoded section bytes, then applies Reed-Solomon decoding
    /// to recover from any corruption.
    fn read_section<R: Read>(&self, reader: &mut R, section_type: SectionType, length: u32) -> Result<Vec<u8>> {
        // Read Reed-Solomon encoded section data.
        // The length tells us exactly how many bytes to read.
        let mut encoded = vec![0u8; length as usize];
        reader.read_exact(&mut encoded).with_context(|| format!("failed to read encoded {section_type}"))?;

        // Wrap in EncodedSection and decode.
        // This will attempt reconstruction if the data is corrupted.
        let section = EncodedSection::new(encoded);
        self.encoder.decode_section(&section)
    }

    /// Parses header metadata from the HeaderData section.
    ///
    /// Extracts version, flags, and original_size from the 14-byte HeaderData section.
    /// The data is stored in big-endian format for cross-platform consistency.
    ///
    /// # Layout
    ///
    /// - Bytes 0-1: Version (u16 big-endian)
    /// - Bytes 2-5: Flags (u32 big-endian)
    /// - Bytes 6-13: Original size (u64 big-endian)
    ///
    /// # Arguments
    ///
    /// * `data` - The raw HeaderData section bytes (decoded from Reed-Solomon).
    ///
    /// # Returns
    ///
    /// A tuple of (version, flags, original_size) extracted from the data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data is shorter than HEADER_DATA_SIZE (14 bytes)
    /// - Any of the byte slice conversions fail (shouldn't happen with proper bounds)
    fn parse_header_data(data: &[u8]) -> Result<(u16, u32, u64)> {
        // Validate that we have enough data for all fields.
        // HEADER_DATA_SIZE = 14 bytes (2 + 4 + 8).
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        // Extract version from bytes 0-1.
        // from_be_bytes() converts [u8; 2] to u16 in big-endian byte order.
        // try_into() ensures we get exactly 2 bytes for the conversion.
        // context() provides helpful error messages if conversion fails.
        let version = u16::from_be_bytes(data[0..2].try_into().context("version conversion")?);

        // Extract flags from bytes 2-5.
        // This is a u32, taking 4 bytes.
        let flags = u32::from_be_bytes(data[2..6].try_into().context("flags conversion")?);

        // Extract original_size from bytes 6-13.
        // This is a u64, taking 8 bytes.
        let original_size = u64::from_be_bytes(data[6..14].try_into().context("original size conversion")?);

        // Return all three values as a tuple.
        Ok((version, flags, original_size))
    }

    /// Reads exactly N bytes from the reader.
    ///
    /// This is a helper function that simplifies reading fixed-size byte arrays.
    /// It's used for reading the 16-byte lengths header where we know the exact size.
    ///
    /// # Type Parameters
    ///
    /// * `N` - The number of bytes to read (compile-time constant).
    /// * `R` - A type implementing Read.
    ///
    /// # Arguments
    ///
    /// * `reader` - The reader to read from.
    ///
    /// # Returns
    ///
    /// A fixed-size array of N bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the reader doesn't provide N bytes (EOF or error).
    fn read_exact<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N]> {
        // Pre-allocate a buffer of the exact size needed.
        // This avoids dynamic allocation and ensures we get exactly N bytes.
        let mut buffer = [0u8; N];

        // Read exactly N bytes into the buffer.
        // read_exact() will fail if it can't read all N bytes.
        reader.read_exact(&mut buffer)?;

        // Return the filled buffer.
        Ok(buffer)
    }
}
