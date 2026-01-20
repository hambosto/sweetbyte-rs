use anyhow::{Result, anyhow, ensure};

use crate::encoding::Encoding;

/// Total number of sections in the header.
pub const SECTION_COUNT: usize = 4;
/// Maximum allowed size for any section (16 MB).
const MAX_SECTION_SIZE: u32 = 1 << 24;

/// Types of sections stored in the header.
///
/// Each section contains a specific piece of header metadata,
/// encoded with Reed-Solomon for error correction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SectionType {
    /// Magic bytes for file format identification (0xCAFEBABE).
    Magic = 0,
    /// Salt used for key derivation (32 bytes).
    Salt = 1,
    /// Header metadata (version, flags, original size).
    HeaderData = 2,
    /// HMAC-SHA256 for integrity verification (32 bytes).
    Mac = 3,
}

impl SectionType {
    /// Array of all section types for iteration.
    pub const ALL: [Self; SECTION_COUNT] = [Self::Magic, Self::Salt, Self::HeaderData, Self::Mac];

    /// Converts a section type to its index in the ALL array.
    ///
    /// # Returns
    /// The zero-based index of this section type.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

impl std::fmt::Display for SectionType {
    /// Formats the section type as a human-readable string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Magic => write!(f, "Magic"),
            Self::Salt => write!(f, "Salt"),
            Self::HeaderData => write!(f, "HeaderData"),
            Self::Mac => write!(f, "Mac"),
        }
    }
}

/// An encoded section with Reed-Solomon error correction.
///
/// Sections are encoded to protect against data corruption.
#[derive(Debug, Clone)]
pub struct EncodedSection {
    /// The encoded section data.
    data: Vec<u8>,
}

impl EncodedSection {
    /// Creates a new EncodedSection with the given data.
    ///
    /// # Arguments
    /// * `data` - The encoded data.
    ///
    /// # Returns
    /// A new EncodedSection instance.
    #[inline]
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns a reference to the section data.
    ///
    /// # Returns
    /// A slice of the encoded data.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the section data.
    ///
    /// # Returns
    /// The length as a 32-bit unsigned integer.
    #[inline]
    #[must_use]
    pub fn length(&self) -> u32 {
        self.data.len() as u32
    }
}

/// Collection of decoded header sections.
///
/// Stores the raw bytes for each section type.
#[derive(Debug, Clone)]
pub struct Sections {
    /// The magic bytes section.
    magic: Vec<u8>,
    /// The salt section.
    salt: Vec<u8>,
    /// The header data section.
    header_data: Vec<u8>,
    /// The MAC section.
    mac: Vec<u8>,
}

/// Specifies how to validate section lengths.
#[derive(Clone, Copy)]
pub enum LengthCheck {
    /// Section must have exactly this length.
    Exact(usize),
    /// Section must have at least this length.
    Min(usize),
}

impl Sections {
    /// Retrieves a section by type.
    ///
    /// # Arguments
    /// * `section_type` - The type of section to retrieve.
    ///
    /// # Returns
    /// Some(&[u8]) if the section exists and is non-empty, None otherwise.
    #[must_use]
    pub fn get(&self, section_type: SectionType) -> Option<&[u8]> {
        let data = match section_type {
            SectionType::Magic => &self.magic,
            SectionType::Salt => &self.salt,
            SectionType::HeaderData => &self.header_data,
            SectionType::Mac => &self.mac,
        };
        if data.is_empty() { None } else { Some(data) }
    }

    /// Retrieves a section with length validation.
    ///
    /// # Arguments
    /// * `section_type` - The type of section to retrieve.
    /// * `check` - The length validation to perform.
    ///
    /// # Returns
    /// The section data if validation passes, or an error.
    pub fn get_len(&self, section_type: SectionType, check: LengthCheck) -> Result<&[u8]> {
        let data = self.get(section_type).ok_or_else(|| anyhow!("{section_type} section not found"))?;

        match check {
            LengthCheck::Exact(expected) => {
                ensure!(data.len() == expected, "{} section wrong size: expected {}, got {}", section_type, expected, data.len());
                Ok(data)
            }
            LengthCheck::Min(min) => {
                ensure!(data.len() >= min, "{} section too small: expected at least {}, got {}", section_type, min, data.len());
                Ok(&data[..min])
            }
        }
    }
}

/// Builder for constructing a Sections instance.
///
/// Provides a fluent interface for setting sections before building.
#[derive(Debug)]
pub struct SectionsBuilder {
    /// Optional magic section.
    magic: Option<Vec<u8>>,
    /// Optional salt section.
    salt: Option<Vec<u8>>,
    /// Optional header data section.
    header_data: Option<Vec<u8>>,
    /// Optional MAC section.
    mac: Option<Vec<u8>>,
}

impl SectionsBuilder {
    /// Creates a new builder with the magic section already set.
    ///
    /// # Arguments
    /// * `magic` - The magic bytes to use.
    ///
    /// # Returns
    /// A new SectionsBuilder instance.
    #[inline]
    #[must_use]
    pub fn with_magic(magic: Vec<u8>) -> Self {
        Self { magic: Some(magic), salt: None, header_data: None, mac: None }
    }

    /// Sets a section value.
    ///
    /// # Arguments
    /// * `section_type` - The type of section to set.
    /// * `value` - The section data.
    ///
    /// # Returns
    /// Mutable reference to this builder for chaining.
    #[inline]
    pub fn set(&mut self, section_type: SectionType, value: Vec<u8>) -> &mut Self {
        match section_type {
            SectionType::Magic => self.magic = Some(value),
            SectionType::Salt => self.salt = Some(value),
            SectionType::HeaderData => self.header_data = Some(value),
            SectionType::Mac => self.mac = Some(value),
        }
        self
    }

    /// Builds the Sections instance.
    ///
    /// Validates that all sections are present and non-empty.
    ///
    /// # Returns
    /// A Sections instance, or an error if validation fails.
    pub fn build(self) -> Result<Sections> {
        // Define all sections with their names for error messages.
        let sections = [("Magic", self.magic), ("Salt", self.salt), ("HeaderData", self.header_data), ("Mac", self.mac)];

        let mut validated: Vec<Vec<u8>> = Vec::with_capacity(SECTION_COUNT);
        // Validate and collect each section.
        for (name, section) in sections {
            let data = section.ok_or_else(|| anyhow!("{name} section is missing"))?;
            ensure!(!data.is_empty(), "{name} section is empty");
            validated.push(data);
        }

        // Convert to fixed-size array and create Sections.
        let [magic, salt, header_data, mac]: [Vec<u8>; 4] = validated.try_into().map_err(|_| anyhow!("unexpected section count"))?;
        Ok(Sections { magic, salt, header_data, mac })
    }
}

/// Encoder/decoder for header sections using Reed-Solomon.
///
/// Provides methods to encode and decode sections with error correction.
pub struct SectionEncoder {
    /// The underlying Reed-Solomon encoder/decoder.
    encoder: Encoding,
}

impl SectionEncoder {
    /// Creates a new SectionEncoder with the specified shard configuration.
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards for encoding.
    /// * `parity_shards` - Number of parity shards for error correction.
    ///
    /// # Returns
    /// A new SectionEncoder instance.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    /// Encodes a section with Reed-Solomon error correction.
    ///
    /// # Arguments
    /// * `data` - The raw section data to encode.
    ///
    /// # Returns
    /// The encoded section, or an error.
    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Encode the data using Reed-Solomon error correction.
        let encoded = self.encoder.encode(data)?;

        Ok(EncodedSection::new(encoded))
    }

    /// Decodes an encoded section.
    ///
    /// # Arguments
    /// * `section` - The encoded section to decode.
    ///
    /// # Returns
    /// The decoded data, or an error.
    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        ensure!(!section.data.is_empty(), "invalid encoded section");

        // Decode the data using Reed-Solomon error correction.
        self.encoder.decode(&section.data)
    }

    /// Encodes a length value as a section.
    ///
    /// # Arguments
    /// * `length` - The length to encode.
    ///
    /// # Returns
    /// The encoded length section.
    #[inline]
    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        // Encode the length as a section.
        self.encode_section(&length.to_be_bytes())
    }

    /// Decodes a length from a section.
    ///
    /// # Arguments
    /// * `section` - The encoded length section.
    ///
    /// # Returns
    /// The decoded length value, or an error if validation fails.
    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;
        ensure!(decoded.len() >= 4, "invalid length prefix size");

        // Extract first 4 bytes as big-endian u32.
        let bytes: [u8; 4] = decoded[..4].try_into().map_err(|_| anyhow!("length conversion failed"))?;
        let length = u32::from_be_bytes(bytes);

        // Validate length doesn't exceed maximum.
        ensure!(length <= MAX_SECTION_SIZE, "section size {length} exceeds maximum {MAX_SECTION_SIZE}");

        Ok(length)
    }
}
