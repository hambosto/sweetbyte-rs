use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{ARGON_SALT_LEN, CURRENT_VERSION, DATA_SHARDS, FLAG_PROTECTED, HEADER_DATA_SIZE, MAC_SIZE, MAGIC_SIZE, PARITY_SHARDS};
use crate::header::deserializer::{Deserializer, ParsedHeaderData};
use crate::header::mac::Mac;
use crate::header::section::{LengthCheck, SectionEncoder, SectionType, Sections};
use crate::header::serializer::Serializer;

pub mod deserializer;
pub mod mac;
pub mod section;
pub mod serializer;

/// File header containing metadata and cryptographic parameters.
///
/// The header is stored at the beginning of each encrypted file and contains:
/// - Version number
/// - Flags (e.g., protected status)
/// - Original file size
/// - Salt for key derivation
/// - MAC for integrity verification
///
/// Headers are serialized using Reed-Solomon erasure coding for robustness.
pub struct Header {
    /// Encoder for Reed-Solomon section encoding.
    encoder: SectionEncoder,
    /// File format version.
    version: u16,
    /// Flags indicating file properties (e.g., protection status).
    flags: u32,
    /// Original (unencrypted) file size in bytes.
    original_size: u64,
    /// Deserialized sections (None until deserialized).
    sections: Option<Sections>,
}

impl Header {
    /// Creates a new Header with the specified parameters.
    ///
    /// # Arguments
    /// * `version` - The file format version.
    /// * `original_size` - The original file size in bytes.
    /// * `flags` - The flags indicating file properties.
    ///
    /// # Returns
    /// A new Header instance, or an error if initialization fails.
    pub fn new(version: u16, original_size: u64, flags: u32) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        Ok(Self { encoder, version, original_size, flags, sections: None })
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

    /// Checks if the file is marked as protected.
    ///
    /// # Returns
    /// True if the FLAG_PROTECTED bit is set.
    #[inline]
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.flags & FLAG_PROTECTED != 0
    }

    /// Validates the header parameters.
    ///
    /// Checks that the version is supported, original size is non-zero,
    /// and the protected flag is set.
    ///
    /// # Returns
    /// Ok(()) if valid, or an error if validation fails.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version() >= 1 && self.version() <= CURRENT_VERSION, "unsupported version: {} (valid: 1-{})", self.version(), CURRENT_VERSION);
        ensure!(self.original_size() != 0, "original size cannot be zero");
        ensure!(self.is_protected(), "file is not protected");

        Ok(())
    }

    /// Serializes the header to a byte vector.
    ///
    /// Includes magic bytes, salt, header data (version, flags, size),
    /// and HMAC for integrity.
    ///
    /// # Arguments
    /// * `salt` - The salt used for key derivation.
    /// * `key` - The derived key for MAC computation.
    ///
    /// # Returns
    /// The serialized header bytes.
    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;

        let serializer = Serializer::new(&self.encoder);
        serializer.serialize(self.version(), self.flags(), self.original_size(), salt, key)
    }

    /// Deserializes a header from a reader.
    ///
    /// Reads and decodes the Reed-Solomon encoded sections, validates
    /// magic bytes, and extracts header metadata.
    ///
    /// # Arguments
    /// * `reader` - The reader positioned at the start of the header.
    ///
    /// # Returns
    /// The deserialized Header, or an error if deserialization fails.
    pub fn deserialize<R: Read>(reader: R) -> Result<Self> {
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let deserializer = Deserializer::new(&encoder);

        let parsed = deserializer.deserialize(reader)?;
        Self::from_parsed_data(parsed, encoder)
    }

    /// Retrieves the salt section from the header.
    ///
    /// # Returns
    /// The salt bytes, or an error if not found or wrong size.
    pub fn salt(&self) -> Result<&[u8]> {
        self.get_section(SectionType::Salt, LengthCheck::Exact(ARGON_SALT_LEN))
    }

    /// Verifies the header integrity using HMAC.
    ///
    /// Computes the expected MAC from the header data and compares it
    /// with the stored MAC.
    ///
    /// # Arguments
    /// * `key` - The key to use for MAC verification.
    ///
    /// # Returns
    /// Ok(()) if verification succeeds, or an error if it fails.
    pub fn verify(&self, key: &[u8]) -> Result<()> {
        ensure!(!key.is_empty(), "key cannot be empty");

        // Get all sections needed for MAC verification.
        let expected_mac = self.get_section(SectionType::Mac, LengthCheck::Exact(MAC_SIZE))?;
        let magic = self.get_section(SectionType::Magic, LengthCheck::Exact(MAGIC_SIZE))?;
        let salt = self.get_section(SectionType::Salt, LengthCheck::Exact(ARGON_SALT_LEN))?;
        let header_data = self.get_section(SectionType::HeaderData, LengthCheck::Min(HEADER_DATA_SIZE))?;

        // Verify the MAC.
        Mac::verify_bytes(key, expected_mac, &[magic, salt, header_data])
    }

    /// Creates a Header from parsed deserializer data.
    ///
    /// # Arguments
    /// * `data` - The parsed header data from the deserializer.
    /// * `encoder` - The section encoder.
    ///
    /// # Returns
    /// A validated Header instance.
    fn from_parsed_data(data: ParsedHeaderData, encoder: SectionEncoder) -> Result<Self> {
        let header = Self { encoder, version: data.version(), flags: data.flags(), original_size: data.original_size(), sections: Some(data.into_sections()) };
        header.validate()?;
        Ok(header)
    }

    /// Internal helper to get a section with length validation.
    ///
    /// # Arguments
    /// * `section_type` - The type of section to retrieve.
    /// * `check` - The length validation to perform.
    ///
    /// # Returns
    /// The section bytes, or an error.
    fn get_section(&self, section_type: SectionType, check: LengthCheck) -> Result<&[u8]> {
        let sections = self.sections.as_ref().context("header not deserialized yet")?;
        sections.get_len(section_type, check)
    }
}
