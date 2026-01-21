//! Secure file header serialization and deserialization.
//!
//! Implements a resilient header format for SweetByte encrypted files.
//! Each header section is protected by Reed-Solomon error correction,
//! and the entire header is authenticated with HMAC-SHA256.
//!
//! # Header Structure
//!
//! The header consists of:
//!
//! 1. **Lengths Header** (16 bytes): Fixed-size, contains 4 big-endian u32s
//!    specifying the encoded length of each section
//! 2. **Length Prefixes** (variable): Reed-Solomon encoded lengths of each section
//! 3. **Data Sections** (variable): Reed-Solomon encoded sections containing:
//!    - Magic bytes (4 bytes): `0xCAFEBABE`
//!    - Salt (32 bytes): Random salt for key derivation
//!    - Header data (14 bytes): Version, flags, original size
//!    - MAC (32 bytes): HMAC-SHA256 authentication tag
//!
//! # Resilience
//!
//! Each section is individually Reed-Solomon encoded, allowing recovery
//! from partial corruption. The lengths header is small enough to potentially
//! survive corruption, enabling graceful degradation.

use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::config::{ARGON_SALT_LEN, CURRENT_VERSION, DATA_SHARDS, FLAG_PROTECTED, HEADER_DATA_SIZE, MAC_SIZE, MAGIC_SIZE, PARITY_SHARDS};
use crate::header::deserializer::{Deserializer, ParsedHeaderData};
use crate::header::mac::Mac;
use crate::header::section::{SectionEncoder, SectionType, Sections};
use crate::header::serializer::Serializer;

pub mod deserializer;
pub mod mac;
pub mod section;
pub mod serializer;

/// Secure file header containing metadata and authentication.
///
/// The header is designed for resilience against partial corruption
/// while maintaining strong authentication guarantees.
pub struct Header {
    /// Encoder for Reed-Solomon protection of sections.
    encoder: SectionEncoder,

    /// File format version.
    version: u16,

    /// Processing flags (e.g., FLAG_PROTECTED).
    flags: u32,

    /// Original uncompressed file size in bytes.
    original_size: u64,

    /// Deserialized sections (None before deserialization).
    sections: Option<Sections>,
}

impl Header {
    /// Creates a new header with specified metadata.
    ///
    /// This constructor initializes the Header struct with version, size, and flags.
    /// It also creates the SectionEncoder used for Reed-Solomon protection.
    ///
    /// The SectionEncoder is configured with DATA_SHARDS (4) and PARITY_SHARDS (10),
    /// allowing recovery from up to 10 corrupted shards per section.
    ///
    /// # Arguments
    ///
    /// * `version` - File format version (e.g., CURRENT_VERSION).
    /// * `original_size` - Original uncompressed file size in bytes.
    /// * `flags` - Processing flags (e.g., FLAG_PROTECTED to indicate encryption).
    ///
    /// # Returns
    ///
    /// A new Header with sections set to None (until deserialized).
    ///
    /// # Errors
    ///
    /// Returns an error if the Reed-Solomon section encoder cannot be created
    /// with the specified shard counts.
    pub fn new(version: u16, original_size: u64, flags: u32) -> Result<Self> {
        // Create the SectionEncoder with configured shard counts.
        // This encoder handles Reed-Solomon encoding/decoding for all sections.
        // The ? propagates any errors from encoder creation.
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Return the initialized Header with sections = None.
        // sections will be populated during deserialization.
        Ok(Self { encoder, version, original_size, flags, sections: None })
    }

    /// Deserializes a header from a reader.
    ///
    /// This is the primary entry point for reading a header from an encrypted file.
    /// It creates the necessary encoders/decoders and reads all header components.
    ///
    /// The deserialization process:
    /// 1. Create a SectionEncoder for decoding sections
    /// 2. Create a Deserializer with the encoder
    /// 3. Read and decode the lengths header, length prefixes, and data sections
    /// 4. Validate magic bytes and parse metadata
    /// 5. Create and validate the final Header
    ///
    /// # Type Parameters
    ///
    /// * `R` - A readable type implementing [`Read`] (e.g., &mut File, &mut &[u8]).
    ///
    /// # Arguments
    ///
    /// * `reader` - The reader positioned at the start of the header data.
    ///
    /// # Returns
    ///
    /// A fully deserialized and validated Header instance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Section encoder creation fails
    /// - Reading the lengths header fails
    /// - Decoding any section fails (corruption exceeds recovery capacity)
    /// - Magic bytes don't match expected value (not a SweetByte file)
    /// - Header validation fails (unsupported version, zero size, etc.)
    pub fn deserialize<R: Read>(reader: R) -> Result<Self> {
        // Create a fresh SectionEncoder for decoding sections.
        // We need a new encoder rather than using an existing one because
        // this is a standalone deserialization operation.
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Create a Deserializer with the encoder.
        // The deserializer handles the reading and decoding of all header parts.
        let deserializer = Deserializer::new(&encoder);

        // Read and parse all header data.
        // This includes: lengths header, length prefixes, data sections, magic verification.
        let parsed = deserializer.deserialize(reader)?;

        // Convert ParsedHeaderData into a validated Header.
        // This also performs final validation (version, flags, size).
        Self::from_parsed_data(parsed, encoder)
    }

    /// Returns the original file size stored in the header.
    ///
    /// This is the size of the original (uncompressed) file before encryption.
    /// It's used for progress tracking and output file validation.
    #[inline]
    #[must_use]
    pub const fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Returns the salt from the header.
    ///
    /// The salt is used during key derivation to ensure that the same password
    /// produces different keys for different encrypted files.
    ///
    /// # Returns
    ///
    /// A slice reference to the 32-byte salt.
    ///
    /// # Errors
    ///
    /// Returns an error if the header hasn't been deserialized yet.
    pub fn salt(&self) -> Result<&[u8]> {
        self.get_section(SectionType::Salt, ARGON_SALT_LEN)
    }

    /// Validates header fields for consistency and correctness.
    ///
    /// This method checks that the header contains valid values before use.
    /// It's called automatically during deserialization and can be called
    /// on newly created headers before serialization.
    ///
    /// # Validation Checks
    ///
    /// 1. Version must be between 1 and CURRENT_VERSION (inclusive)
    /// 2. Original size must be non-zero (can't encrypt empty files)
    /// 3. FLAG_PROTECTED must be set (ensures this is actually an encrypted file)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Version is 0 or greater than CURRENT_VERSION
    /// - Original size is 0
    /// - FLAG_PROTECTED bit is not set in flags
    pub fn validate(&self) -> Result<()> {
        // Check version is within supported range.
        // This prevents issues with future or unknown file format versions.
        ensure!(self.version >= 1 && self.version <= CURRENT_VERSION, "unsupported version: {} (valid: 1-{}", self.version, CURRENT_VERSION);

        // Verify original size is non-zero.
        // We can't encrypt an empty file (no data to protect).
        ensure!(self.original_size != 0, "original size cannot be zero");

        // Check that FLAG_PROTECTED is set.
        // This ensures the file was actually encrypted (not corrupted plain data).
        ensure!(self.flags & FLAG_PROTECTED != 0, "file is not protected");

        // All checks passed, return Ok.
        Ok(())
    }

    /// Serializes the header to bytes.
    ///
    /// This converts the header metadata into the binary format used in encrypted files.
    /// The serialization includes: header validation, HMAC computation, and Reed-Solomon encoding.
    ///
    /// # Process
    ///
    /// 1. Validate header fields (version, size, flags)
    /// 2. Serialize the header metadata into 14 bytes
    /// 3. Compute HMAC over magic, salt, and header data
    /// 4. Reed-Solomon encode all sections (magic, salt, header_data, mac)
    /// 5. Encode the lengths of each encoded section
    /// 6. Build the 16-byte lengths header
    /// 7. Assemble all parts into final byte vector
    ///
    /// # Arguments
    ///
    /// * `salt` - The 32-byte random salt used for key derivation.
    /// * `key` - The derived cryptographic key for HMAC computation.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the complete serialized header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Header validation fails
    /// - Salt size is invalid (not 32 bytes)
    /// - Key is empty
    /// - Any encoding step fails
    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // First, validate the header fields.
        // This ensures we don't serialize invalid headers.
        self.validate()?;

        // Create a Serializer with our SectionEncoder.
        // The serializer handles all the encoding steps.
        let serializer = Serializer::new(&self.encoder);

        // Delegate to the serializer.
        // This performs: HMAC computation, section encoding, length encoding, assembly.
        serializer.serialize(self.version, self.flags, self.original_size, salt, key)
    }

    /// Verifies the header's HMAC authentication.
    ///
    /// This is the critical step that confirms:
    /// 1. The header hasn't been tampered with
    /// 2. The correct password was used (derived key matches)
    ///
    /// The verification reads all sections (magic, salt, header_data) and
    /// computes an HMAC, then compares it with the stored MAC using
    /// constant-time comparison to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `key` - The derived cryptographic key for HMAC verification.
    ///   This should be the same key used during encryption.
    ///
    /// # Returns
    ///
    /// Ok(()) if verification succeeds, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key is empty
    /// - Header hasn't been deserialized yet
    /// - Any section is missing or too short
    /// - Computed HMAC doesn't match stored MAC (wrong password or corruption)
    pub fn verify(&self, key: &[u8]) -> Result<()> {
        // Validate key is not empty.
        // Empty keys would always fail verification anyway.
        ensure!(!key.is_empty(), "key cannot be empty");

        // Get all sections needed for MAC computation.
        // These sections were stored in the encrypted file header.
        let expected_mac = self.get_section(SectionType::Mac, MAC_SIZE)?;
        let magic = self.get_section(SectionType::Magic, MAGIC_SIZE)?;
        let salt = self.get_section(SectionType::Salt, ARGON_SALT_LEN)?;
        let header_data = self.get_section(SectionType::HeaderData, HEADER_DATA_SIZE)?;

        // Create a new Mac calculator and verify the HMAC.
        // Mac::new() creates the HMAC-SHA256 hasher.
        // verify() computes HMAC over the given parts and compares with expected.
        Mac::new(key)?.verify(expected_mac, &[magic, salt, header_data])
    }

    /// Creates a Header from parsed deserialized data.
    ///
    /// This is a helper function that wraps the conversion from ParsedHeaderData
    /// to Header, including validation.
    ///
    /// # Arguments
    ///
    /// * `data` - The parsed header data containing version, flags, size, and sections.
    /// * `encoder` - The SectionEncoder to store in the Header.
    ///
    /// # Returns
    ///
    /// A validated Header instance.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    fn from_parsed_data(data: ParsedHeaderData, encoder: SectionEncoder) -> Result<Self> {
        // Construct the Header from parsed data.
        // version(), flags(), original_size() extract values from ParsedHeaderData.
        // into_sections() consumes the ParsedHeaderData and returns the Sections.
        let header = Self { encoder, version: data.version(), flags: data.flags(), original_size: data.original_size(), sections: Some(data.into_sections()) };

        // Validate the header before returning.
        // This catches any issues with the parsed values.
        header.validate()?;
        Ok(header)
    }

    /// Retrieves a section from the deserialized header.
    ///
    /// This is a helper method that handles the common pattern of:
    /// 1. Getting a section by type
    /// 2. Ensuring it meets minimum length requirement
    ///
    /// # Arguments
    ///
    /// * `section_type` - Which section to retrieve (Magic, Salt, HeaderData, or Mac).
    /// * `min_len` - Minimum expected length in bytes.
    ///
    /// # Returns
    ///
    /// A slice reference to the requested section data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Header hasn't been deserialized yet
    /// - The section is missing
    /// - The section is shorter than min_len
    fn get_section(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        // Get a reference to the sections.
        // context() provides a helpful error message if sections is None.
        self.sections
            .as_ref()
            .context("header not deserialized yet")?
            // Delegate to get_with_min_len for the actual lookup.
            .get_with_min_len(section_type, min_len)
    }
}
