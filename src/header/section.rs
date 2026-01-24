//! Reed-Solomon Section Management
//!
//! This module provides the core functionality for managing Reed-Solomon encoded
//! header sections. The header is divided into 5 distinct sections, each protected
//! by Reed-Solomon error correction to provide both data integrity and recovery
//! capabilities.
//!
//! ## Section Architecture
//!
//! The encrypted file header uses a 5-section structure:
//!
//! 1. **Magic Bytes** - File format identifier (`0x53574254` = "SWBT")
//! 2. **Salt** - Cryptographic salt for key derivation (16 bytes)
//! 3. **Header Data** - Encryption parameters (12 bytes)
//! 4. **Metadata** - File information (variable size)
//! 5. **MAC** - Message authentication code (32 bytes)
//!
//! ## Reed-Solomon Protection
//!
//! Each section is Reed-Solomon encoded with configurable data and parity shards:
// - **Data Shards**: Original section data split across multiple shards
// - **Parity Shards**: Redundant information for error recovery
// - **Recovery Capability**: Can reconstruct data from up to 50% corruption
//
// ## Binary Storage Format
//
// The on-disk format consists of:
//
// ```text
// [20 bytes] Lengths Header (4 bytes × 5 sections)
// [Variable] Encoded Lengths (Reed-Solomon encoded section sizes)
// [Variable] Encoded Sections (Reed-Solomon encoded section data)
// ```
//
// ## Security Benefits
//
// - **Tamper Resistance**: Reed-Solomon encoding makes unauthorized modifications detectable
// - **Error Recovery**: Can recover from storage corruption or transmission errors
// - **Data Integrity**: Combined with MAC provides multiple layers of integrity protection
use std::io::Read;

use anyhow::{Context, Result, anyhow, ensure};
use hashbrown::HashMap;

use crate::config::MAGIC_BYTES;
use crate::encoding::Encoding;

/// Header section type identifier
///
/// Each section in the encrypted header has a specific type and purpose.
/// The numeric values are used for section ordering and identification
/// in the binary format.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    /// File format magic bytes (identifies this as a SweetByte file)
    Magic = 0,

    /// Cryptographic salt for key derivation
    Salt = 1,

    /// Header data containing encryption parameters
    HeaderData = 2,

    /// File metadata (name, size, content hash)
    Metadata = 3,

    /// Message authentication code for integrity verification
    Mac = 4,
}

impl SectionType {
    /// Array of all section types in order
    ///
    /// This constant provides the canonical ordering of sections for
    /// serialization and deserialization operations.
    pub const ALL: [Self; 5] = [Self::Magic, Self::Salt, Self::HeaderData, Self::Metadata, Self::Mac];

    /// Get the human-readable name of this section type
    ///
    /// # Returns
    ///
    /// A string slice containing the section name for debugging
    /// and error reporting purposes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Magic => "Magic",
            Self::Salt => "Salt",
            Self::HeaderData => "HeaderData",
            Self::Metadata => "Metadata",
            Self::Mac => "Mac",
        }
    }
}

impl std::fmt::Display for SectionType {
    /// Format the section type for display
    ///
    /// Implements the Display trait to provide human-readable
    /// section names for logging and error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Reed-Solomon encoded section
///
/// This structure represents a header section that has been Reed-Solomon
/// encoded for error correction and tamper resistance. The encoded data
/// includes both the original data and parity information for recovery.
///
/// The encoded section is larger than the original data due to the addition
/// of parity shards. The exact size depends on the Reed-Solomon parameters
/// (data_shards + parity_shards).
#[derive(Debug, Clone)]
pub struct EncodedSection {
    /// Reed-Solomon encoded data including original data and parity information
    data: Vec<u8>,
}

impl EncodedSection {
    /// Create a new encoded section
    ///
    /// # Arguments
    ///
    /// * `data` - Reed-Solomon encoded data (original + parity)
    ///
    /// # Returns
    ///
    /// A new EncodedSection instance.
    #[inline]
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the encoded data
    ///
    /// # Returns
    ///
    /// Reference to the Reed-Solomon encoded data including parity information.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Check if the section is empty
    ///
    /// # Returns
    ///
    /// True if the section contains no encoded data.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the length of the encoded data
    ///
    /// # Returns
    ///
    /// Length of the encoded data as u32 (fits within protocol limits).
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.data.len() as u32
    }
}

/// Container for decoded header sections
///
/// This structure holds all 5 header sections after they have been
/// Reed-Solomon decoded. It provides convenient access to individual
/// sections while maintaining the original data integrity.
///
/// The sections are stored in a HashMap for O(1) lookup by section type.
/// Empty sections are filtered out during access to prevent returning
/// invalid data.
pub struct Sections {
    /// HashMap mapping section types to their decoded data
    sections: HashMap<SectionType, Vec<u8>>,
}

impl Sections {
    /// Get a section's data
    ///
    /// Returns the decoded data for the specified section type.
    /// Empty sections are filtered out and return None.
    ///
    /// # Arguments
    ///
    /// * `section_type` - The type of section to retrieve
    ///
    /// # Returns
    ///
    /// Option containing either the section data as a byte slice or None
    /// if the section doesn't exist or is empty.
    #[must_use]
    pub fn get(&self, section_type: SectionType) -> Option<&[u8]> {
        self.sections
            .get(&section_type)
            .filter(|d| !d.is_empty()) // Filter out empty sections
            .map(|d| d.as_slice())
    }

    /// Get a section with minimum length validation
    ///
    /// Retrieves a section and validates that it meets the minimum required
    /// length, returning a slice of exactly the minimum size if valid.
    ///
    /// # Arguments
    ///
    /// * `section_type` - The type of section to retrieve
    /// * `min_len` - Minimum required length of the section data
    ///
    /// # Returns
    ///
    /// Result containing either a slice of exactly `min_len` bytes or an error.
    ///
    /// # Errors
    ///
    /// - Section not found or empty
    /// - Section data shorter than the minimum required length
    pub fn get_with_min_len(&self, section_type: SectionType, min_len: usize) -> Result<&[u8]> {
        let data = self.get(section_type).ok_or_else(|| anyhow!("{section_type} section not found"))?;
        ensure!(data.len() >= min_len, "{} section too short: expected at least {}, got {}", section_type, min_len, data.len());

        // Return exactly the requested minimum length
        Ok(&data[..min_len])
    }
}

/// Builder for creating validated Sections
///
/// This builder provides a convenient interface for constructing a Sections
/// instance while ensuring all required sections are present and non-empty.
///
/// The builder pattern allows for stepwise construction with validation
/// only occurring at the final build step.
pub struct SectionsBuilder {
    /// HashMap containing the sections being built
    sections: HashMap<SectionType, Vec<u8>>,
}

impl SectionsBuilder {
    /// Create a new builder with the magic bytes section
    ///
    /// This is the standard way to start building a Sections instance,
    /// as the magic bytes are always required and typically available first.
    ///
    /// # Arguments
    ///
    /// * `magic` - The decoded magic bytes data
    ///
    /// # Returns
    ///
    /// A new SectionsBuilder with the magic section pre-populated.
    #[inline]
    #[must_use]
    pub fn with_magic(magic: Vec<u8>) -> Self {
        let mut sections = HashMap::new();
        sections.insert(SectionType::Magic, magic);
        Self { sections }
    }

    /// Set a section's data
    ///
    /// Adds or replaces a section's data in the builder.
    ///
    /// # Arguments
    ///
    /// * `section_type` - The type of section to set
    /// * `value` - The section's decoded data
    ///
    /// # Returns
    ///
    /// Mutable reference to self for method chaining.
    #[inline]
    pub fn set(&mut self, section_type: SectionType, value: Vec<u8>) -> &mut Self {
        self.sections.insert(section_type, value);
        self
    }

    /// Build the validated Sections instance
    ///
    /// Validates that all required sections are present and non-empty,
    /// then constructs the final Sections instance.
    ///
    /// # Returns
    ///
    /// Result containing either the validated Sections or an error.
    ///
    /// # Errors
    ///
    /// - Missing required sections (any of the 5 section types)
    /// - Empty sections (sections with zero-length data)
    ///
    /// # Validation Logic
    ///
    /// - Checks that all 5 section types (from SectionType::ALL) are present
    /// - Ensures no section contains empty data
    /// - Provides detailed error messages for missing/empty sections
    pub fn build(self) -> Result<Sections> {
        // Validate that all required sections are present and non-empty
        for &ty in &SectionType::ALL {
            let data = self.sections.get(&ty).ok_or_else(|| anyhow!("{ty} section is missing"))?;
            ensure!(!data.is_empty(), "{ty} section is empty");
        }
        Ok(Sections { sections: self.sections })
    }
}

/// Reed-Solomon section encoder
///
/// This encoder handles the Reed-Solomon encoding of header sections,
/// providing error correction and tamper resistance for the header data.
///
/// The encoder uses configurable data and parity shard counts to balance
/// between storage overhead and error recovery capability.
pub struct SectionEncoder {
    /// Underlying Reed-Solomon encoder implementation
    encoder: Encoding,
}

impl SectionEncoder {
    /// Create a new section encoder
    ///
    /// Initializes a Reed-Solomon encoder with the specified number of
    /// data and parity shards.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards (original data splits)
    /// * `parity_shards` - Number of parity shards (error recovery)
    ///
    /// # Returns
    ///
    /// Result containing either the encoder or an error.
    ///
    /// # Errors
    ///
    /// Invalid Reed-Solomon parameters (e.g., total shards > 255)
    ///
    /// # Performance Notes
    ///
    /// - Higher parity shard count increases storage overhead but improves error recovery
    /// - Can recover from up to `parity_shards` corrupted data shards
    /// - Common configuration: 4 data shards, 2 parity shards (33% overhead, 50% recovery)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    /// Encode raw section data with Reed-Solomon
    ///
    /// Takes raw section data and applies Reed-Solomon encoding to add
    /// error correction capabilities.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw section data to encode
    ///
    /// # Returns
    ///
    /// Result containing either the encoded section or an error.
    ///
    /// # Errors
    ///
    /// - Empty input data
    /// - Reed-Solomon encoding failures
    ///
    /// # Security Notes
    ///
    /// The encoded output is larger than the input due to added parity data,
    /// providing both error correction and making unauthorized modifications
    /// more detectable.
    pub fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        ensure!(!data.is_empty(), "data cannot be empty");
        let encoded = self.encoder.encode(data)?;
        Ok(EncodedSection::new(encoded))
    }

    /// Encode a length value with Reed-Solomon
    ///
    /// Encodes a 4-byte length value using Reed-Solomon for the same
    /// error protection as section data.
    ///
    /// # Arguments
    ///
    /// * `length` - Length value to encode (big-endian)
    ///
    /// # Returns
    ///
    /// Result containing either the encoded length or an error.
    #[inline]
    pub fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        self.encode_section(&length.to_be_bytes())
    }

    /// Encode all sections and their lengths
    ///
    /// Processes the complete set of 5 header sections, encoding both
    /// the section data and the length information for each section.
    ///
    /// # Arguments
    ///
    /// * `raw_sections` - Array of 5 raw sections in order [Magic, Salt, HeaderData, Metadata, Mac]
    ///
    /// # Returns
    ///
    /// Result containing either:
    /// - Tuple of (encoded sections, encoded length sections)
    /// - Error if encoding fails for any section
    ///
    /// # Process
    ///
    /// 1. Encode each section's data
    /// 2. Calculate the length of each encoded section
    /// 3. Encode each length value
    /// 4. Return both sets of encoded data
    ///
    /// # Performance Notes
    ///
    /// - Processes all sections in parallel during collection
    /// - Each section encoding is independent
    /// - Total overhead depends on Reed-Solomon parameters
    pub fn encode_sections_and_lengths(&self, raw_sections: &[&[u8]; 5]) -> Result<(Vec<EncodedSection>, Vec<EncodedSection>)> {
        // Encode all section data first
        let sections: Vec<EncodedSection> = raw_sections.iter().map(|data| self.encode_section(data)).collect::<Result<Vec<EncodedSection>>>()?;

        // Then encode the length of each encoded section
        let length_sections: Vec<EncodedSection> = sections.iter().map(|section| self.encode_length(section.len())).collect::<Result<Vec<EncodedSection>>>()?;

        Ok((sections, length_sections))
    }

    /// Build the lengths header
    ///
    /// Creates the fixed 20-byte lengths header that contains the sizes
    /// of each encoded length section. This header is stored unencoded
    /// (but still Reed-Solomon protected by being stored as data).
    ///
    /// # Arguments
    ///
    /// * `length_sections` - Array of 5 encoded length sections
    ///
    /// # Returns
    ///
    /// A 20-byte array containing the section sizes in big-endian format.
    ///
    /// # Binary Format
    ///
    /// ```text
    /// [0-3]   Length of encoded Magic length section
    /// [4-7]   Length of encoded Salt length section  
    /// [8-11]  Length of encoded HeaderData length section
    /// [12-15] Length of encoded Metadata length section
    /// [16-19] Length of encoded Mac length section
    /// ```
    pub fn build_lengths_header(length_sections: &[EncodedSection]) -> [u8; 20] {
        let mut header = [0u8; 20];
        for (i, section) in length_sections.iter().enumerate() {
            let offset = i * 4;
            header[offset..offset + 4].copy_from_slice(&section.len().to_be_bytes());
        }
        header
    }
}

/// Reed-Solomon section decoder
///
/// This decoder handles the Reed-Solomon decoding of header sections,
/// providing error recovery and validation capabilities. It can reconstruct
/// the original section data even if up to 50% of the encoded data is corrupted.
///
/// The decoder uses the same Reed-Solomon parameters as the encoder to ensure
/// compatibility and proper error correction.
pub struct SectionDecoder {
    /// Underlying Reed-Solomon encoder/decoder implementation
    encoder: Encoding,
}

impl SectionDecoder {
    /// Create a new section decoder
    ///
    /// Initializes a Reed-Solomon decoder with the specified number of
    /// data and parity shards. The parameters must match those used
    /// during encoding for successful decoding.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards used during encoding
    /// * `parity_shards` - Number of parity shards used during encoding
    ///
    /// # Returns
    ///
    /// Result containing either the decoder or an error.
    ///
    /// # Errors
    ///
    /// Invalid Reed-Solomon parameters
    ///
    /// # Compatibility Notes
    ///
    /// The decoder parameters must exactly match the encoder parameters,
    /// otherwise Reed-Solomon decoding will fail.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    /// Decode a Reed-Solomon encoded section
    ///
    /// Reconstructs the original section data from the Reed-Solomon encoded
    /// version, handling any corruption or errors during transmission/storage.
    ///
    /// # Arguments
    ///
    /// * `section` - The Reed-Solomon encoded section to decode
    ///
    /// # Returns
    ///
    /// Result containing either the original decoded data or an error.
    ///
    /// # Errors
    ///
    /// - Empty encoded section
    /// - Reed-Solomon decoding failure (too much corruption)
    /// - Invalid encoded data format
    ///
    /// # Error Recovery
    ///
    /// Can successfully decode even if up to `parity_shards` of the encoded
    /// data is corrupted, providing significant robustness.
    pub fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        ensure!(!section.is_empty(), "invalid encoded section");
        self.encoder.decode(section.data())
    }

    /// Decode a Reed-Solomon encoded length value
    ///
    /// Decodes a 4-byte length value that was Reed-Solomon encoded.
    /// This is used to decode the section length information stored
    /// in the header.
    ///
    /// # Arguments
    ///
    /// * `section` - Reed-Solomon encoded length section
    ///
    /// # Returns
    ///
    /// Result containing either the decoded length value or an error.
    ///
    /// # Errors
    ///
    /// - Reed-Solomon decoding failure
    /// - Invalid length prefix size (must be at least 4 bytes)
    /// - Type conversion failure
    pub fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        let decoded = self.decode_section(section)?;
        ensure!(decoded.len() >= 4, "invalid length prefix size");

        // Convert the first 4 bytes from big-endian u32
        decoded[..4].try_into().map(u32::from_be_bytes).map_err(|_| anyhow!("length conversion failed"))
    }

    /// Read the lengths header from the data stream
    ///
    /// Reads the fixed 20-byte lengths header that contains the sizes
    /// of each encoded length section. This header is not Reed-Solomon
    /// encoded itself.
    ///
    /// # Arguments
    ///
    /// * `reader` - Data stream to read from
    ///
    /// # Returns
    ///
    /// Result containing either an array of 5 length values or an error.
    ///
    /// # Errors
    ///
    /// - I/O errors during reading
    /// - Type conversion failures
    ///
    /// # Binary Format
    ///
    /// The header contains 5 big-endian u32 values, one for each section type.
    pub fn read_lengths_header<R: Read>(&self, reader: &mut R) -> Result<[u32; 5]> {
        let mut header = [0u8; 20];
        reader.read_exact(&mut header).context("failed to read lengths header")?;

        // Convert each 4-byte chunk to a big-endian u32
        let mut result = [0u32; 5];
        for (i, slot) in result.iter_mut().enumerate() {
            let offset = i * 4;
            let bytes: [u8; 4] = header[offset..offset + 4].try_into()?;
            *slot = u32::from_be_bytes(bytes);
        }
        Ok(result)
    }

    /// Read and decode all section lengths
    ///
    /// Reads the encoded length sections from the data stream and decodes
    /// each one to recover the actual section sizes.
    ///
    /// # Arguments
    ///
    /// * `reader` - Data stream to read from
    /// * `length_sizes` - Sizes of each encoded length section from the lengths header
    ///
    /// # Returns
    ///
    /// Result containing either an array of 5 decoded lengths or an error.
    ///
    /// # Errors
    ///
    /// - I/O errors during reading
    /// - Reed-Solomon decoding failures
    /// - Invalid length data
    ///
    /// # Process
    ///
    /// 1. Read each encoded length section according to its size
    /// 2. Apply Reed-Solomon decoding to recover the original 4-byte length
    /// 3. Convert from big-endian to native format
    /// 4. Return all 5 section lengths
    pub fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, length_sizes: &[u32; 5]) -> Result<[u32; 5]> {
        let mut result = [0u32; 5];
        for (i, (&section_type, &size)) in SectionType::ALL.iter().zip(length_sizes).enumerate() {
            // Read the encoded length section
            let encoded = self.read_exact(reader, size as usize, || format!("failed to read encoded length for {section_type}"))?;

            // Decode it to recover the original length value
            result[i] = self.decode_length(&EncodedSection::new(encoded))?;
        }
        Ok(result)
    }

    /// Read and decode all sections
    ///
    /// Reads and decodes all 5 header sections from the data stream,
    /// validating the magic bytes and constructing a complete Sections instance.
    ///
    /// # Arguments
    ///
    /// * `reader` - Data stream to read from
    /// * `section_lengths` - Decoded lengths of each section
    ///
    /// # Returns
    ///
    /// Result containing either the complete decoded Sections or an error.
    ///
    /// # Errors
    ///
    /// - I/O errors during reading
    /// - Reed-Solomon decoding failures
    /// - Invalid magic bytes (file format mismatch)
    /// - Missing or empty sections
    ///
    /// # Security Validation
    ///
    /// - Validates magic bytes to ensure correct file format
    /// - Ensures all required sections are present and non-empty
    /// - Applies Reed-Solomon error correction to each section
    ///
    /// # Process
    ///
    /// 1. Read and decode the Magic section, validating against expected magic bytes
    /// 2. Create a SectionsBuilder with the validated magic bytes
    /// 3. Read and decode each remaining section in order
    /// 4. Add each section to the builder
    /// 5. Build the final validated Sections instance
    pub fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; 5]) -> Result<Sections> {
        // Step 1: Read and decode the Magic section first for validation
        let encoded = self.read_exact(reader, section_lengths[0] as usize, || format!("failed to read encoded {}", SectionType::Magic))?;
        let magic = self.decode_section(&EncodedSection::new(encoded))?;

        // Validate magic bytes to ensure correct file format
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes: expected {:?}, got {:?}", MAGIC_BYTES.to_be_bytes(), magic);

        // Step 2: Start building sections with validated magic bytes
        let mut builder = SectionsBuilder::with_magic(magic);

        // Step 3: Process remaining sections in order
        for (&section_type, &length) in SectionType::ALL[1..].iter().zip(&section_lengths[1..]) {
            let encoded = self.read_exact(reader, length as usize, || format!("failed to read encoded {section_type}"))?;
            let decoded = self.decode_section(&EncodedSection::new(encoded))?;
            builder.set(section_type, decoded);
        }

        // Step 4: Build and return the validated sections
        builder.build()
    }

    /// Helper to read exact number of bytes with context
    ///
    /// Reads exactly the specified number of bytes from the reader,
    /// providing detailed error context for debugging.
    ///
    /// # Arguments
    ///
    /// * `reader` - Data stream to read from
    /// * `size` - Number of bytes to read
    /// * `context_fn` - Function to generate error context message
    ///
    /// # Returns
    ///
    /// Result containing either the read bytes or an error.
    ///
    /// # Errors
    ///
    /// I/O errors during reading (with context from context_fn)
    fn read_exact<R: Read, F>(&self, reader: &mut R, size: usize, context_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce() -> String,
    {
        let mut buffer = vec![0u8; size];
        reader.read_exact(&mut buffer).with_context(context_fn)?;
        Ok(buffer)
    }
}
