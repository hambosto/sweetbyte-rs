//! Reed-Solomon Header Deserialization
//!
//! This module provides functionality to deserialize encrypted file headers that have been
//! encoded using Reed-Solomon error correction. The deserializer handles the complete
//! process of reading and decoding the 5-section header structure:
//!
//! 1. **Magic Bytes** - File format identifier (4 bytes)
//! 2. **Salt** - Cryptographic salt for key derivation
//! 3. **Header Data** - Encryption and compression parameters
//! 4. **Metadata** - File name, size, and content hash
//! 5. **MAC** - Message authentication code for integrity verification
//!
//! ## Binary Layout
//!
//! The on-disk format consists of:
//! - **Lengths Header** (20 bytes): Sizes of each encoded length section
//! - **Encoded Lengths**: Reed-Solomon encoded section lengths (variable size)
//! - **Encoded Sections**: Reed-Solomon encoded section data (variable size)
//!
//! ## Security Notes
//!
//! - All sections are protected by Reed-Solomon encoding, providing both error correction and
//!   tamper resistance
//! - The deserializer validates the magic bytes to ensure file format compatibility
//! - Section validation ensures all required sections are present and non-empty
//!
//! ## Performance Characteristics
//!
//! - Reed-Solomon decoding is computationally intensive but provides significant error recovery
//!   capabilities (up to 50% data corruption tolerance)
//! - Memory usage scales with the size of the header sections (typically < 1KB total)

use std::io::Read;

use anyhow::{Result, anyhow};

use crate::header::Params;
use crate::header::metadata::FileMetadata;
use crate::header::section::{SectionDecoder, SectionType, Sections};

/// Container for deserialized header data
///
/// This structure holds the parsed components of an encrypted file header,
/// providing convenient access to the encryption parameters, file metadata,
/// and the original encoded sections for further processing if needed.
#[derive(Debug)]
pub struct ParsedData {
    /// Encryption and compression parameters
    params: Params,
    /// File metadata including name, size, and content hash
    metadata: FileMetadata,
    /// Raw Reed-Solomon encoded sections (for validation or re-processing)
    sections: Sections,
}

impl ParsedData {
    /// Get the encryption parameters
    ///
    /// # Returns
    ///
    /// Reference to the parsed encryption parameters containing algorithm
    /// identifiers, key derivation parameters, and compression settings.
    #[inline]
    #[must_use]
    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// Get the file metadata
    ///
    /// # Returns
    ///
    /// Reference to the file metadata containing the original filename,
    /// file size, and content hash for integrity verification.
    #[inline]
    #[must_use]
    pub const fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Consume this instance and return the raw sections
    ///
    /// This method extracts the underlying Reed-Solomon encoded sections,
    /// allowing callers to perform additional validation or processing
    /// on the raw section data.
    ///
    /// # Returns
    ///
    /// The sections container holding all 5 header sections in their
    /// encoded form.
    #[inline]
    pub fn into_sections(self) -> Sections {
        self.sections
    }
}

/// Reed-Solomon header deserializer
///
/// This struct handles the complete deserialization of encrypted file headers,
/// coordinating the Reed-Solomon decoding process and extracting the individual
/// header components. It maintains a reference to a SectionDecoder for the
/// actual Reed-Solomon operations.
pub struct Deserializer<'a> {
    /// Reed-Solomon decoder for handling section reconstruction
    decoder: &'a SectionDecoder,
}

impl<'a> Deserializer<'a> {
    /// Create a new deserializer with the given Reed-Solomon decoder
    ///
    /// # Arguments
    ///
    /// * `decoder` - Reference to a SectionDecoder configured with appropriate data and parity
    ///   shard counts for the expected header protection level
    ///
    /// # Returns
    ///
    /// A new Deserializer instance ready to process encrypted file headers.
    #[inline]
    #[must_use]
    pub fn new(decoder: &'a SectionDecoder) -> Self {
        Self { decoder }
    }

    /// Deserialize a complete header from the given reader
    ///
    /// This method performs the full deserialization process:
    /// 1. Read the lengths header (20 bytes total, 4 bytes per section)
    /// 2. Read and decode the encoded section lengths using Reed-Solomon
    /// 3. Read and decode the actual section data using Reed-Solomon
    /// 4. Extract and parse the HeaderData and Metadata sections
    /// 5. Return the combined parsed data structure
    ///
    /// # Arguments
    ///
    /// * `reader` - Any type implementing Read that provides the header data stream
    ///
    /// # Returns
    ///
    /// A Result containing either the parsed header data or an error if:
    /// - Reed-Solomon decoding fails (exceeded error correction capability)
    /// - Required sections are missing or empty
    /// - Binary format is invalid
    /// - I/O operations fail
    ///
    /// # Errors
    ///
    /// - `anyhow::Error` for Reed-Solomon decoding failures
    /// - `anyhow::Error` for missing required sections
    /// - `std::io::Error` for I/O failures during reading
    /// - Format errors for invalid binary data
    ///
    /// # Performance Notes
    ///
    /// - Reed-Solomon decoding processes each section independently
    /// - Memory allocation occurs for section data but not for the lengths header
    /// - The method validates magic bytes early to fail fast on incompatible files
    pub fn deserialize<R: Read>(&self, mut reader: R) -> Result<ParsedData> {
        // Step 1: Read the fixed-size lengths header (20 bytes)
        // This contains the sizes of each encoded length section
        let length_sizes = self.decoder.read_lengths_header(&mut reader)?;

        // Step 2: Read and decode the actual section lengths
        // Each length is Reed-Solomon encoded to provide error correction
        let section_lengths = self.decoder.read_and_decode_lengths(&mut reader, &length_sizes)?;

        // Step 3: Read and decode all section data
        // This includes the Reed-Solomon encoded magic bytes and all 5 header sections
        let sections = self.decoder.read_and_decode_sections(&mut reader, &section_lengths)?;

        // Step 4: Extract and parse the HeaderData section (encryption parameters)
        let header_data = sections.get(SectionType::HeaderData).ok_or_else(|| anyhow!("HeaderData section not found"))?;
        let params = Params::deserialize(header_data)?;

        // Step 5: Extract and parse the Metadata section (file information)
        let metadata_bytes = sections.get(SectionType::Metadata).ok_or_else(|| anyhow!("Metadata section not found"))?;
        let metadata = FileMetadata::deserialize(metadata_bytes)?;

        // Step 6: Return the complete parsed structure
        Ok(ParsedData { params, metadata, sections })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::header::section::SectionEncoder;

    #[test]
    fn test_deserializer_invalid_magic() {
        let encoder = SectionEncoder::new(4, 2).unwrap();

        let invalid_magic = vec![0, 0, 0, 0];
        let magic_section = encoder.encode_section(&invalid_magic).unwrap();

        let dummy = vec![1];
        let dummy_section = encoder.encode_section(&dummy).unwrap();

        let length_sections = vec![
            encoder.encode_length(magic_section.len()).unwrap(),
            encoder.encode_length(dummy_section.len()).unwrap(),
            encoder.encode_length(dummy_section.len()).unwrap(),
            encoder.encode_length(dummy_section.len()).unwrap(),
            encoder.encode_length(dummy_section.len()).unwrap(),
        ];

        let header = SectionEncoder::build_lengths_header(&length_sections);

        let mut full_data = Vec::new();
        full_data.extend_from_slice(&header);
        for s in &length_sections {
            full_data.extend_from_slice(s.data());
        }
        full_data.extend_from_slice(magic_section.data());
        for _ in 0..4 {
            full_data.extend_from_slice(dummy_section.data());
        }

        let decoder = SectionDecoder::new(4, 2).unwrap();
        let deserializer = Deserializer::new(&decoder);

        let mut cursor = Cursor::new(full_data);
        let result = deserializer.deserialize(&mut cursor);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid magic bytes"));
    }
}
