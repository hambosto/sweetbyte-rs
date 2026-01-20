use anyhow::{Result, ensure};

use crate::config::{ARGON_SALT_LEN, HEADER_DATA_SIZE, MAGIC_BYTES};
use crate::header::mac::Mac;
use crate::header::section::{EncodedSection, SECTION_COUNT, SectionEncoder, SectionType};

/// Size of the lengths header (4 bytes per section * 4 sections = 16 bytes).
const LENGTHS_HEADER_SIZE: usize = 16;

/// Serializes header sections into a byte vector.
///
/// Handles the complete serialization process including:
/// - Computing the header data (version, flags, size)
/// - Computing the MAC for integrity
/// - Encoding all sections with Reed-Solomon error correction
/// - Assembling the final byte stream
pub struct Serializer<'a> {
    /// Reference to the section encoder.
    encoder: &'a SectionEncoder,
}

impl<'a> Serializer<'a> {
    /// Creates a new Serializer with the given encoder.
    ///
    /// # Arguments
    /// * `encoder` - The section encoder to use.
    ///
    /// # Returns
    /// A new Serializer instance.
    #[inline]
    #[must_use]
    pub fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    /// Serializes all header components into a byte vector.
    ///
    /// # Arguments
    /// * `version` - The file format version.
    /// * `flags` - The flags value.
    /// * `original_size` - The original file size.
    /// * `salt` - The salt for key derivation.
    /// * `key` - The key for MAC computation.
    ///
    /// # Returns
    /// The serialized header bytes.
    pub fn serialize(&self, version: u16, flags: u32, original_size: u64, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Validate inputs.
        ensure!(salt.len() == ARGON_SALT_LEN, "invalid salt size: expected {}, got {}", ARGON_SALT_LEN, salt.len());
        ensure!(!key.is_empty(), "key cannot be empty");

        // Convert magic bytes to big-endian.
        let magic = MAGIC_BYTES.to_be_bytes();
        // Serialize header metadata.
        let header_data = Self::serialize_header_data(version, flags, original_size);
        // Compute MAC over magic, salt, and header data.
        let mac = Mac::compute_bytes(key, &[&magic, salt, &header_data])?;

        // Encode all sections with Reed-Solomon.
        let raw_sections: [&[u8]; SECTION_COUNT] = [&magic, salt, &header_data, &mac];
        let sections = self.encode_all_sections(&raw_sections)?;

        // Encode length prefixes for each section.
        let length_sections = self.encode_length_prefixes(&sections)?;

        // Build the final output.
        let lengths_header = Self::build_lengths_header(&length_sections);
        Ok(Self::assemble(&lengths_header, &length_sections, &sections))
    }

    /// Encodes all raw sections using Reed-Solomon.
    ///
    /// # Arguments
    /// * `raw` - Array of raw section data.
    ///
    /// # Returns
    /// Array of encoded sections.
    fn encode_all_sections(&self, raw: &[&[u8]; SECTION_COUNT]) -> Result<[EncodedSection; SECTION_COUNT]> {
        // Encode all sections with Reed-Solomon error correction.
        let encoded: Vec<EncodedSection> = SectionType::ALL.iter().map(|st| self.encoder.encode_section(raw[st.index()])).collect::<Result<_>>()?;
        // Convert Vec<EncodedSection> to [EncodedSection; SECTION_COUNT].
        encoded.try_into().map_err(|_| anyhow::anyhow!("unexpected section count"))
    }

    /// Encodes length prefixes for all sections.
    ///
    /// # Arguments
    /// * `sections` - The encoded sections.
    ///
    /// # Returns
    /// Array of encoded length sections.
    fn encode_length_prefixes(&self, sections: &[EncodedSection; SECTION_COUNT]) -> Result<[EncodedSection; SECTION_COUNT]> {
        // Encode length prefixes for each section.
        let encoded: Vec<EncodedSection> = SectionType::ALL.iter().map(|st| self.encoder.encode_length(sections[st.index()].length())).collect::<Result<_>>()?;
        // Convert Vec<EncodedSection> to [EncodedSection; SECTION_COUNT].
        encoded.try_into().map_err(|_| anyhow::anyhow!("unexpected section count"))
    }

    /// Builds the lengths header containing section lengths.
    ///
    /// Each section length is stored as a big-endian u32.
    ///
    /// # Arguments
    /// * `length_sections` - The encoded length sections.
    ///
    /// # Returns
    /// A 16-byte array containing all section lengths.
    fn build_lengths_header(length_sections: &[EncodedSection; SECTION_COUNT]) -> [u8; LENGTHS_HEADER_SIZE] {
        let mut header = [0u8; LENGTHS_HEADER_SIZE];

        // Write each section length as big-endian u32.
        for (i, section) in length_sections.iter().enumerate() {
            header[i * 4..][..4].copy_from_slice(&section.length().to_be_bytes());
        }

        header
    }

    /// Assembles all components into the final header byte vector.
    ///
    /// The format is: lengths_header | length_sections | data_sections
    ///
    /// # Arguments
    /// * `lengths_header` - The 16-byte lengths header.
    /// * `length_sections` - The encoded length sections.
    /// * `data_sections` - The encoded data sections.
    ///
    /// # Returns
    /// The complete serialized header.
    fn assemble(lengths_header: &[u8], length_sections: &[EncodedSection; SECTION_COUNT], data_sections: &[EncodedSection; SECTION_COUNT]) -> Vec<u8> {
        // Calculate total size for pre-allocation.
        let total_size = lengths_header.len() + length_sections.iter().map(|s| s.data().len()).sum::<usize>() + data_sections.iter().map(|s| s.data().len()).sum::<usize>();

        let mut result = Vec::with_capacity(total_size);
        // Write lengths header.
        result.extend_from_slice(lengths_header);

        // Write encoded length sections.
        for section in length_sections {
            result.extend_from_slice(section.data());
        }

        // Write encoded data sections.
        for section in data_sections {
            result.extend_from_slice(section.data());
        }

        result
    }

    /// Serializes header metadata into a fixed-size byte array.
    ///
    /// # Arguments
    /// * `version` - The file format version (2 bytes).
    /// * `flags` - The flags value (4 bytes).
    /// * `original_size` - The original file size (8 bytes).
    ///
    /// # Returns
    /// A 14-byte array containing the header data.
    #[inline]
    fn serialize_header_data(version: u16, flags: u32, original_size: u64) -> [u8; HEADER_DATA_SIZE] {
        let mut data = [0u8; HEADER_DATA_SIZE];
        // Write version as big-endian u16.
        data[0..2].copy_from_slice(&version.to_be_bytes());
        // Write flags as big-endian u32.
        data[2..6].copy_from_slice(&flags.to_be_bytes());
        // Write original size as big-endian u64.
        data[6..14].copy_from_slice(&original_size.to_be_bytes());
        data
    }
}
