//! Header serialization for secure file format.
//!
//! Converts header metadata and authentication data into the binary
//! format used in encrypted files. Each section is Reed-Solomon encoded
//! for resilience against corruption.
//!
//! # Serialization Process
//!
//! 1. Serialize header metadata (version, flags, original_size)
//! 2. Compute HMAC over magic, salt, and header data
//! 3. Reed-Solomon encode each of the 4 sections
//! 4. Encode the lengths of each encoded section
//! 5. Build the lengths header (16 bytes)
//! 6. Assemble: lengths header + length sections + data sections

use anyhow::{Result, ensure};

use crate::config::{ARGON_SALT_LEN, HEADER_DATA_SIZE, MAGIC_BYTES};
use crate::header::mac::Mac;
use crate::header::section::{EncodedSection, SectionEncoder, SectionType};

/// Serializes header data into the secure file format.
pub struct Serializer<'a> {
    /// Reference to the section encoder for Reed-Solomon encoding.
    encoder: &'a SectionEncoder,
}

impl<'a> Serializer<'a> {
    /// Creates a new serializer with the given section encoder.
    #[inline]
    #[must_use]
    pub const fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    /// Serializes all header components into bytes.
    ///
    /// # Arguments
    ///
    /// * `version` - File format version.
    /// * `flags` - Processing flags.
    /// * `original_size` - Original file size in bytes.
    /// * `salt` - Random salt for key derivation.
    /// * `key` - Derived key for HMAC.
    ///
    /// # Returns
    ///
    /// The complete serialized header.
    ///
    /// # Errors
    ///
    /// Returns an error if salt size is invalid, key is empty, or encoding fails.
    pub fn serialize(&self, version: u16, flags: u32, original_size: u64, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Validate inputs
        ensure!(salt.len() == ARGON_SALT_LEN, "invalid salt size: expected {}, got {}", ARGON_SALT_LEN, salt.len());
        ensure!(!key.is_empty(), "key cannot be empty");

        // Create magic bytes
        let magic = MAGIC_BYTES.to_be_bytes();

        // Serialize header metadata
        let header_data = Self::serialize_header_data(version, flags, original_size);

        // Compute HMAC over magic, salt, and header data
        let mac = Mac::new(key)?.compute(&[&magic, salt, &header_data])?;

        // Raw sections in order: Magic, Salt, HeaderData, Mac
        let raw_sections: [&[u8]; 4] = [&magic, salt, &header_data, &mac];

        // Reed-Solomon encode each section
        let sections = self.encode_all_sections(&raw_sections)?;

        // Encode the lengths of each encoded section
        let length_sections = self.encode_length_prefixes(&sections)?;

        // Build the fixed 16-byte lengths header
        let lengths_header = Self::build_lengths_header(&length_sections);

        // Combine all parts into final header
        Ok(Self::assemble(&lengths_header, &length_sections, &sections))
    }

    /// Encodes all raw sections using Reed-Solomon.
    ///
    /// Takes the 4 raw byte arrays (magic, salt, header_data, mac) and applies
    /// Reed-Solomon encoding to each one. This adds parity bytes for error correction.
    ///
    /// # Arguments
    ///
    /// * `raw` - Array of 4 references to raw section data. Index 0 = Magic, 1 = Salt, 2 =
    ///   HeaderData, 3 = Mac.
    ///
    /// # Returns
    ///
    /// An array of 4 EncodedSection objects, one for each input section.
    ///
    /// # Errors
    ///
    /// Returns an error if any section encoding fails.
    fn encode_all_sections(&self, raw: &[&[u8]; 4]) -> Result<[EncodedSection; 4]> {
        // Iterate over all section types in order.
        // SectionType::ALL = [Magic, Salt, HeaderData, Mac]
        SectionType::ALL
            .iter()
            // For each section type, encode the corresponding raw data.
            // st.index() returns 0, 1, 2, or 3 to index into the raw array.
            .map(|st| self.encoder.encode_section(raw[st.index()]))
            // Collect results into a Vec, converting Result<Vec<T>> to Result<Vec<T>>.
            .collect::<Result<Vec<EncodedSection>>>()?
            // Convert Vec to fixed-size array [EncodedSection; 4].
            // This is safe because we know we have exactly 4 sections.
            .try_into()
            // Map any conversion errors to a more descriptive message.
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    /// Encodes the lengths of each section using Reed-Solomon.
    ///
    /// Each section's encoded length is itself Reed-Solomon encoded for
    /// corruption resistance. This allows recovery of length values even
    /// if the lengths section is damaged.
    ///
    /// # Arguments
    ///
    /// * `sections` - Array of 4 EncodedSection objects (already RS-encoded).
    ///
    /// # Returns
    ///
    /// An array of 4 EncodedSection objects containing the encoded lengths.
    ///
    /// # Errors
    ///
    /// Returns an error if any length encoding fails.
    fn encode_length_prefixes(&self, sections: &[EncodedSection; 4]) -> Result<[EncodedSection; 4]> {
        // Iterate over all section types in order.
        SectionType::ALL
            .iter()
            // For each section type, get the encoded section and extract its length.
            // sections[st.index()] gets the section by type.
            // .length_u32() returns the encoded section's byte length as u32.
            .map(|st| self.encoder.encode_length(sections[st.index()].length_u32()))
            // Collect and convert to fixed-size array, same as encode_all_sections.
            .collect::<Result<Vec<EncodedSection>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("section count mismatch"))
    }

    /// Builds the 16-byte lengths header from length sections.
    ///
    /// This is a fixed-size header that tells the deserializer how large
    /// each Reed-Solomon encoded section is, allowing it to know how many
    /// bytes to read for each section.
    ///
    /// Format: [magic_len: u32][salt_len: u32][header_data_len: u32][mac_len: u32]
    /// All lengths are stored as big-endian 32-bit integers.
    fn build_lengths_header(length_sections: &[EncodedSection; 4]) -> [u8; 16] {
        // Pre-allocate the 16-byte header.
        // This matches the total of 4 u32 values (4 bytes each).
        let mut header = [0u8; 16];
        for (i, section) in length_sections.iter().enumerate() {
            // Calculate byte offset: each section gets 4 bytes.
            let offset = i * 4;
            // Write each length as big-endian u32.
            // This ensures consistent byte order across platforms.
            header[offset..offset + 4].copy_from_slice(&section.length_u32().to_be_bytes());
        }
        header
    }

    /// Assembles all header components into a single byte vector.
    ///
    /// The final header layout is:
    /// 1. Lengths header (16 bytes): sizes of each encoded section
    /// 2. Length sections (variable): RS-encoded lengths
    /// 3. Data sections (variable): RS-encoded header data
    ///
    /// This layered approach allows recovery from partial corruption:
    /// - If data sections are corrupted, lengths help identify the damage
    /// - Both data and lengths have Reed-Solomon protection
    ///
    /// Order: lengths_header + length_sections + data_sections
    fn assemble(lengths_header: &[u8], length_sections: &[EncodedSection; 4], data_sections: &[EncodedSection; 4]) -> Vec<u8> {
        // Calculate total size for pre-allocation to avoid reallocations.
        // Sum: 16-byte header + all length sections + all data sections.
        let total_size = lengths_header.len() + length_sections.iter().map(|s| s.len()).sum::<usize>() + data_sections.iter().map(|s| s.len()).sum::<usize>();

        let mut result = Vec::with_capacity(total_size);

        // Append lengths header first (fixed 16 bytes).
        // This tells the reader where each section begins.
        result.extend_from_slice(lengths_header);

        // Append Reed-Solomon encoded lengths for each section.
        // These allow recovery of corrupted length values.
        for section in length_sections {
            result.extend_from_slice(section.data());
        }

        // Append Reed-Solomon encoded data sections (Magic, Salt, HeaderData, MAC).
        // These contain the actual header information with error correction.
        for section in data_sections {
            result.extend_from_slice(section.data());
        }

        result
    }

    /// Serializes header metadata into a 14-byte array.
    ///
    /// Creates the fixed-size HeaderData section that stores version, flags,
    /// and original file size. This data is stored in big-endian byte order
    /// for consistent representation across different architectures.
    ///
    /// # Layout
    ///
    /// - Bytes 0-1: Version (u16 big-endian) - File format version
    /// - Bytes 2-5: Flags (u32 big-endian) - Processing flags (e.g., FLAG_PROTECTED)
    /// - Bytes 6-13: Original size (u64 big-endian) - Original uncompressed file size
    ///
    /// # Arguments
    ///
    /// * `version` - File format version (e.g., 0x0001).
    /// * `flags` - Processing flags as a bitfield.
    /// * `original_size` - Original file size in bytes.
    ///
    /// # Returns
    ///
    /// A fixed-size 14-byte array containing the serialized header metadata.
    #[inline]
    fn serialize_header_data(version: u16, flags: u32, original_size: u64) -> [u8; HEADER_DATA_SIZE] {
        // Pre-allocate a zeroed array of HEADER_DATA_SIZE (14 bytes).
        // This avoids dynamic allocation and ensures exact size.
        let mut data = [0u8; HEADER_DATA_SIZE];

        // Write version to bytes 0-1 (2 bytes).
        // to_be_bytes() converts u16 to big-endian byte array [u8; 2].
        // copy_from_slice() copies exactly 2 bytes into positions 0-1.
        data[0..2].copy_from_slice(&version.to_be_bytes());

        // Write flags to bytes 2-5 (4 bytes).
        // u32 occupies 4 bytes, positioned after the 2-byte version.
        data[2..6].copy_from_slice(&flags.to_be_bytes());

        // Write original_size to bytes 6-13 (8 bytes).
        // u64 occupies 8 bytes, positioned after version and flags.
        // This is the last field in the HeaderData section.
        data[6..14].copy_from_slice(&original_size.to_be_bytes());

        // Return the filled byte array.
        // The caller will Reed-Solomon encode this for error correction.
        data
    }
}
