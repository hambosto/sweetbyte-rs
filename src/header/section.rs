//! # Header Section Encoding and Decoding
//!
//! This module provides functionality for encoding and decoding header sections in the SweetByte file format.
//! It implements a robust encoding scheme using Reed-Solomon error correction to ensure data integrity
//! and resilience against corruption.
//!
//! ## Architecture
//!
//! The module follows a layered approach:
//! 1. **EncodedSection**: Wrapper around Reed-Solomon encoded data
//! 2. **LengthsHeader**: Metadata describing the size of each encoded section
//! 3. **SectionEncoder/SectionDecoder**: High-level interfaces for packing/unpacking header data
//!
//! ## Key Concepts
//!
//! - **Reed-Solomon Encoding**: Each data section is encoded with configurable data and parity shards
//! - **Length Prefixing**: The size of each encoded section is also encoded for verification
//! - **Magic Byte Verification**: Ensures file format compatibility during decoding
//! - **Error Recovery**: Reed-Solomon allows recovery from up to parity_shards of corruption

use std::io::Read;

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::MAGIC_BYTES;
use crate::encoding::Encoding;

/// Represents the decoded header sections of a SweetByte file.
///
/// This structure contains all the essential components of the file header after
/// Reed-Solomon decoding and verification. Each field contains raw byte data
/// that corresponds to specific sections in the file format.
#[derive(Debug)]
pub struct DecodedSections {
    /// Magic bytes that identify the file format (should match MAGIC_BYTES)
    pub magic: Vec<u8>,
    /// Cryptographic salt used for key derivation (Argon2id)
    pub salt: Vec<u8>,
    /// Encrypted header data containing encryption parameters
    pub header_data: Vec<u8>,
    /// Optional metadata section for user-defined information
    pub metadata: Vec<u8>,
    /// Message Authentication Code for integrity verification
    pub mac: Vec<u8>,
}

/// Internal structure representing the lengths of encoded sections.
///
/// This header is stored at the beginning of the encoded file format and contains
/// the size (in bytes) of each Reed-Solomon encoded section. The lengths themselves
/// are also Reed-Solomon encoded for resilience.
#[derive(Debug, Serialize, Deserialize, SchemaRead, SchemaWrite)]
struct LengthsHeader {
    /// Length of the Reed-Solomon encoded magic bytes section
    magic_len: u32,
    /// Length of the Reed-Solomon encoded salt section
    salt_len: u32,
    /// Length of the Reed-Solomon encoded header data section
    header_data_len: u32,
    /// Length of the Reed-Solomon encoded metadata section
    metadata_len: u32,
    /// Length of the Reed-Solomon encoded MAC section
    mac_len: u32,
}

impl LengthsHeader {
    /// Constant representing the serialized size of the LengthsHeader.
    ///
    /// Each u32 field occupies 4 bytes, and there are 5 fields total:
    /// 5 fields × 4 bytes/field = 20 bytes
    const SIZE: usize = 20;

    /// Converts the LengthsHeader into a fixed-size array for easier iteration.
    ///
    /// # Returns
    ///
    /// A 5-element array containing the lengths in the order:
    /// [magic_len, salt_len, header_data_len, metadata_len, mac_len]
    fn as_array(&self) -> [u32; 5] {
        [self.magic_len, self.salt_len, self.header_data_len, self.metadata_len, self.mac_len]
    }
}

/// Wrapper around Reed-Solomon encoded data.
///
/// This structure provides a thin wrapper around encoded byte data,
/// ensuring that the data has passed through the Reed-Solomon encoding process.
/// It's used internally to distinguish between raw and encoded data.
#[derive(Debug, Clone)]
struct EncodedSection {
    /// Reed-Solomon encoded byte data
    data: Vec<u8>,
}

impl EncodedSection {
    /// Creates a new EncodedSection from Reed-Solomon encoded data.
    ///
    /// # Arguments
    ///
    /// * `data` - Reed-Solomon encoded byte vector
    ///
    /// # Returns
    ///
    /// A new EncodedSection instance wrapping the provided data
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns a reference to the underlying encoded data.
    ///
    /// # Returns
    ///
    /// A byte slice reference to the encoded data
    fn data(&self) -> &[u8] {
        &self.data
    }

    /// Checks if the encoded section contains no data.
    ///
    /// This is used during decoding to validate that sections were properly encoded.
    ///
    /// # Returns
    ///
    /// true if the section is empty, false otherwise
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the length of the encoded data as a u32.
    ///
    /// The length is returned as u32 to match the serialization format requirements.
    ///
    /// # Returns
    ///
    /// The length of the encoded data in bytes
    fn len(&self) -> u32 {
        self.data.len() as u32
    }
}

/// High-level encoder for SweetByte header sections.
///
/// This struct provides the main interface for encoding header sections into the
/// SweetByte file format. It handles Reed-Solomon encoding, length prefixing,
/// and serialization of the complete header structure.
///
/// # Security
///
/// The Reed-Solomon encoding provides integrity protection but not confidentiality.
/// Sensitive data should be encrypted before being passed to this encoder.
#[derive(Debug)]
pub struct SectionEncoder {
    /// Reed-Solomon encoder instance with configured data and parity shards
    encoder: Encoding,
}

impl SectionEncoder {
    /// Creates a new SectionEncoder with specified Reed-Solomon parameters.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards in the Reed-Solomon encoding (typically 4)
    /// * `parity_shards` - Number of parity shards for error correction (typically 2)
    ///
    /// # Returns
    ///
    /// A Result containing the new SectionEncoder or an error if encoding parameters are invalid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - data_shards or parity_shards is zero
    /// - The Reed-Solomon encoder cannot be initialized with the specified parameters
    ///
    /// # Performance
    ///
    /// Reed-Solomon encoding has O(n) complexity where n is the total data size.
    /// Higher parity shard counts provide better error recovery but increase storage overhead.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        // Initialize Reed-Solomon encoder with specified shard configuration
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    /// Packs header sections into the complete SweetByte file format.
    ///
    /// This method performs the complete encoding process:
    /// 1. Reed-Solomon encodes each data section
    /// 2. Reed-Solomon encodes each section length
    /// 3. Serializes the lengths header
    /// 4. Concatenates all components into the final byte format
    ///
    /// # Arguments
    ///
    /// * `magic` - Magic bytes identifying the file format (must match MAGIC_BYTES)
    /// * `salt` - Cryptographic salt for key derivation
    /// * `header_data` - Encrypted header containing encryption parameters
    /// * `metadata` - Optional user metadata (can be empty)
    /// * `mac` - Message Authentication Code for integrity verification
    ///
    /// # Returns
    ///
    /// A Result containing the complete encoded byte vector or an error if encoding fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any input section is empty (Reed-Solomon requires non-empty data)
    /// - Reed-Solomon encoding fails for any section
    /// - Serialization of the LengthsHeader fails
    ///
    /// # Security
    ///
    /// The Reed-Solomon encoding provides protection against data corruption but not
    /// against malicious tampering. The MAC should be verified separately for authenticity.
    ///
    /// # Performance
    ///
    /// This method performs 10 Reed-Solomon encodings (5 data + 5 length sections) and
    /// allocates memory for all encoded sections. Memory usage is O(n) where n is total input size.
    pub fn pack(&self, magic: &[u8], salt: &[u8], header_data: &[u8], metadata: &[u8], mac: &[u8]) -> Result<Vec<u8>> {
        // Combine all raw data sections into a single array for consistent processing
        let raw_sections = [magic, salt, header_data, metadata, mac];

        // 1. Apply Reed-Solomon encoding to each data section
        // This provides error correction capabilities for each section independently
        let sections: Vec<EncodedSection> = raw_sections.iter().map(|data| self.encode_section(data)).collect::<Result<Vec<EncodedSection>>>()?;

        // 2. Apply Reed-Solomon encoding to the length of each encoded section
        // This ensures that even the size information is protected against corruption
        let length_sections: Vec<EncodedSection> = sections.iter().map(|section| self.encode_length(section.len())).collect::<Result<Vec<EncodedSection>>>()?;

        // 3. Create the LengthsHeader structure with the sizes of encoded length sections
        // This metadata allows the decoder to know how many bytes to read for each section
        let lengths_header = LengthsHeader {
            magic_len: length_sections[0].len(),
            salt_len: length_sections[1].len(),
            header_data_len: length_sections[2].len(),
            metadata_len: length_sections[3].len(),
            mac_len: length_sections[4].len(),
        };

        // 4. Serialize the LengthsHeader using the wincode binary format
        // This creates a fixed 20-byte header at the beginning of the file
        let lengths_header_bytes = wincode::serialize(&lengths_header)?;

        // 5. Concatenate all components in the correct order:
        // - LengthsHeader (20 bytes)
        // - Encoded length sections (variable size)
        // - Encoded data sections (variable size)
        let result: Vec<u8> = lengths_header_bytes
            .iter()
            .cloned()
            .chain(length_sections.iter().flat_map(|s| s.data().iter().cloned()))
            .chain(sections.iter().flat_map(|s| s.data().iter().cloned()))
            .collect();

        Ok(result)
    }

    /// Encodes a single data section using Reed-Solomon.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw data bytes to encode
    ///
    /// # Returns
    ///
    /// A Result containing the EncodedSection or an error if encoding fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input data is empty (Reed-Solomon requires non-empty data)
    /// - The Reed-Solomon encoding process fails
    fn encode_section(&self, data: &[u8]) -> Result<EncodedSection> {
        // Validate that data is not empty - Reed-Solomon encoding requires non-empty input
        ensure!(!data.is_empty(), "data cannot be empty");

        // Apply Reed-Solomon encoding to create parity shards
        let encoded = self.encoder.encode(data)?;

        // Wrap the encoded data in an EncodedSection for type safety
        Ok(EncodedSection::new(encoded))
    }

    /// Encodes a length value using Reed-Solomon.
    ///
    /// This method encodes the 4-byte length of an encoded section, providing
    /// error correction for the size metadata itself.
    ///
    /// # Arguments
    ///
    /// * `length` - The length value to encode (as u32)
    ///
    /// # Returns
    ///
    /// A Result containing the Reed-Solomon encoded length or an error if encoding fails
    ///
    /// # Performance
    ///
    /// Always encodes exactly 4 bytes of data, resulting in a predictable output size.
    fn encode_length(&self, length: u32) -> Result<EncodedSection> {
        // Convert the u32 length to big-endian bytes for consistent serialization
        // Big-endian ensures cross-platform compatibility
        self.encode_section(&length.to_be_bytes())
    }
}

/// High-level decoder for SweetByte header sections.
///
/// This struct provides the main interface for decoding header sections from the
/// SweetByte file format. It handles Reed-Solomon decoding, length verification,
/// and magic byte validation.
///
/// # Security
///
/// The decoder validates magic bytes to ensure file format compatibility and
/// uses Reed-Solomon to recover from data corruption. However, it does not
/// verify cryptographic integrity - that must be done separately with the MAC.
pub struct SectionDecoder {
    /// Reed-Solomon encoder/decoder instance with matching shard configuration
    encoder: Encoding,
}

impl SectionDecoder {
    /// Creates a new SectionDecoder with specified Reed-Solomon parameters.
    ///
    /// The shard configuration must match the configuration used during encoding
    /// for successful decoding and error recovery.
    ///
    /// # Arguments
    ///
    /// * `data_shards` - Number of data shards (must match encoder configuration)
    /// * `parity_shards` - Number of parity shards (must match encoder configuration)
    ///
    /// # Returns
    ///
    /// A Result containing the new SectionDecoder or an error if parameters are invalid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - data_shards or parity_shards is zero
    /// - The Reed-Solomon encoder cannot be initialized
    ///
    /// # Security
    ///
    /// Mismatched shard parameters between encoder and decoder will result in
    /// complete failure to decode the data, acting as a form of integrity check.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        // Initialize Reed-Solomon decoder with matching shard configuration
        let encoder = Encoding::new(data_shards, parity_shards)?;
        Ok(Self { encoder })
    }

    /// Unpacks and decodes header sections from a readable source.
    ///
    /// This method performs the complete decoding process:
    /// 1. Reads and deserializes the LengthsHeader
    /// 2. Reads and decodes the encoded length sections
    /// 3. Reads and decodes the encoded data sections
    /// 4. Validates magic bytes for format compatibility
    ///
    /// # Type Parameters
    ///
    /// * `R` - Any type implementing the Read trait (files, memory streams, etc.)
    ///
    /// # Arguments
    ///
    /// * `reader` - Mutable reference to a readable source containing the encoded data
    ///
    /// # Returns
    ///
    /// A Result containing the DecodedSections or an error if decoding fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot read the LengthsHeader (IO error or EOF)
    /// - LengthsHeader deserialization fails (corruption)
    /// - Reed-Solomon decoding fails for any section
    /// - Magic bytes don't match expected format
    ///
    /// # Security
    ///
    /// Magic byte verification prevents processing files with incompatible formats.
    /// Reed-Solomon decoding can recover from up to parity_shards of corruption per section.
    ///
    /// # Performance
    ///
    /// Performs 10 Reed-Solomon decodings and reads the entire header into memory.
    /// Memory usage is O(n) where n is the total header size.
    pub fn unpack<R: Read>(&self, reader: &mut R) -> Result<DecodedSections> {
        // 1. Read the fixed-size LengthsHeader from the beginning of the stream
        let mut buffer = [0u8; LengthsHeader::SIZE];
        reader.read_exact(&mut buffer).context("failed to read lengths header")?;
        let lengths_header: LengthsHeader = wincode::deserialize(&buffer).context("failed to deserialize lengths header")?;

        // 2. Read and decode the Reed-Solomon encoded length sections
        // These lengths tell us how many bytes to read for each data section
        let section_lengths = self.read_and_decode_lengths(reader, &lengths_header)?;

        // 3. Read and decode the actual data sections using the decoded lengths
        // This step also validates magic bytes to ensure format compatibility
        let sections = self.read_and_decode_sections(reader, &section_lengths)?;

        Ok(sections)
    }

    /// Decodes a Reed-Solomon encoded section back to raw data.
    ///
    /// # Arguments
    ///
    /// * `section` - The EncodedSection to decode
    ///
    /// # Returns
    ///
    /// A Result containing the decoded raw data or an error if decoding fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The section is empty (indicates corruption or encoding failure)
    /// - Reed-Solomon decoding fails (excessive corruption beyond recovery capability)
    ///
    /// # Security
    ///
    /// Reed-Solomon can recover from up to parity_shards of corruption.
    /// Beyond that, data is lost and decoding fails, preventing use of corrupted data.
    fn decode_section(&self, section: &EncodedSection) -> Result<Vec<u8>> {
        // Validate that the section is not empty - empty sections indicate corruption
        ensure!(!section.is_empty(), "invalid encoded section");

        // Apply Reed-Solomon decoding to recover the original data
        // This will succeed if corruption is within the recovery threshold
        self.encoder.decode(section.data())
    }

    /// Decodes an encoded length value back to a u32.
    ///
    /// This method decodes a Reed-Solomon encoded 4-byte length value.
    ///
    /// # Arguments
    ///
    /// * `section` - The EncodedSection containing the encoded length
    ///
    /// # Returns
    ///
    /// A Result containing the decoded u32 length or an error if decoding fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reed-Solomon decoding fails
    /// - Decoded data is less than 4 bytes (corruption)
    /// - Cannot convert bytes to u32 (severe corruption)
    ///
    /// # Security
    ///
    /// Length validation prevents buffer overflow attacks by ensuring we only
    /// read the specified number of bytes for each section.
    fn decode_length(&self, section: &EncodedSection) -> Result<u32> {
        // First decode the Reed-Solomon encoded data
        let decoded = self.decode_section(section)?;

        // Validate that we have at least 4 bytes for a u32
        ensure!(decoded.len() >= 4, "invalid length prefix size");

        // Convert the first 4 bytes from big-endian format to u32
        // Use try_into for safe array slicing with proper error handling
        decoded[..4].try_into().map(u32::from_be_bytes).map_err(|_| anyhow!("length conversion failed"))
    }

    /// Reads and decodes all encoded length sections from the stream.
    ///
    /// This method reads the Reed-Solomon encoded length sections in order
    /// and decodes them back to their original u32 values.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Any type implementing the Read trait
    ///
    /// # Arguments
    ///
    /// * `reader` - Mutable reference to the readable source
    /// * `header` - The LengthsHeader containing the sizes of encoded length sections
    ///
    /// # Returns
    ///
    /// A Result containing a 5-element array of decoded lengths or an error if reading fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot read any of the encoded length sections
    /// - Reed-Solomon decoding fails for any length section
    /// - Cannot convert the resulting vector to a fixed-size array (programming error)
    ///
    /// # Performance
    ///
    /// Reads exactly the number of bytes specified in the LengthsHeader and
    /// performs 5 Reed-Solomon decodings, one for each section length.
    fn read_and_decode_lengths<R: Read>(&self, reader: &mut R, header: &LengthsHeader) -> Result<[u32; 5]> {
        // Get the array of encoded length section sizes
        let lengths_array = header.as_array();

        // Create a vector to store the decoded length values
        let mut decoded_lengths = Vec::with_capacity(5);

        // Process each length section individually for clarity
        // Using enumerate to avoid the clippy warning about needless range loops
        for (i, &size) in lengths_array.iter().enumerate() {
            // Read the exact number of bytes for this encoded length section
            let encoded = self.read_exact(reader, size as usize, || format!("failed to read encoded length section {}", i))?;

            // Decode the Reed-Solomon encoded length back to u32
            let decoded_length = self.decode_length(&EncodedSection::new(encoded))?;

            // Add the decoded length to our results vector
            decoded_lengths.push(decoded_length);
        }

        // Convert the vector to a fixed-size array for return
        // This should always succeed since we ensure exactly 5 elements above
        let result_array: [u32; 5] = decoded_lengths.try_into().map_err(|_| anyhow!("failed to convert lengths vector to array"))?;

        Ok(result_array)
    }

    /// Reads and decodes all data sections using the decoded lengths.
    ///
    /// This method reads each data section in order, decodes them using Reed-Solomon,
    /// and validates the magic bytes to ensure format compatibility.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Any type implementing the Read trait
    ///
    /// # Arguments
    ///
    /// * `reader` - Mutable reference to the readable source
    /// * `section_lengths` - Array containing the lengths of each encoded data section
    ///
    /// # Returns
    ///
    /// A Result containing the fully decoded DecodedSections or an error if reading fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot read any of the encoded data sections
    /// - Reed-Solomon decoding fails for any section
    /// - Magic bytes don't match the expected format (incompatible file)
    ///
    /// # Security
    ///
    /// Magic byte verification is the first line of defense against processing
    /// malicious or incompatible file formats. This prevents potential vulnerabilities
    /// from attempting to decode files with different formats.
    ///
    /// # Performance
    ///
    /// Performs 5 Reed-Solomon decodings and reads all header data into memory.
    /// Total memory usage is proportional to the sum of all section sizes.
    fn read_and_decode_sections<R: Read>(&self, reader: &mut R, section_lengths: &[u32; 5]) -> Result<DecodedSections> {
        // Read and decode the magic bytes section first
        let magic = self.read_decoded_section(reader, section_lengths[0], "magic")?;

        // Verify magic bytes match expected format to ensure compatibility
        // This is a critical security check to prevent processing incompatible files
        ensure!(magic == MAGIC_BYTES.to_be_bytes(), "invalid magic bytes");

        // If magic bytes are valid, proceed to decode remaining sections
        Ok(DecodedSections {
            magic,
            // Salt section: contains cryptographic salt for key derivation
            salt: self.read_decoded_section(reader, section_lengths[1], "salt")?,
            // Header data section: contains encrypted encryption parameters
            header_data: self.read_decoded_section(reader, section_lengths[2], "header data")?,
            // Metadata section: optional user-defined data
            metadata: self.read_decoded_section(reader, section_lengths[3], "metadata")?,
            // MAC section: message authentication code for integrity verification
            mac: self.read_decoded_section(reader, section_lengths[4], "mac")?,
        })
    }

    /// Reads and decodes a single data section.
    ///
    /// This is a convenience method that combines reading the exact number of bytes
    /// and immediately decoding them using Reed-Solomon.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Any type implementing the Read trait
    ///
    /// # Arguments
    ///
    /// * `reader` - Mutable reference to the readable source
    /// * `size` - The size of the encoded section to read
    /// * `name` - Human-readable name for error reporting
    ///
    /// # Returns
    ///
    /// A Result containing the decoded raw data or an error if reading/decoding fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot read the specified number of bytes (EOF or IO error)
    /// - Reed-Solomon decoding fails (excessive corruption)
    ///
    /// # Security
    ///
    /// The size parameter must be trusted and validated through the LengthsHeader
    /// to prevent reading arbitrary amounts of data from the stream.
    fn read_decoded_section<R: Read>(&self, reader: &mut R, size: u32, name: &str) -> Result<Vec<u8>> {
        // Read the exact number of bytes specified for this section
        let encoded_data = self.read_exact(reader, size as usize, || format!("failed to read encoded {}", name))?;

        // Immediately decode the Reed-Solomon encoded data
        self.decode_section(&EncodedSection::new(encoded_data))
    }

    /// Reads exactly the specified number of bytes from the reader.
    ///
    /// This is a utility method that ensures all requested bytes are read,
    /// providing better error messages than the standard read_exact.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Any type implementing the Read trait
    /// * `F` - A closure that generates error context (FnOnce() -> String)
    ///
    /// # Arguments
    ///
    /// * `reader` - Mutable reference to the readable source
    /// * `size` - Exact number of bytes to read
    /// * `context_fn` - Closure that generates context for error reporting
    ///
    /// # Returns
    ///
    /// A Result containing the read bytes or an error if reading fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The stream ends before reading all bytes (EOF)
    /// - An IO error occurs during reading
    ///
    /// # Security
    ///
    /// This method validates that exactly the expected number of bytes are read,
    /// preventing partial reads that could lead to data corruption or security issues.
    ///
    /// # Performance
    ///
    /// Allocates exactly the required number of bytes and performs a single read operation.
    /// Memory allocation is O(n) where n is the requested size.
    fn read_exact<R: Read, F>(&self, reader: &mut R, size: usize, context_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce() -> String,
    {
        // Allocate a buffer of the exact required size
        let mut buffer = vec![0u8; size];

        // Read exactly the requested number of bytes, providing context on failure
        // The context_fn closure allows for specific error messages for each call site
        reader.read_exact(&mut buffer).with_context(context_fn)?;

        Ok(buffer)
    }
}
