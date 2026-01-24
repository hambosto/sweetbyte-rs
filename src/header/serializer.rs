//! Reed-Solomon Header Serialization
//!
//! This module handles the complete serialization of encrypted file headers,
//! combining Reed-Solomon encoding with cryptographic authentication to create
//! robust, tamper-resistant file headers.
//!
//! ## Serialization Process
//!
//! The serializer orchestrates the complete header creation process:
//!
// 1. **Parameter Preparation** - Collect encryption parameters, metadata, salt, and key
// 2. **HMAC Calculation** - Compute MAC over all header components for integrity
// 3. **Section Encoding** - Apply Reed-Solomon encoding to all 5 sections
// 4. **Length Encoding** - Encode section sizes for proper reconstruction
// 5. **Binary Assembly** - Combine all components into the final binary format
//
// ## Binary Output Format
//
// The serialized header has the following structure:
//
// ```text
// [20 bytes]  Lengths Header (sizes of encoded length sections)
// [Variable]  Encoded Lengths (Reed-Solomon encoded section lengths)
// [Variable]  Encoded Sections (Reed-Solomon encoded section data)
// ```
//
// ## Security Model
//
// The header provides multiple layers of security:
//
// - **HMAC Authentication**: MAC ensures integrity of all header components
// - **Reed-Solomon Protection**: Error correction makes tampering more difficult
// - **Magic Byte Validation**: Prevents processing of incorrect file formats
// - **Parameter Validation**: All encryption parameters are validated before use
//
// ## Performance Characteristics
//
// - Reed-Solomon encoding is computationally intensive but provides significant robustness
// - Memory allocation is optimized by pre-calculating buffer requirements
// - The serializer validates all inputs before performing expensive operations
use anyhow::{Result, ensure};

use crate::cipher::Mac;
use crate::config::{ARGON_SALT_LEN, MAGIC_BYTES};
use crate::header::metadata::FileMetadata;
use crate::header::parameter::Params;
use crate::header::section::SectionEncoder;

/// Parameters for header serialization
///
/// This structure contains all the necessary components to create an
/// encrypted file header. The serializer uses these components to build
/// a Reed-Solomon protected, authenticated header.
///
/// All components are passed by reference (except Params) to minimize
/// memory allocation and copying during the serialization process.
///
/// ## Field Descriptions
///
/// - `params`: Encryption and compression parameters (copied, not borrowed)
/// - `metadata`: File information including name, size, and content hash
/// - `salt`: Cryptographic salt for key derivation (must be ARGON_SALT_LEN bytes)
/// - `key`: HMAC key for header authentication (must be non-empty)
///
/// ## Security Requirements
///
/// - Salt must be exactly 16 bytes for Argon2 key derivation
/// - Key must be cryptographically strong and non-empty for HMAC calculation
/// - All components are validated before serialization begins
pub struct SerializeParameter<'a> {
    /// Encryption parameters (owned, as these may be modified or copied)
    pub params: Params,
    /// File metadata (borrowed to avoid copying)
    pub metadata: &'a FileMetadata,
    /// Cryptographic salt for key derivation (borrowed, fixed size)
    pub salt: &'a [u8],
    /// HMAC key for authentication (borrowed, variable size)
    pub key: &'a [u8],
}

/// Reed-Solomon header serializer
///
/// This serializer creates complete encrypted file headers by combining
/// Reed-Solomon encoding with HMAC authentication. The resulting header
/// is both error-tolerant and cryptographically authenticated.
///
/// The serializer maintains a reference to a SectionEncoder for the
/// Reed-Solomon operations, allowing reuse of the encoder across
/// multiple serialization operations.
pub struct Serializer<'a> {
    /// Reed-Solomon encoder for section protection
    encoder: &'a SectionEncoder,
}

impl<'a> Serializer<'a> {
    /// Create a new serializer with the given Reed-Solomon encoder
    ///
    /// # Arguments
    ///
    /// * `encoder` - Reference to a SectionEncoder configured with appropriate
    ///   Reed-Solomon parameters for the desired level of error protection
    ///
    /// # Returns
    ///
    /// A new Serializer instance ready to process header components.
    #[inline]
    #[must_use]
    pub fn new(encoder: &'a SectionEncoder) -> Self {
        Self { encoder }
    }

    /// Serialize a complete header from the given parameters
    ///
    /// This method performs the complete header serialization process:
    ///
    /// 1. **Input Validation** - Verify salt size and key requirements
    /// 2. **Component Preparation** - Convert parameters to binary format
    /// 3. **HMAC Calculation** - Compute MAC over all header components
    /// 4. **Reed-Solomon Encoding** - Apply error correction to all sections
    /// 5. **Binary Assembly** - Combine into final header format
    ///
    /// # Arguments
    ///
    /// * `params` - All components needed for header creation
    ///
    /// # Returns
    ///
    /// Result containing either the serialized header or an error.
    ///
    /// # Errors
    ///
    /// - Invalid salt size (must be exactly ARGON_SALT_LEN bytes)
    /// - Empty HMAC key
    /// - HMAC computation failures
    /// - Reed-Solomon encoding failures
    ///
    /// # Security Validation
    ///
    /// - Validates salt size before any cryptographic operations
    /// - Ensures HMAC key is non-empty to prevent weak authentication
    /// - HMAC covers all header components for complete integrity protection
    /// - Reed-Solomon encoding provides additional tamper resistance
    ///
    /// # Process Details
    ///
    /// ```text
    /// 1. Validate salt (16 bytes) and key (non-empty)
    /// 2. Prepare sections: Magic, Salt, HeaderData, Metadata
    /// 3. Compute HMAC over: Magic + Salt + HeaderData + Metadata
    /// 4. Create 5 sections: Magic, Salt, HeaderData, Metadata, MAC
    /// 5. Reed-Solomon encode all sections and their lengths
    /// 6. Assemble: LengthsHeader + EncodedLengths + EncodedSections
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - HMAC computation is fast and provides cryptographic guarantees
    /// - Reed-Solomon encoding is the most expensive operation but provides
    ///   significant error recovery (up to 50% data corruption tolerance)
    /// - Memory allocation is minimized by using iterators and pre-calculated sizes
    /// - All validation happens before expensive operations to fail fast
    pub fn serialize(&self, params: &SerializeParameter<'_>) -> Result<Vec<u8>> {
        // Step 1: Validate all inputs before performing expensive operations
        ensure!(params.salt.len() == ARGON_SALT_LEN, "invalid salt size: expected {}, got {}", ARGON_SALT_LEN, params.salt.len());
        ensure!(!params.key.is_empty(), "key cannot be empty");

        // Step 2: Prepare individual header components in binary format
        let magic = MAGIC_BYTES.to_be_bytes(); // File format identifier
        let header_data = params.params.serialize(); // Encryption parameters
        let metadata_bytes = params.metadata.serialize(); // File information

        // Step 3: Compute HMAC over all header components for integrity protection
        // The MAC ensures any modification to the header will be detected
        let mac = Mac::new(params.key)?.compute(&[&magic, params.salt, &header_data, &metadata_bytes])?;

        // Step 4: Create the raw sections array for Reed-Solomon encoding
        let raw_sections: [&[u8]; 5] = [
            &magic,          // Section 0: Magic bytes (file format)
            params.salt,     // Section 1: Cryptographic salt
            &header_data,    // Section 2: Encryption parameters
            &metadata_bytes, // Section 3: File metadata
            &mac,            // Section 4: HMAC for integrity
        ];

        // Step 5: Apply Reed-Solomon encoding to protect all sections
        let (sections, length_sections) = self.encoder.encode_sections_and_lengths(&raw_sections)?;

        // Step 6: Build the lengths header (20 bytes, unencoded but section-protected)
        let lengths_header = SectionEncoder::build_lengths_header(&length_sections);

        // Step 7: Assemble the final binary header using iterators for efficiency
        let result: Vec<u8> = lengths_header
            .iter()
            .cloned()
            .chain(length_sections.iter().flat_map(|s| s.data().iter().cloned()))
            .chain(sections.iter().flat_map(|s| s.data().iter().cloned()))
            .collect();

        Ok(result)
    }
}
