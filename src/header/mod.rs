//! # File Header Management Module
//!
//! This module provides comprehensive header management for encrypted files.
//! Headers contain all metadata required to decrypt and verify file contents,
//! including encryption parameters, file metadata, and integrity protection.
//!
//! ## Architecture
//!
//! The header system follows a modular design:
//! - **Serialization**: Converts structured data to binary format with Reed-Solomon encoding
//! - **Deserialization**: Reconstructs structured data from binary format with error correction
//! - **Validation**: Ensures header integrity and authenticity using HMAC
//! - **Metadata**: Stores file information like name, size, and content hash
//!
//! ## Security Features
//!
//! - **Reed-Solomon Encoding**: Provides error correction for corrupted headers
//! - **HMAC Authentication**: Prevents tampering with header contents
//! - **Parameter Validation**: Ensures only supported algorithms are used
//! - **Magic Bytes**: File format identification and corruption detection
//!
//! ## Header Structure
//!
/// Each header consists of 5 sections, all Reed-Solomon encoded:
/// 1. Magic Bytes (4 bytes) - File format identifier
/// 2. Salt (16 bytes) - Argon2id key derivation salt
/// 3. Header Data (12 bytes) - Encryption and compression parameters
/// 4. Metadata (variable) - File name, size, and content hash
/// 5. MAC (32 bytes) - HMAC-SHA256 authentication tag
use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::cipher::Mac;
use crate::config::{
    ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, COMPRESSION_ZLIB, CURRENT_VERSION, DATA_SHARDS, ENCODING_REED_SOLOMON, HASH_SIZE,
    HEADER_DATA_SIZE, KDF_ARGON2, MAC_SIZE, MAGIC_SIZE, PARITY_SHARDS,
};
use crate::header::deserializer::{Deserializer, ParsedData};
use crate::header::metadata::FileMetadata;
use crate::header::parameter::Params;
use crate::header::section::{SectionDecoder, SectionEncoder, SectionType, Sections};
use crate::header::serializer::{SerializeParameter, Serializer};

pub mod deserializer;
pub mod metadata;
pub mod parameter;
pub mod section;
pub mod serializer;

/// # File Header Management
///
/// Main struct for managing encrypted file headers. Provides both creation
/// of new headers for encryption and parsing of existing headers for decryption.
///
/// Headers contain all the information needed to decrypt and verify file contents,
/// protected by Reed-Solomon encoding for error correction and HMAC for authenticity.
///
/// ## Security Considerations
///
/// - Headers are authenticated with HMAC to prevent tampering
/// - Reed-Solomon encoding provides resilience against corruption
/// - All parameters are validated against supported values
/// - File metadata integrity is verified using BLAKE3 hashes
///
/// ## Memory Layout
///
/// Serialized headers follow this structure:
/// ```
/// [Lengths Header (20 bytes)]                    // Length of each encoded section
/// [Encoded Section Lengths (variable)]          // Reed-Solomon encoded length data
/// [Encoded Sections (variable)]                  // Reed-Solomon encoded section data
/// ```
///
/// Each encoded section can be recovered even if partially corrupted,
/// providing robustness against storage or transmission errors.
pub struct Header {
    /// Reed-Solomon encoder for protecting header sections
    /// Used when serializing new headers for storage
    encoder: SectionEncoder,

    /// Encryption and processing parameters
    /// Includes algorithm selection, compression, encoding, and KDF settings
    params: Params,

    /// File metadata information
    /// Contains original filename, file size, and BLAKE3 content hash
    metadata: FileMetadata,

    /// Parsed sections from deserialized headers
    /// None for newly created headers, Some for parsed headers
    sections: Option<Sections>,
}

impl Header {
    /// Creates a new header with default parameters
    ///
    /// Creates a header for encryption using system-configured default parameters.
    /// This is the recommended constructor for most use cases.
    ///
    /// # Arguments
    /// * `metadata` - File metadata including name, size, and content hash
    ///
    /// # Returns
    /// Configured Header instance ready for serialization
    ///
    /// # Errors
    /// Returns error if Reed-Solomon encoder initialization fails
    ///
    /// # Default Parameters
    /// - Dual encryption: AES-256-GCM + XChaCha20-Poly1305
    /// - Compression: ZLIB (for space efficiency)
    /// - Encoding: Reed-Solomon (for error correction)
    /// - KDF: Argon2id with system defaults
    pub fn new(metadata: FileMetadata) -> Result<Self> {
        // Initialize Reed-Solomon encoder with configured shard counts
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Create default parameters using system configuration
        let parameter = Params {
            version: CURRENT_VERSION,
            algorithm: ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305,
            compression: COMPRESSION_ZLIB,
            encoding: ENCODING_REED_SOLOMON,
            kdf: KDF_ARGON2,
            kdf_memory: ARGON_MEMORY,
            kdf_time: ARGON_TIME as u8,
            kdf_parallelism: ARGON_THREADS as u8,
        };

        Self::new_with_parameter(encoder, parameter, metadata)
    }

    /// Creates a new header with custom parameters
    ///
    /// Creates a header for encryption using explicitly provided parameters.
    /// Useful for testing or custom configuration scenarios.
    ///
    /// # Arguments
    /// * `encoder` - Reed-Solomon encoder for error correction
    /// * `params` - Custom encryption and processing parameters
    /// * `metadata` - File metadata including name, size, and content hash
    ///
    /// # Returns
    /// Configured Header instance with custom parameters
    ///
    /// # Errors
    /// Returns error if:
    /// - Parameters validation fails (unsupported algorithms)
    /// - File size is zero (invalid for encryption)
    pub fn new_with_parameter(encoder: SectionEncoder, params: Params, metadata: FileMetadata) -> Result<Self> {
        // Validate parameters to ensure compatibility
        Self::validate(&params)?;
        // Ensure we're not encrypting empty files
        ensure!(metadata.size() != 0, "file size cannot be zero");

        Ok(Self {
            encoder,
            params,
            metadata,
            sections: None, // No sections for newly created headers
        })
    }

    /// Deserializes a header from binary data
    ///
    /// Parses a previously serialized header from a readable source.
    /// Automatically performs Reed-Solomon decoding and parameter validation.
    ///
    /// # Type Parameters
    /// * `R` - Any type implementing Read (file, network stream, memory buffer)
    ///
    /// # Arguments
    /// * `reader` - Source containing serialized header data
    ///
    /// # Returns
    /// Parsed Header instance with all sections reconstructed
    ///
    /// # Errors
    /// Returns error if:
    /// - Reed-Solomon decoding fails (severe corruption)
    /// - Required sections are missing
    /// - Parameter validation fails
    /// - File metadata is invalid
    ///
    /// # Security Notes
    /// - All sections are authenticated during deserialization
    /// - Reed-Solomon provides error correction for minor corruption
    /// - Parameters are validated against supported algorithms
    /// - Magic bytes verify correct file format
    pub fn deserialize<R: Read>(reader: R) -> Result<Self> {
        // Initialize both encoder and decoder with same Reed-Solomon parameters
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        let decoder = SectionDecoder::new(DATA_SHARDS, PARITY_SHARDS)?;
        // Create deserializer and parse the header data
        let deserializer = Deserializer::new(&decoder);
        let parsed = deserializer.deserialize(reader)?;
        // Reconstruct Header instance from parsed data
        Self::from_parsed_data(parsed, encoder)
    }

    /// Returns the original filename
    ///
    /// # Returns
    /// Reference to the filename string from metadata
    ///
    /// # Security Notes
    /// - Filenames are not encrypted and may contain sensitive information
    /// - Consider filename encryption for privacy-sensitive applications
    #[inline]
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    /// Returns the original file size in bytes
    ///
    /// # Returns
    /// File size as a 64-bit unsigned integer
    ///
    /// # Notes
    /// - Used for memory allocation and progress tracking
    /// - Helps detect truncated or padded files during decryption
    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    /// Returns the BLAKE3 hash of the original file content
    ///
    /// # Returns
    /// Reference to the 32-byte BLAKE3 hash digest
    ///
    /// # Security Guarantees
    /// - Used to verify file integrity after decryption
    /// - Detects any corruption or tampering with encrypted content
    /// - Constant-time comparison prevents timing attacks during verification
    #[inline]
    #[must_use]
    pub fn file_hash(&self) -> &[u8; HASH_SIZE] {
        self.metadata.hash()
    }

    /// Returns the Argon2id memory cost parameter
    ///
    /// # Returns
    /// Memory cost in KiB (e.g., 65536 = 64MB)
    ///
    /// # Notes
    /// - Higher values increase resistance to GPU/ASIC attacks
    /// - Should be tuned based on available system memory
    #[inline]
    #[must_use]
    pub const fn kdf_memory(&self) -> u32 {
        self.params.kdf_memory
    }

    /// Returns the Argon2id time cost parameter
    ///
    /// # Returns
    /// Number of iterations for key derivation
    ///
    /// # Notes
    /// - Higher values increase computation time for attackers
    /// - Should be balanced against user experience requirements
    #[inline]
    #[must_use]
    pub const fn kdf_time(&self) -> u8 {
        self.params.kdf_time
    }

    /// Returns the Argon2id parallelism parameter
    ///
    /// # Returns
    /// Number of threads to use for key derivation
    ///
    /// # Notes
    /// - Should typically match the number of CPU cores
    /// - Higher values may improve performance on multi-core systems
    #[inline]
    #[must_use]
    pub const fn kdf_parallelism(&self) -> u8 {
        self.params.kdf_parallelism
    }

    /// Returns the Argon2id salt from deserialized header
    ///
    /// # Returns
    /// Reference to the salt byte array
    ///
    /// # Errors
    /// Returns error if header was created (not deserialized)
    ///
    /// # Security Notes
    /// - Salt is not secret and can be stored alongside encrypted data
    /// - Each file should use a unique random salt
    /// - Salt length is validated to be exactly 16 bytes
    pub fn salt(&self) -> Result<&[u8]> {
        self.sections.as_ref().context("header not deserialized yet")?.get_with_min_len(SectionType::Salt, ARGON_SALT_LEN)
    }

    /// Serializes the header to binary format
    ///
    /// Creates a binary representation of the header with all sections
    /// Reed-Solomon encoded and authenticated with HMAC.
    ///
    /// # Arguments
    /// * `salt` - 16-byte Argon2id salt for key derivation
    /// * `key` - HMAC key for header authentication (derived from user password)
    ///
    /// # Returns
    /// Serialized header data suitable for storage or transmission
    ///
    /// # Errors
    /// Returns error if:
    /// - Salt length is invalid (not 16 bytes)
    /// - HMAC key is empty
    /// - Reed-Solomon encoding fails
    /// - MAC computation fails
    ///
    /// # Security Guarantees
    /// - All sections are authenticated with HMAC-SHA256
    /// - Reed-Solomon encoding provides error correction
    /// - Magic bytes identify the file format
    /// - Parameters are included to prevent tampering
    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Create serializer with the encoder
        let serializer = Serializer::new(&self.encoder);
        // Prepare parameters for serialization
        let serialize_params = SerializeParameter { params: self.params, metadata: &self.metadata, salt, key };
        // Perform serialization with Reed-Solomon encoding and HMAC authentication
        serializer.serialize(&serialize_params)
    }

    /// Verifies the header integrity and authenticity
    ///
    /// Validates that the header has not been tampered with by recomputing
    /// the HMAC and comparing it with the stored value.
    ///
    /// # Arguments
    /// * `key` - HMAC key for verification (same key used during serialization)
    ///
    /// # Returns
    /// Ok(()) if verification succeeds
    ///
    /// # Errors
    /// Returns error if:
    /// - Header was not deserialized (no sections to verify)
    /// - HMAC key is empty
    /// - Required sections are missing or too short
    /// - HMAC verification fails (indicates tampering)
    ///
    /// # Security Guarantees
    /// - Constant-time HMAC comparison prevents timing attacks
    /// - Any modification to header sections will be detected
    /// - Verification failure provides no information about the correct HMAC
    /// - Protects against malicious header modification attacks
    pub fn verify(&self, key: &[u8]) -> Result<()> {
        // Validate HMAC key
        ensure!(!key.is_empty(), "key cannot be empty");
        // Get sections (must be deserialized first)
        let sections = self.sections.as_ref().context("header not deserialized yet")?;
        // Extract all sections needed for HMAC verification
        let expected_mac = sections.get_with_min_len(SectionType::Mac, MAC_SIZE)?;
        let magic = sections.get_with_min_len(SectionType::Magic, MAGIC_SIZE)?;
        let salt = sections.get_with_min_len(SectionType::Salt, ARGON_SALT_LEN)?;
        let header_data = sections.get_with_min_len(SectionType::HeaderData, HEADER_DATA_SIZE)?;
        let metadata_bytes = self.metadata.serialize();

        // Verify HMAC covers all critical header sections
        Mac::new(key)?.verify(expected_mac, &[magic, salt, header_data, &metadata_bytes])
    }

    /// Creates a Header instance from parsed deserialization data
    ///
    /// Internal helper method used during header deserialization.
    ///
    /// # Arguments
    /// * `data` - Parsed header data from deserializer
    /// * `encoder` - Reed-Solomon encoder for future operations
    ///
    /// # Returns
    /// Configured Header instance with deserialized sections
    ///
    /// # Errors
    /// Returns error if:
    /// - Parameter validation fails
    /// - File size is zero (invalid)
    fn from_parsed_data(data: ParsedData, encoder: SectionEncoder) -> Result<Self> {
        // Copy parameters from parsed data
        let params = *data.params();
        // Validate the parsed parameters
        Self::validate(&params)?;
        // Ensure file size is reasonable
        ensure!(data.metadata().size() != 0, "file size cannot be zero");

        Ok(Self { encoder, params, metadata: data.metadata().clone(), sections: Some(data.into_sections()) })
    }

    /// Validates header parameters against supported values
    ///
    /// Ensures that all header parameters use supported algorithms
    /// and configurations to maintain compatibility and security.
    ///
    /// # Arguments
    /// * `params` - Parameters to validate
    ///
    /// # Returns
    /// Ok(()) if all parameters are valid
    ///
    /// # Errors
    /// Returns error if any parameter is invalid:
    /// - Unsupported version number
    /// - Invalid algorithm identifier
    /// - Unsupported compression method
    /// - Invalid encoding method
    /// - Unsupported key derivation function
    fn validate(params: &Params) -> Result<()> {
        // Validate version compatibility
        ensure!(params.version == CURRENT_VERSION, "unsupported version: {} (expected {})", params.version, CURRENT_VERSION);
        // Validate algorithm selection (must include both ciphers)
        ensure!(params.algorithm == (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305), "invalid algorithm identifier: {:#04x}", params.algorithm);
        // Validate compression method
        ensure!(params.compression == COMPRESSION_ZLIB, "invalid compression identifier: {:#04x}", params.compression);
        // Validate error correction method
        ensure!(params.encoding == ENCODING_REED_SOLOMON, "invalid encoding identifier: {:#04x}", params.encoding);
        // Validate key derivation function
        ensure!(params.kdf == KDF_ARGON2, "invalid kdf identifier: {:#04x}", params.kdf);

        Ok(())
    }
}
