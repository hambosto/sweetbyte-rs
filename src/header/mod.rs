//! Header module for the SweetByte encrypted archive format.
//!
//! This module implements the binary header format that precedes encrypted payload data in SweetByte archives.
//! The header contains metadata about the encrypted file, cryptographic parameters, and integrity verification data.
//!
//! # Architecture
//! The header is divided into several logical components:
//! - **Metadata**: File information (name, size, content hash)
//! - **Parameters**: Cryptographic and encoding configuration
//! - **Sections**: Binary layout and Reed-Solomon encoding/decoding
//!
//! The header follows a specific binary layout with Reed-Solomon error correction for resilience against corruption.
//! All sections are encoded separately and then combined with length prefixes for proper parsing.
//!
//! # Key Concepts
//! - **Reed-Solomon Encoding**: Forward error correction allows recovery from corrupted header data
//! - **MAC Verification**: Message Authentication Code ensures header integrity and authenticity
//! - **Parameter Validation**: Strict validation prevents configuration mismatches between encode/decode operations
//! - **Magic Bytes**: Fixed identifier to validate file format compatibility

use std::io::Read;

use anyhow::{Context, Result, ensure};

use crate::cipher::Mac;
use crate::config::{
    ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, COMPRESSION_ZLIB, CURRENT_VERSION, DATA_SHARDS, ENCODING_REED_SOLOMON, HASH_SIZE,
    KDF_ARGON2, MAGIC_BYTES, MAX_FILENAME_LENGTH, PARITY_SHARDS,
};
use crate::header::metadata::Metadata;
use crate::header::parameter::Parameters;
use crate::header::section::{DecodedSections, SectionDecoder, SectionEncoder};

pub mod metadata;
pub mod parameter;
pub mod section;

/// Main header structure for SweetByte encrypted archives.
///
/// This structure encapsulates all information needed to decrypt and verify a SweetByte archive.
/// It combines file metadata, cryptographic parameters, and the necessary encoding/decoding
/// infrastructure for header serialization and deserialization.
///
/// The header maintains an optional `DecodedSections` field that is populated only after
/// deserialization, containing the raw binary data needed for MAC verification operations.
#[derive(Debug)]
pub struct Header {
    /// Reed-Solomon encoder for header data during serialization
    encoder: SectionEncoder,
    /// Cryptographic and encoding parameters
    parameters: Parameters,
    /// File metadata (name, size, content hash)
    metadata: Metadata,
    /// Raw decoded sections (populated only after deserialization)
    sections: Option<DecodedSections>,
}

impl Header {
    /// Creates a new header with default cryptographic parameters.
    ///
    /// # Arguments
    /// * `metadata` - File metadata including name, size, and content hash
    ///
    /// # Returns
    /// A new Header instance with default parameters
    ///
    /// # Errors
    /// Returns error if Reed-Solomon encoder initialization fails
    ///
    /// # Security Notes
    /// Uses default cryptographic parameters which are considered secure:
    /// - Argon2id with configured memory and time cost
    /// - AES-256-GCM and ChaCha20-Poly1305 support
    /// - Reed-Solomon error correction with default shard configuration
    pub fn new(metadata: Metadata) -> Result<Self> {
        // Initialize Reed-Solomon encoder with data and parity shard configuration
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Create default parameter set with current version and cryptographic settings
        let parameters = Parameters {
            version: CURRENT_VERSION,
            algorithm: ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305,
            compression: COMPRESSION_ZLIB,
            encoding: ENCODING_REED_SOLOMON,
            kdf: KDF_ARGON2,
            kdf_memory: ARGON_MEMORY,
            kdf_time: ARGON_TIME as u8,
            kdf_parallelism: ARGON_THREADS as u8,
        };

        // Delegate to parameter-specific constructor
        Self::new_with_parameter(encoder, parameters, metadata)
    }

    /// Creates a new header with custom parameters and encoder.
    ///
    /// # Arguments
    /// * `encoder` - Pre-configured Reed-Solomon encoder
    /// * `parameters` - Custom cryptographic and encoding parameters
    /// * `metadata` - File metadata
    ///
    /// # Returns
    /// A new Header instance with the provided components
    ///
    /// # Errors
    /// - Returns error if parameter validation fails
    /// - Returns error if metadata size is zero (empty files not supported)
    ///
    /// # Security Considerations
    /// The parameter validation ensures only supported cryptographic algorithms
    /// and configurations are used, preventing configuration-based attacks.
    pub fn new_with_parameter(encoder: SectionEncoder, parameters: Parameters, metadata: Metadata) -> Result<Self> {
        // Validate cryptographic parameters to prevent misconfiguration
        parameters.validate()?;

        // Reject zero-size files as they don't make sense in the context of encrypted archives
        ensure!(metadata.size() != 0, "file size cannot be zero");

        // Construct header with validated components
        Ok(Self {
            encoder,
            parameters,
            metadata,
            sections: None, // No decoded sections available for new headers
        })
    }

    /// Deserializes a header from binary data.
    ///
    /// This method reads the complete header structure from the provided reader,
    /// applies Reed-Solomon error correction, validates all parameters, and reconstructs
    /// the Header instance with all decoded sections for later verification.
    ///
    /// # Arguments
    /// * `reader` - Readable source containing the serialized header data
    ///
    /// # Returns
    /// A fully reconstructed Header with decoded sections
    ///
    /// # Errors
    /// - Returns error if Reed-Solomon decoder initialization fails
    /// - Returns error if header unpacking (decoding) fails
    /// - Returns error if parameter deserialization or validation fails
    /// - Returns error if metadata deserialization fails
    /// - Returns error if metadata validation (size, filename length) fails
    ///
    /// # Performance Characteristics
    /// - Reed-Solomon decoding: O(n) where n is header size
    /// - Binary deserialization: O(n) for both parameters and metadata
    /// - Memory allocation: O(n) for decoded sections storage
    ///
    /// # Security Notes
    /// Validates magic bytes and all cryptographic parameters to prevent
    /// malicious or corrupted headers from being processed.
    pub fn deserialize<R: Read>(mut reader: R) -> Result<Self> {
        // Initialize Reed-Solomon encoder for future serialization operations
        let encoder = SectionEncoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Initialize Reed-Solomon decoder for error correction during deserialization
        let decoder = SectionDecoder::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Unpack and decode all header sections with error correction
        let sections = decoder.unpack(&mut reader)?;

        // Deserialize cryptographic parameters from header section
        let params: Parameters = wincode::deserialize(&sections.header_data)?;

        // Deserialize file metadata from metadata section
        let metadata: Metadata = wincode::deserialize(&sections.metadata)?;

        // Validate parameters to ensure cryptographic correctness
        params.validate()?;

        // Validate metadata constraints
        ensure!(metadata.size() != 0, "file size cannot be zero");
        ensure!(metadata.name().len() <= MAX_FILENAME_LENGTH, "filename too long");

        // Return reconstructed header with all decoded sections for verification
        Ok(Self {
            encoder,
            parameters: params,
            metadata,
            sections: Some(sections), // Store decoded sections for MAC verification
        })
    }

    /// Returns the filename from the metadata.
    ///
    /// # Returns
    /// A string slice containing the filename (may be truncated if original exceeded MAX_FILENAME_LENGTH)
    #[inline]
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    /// Returns the original file size in bytes.
    ///
    /// # Returns
    /// The uncompressed file size
    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    /// Returns the BLAKE3 hash of the original file content.
    ///
    /// # Returns
    /// A 32-byte array containing the content hash for integrity verification
    #[inline]
    #[must_use]
    pub fn file_hash(&self) -> &[u8; HASH_SIZE] {
        self.metadata.hash()
    }

    /// Returns the Argon2id memory cost parameter.
    ///
    /// # Returns
    /// Memory cost in kilobytes for key derivation
    #[inline]
    #[must_use]
    pub const fn kdf_memory(&self) -> u32 {
        self.parameters.kdf_memory
    }

    /// Returns the Argon2id time cost parameter.
    ///
    /// # Returns
    /// Number of iterations for key derivation
    #[inline]
    #[must_use]
    pub const fn kdf_time(&self) -> u8 {
        self.parameters.kdf_time
    }

    /// Returns the Argon2id parallelism parameter.
    ///
    /// # Returns
    /// Number of parallel threads for key derivation
    #[inline]
    #[must_use]
    pub const fn kdf_parallelism(&self) -> u8 {
        self.parameters.kdf_parallelism
    }

    /// Returns the salt used for key derivation.
    ///
    /// # Returns
    /// A byte slice containing the Argon2id salt
    ///
    /// # Errors
    /// Returns error if called on a header that hasn't been deserialized yet
    ///
    /// # Security Notes
    /// The salt must be exactly ARGON_SALT_LEN bytes and should be randomly generated
    /// for each encryption operation to prevent rainbow table attacks.
    pub fn salt(&self) -> Result<&[u8]> {
        Ok(&self.sections.as_ref().context("header not deserialized yet")?.salt)
    }

    /// Serializes the header with Reed-Solomon encoding and MAC authentication.
    ///
    /// This method creates the complete binary header that precedes the encrypted payload.
    /// It combines magic bytes, salt, parameters, metadata, and a MAC, then applies
    /// Reed-Solomon error correction for resilience against data corruption.
    ///
    /// # Arguments
    /// * `salt` - Argon2id salt (must be exactly ARGON_SALT_LEN bytes)
    /// * `key` - Derivation key for MAC computation
    ///
    /// # Returns
    /// Serialized header bytes ready to be written to file
    ///
    /// # Errors
    /// - Returns error if salt size is incorrect
    /// - Returns error if key is empty
    /// - Returns error if MAC computation fails
    /// - Returns error if parameter serialization fails
    /// - Returns error if metadata serialization fails
    /// - Returns error if Reed-Solomon encoding fails
    ///
    /// # Security Characteristics
    /// - MAC authenticates all header components (magic, salt, params, metadata)
    /// - Uses constant-time comparison in MAC verification (via Mac implementation)
    /// - Reed-Solomon provides forward error correction without compromising security
    ///
    /// # Performance Notes
    /// - Reed-Solomon encoding: O(n) complexity with data+parity shards
    /// - MAC computation: O(n) over header components
    /// - Memory allocation: O(n) for final serialized output
    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Validate salt size matches Argon2id requirements
        ensure!(salt.len() == ARGON_SALT_LEN, "invalid salt size");

        // Ensure key is not empty for MAC computation
        ensure!(!key.is_empty(), "key cannot be empty");

        // Convert magic bytes to network byte order for consistent serialization
        let magic = MAGIC_BYTES.to_be_bytes();

        // Serialize cryptographic parameters with binary format
        let header_data = wincode::serialize(&self.parameters)?;

        // Serialize file metadata with binary format
        let metadata_bytes = wincode::serialize(&self.metadata)?;

        // Compute MAC over all header components for authentication
        // MAC covers magic bytes, salt, serialized parameters, and serialized metadata
        let mac = Mac::new(key)?.compute(&[&magic, salt, &header_data, &metadata_bytes])?;

        // Apply Reed-Solomon encoding to all sections and pack into final format
        self.encoder.pack(&magic, salt, &header_data, &metadata_bytes, &mac)
    }

    /// Verifies the MAC authentication of a deserialized header.
    ///
    /// This method recomputes the MAC over the header components and compares
    /// it with the stored MAC from the deserialized sections. This ensures
    /// the header hasn't been tampered with or corrupted.
    ///
    /// # Arguments
    /// * `key` - Derivation key used for MAC computation (must match the key used during serialization)
    ///
    /// # Returns
    /// Ok(()) if MAC verification succeeds
    ///
    /// # Errors
    /// - Returns error if key is empty
    /// - Returns error if header hasn't been deserialized yet
    /// - Returns error if MAC verification fails (tampering or corruption detected)
    /// - Returns error if parameter serialization fails during recomputation
    /// - Returns error if metadata serialization fails during recomputation
    ///
    /// # Security Characteristics
    /// - Uses constant-time comparison to prevent timing attacks
    /// - Verifies integrity of all header components
    /// - Prevents acceptance of tampered or malicious headers
    ///
    /// # Performance Notes
    /// - MAC recomputation: O(n) over header components
    /// - Comparison: O(n) constant-time for MAC verification
    pub fn verify(&self, key: &[u8]) -> Result<()> {
        // Ensure key is not empty for MAC computation
        ensure!(!key.is_empty(), "key cannot be empty");

        // Ensure we have decoded sections available (header must be deserialized)
        let sections = self.sections.as_ref().context("header not deserialized yet")?;

        // Extract stored MAC and header components from decoded sections
        let expected_mac = &sections.mac;
        let magic = &sections.magic;
        let salt = &sections.salt;

        // Reserialize parameters and metadata to exactly match the data used for original MAC
        let header_data = wincode::serialize(&self.parameters)?;
        let metadata_bytes = wincode::serialize(&self.metadata)?;

        // Verify MAC using constant-time comparison
        Mac::new(key)?.verify(expected_mac, &[magic, salt, &header_data, &metadata_bytes])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ARGON_SALT_LEN, KEY_SIZE};
    use crate::header::metadata::Metadata;

    fn valid_metadata() -> Metadata {
        Metadata::new("test.txt", 1024, [0u8; HASH_SIZE])
    }

    #[test]
    fn test_header_new_valid() {
        let metadata = valid_metadata();
        let header = Header::new(metadata);
        assert!(header.is_ok());
    }

    #[test]
    fn test_header_new_empty_file() {
        let metadata = Metadata::new("empty.txt", 0, [0u8; HASH_SIZE]);
        let header = Header::new(metadata);
        assert!(header.is_err());
        assert_eq!(header.unwrap_err().to_string(), "file size cannot be zero");
    }

    #[test]
    fn test_header_accessors() {
        let metadata = valid_metadata();
        let header = Header::new(metadata).unwrap();

        assert_eq!(header.file_name(), "test.txt");
        assert_eq!(header.file_size(), 1024);
        assert_eq!(header.file_hash(), &[0u8; HASH_SIZE]);
        assert_eq!(header.kdf_memory(), ARGON_MEMORY);
        assert_eq!(header.kdf_time(), ARGON_TIME as u8);
        assert_eq!(header.kdf_parallelism(), ARGON_THREADS as u8);
    }

    #[test]
    fn test_header_salt_access_before_deserialize() {
        let metadata = valid_metadata();
        let header = Header::new(metadata).unwrap();
        assert!(header.salt().is_err());
    }

    #[test]
    fn test_header_roundtrip_serialize_deserialize() {
        let metadata = valid_metadata();
        let header = Header::new(metadata).unwrap();

        let salt = [1u8; ARGON_SALT_LEN];
        let key = [2u8; KEY_SIZE];

        let serialized = header.serialize(&salt, &key).unwrap();

        let deserialized_header = Header::deserialize(&serialized[..]).unwrap();

        assert_eq!(deserialized_header.file_name(), "test.txt");
        assert_eq!(deserialized_header.file_size(), 1024);

        assert!(deserialized_header.verify(&key).is_ok());

        assert_eq!(deserialized_header.salt().unwrap(), &salt);
    }

    #[test]
    fn test_header_verify_invalid_key() {
        let metadata = valid_metadata();
        let header = Header::new(metadata).unwrap();
        let salt = [1u8; ARGON_SALT_LEN];
        let key = [2u8; KEY_SIZE];

        let serialized = header.serialize(&salt, &key).unwrap();
        let deserialized_header = Header::deserialize(&serialized[..]).unwrap();

        let wrong_key = [3u8; KEY_SIZE];
        assert!(deserialized_header.verify(&wrong_key).is_err());
    }

    #[test]
    fn test_validate_params() {
        let mut params = Parameters {
            version: CURRENT_VERSION,
            algorithm: ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305,
            compression: COMPRESSION_ZLIB,
            encoding: ENCODING_REED_SOLOMON,
            kdf: KDF_ARGON2,
            kdf_memory: ARGON_MEMORY,
            kdf_time: ARGON_TIME as u8,
            kdf_parallelism: ARGON_THREADS as u8,
        };

        assert!(params.validate().is_ok());

        params.version = 0;
        assert!(params.validate().is_err());
        params.version = CURRENT_VERSION;

        params.algorithm = 0;
        assert!(params.validate().is_err());
    }
}
