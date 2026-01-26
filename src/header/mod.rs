//! Secure file header management.
//!
//! This module defines the structure and logic for the encrypted file header.
//! The header contains all necessary information to decrypt the file (except the password),
//! including:
//! - Cryptographic salt
//! - Algorithm parameters
//! - File metadata (filename, size, hash)
//! - Integrity check (HMAC)
//!
//! # Robustness
//!
//! The header is the single point of failure for an encrypted file. If the header is corrupted,
//! the entire file becomes unreadable. To prevent this, **every section of the header is
//! protected by Reed-Solomon erasure coding**. This allows the header to be recovered even
//! if significant portions are overwritten or corrupted.

use anyhow::{Context, Result, ensure};
use tokio::io::AsyncRead;

use crate::cipher::Mac;
use crate::config::{
    ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, COMPRESSION_ZLIB, CURRENT_VERSION, DATA_SHARDS, ENCODING_REED_SOLOMON, HASH_SIZE,
    KDF_ARGON2, MAGIC_BYTES, MAX_FILENAME_LENGTH, PARITY_SHARDS,
};
use crate::header::metadata::Metadata;
use crate::header::parameter::Parameters;
use crate::header::section::{DecodedSections, SectionShield};

pub mod metadata;
pub mod parameter;
pub mod section;

/// Represents the decrypted and parsed header of a SweetByte file.
#[derive(Debug)]
pub struct Header {
    /// The shield responsible for encoding/decoding header sections.
    shield: SectionShield,

    /// The cryptographic and format parameters.
    parameters: Parameters,

    /// The file metadata (name, size, hash).
    metadata: Metadata,

    /// The raw decoded sections (only present after deserialization).
    sections: Option<DecodedSections>,
}

impl Header {
    /// Creates a new Header for a fresh encryption operation.
    ///
    /// This initializes the header with default parameters (Argon2id, AES+ChaCha, etc.)
    /// and the provided file metadata.
    ///
    /// # Arguments
    ///
    /// * `metadata` - Metadata about the file being encrypted.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata is invalid (e.g., zero size).
    pub fn new(metadata: Metadata) -> Result<Self> {
        // Initialize the RS encoder shield with default shard counts.
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Set default parameters for new files.
        // We currently enforce the dual-cipher suite + Zlib + RS + Argon2.
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

        Self::new_with_parameter(shield, parameters, metadata)
    }

    /// Creates a new Header with custom parameters (internal use).
    ///
    /// # Errors
    ///
    /// Returns an error if parameters or metadata are invalid.
    pub fn new_with_parameter(shield: SectionShield, parameters: Parameters, metadata: Metadata) -> Result<Self> {
        // Validate the parameters structure to ensure no unsupported flags are set.
        parameters.validate()?;

        // Basic sanity check: zero-byte files are not supported by the pipeline.
        ensure!(metadata.size() != 0, "file size cannot be zero");

        Ok(Self { shield, parameters, metadata, sections: None })
    }

    /// Reads and deserializes a header from an async stream.
    ///
    /// This performs the full recovery process:
    /// 1. Reads the lengths header.
    /// 2. Reads and RS-decodes the section lengths.
    /// 3. Reads and RS-decodes the content sections.
    /// 4. Deserializes the parameters and metadata structs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The stream ends prematurely.
    /// - Reed-Solomon reconstruction fails (too much corruption).
    /// - Magic bytes don't match.
    /// - Deserialization of structs fails.
    pub async fn deserialize<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self> {
        // Initialize shield for decoding.
        let shield = SectionShield::new(DATA_SHARDS, PARITY_SHARDS)?;

        // Perform the heavy lifting: read and decode all sections from the stream.
        let sections = shield.unpack(&mut reader).await?;

        // Deserialize the parameters struct from the decoded bytes.
        let params: Parameters = wincode::deserialize(&sections.header_data)?;

        // Deserialize the metadata struct.
        let metadata: Metadata = wincode::deserialize(&sections.metadata)?;

        // Validate the loaded parameters.
        params.validate()?;

        // Validate metadata constraints.
        ensure!(metadata.size() != 0, "file size cannot be zero");
        ensure!(metadata.name().len() <= MAX_FILENAME_LENGTH, "filename too long");

        Ok(Self { shield, parameters: params, metadata, sections: Some(sections) })
    }

    /// Returns the original filename.
    #[inline]
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.metadata.name()
    }

    /// Returns the original file size in bytes.
    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.metadata.size()
    }

    /// Returns the BLAKE3 hash of the original content.
    #[inline]
    #[must_use]
    pub fn file_hash(&self) -> &[u8; HASH_SIZE] {
        self.metadata.hash()
    }

    /// Returns the Argon2 memory cost used for this file.
    #[inline]
    #[must_use]
    pub const fn kdf_memory(&self) -> u32 {
        self.parameters.kdf_memory
    }

    /// Returns the Argon2 time cost used for this file.
    #[inline]
    #[must_use]
    pub const fn kdf_time(&self) -> u8 {
        self.parameters.kdf_time
    }

    /// Returns the Argon2 parallelism factor used for this file.
    #[inline]
    #[must_use]
    pub const fn kdf_parallelism(&self) -> u8 {
        self.parameters.kdf_parallelism
    }

    /// Returns the raw salt bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if called on a newly created Header that hasn't been serialized yet
    /// (since salt is generated/provided during serialization or deserialization).
    /// Actually, for `deserialize`, `sections` is Some. For `new`, it's None.
    pub fn salt(&self) -> Result<&[u8]> {
        Ok(&self.sections.as_ref().context("header not deserialized yet")?.salt)
    }

    /// Serializes the header into a byte vector for writing to disk.
    ///
    /// # Arguments
    ///
    /// * `salt` - The random salt to include (must be `ARGON_SALT_LEN` bytes).
    /// * `key` - The derived master key used to compute the HMAC.
    ///
    /// # Returns
    ///
    /// The fully encoded header bytes.
    pub fn serialize(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        ensure!(salt.len() == ARGON_SALT_LEN, "invalid salt size");
        ensure!(!key.is_empty(), "key cannot be empty");

        // Convert magic constant to bytes.
        let magic = MAGIC_BYTES.to_be_bytes();

        // Serialize internal structs to bytes.
        let header_data = wincode::serialize(&self.parameters)?;
        let metadata_bytes = wincode::serialize(&self.metadata)?;

        // Compute HMAC over the critical sections: magic, salt, params, metadata.
        // This ensures that any tampering with these fields will be detected
        // before we attempt to parse them or derive keys.
        let mac = Mac::new(key)?.compute(&[&magic, salt, &header_data, &metadata_bytes])?;

        // Hand off to the shield to apply Reed-Solomon encoding and pack the final blob.
        self.shield.pack(&magic, salt, &header_data, &metadata_bytes, &mac)
    }

    /// Verifies the integrity of the header using the provided key.
    ///
    /// # Arguments
    ///
    /// * `key` - The derived master key.
    ///
    /// # Errors
    ///
    /// Returns an error if the computed MAC doesn't match the stored MAC.
    pub fn verify(&self, key: &[u8]) -> Result<()> {
        ensure!(!key.is_empty(), "key cannot be empty");

        // Retrieve the raw sections.
        let sections = self.sections.as_ref().context("header not deserialized yet")?;

        let expected_mac = &sections.mac;
        let magic = &sections.magic;
        let salt = &sections.salt;

        // Re-serialize structs to reproduce the byte stream used for MAC computation.
        // Ideally we would use the raw bytes from `sections` directly if we were sure
        // they matched `self.parameters`/`self.metadata` exactly (which they should).
        // Using serialize ensures we verify what is currently in memory.
        let header_data = wincode::serialize(&self.parameters)?;
        let metadata_bytes = wincode::serialize(&self.metadata)?;

        // Verify HMAC.
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
        // Should fail because salt is not stored in the struct until deserialize/serialize context
        assert!(header.salt().is_err());
    }

    #[tokio::test]
    async fn test_header_roundtrip_serialize_deserialize() {
        let metadata = valid_metadata();
        let header = Header::new(metadata).unwrap();

        let salt = [1u8; ARGON_SALT_LEN];
        let key = [2u8; KEY_SIZE];

        let serialized = header.serialize(&salt, &key).unwrap();

        let deserialized_header = Header::deserialize(&serialized[..]).await.unwrap();

        assert_eq!(deserialized_header.file_name(), "test.txt");
        assert_eq!(deserialized_header.file_size(), 1024);

        assert!(deserialized_header.verify(&key).is_ok());

        assert_eq!(deserialized_header.salt().unwrap(), &salt);
    }

    #[tokio::test]
    async fn test_header_verify_invalid_key() {
        let metadata = valid_metadata();
        let header = Header::new(metadata).unwrap();
        let salt = [1u8; ARGON_SALT_LEN];
        let key = [2u8; KEY_SIZE];

        let serialized = header.serialize(&salt, &key).unwrap();
        let deserialized_header = Header::deserialize(&serialized[..]).await.unwrap();

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
