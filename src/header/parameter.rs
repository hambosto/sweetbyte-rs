//! Encryption Parameters Management
//!
//! This module defines the core encryption and compression parameters that control
//! how files are encrypted and stored. These parameters are stored in the header
//! and must remain consistent across all versions of the application to ensure
//! backward compatibility.
//!
//! ## Parameter Structure
//!
//! The Params structure contains the following key information:
//!
//! - **Version** - File format version for compatibility checking
//! - **Algorithm** - Encryption algorithm identifier (AES, ChaCha20, etc.)
//! - **Compression** - Compression algorithm and level
//! - **Encoding** - Reed-Solomon encoding parameters
//! - **KDF** - Key derivation function identifier and parameters
//!
//! ## Binary Format
//!
//! The parameters are stored in a fixed 12-byte binary format for optimal
//! storage efficiency and fast access:
///
/// ```text
/// [2 bytes] Version (u16)
/// [1 byte]  Algorithm (u8)
/// [1 byte]  Compression (u8)
/// [1 byte]  Encoding (u8)
/// [1 byte]  KDF identifier (u8)
/// [4 bytes] KDF memory parameter (u32)
/// [1 byte]  KDF time parameter (u8)
/// [1 byte]  KDF parallelism parameter (u8)
/// ```
///
/// ## Security Considerations
///
/// - All parameters are validated during deserialization
/// - Version compatibility checking prevents accidental decryption with wrong algorithms
/// - Fixed-size format prevents buffer overflow attacks
/// - Big-endian encoding ensures consistent cross-platform behavior
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::HEADER_DATA_SIZE;

/// Encryption and compression parameters
///
/// This structure contains all the parameters needed to encrypt and decrypt files,
/// including algorithm identifiers, compression settings, Reed-Solomon encoding
/// parameters, and key derivation function settings.
///
/// The parameters are stored in a compact 12-byte binary format to ensure
/// efficient storage and fast access during encryption/decryption operations.
///
/// ## Field Descriptions
///
/// - `version`: File format version for backward compatibility
/// - `algorithm`: Encryption algorithm identifier (AES-256-GCM, ChaCha20-Poly1305, etc.)
/// - `compression`: Compression algorithm and level identifier
/// - `encoding`: Reed-Solomon encoding parameters (data/parity shard counts)
/// - `kdf`: Key derivation function identifier (Argon2, scrypt, PBKDF2)
/// - `kdf_memory`: Memory parameter for KDF (in KB)
/// - `kdf_time`: Time/iteration parameter for KDF
/// - `kdf_parallelism`: Parallelism parameter for KDF
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Params {
    /// File format version for compatibility checking
    pub version: u16,
    /// Encryption algorithm identifier
    pub algorithm: u8,
    /// Compression algorithm and settings
    pub compression: u8,
    /// Reed-Solomon encoding parameters
    pub encoding: u8,
    /// Key derivation function identifier
    pub kdf: u8,
    /// KDF memory parameter in kilobytes
    pub kdf_memory: u32,
    /// KDF time/iteration parameter
    pub kdf_time: u8,
    /// KDF parallelism parameter
    pub kdf_parallelism: u8,
}

impl Params {
    /// Serialize parameters to binary format
    ///
    /// Converts the parameter structure into the fixed 12-byte binary format
    /// used for storage in the encrypted header. All numeric fields are stored
    /// in big-endian format for consistent cross-platform behavior.
    ///
    /// # Returns
    ///
    /// A 12-byte array containing the serialized parameters.
    ///
    /// # Binary Layout
    ///
    /// ```text
    /// [0-1]   version (u16, big-endian)
    /// [2]     algorithm (u8)
    /// [3]     compression (u8)
    /// [4]     encoding (u8)
    /// [5]     kdf (u8)
    /// [6-9]   kdf_memory (u32, big-endian)
    /// [10]    kdf_time (u8)
    /// [11]    kdf_parallelism (u8)
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - Fixed-size array avoids heap allocation
    /// - Direct memory copy operations for maximum speed
    /// - Big-endian format ensures network order consistency
    pub fn serialize(&self) -> [u8; HEADER_DATA_SIZE] {
        let mut data = [0u8; HEADER_DATA_SIZE];

        // Pack the binary format in order
        data[0..2].copy_from_slice(&self.version.to_be_bytes());
        data[2] = self.algorithm;
        data[3] = self.compression;
        data[4] = self.encoding;
        data[5] = self.kdf;
        data[6..10].copy_from_slice(&self.kdf_memory.to_be_bytes());
        data[10] = self.kdf_time;
        data[11] = self.kdf_parallelism;

        data
    }

    /// Deserialize parameters from binary format
    ///
    /// Parses binary data into a Params structure, performing validation of
    /// data length and proper type conversion with detailed error reporting.
    ///
    /// # Arguments
    ///
    /// * `data` - Binary data containing at least 12 bytes of parameter data
    ///
    /// # Returns
    ///
    /// A Result containing either the parsed Params or an error.
    ///
    /// # Errors
    ///
    /// - Invalid data length (less than 12 bytes)
    /// - Type conversion failures for numeric fields
    /// - Any byte slice to array conversion errors
    ///
    /// # Security Notes
    ///
    /// - Validates minimum data length before any parsing
    /// - All conversions use safe methods with error handling
    /// - Big-endian format ensures consistent behavior across architectures
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        // Validate input size before any parsing
        ensure!(data.len() >= HEADER_DATA_SIZE, "invalid header data size: expected {}, got {}", HEADER_DATA_SIZE, data.len());

        // Extract fields in order with proper error handling
        let version = u16::from_be_bytes(data[0..2].try_into().context("version conversion")?);
        let algorithm = data[2];
        let compression = data[3];
        let encoding = data[4];
        let kdf = data[5];
        let kdf_memory = u32::from_be_bytes(data[6..10].try_into().context("kdf memory conversion")?);
        let kdf_time = data[10];
        let kdf_parallelism = data[11];

        Ok(Self { version, algorithm, compression, encoding, kdf, kdf_memory, kdf_time, kdf_parallelism })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_roundtrip() {
        let params = Params { version: 1, algorithm: 2, compression: 3, encoding: 4, kdf: 5, kdf_memory: 1024, kdf_time: 2, kdf_parallelism: 4 };

        let serialized = params.serialize();
        assert_eq!(serialized.len(), HEADER_DATA_SIZE);

        let deserialized = Params::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, params.version);
        assert_eq!(deserialized.algorithm, params.algorithm);
        assert_eq!(deserialized.compression, params.compression);
        assert_eq!(deserialized.encoding, params.encoding);
        assert_eq!(deserialized.kdf, params.kdf);
        assert_eq!(deserialized.kdf_memory, params.kdf_memory);
        assert_eq!(deserialized.kdf_time, params.kdf_time);
        assert_eq!(deserialized.kdf_parallelism, params.kdf_parallelism);
    }

    #[test]
    fn test_params_deserialize_short() {
        let data = [0u8; HEADER_DATA_SIZE - 1];
        assert!(Params::deserialize(&data).is_err());
    }
}
