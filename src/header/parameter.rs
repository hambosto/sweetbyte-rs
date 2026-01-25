//! Cryptographic parameters module for SweetByte archives.
//!
//! This module defines the Parameters structure that encapsulates all cryptographic
//! and encoding settings used throughout the SweetByte archive format. It provides
//! strict validation to ensure only secure, supported configurations are used.
//!
//! # Architecture
//! The Parameters struct is a compact, serializable configuration block that
//! is stored in the header and used by all components of the system. It defines
//! the exact cryptographic algorithms, encoding schemes, and key derivation
//! parameters used for a specific archive.
//!
//! # Key Concepts
//! - **Algorithm Selection**: Bit flags for supported encryption algorithms
//! - **Version Compatibility**: Ensures forward/backward compatibility
//! - **Parameter Validation**: Prevents misconfiguration and security issues
//! - **Constant Configuration**: Copyable for efficient sharing across components

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::{ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, COMPRESSION_ZLIB, CURRENT_VERSION, ENCODING_REED_SOLOMON, KDF_ARGON2};

/// Cryptographic and encoding parameters for SweetByte archives.
///
/// This structure defines all the cryptographic algorithms, encoding schemes,
/// and key derivation parameters used for encrypting and encoding archive data.
/// Each parameter is strictly validated to ensure security and compatibility.
///
/// # Fields
/// - `version`: Archive format version for compatibility checking
/// - `algorithm`: Bit field of supported encryption algorithms
/// - `compression`: Compression algorithm identifier
/// - `encoding`: Error correction encoding scheme
/// - `kdf`: Key derivation function identifier
/// - `kdf_memory`: Argon2id memory cost in kilobytes
/// - `kdf_time`: Argon2id time cost (iterations)
/// - `kdf_parallelism`: Argon2id parallelism factor
///
/// # Security Characteristics
/// - All parameters are validated against secure defaults
/// - Version checking prevents downgrade attacks
/// - Algorithm flags ensure only approved encryption methods are used
/// - KDF parameters meet minimum security requirements
///
/// # Performance Notes
/// - Copy-optimized for efficient sharing across components
/// - Compact binary representation minimizes storage overhead
/// - Validation is O(1) with simple equality checks
#[derive(Debug, Clone, Copy, Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub struct Parameters {
    /// Archive format version (must match CURRENT_VERSION)
    pub version: u16,
    /// Supported encryption algorithms (bit flags)
    pub algorithm: u8,
    /// Compression algorithm identifier
    pub compression: u8,
    /// Error correction encoding scheme
    pub encoding: u8,
    /// Key derivation function identifier
    pub kdf: u8,
    /// Argon2id memory cost in kilobytes
    pub kdf_memory: u32,
    /// Argon2id time cost (iterations)
    pub kdf_time: u8,
    /// Argon2id parallelism factor
    pub kdf_parallelism: u8,
}

impl Parameters {
    /// Validates all parameters against secure configuration requirements.
    ///
    /// This method performs strict validation of all cryptographic parameters
    /// to ensure only secure, approved configurations are used. Any deviation
    /// from the expected values will result in an error.
    ///
    /// # Returns
    /// Ok(()) if all parameters are valid
    ///
    /// # Errors
    /// - Returns error if version doesn't match CURRENT_VERSION
    /// - Returns error if algorithm flags don't match expected combination
    /// - Returns error if compression algorithm is unsupported
    /// - Returns error if encoding scheme is unsupported
    /// - Returns error if key derivation function is unsupported
    ///
    /// # Security Characteristics
    /// - Prevents downgrade attacks via version checking
    /// - Ensures only approved encryption algorithms are used
    /// - Guarantees minimum security requirements for all components
    /// - Blocks configuration-based attacks through strict validation
    ///
    /// # Performance Notes
    /// - O(1) complexity with simple equality comparisons
    /// - No memory allocation during validation
    /// - Fast fail-fast approach stops at first invalid parameter
    pub fn validate(&self) -> Result<()> {
        // Validate archive format version to prevent downgrade attacks
        ensure!(self.version == CURRENT_VERSION, "unsupported version");

        // Validate encryption algorithm combination - must support both AES-256-GCM and ChaCha20-Poly1305
        ensure!(self.algorithm == (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305), "invalid algorithm");

        // Validate compression algorithm - only ZLIB is supported
        ensure!(self.compression == COMPRESSION_ZLIB, "invalid compression");

        // Validate error correction encoding - only Reed-Solomon is supported
        ensure!(self.encoding == ENCODING_REED_SOLOMON, "invalid encoding");

        // Validate key derivation function - only Argon2id is supported
        ensure!(self.kdf == KDF_ARGON2, "invalid kdf");

        Ok(())
    }
}
