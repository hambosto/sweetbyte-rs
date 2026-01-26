//! Cryptographic parameter definitions.
//!
//! This module defines the `Parameters` struct, which specifies the algorithms
//! and configuration used to encrypt the file. This ensures forward compatibility
//! and allows the decryption process to adapt to different settings.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

use crate::config::{ALGORITHM_AES_256_GCM, ALGORITHM_CHACHA20_POLY1305, COMPRESSION_ZLIB, CURRENT_VERSION, ENCODING_REED_SOLOMON, KDF_ARGON2};

/// Configuration parameters for file encryption.
///
/// This struct acts as a manifest for the cryptographic pipeline, detailing:
/// - File format version
/// - Encryption algorithms used
/// - Key derivation settings (Argon2 params)
/// - Compression and encoding settings
#[derive(Debug, Clone, Copy, Serialize, Deserialize, SchemaRead, SchemaWrite)]
pub struct Parameters {
    /// The file format version (e.g., 2).
    pub version: u16,

    /// Bitmask of used encryption algorithms.
    /// Typically `AES_256_GCM | CHACHA20_POLY1305`.
    pub algorithm: u8,

    /// Compression algorithm identifier.
    pub compression: u8,

    /// Error correction encoding identifier.
    pub encoding: u8,

    /// Key Derivation Function identifier.
    pub kdf: u8,

    /// Argon2id memory cost in KiB.
    pub kdf_memory: u32,

    /// Argon2id time cost (passes).
    pub kdf_time: u8,

    /// Argon2id parallelism (threads).
    pub kdf_parallelism: u8,
}

impl Parameters {
    /// Validates the parameters against supported values.
    ///
    /// # Errors
    ///
    /// Returns an error if any parameter specifies an unsupported algorithm,
    /// version, or invalid configuration.
    pub fn validate(&self) -> Result<()> {
        // Check version compatibility.
        // Currently only CURRENT_VERSION is supported.
        ensure!(self.version == CURRENT_VERSION, "unsupported version");

        // Verify that the algorithm bitmask matches our dual-cipher standard.
        // We enforce both bits to be set because the current architecture always layers them.
        ensure!(self.algorithm == (ALGORITHM_AES_256_GCM | ALGORITHM_CHACHA20_POLY1305), "invalid algorithm");

        // Verify compression method.
        ensure!(self.compression == COMPRESSION_ZLIB, "invalid compression");

        // Verify encoding method.
        ensure!(self.encoding == ENCODING_REED_SOLOMON, "invalid encoding");

        // Verify KDF method.
        ensure!(self.kdf == KDF_ARGON2, "invalid kdf");

        Ok(())
    }
}
