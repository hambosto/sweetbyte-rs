//! # Cryptographic Operations Module
//!
//! This module provides the core cryptographic functionality for the SweetByte file encryption system.
//! It implements authenticated encryption using industry-standard algorithms and secure key derivation.
//!
//! ## Architecture
//!
//! The cipher module follows a layered architecture:
//! - **Algorithm Layer**: Provides type-level algorithm selection (AES-256-GCM, XChaCha20-Poly1305)
//! - **Implementation Layer**: Concrete implementations of each cipher
//! - **Abstraction Layer**: Unified interface through the `Cipher` struct and `CipherAlgorithm` trait
//! - **Support Layer**: Key derivation, hashing, and MAC computation utilities
//!
//! ## Key Concepts
//!
//! - **Authenticated Encryption**: All ciphers provide both confidentiality and authenticity
//! - **Nonce Management**: Each encryption operation generates a cryptographically secure random nonce
//! - **Key Splitting**: The master key is split between AES and ChaCha20 for dual encryption
//! - **Constant-Time Operations**: Security-sensitive comparisons use constant-time algorithms
//!
//! ## Security Guarantees
//!
//! - AES-256-GCM: IND-CCA2 secure, 128-bit authentication tags
//! - XChaCha20-Poly1305: IND-CCA2 secure, 192-bit nonces for better collision resistance
//! - Argon2id: Memory-hard key derivation resistant to GPU/ASIC attacks
//! - BLAKE3: Fast, secure hashing with parallelization support

use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;
mod hash;
mod mac;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::Derive;
pub use hash::Hash;
pub use mac::Mac;

use crate::config::{ARGON_KEY_LEN, KEY_SIZE};

/// # Algorithm Selection Types
///
/// This module provides marker types for compile-time algorithm selection.
/// Using types instead of runtime strings enables zero-cost abstractions
/// and prevents algorithm confusion attacks.
pub mod algorithm {
    /// Marker type for AES-256-GCM algorithm selection
    ///
    /// AES-256-GCM provides:
    /// - 256-bit encryption key
    /// - 96-bit nonce (12 bytes)
    /// - 128-bit authentication tag
    /// - Hardware acceleration on modern CPUs (AES-NI)
    pub struct Aes256Gcm;
    /// Marker type for XChaCha20-Poly1305 algorithm selection
    ///
    /// XChaCha20-Poly1305 provides:
    /// - 256-bit encryption key
    /// - 192-bit extended nonce (24 bytes) for better collision resistance
    /// - 128-bit authentication tag
    /// - Better security guarantees when nonces are randomly generated
    pub struct XChaCha20Poly1305;
}

pub use algorithm::{Aes256Gcm, XChaCha20Poly1305};

/// # Cipher Algorithm Trait
///
/// This trait defines the interface for all cipher implementations.
/// It enables generic programming over different cipher algorithms while
/// maintaining type safety and zero-cost abstractions.
///
/// # Type Parameters
///
/// The generic parameter `A` in implementations allows compile-time
/// algorithm selection through the marker types in the `algorithm` module.
pub trait CipherAlgorithm {
    /// Encrypts plaintext using the specified cipher algorithm
    ///
    /// # Arguments
    /// * `cipher` - The cipher instance containing the algorithm-specific context
    /// * `plaintext` - The data to encrypt, must not be empty
    ///
    /// # Returns
    /// Ciphertext with nonce prepended, suitable for storage/transmission
    ///
    /// # Errors
    /// Returns error if encryption fails due to:
    /// - Empty plaintext input
    /// - Cryptographic operation failures
    /// - Memory allocation errors
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts ciphertext using the specified cipher algorithm
    ///
    /// # Arguments
    /// * `cipher` - The cipher instance containing the algorithm-specific context
    /// * `ciphertext` - The encrypted data with nonce prepended
    ///
    /// # Returns
    /// The original plaintext if authentication succeeds
    ///
    /// # Errors
    /// Returns error if decryption fails due to:
    /// - Authentication tag verification failure (tampering detection)
    /// - Invalid nonce length
    /// - Cryptographic operation failures
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for algorithm::Aes256Gcm {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the AES-GCM implementation
        cipher.aes.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the AES-GCM implementation
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for algorithm::XChaCha20Poly1305 {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the ChaCha20-Poly1305 implementation
        cipher.chacha.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the ChaCha20-Poly1305 implementation
        cipher.chacha.decrypt(ciphertext)
    }
}

/// # Unified Cipher Interface
///
/// This struct provides a unified interface to both AES-256-GCM and XChaCha20-Poly1305
/// implementations. It manages key splitting and provides generic encryption/decryption
/// operations through the `CipherAlgorithm` trait.
///
/// The key splitting strategy divides the Argon2id-derived key into two 32-byte halves:
/// - First half: AES-256-GCM encryption key
/// - Second half: XChaCha20-Poly1305 encryption key
///
/// This dual-encryption approach provides defense-in-depth: if one algorithm
/// is compromised, data remains protected by the other.
pub struct Cipher {
    /// AES-256-GCM cipher instance with 256-bit key
    aes: AesGcm,
    /// XChaCha20-Poly1305 cipher instance with 256-bit key
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    /// Creates a new Cipher instance with dual algorithm support
    ///
    /// # Arguments
    /// * `key` - 64-byte master key derived from Argon2id, split evenly between algorithms
    ///
    /// # Returns
    /// Configured Cipher instance ready for encryption/decryption operations
    ///
    /// # Errors
    /// Returns error if:
    /// - Key length validation fails (should never happen with proper Argon2id configuration)
    /// - Sub-cipher initialization fails
    ///
    /// # Security Notes
    /// - The key is split exactly in half: 32 bytes for AES, 32 bytes for ChaCha20
    /// - Both sub-ciphers are initialized with their respective key portions
    /// - No key material is copied unnecessarily to minimize exposure in memory
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        // Split the 64-byte master key into two 32-byte sub-keys
        // This provides defense-in-depth: compromise of one algorithm doesn't compromise data
        let split_key = key.split_at(KEY_SIZE);
        // Convert the first half to AES-256 key (32 bytes)
        let aes_key: &[u8; KEY_SIZE] = split_key.0.try_into().context("invalid AES key length")?;
        // Convert the second half to ChaCha20 key (32 bytes)
        let chacha_key: &[u8; KEY_SIZE] = split_key.1.try_into().context("invalid ChaCha key length")?;

        // Initialize both cipher instances with their respective keys
        Ok(Self { aes: AesGcm::new(aes_key)?, chacha: ChaCha20Poly1305::new(chacha_key)? })
    }

    /// Encrypts plaintext using the specified algorithm
    ///
    /// This is a generic method that allows compile-time algorithm selection
    /// through the type parameter. The actual encryption is performed by the
    /// specific algorithm implementation.
    ///
    /// # Type Parameters
    /// * `A` - The cipher algorithm to use (Aes256Gcm or XChaCha20Poly1305)
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt, must not be empty
    ///
    /// # Returns
    /// Ciphertext with nonce prepended in algorithm-specific format
    ///
    /// # Errors
    /// Propagates errors from the underlying cipher implementation
    ///
    /// # Performance
    /// - O(n) complexity where n is the plaintext length
    /// - AES-256-GCM: Hardware accelerated on CPUs with AES-NI
    /// - XChaCha20-Poly1305: Constant-time software implementation
    #[inline]
    pub fn encrypt<A: CipherAlgorithm>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        A::encrypt(self, plaintext)
    }

    /// Decrypts ciphertext using the specified algorithm
    ///
    /// This method performs authenticated decryption, automatically verifying
    /// the authentication tag before returning plaintext. Any modification
    /// to the ciphertext will cause decryption to fail.
    ///
    /// # Type Parameters
    /// * `A` - The cipher algorithm to use (Aes256Gcm or XChaCha20Poly1305)
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with nonce prepended
    ///
    /// # Returns
    /// Original plaintext if authentication succeeds
    ///
    /// # Errors
    /// Returns error if:
    /// - Authentication tag verification fails (detects tampering)
    /// - Ciphertext format is invalid
    /// - Underlying cryptographic operation fails
    ///
    /// # Security Guarantees
    /// - Constant-time authentication tag comparison prevents timing attacks
    /// - Authentication failures provide no information about the plaintext
    /// - Successful decryption guarantees ciphertext authenticity
    #[inline]
    pub fn decrypt<A: CipherAlgorithm>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        A::decrypt(self, ciphertext)
    }
}
