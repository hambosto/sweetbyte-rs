//! Cryptographic primitives for encryption and key derivation.
//!
//! Provides dual-layer encryption using AES-256-GCM and XChaCha20-Poly1305
//! with password-based key derivation via Argon2id.
//!
//! # Encryption Layers
//!
//! 1. **AES-256-GCM**: Industry-standard authenticated encryption (32-byte key, 12-byte nonce)
//! 2. **XChaCha20-Poly1305**: Modern stream cipher with authentication (32-byte key, 24-byte nonce)
//!
//! The 64-byte derived key is split: first 32 bytes for AES, next 32 bytes for ChaCha.
//!
//! # Key Derivation
//!
//! Passwords are hardened using Argon2id with:
//! - Memory: 64 MB
//! - Iterations: 3
//! - Parallelism: 4 threads
//! - Output: 64 bytes

use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::Derive;

use crate::config::{AES_KEY_SIZE, ARGON_KEY_LEN, CHACHA_KEY_SIZE};

/// Marker types for cipher algorithms.
///
/// These are zero-sized types (structs with no fields) used as type parameters
/// to select which encryption algorithm to use at compile time. This enables
/// static dispatch for better performance compared to runtime trait objects.
///
/// The #[allow(non_snake_case)] attribute is needed because Rust conventions
/// expect module names to be lowercase, but we use CamelCase for readability.
#[allow(non_snake_case)]
pub mod Algorithm {

    /// Marker type for AES-256-GCM cipher algorithm.
    ///
    /// When used as a type parameter to Cipher::encrypt/decrypt, selects
    /// the AES-256-GCM implementation. This enables compile-time dispatch
    /// to the appropriate encryption method.
    pub struct Aes256Gcm;

    /// Marker type for XChaCha20-Poly1305 cipher algorithm.
    ///
    /// When used as a type parameter to Cipher::encrypt/decrypt, selects
    /// the XChaCha20-Poly1305 implementation.
    pub struct XChaCha20Poly1305;
}

/// Trait defining encryption/decryption operations for cipher algorithms.
///
/// Implementations of this trait delegate to the appropriate cipher instance
/// stored in the parent Cipher struct. This allows the Cipher struct to
/// provide a unified interface while internally using different algorithms.
///
/// # Design Pattern
///
/// This uses the Strategy pattern with type parameters:
/// - The Cipher struct holds both algorithm implementations
/// - The trait provides a common interface
/// - Type parameters select which algorithm to use
/// - No runtime branching overhead (static dispatch)
pub trait CipherAlgorithm {
    /// Encrypts plaintext using the specified algorithm.
    ///
    /// Takes a reference to the parent Cipher (which holds the actual cipher state)
    /// and the plaintext data. Returns the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `cipher` - Reference to the parent Cipher containing algorithm state.
    /// * `plaintext` - The plaintext data to encrypt.
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext, or an error if encryption fails.
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts ciphertext using the specified algorithm.
    ///
    /// Takes a reference to the parent Cipher and the ciphertext data.
    /// Returns the original plaintext. Authentication failure (wrong key
    /// or tampered data) returns an error.
    ///
    /// # Arguments
    ///
    /// * `cipher` - Reference to the parent Cipher containing algorithm state.
    /// * `ciphertext` - The encrypted data to decrypt.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext, or an error if decryption/authentication fails.
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for Algorithm::Aes256Gcm {
    /// Encrypts using AES-256-GCM.
    ///
    /// Delegates to the aes field of the Cipher struct.
    /// This is an inline function for optimal performance.
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Forward the call to the AES cipher instance
        // The cipher.aes field holds the AesGcm struct
        cipher.aes.encrypt(plaintext)
    }

    /// Decrypts using AES-256-GCM.
    ///
    /// Delegates to the aes field of the Cipher struct.
    /// Authentication is built into GCM mode - wrong key = auth failure.
    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for Algorithm::XChaCha20Poly1305 {
    /// Encrypts using XChaCha20-Poly1305.
    ///
    /// Delegates to the chacha field of the Cipher struct.
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.encrypt(plaintext)
    }

    /// Decrypts using XChaCha20-Poly1305.
    ///
    /// Delegates to the chacha field of the Cipher struct.
    /// Authentication is built into Poly1305 - wrong key = auth failure.
    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.decrypt(ciphertext)
    }
}

/// Combined cipher wrapping both AES-256-GCM and XChaCha20-Poly1305.
///
/// This struct provides a unified interface for layered encryption.
/// It holds instances of both cipher algorithms and allows selecting
/// which one to use via type parameters.
///
/// # Thread Safety
///
/// This struct is Clone + Send + Sync safe.
/// The underlying cipher implementations from the aes-gcm and
/// chacha20poly1305 crates are thread-safe.
pub struct Cipher {
    /// AES-256-GCM cipher instance for authenticated encryption.
    ///
    /// AES-256-GCM provides:
    /// - 256-bit key for strong encryption
    /// - 128-bit authentication tag
    /// - 96-bit nonce (12 bytes)
    aes: AesGcm,

    /// XChaCha20-Poly1305 cipher instance for authenticated encryption.
    ///
    /// XChaCha20-Poly1305 provides:
    /// - 256-bit key for strong encryption
    /// - Poly1305 authentication tag
    /// - 192-bit extended nonce (24 bytes) for higher throughput
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    /// Creates a new cipher from a 64-byte derived key.
    ///
    /// The 64-byte key is split into two 32-byte portions:
    /// - First 32 bytes (indices 0-31) → AES-256-GCM key
    /// - Next 32 bytes (indices 32-63) → XChaCha20-Poly1305 key
    ///
    /// This key separation ensures each cipher gets its own dedicated key
    /// material, following cryptographic best practices.
    ///
    /// # Arguments
    ///
    /// * `key` - A 64-byte array containing the derived key material.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key slice cannot be converted to the required array sizes
    /// - Either cipher fails to initialize
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        // Extract the AES-256-GCM key portion
        // key[..AES_KEY_SIZE] is a slice of bytes 0-31 (32 bytes)
        // try_into() attempts to convert to a fixed-size array
        // This will fail if the slice length doesn't match
        let aes_key: [u8; AES_KEY_SIZE] = key[..AES_KEY_SIZE].try_into().context("invalid aes-gcm key")?;

        // Extract the XChaCha20-Poly1305 key portion
        // key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE] is bytes 32-63
        // This is also a 32-byte slice for conversion
        let chacha_key: [u8; CHACHA_KEY_SIZE] = key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE].try_into().context("invalid chacha20poly1305 key")?;

        // Create both cipher instances
        // The ? operator propagates any initialization errors
        // AesGcm::new and ChaCha20Poly1305::new validate the key size
        // and initialize the cipher state
        Ok(Self { aes: AesGcm::new(&aes_key)?, chacha: ChaCha20Poly1305::new(&chacha_key)? })
    }

    /// Encrypts data using the specified algorithm.
    ///
    /// This is a generic method that uses type parameters to select
    /// which cipher algorithm to use. The type parameter A must
    /// implement the CipherAlgorithm trait.
    ///
    /// # Type Parameters
    ///
    /// * `A` - The cipher algorithm to use (Aes256Gcm or XChaCha20Poly1305).
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext with nonce prepended.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (should be rare with valid inputs).
    #[inline]
    pub fn encrypt<A: CipherAlgorithm>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Static dispatch to the appropriate algorithm
        // A::encrypt() is resolved at compile time based on type parameter
        A::encrypt(self, plaintext)
    }

    /// Decrypts data using the specified algorithm.
    ///
    /// This is a generic method that uses type parameters to select
    /// which cipher algorithm to use. The type parameter A must
    /// implement the CipherAlgorithm trait.
    ///
    /// # Type Parameters
    ///
    /// * `A` - The cipher algorithm to use (Aes256Gcm or XChaCha20Poly1305).
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data, including nonce prefix.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Ciphertext is too short to contain nonce
    /// - Authentication fails (wrong key or tampered data)
    #[inline]
    pub fn decrypt<A: CipherAlgorithm>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Static dispatch to the appropriate algorithm
        // A::decrypt() is resolved at compile time based on type parameter
        A::decrypt(self, ciphertext)
    }
}
