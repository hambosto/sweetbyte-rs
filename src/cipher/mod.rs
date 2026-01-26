//! Cryptographic primitives and unified cipher interface.
//!
//! This module provides the core cryptographic functionality, including:
//! - **Dual-Algorithm Support**: AES-256-GCM and XChaCha20-Poly1305.
//! - **Key Derivation**: Argon2id for password-based key derivation.
//! - **Hashing**: BLAKE3 for content integrity.
//! - **Message Authentication**: HMAC-SHA256 for header integrity.
//!
//! # Architecture
//!
//! The [`Cipher`] struct acts as a facade, holding initialized instances of both
//! AES-GCM and XChaCha20-Poly1305 engines. The specific algorithm to use is
//! selected at runtime (or compile time via generics) using the [`CipherAlgorithm`]
//! trait.

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

/// Marker types for supported encryption algorithms.
pub mod algorithm {
    /// Marker type for the AES-256-GCM algorithm.
    pub struct Aes256Gcm;
    /// Marker type for the XChaCha20-Poly1305 algorithm.
    pub struct XChaCha20Poly1305;
}

pub use algorithm::{Aes256Gcm, XChaCha20Poly1305};

/// A trait for dispatching encryption/decryption operations to the specific backend.
///
/// This trait allows the [`Cipher`] struct to be used generically, decoupling the
/// high-level API from the specific cryptographic implementation.
pub trait CipherAlgorithm {
    /// Encrypts the plaintext using the specified algorithm within the cipher instance.
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts the ciphertext using the specified algorithm within the cipher instance.
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for algorithm::Aes256Gcm {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the stored AES-GCM instance.
        // We use the inner implementation which handles nonce generation.
        cipher.aes.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the stored AES-GCM instance.
        // Expects the nonce to be prepended to the ciphertext.
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for algorithm::XChaCha20Poly1305 {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the stored XChaCha20-Poly1305 instance.
        // We use the inner implementation which handles extended nonce generation.
        cipher.chacha.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Delegate to the stored XChaCha20-Poly1305 instance.
        // Expects the extended nonce to be prepended to the ciphertext.
        cipher.chacha.decrypt(ciphertext)
    }
}

/// A unified container for all symmetric encryption contexts.
///
/// `Cipher` is initialized with a master key (derived from a password) and
/// splits it to initialize both AES-GCM and XChaCha20-Poly1305 contexts.
/// This allows the application to switch algorithms on the fly or use them
/// in combination without re-deriving keys.
///
/// # Examples
///
/// ```
/// use sweetbyte_rs::cipher::{Cipher, Aes256Gcm};
/// use sweetbyte_rs::config::ARGON_KEY_LEN;
///
/// # fn main() -> anyhow::Result<()> {
/// let key = [0u8; ARGON_KEY_LEN];
/// let cipher = Cipher::new(&key)?;
///
/// let plaintext = b"secret message";
/// let ciphertext = cipher.encrypt::<Aes256Gcm>(plaintext)?;
/// # Ok(())
/// # }
/// ```
pub struct Cipher {
    /// The initialized AES-256-GCM context.
    aes: AesGcm,
    /// The initialized XChaCha20-Poly1305 context.
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    /// Creates a new `Cipher` instance by splitting the master key.
    ///
    /// The provided master key (typically 64 bytes) is split into two halves:
    /// - First 32 bytes: AES-256 key
    /// - Second 32 bytes: XChaCha20 key
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be split or if context initialization fails.
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        // Split the 64-byte master key into two 32-byte chunks.
        // This allows independent keys for each algorithm, preventing
        // cross-algorithm key reuse vulnerabilities.
        let split_key = key.split_at(KEY_SIZE);

        // Convert the first slice to a fixed-size array for AES.
        // We use try_into() to enforce strict size checking at runtime.
        let aes_key: &[u8; KEY_SIZE] = split_key.0.try_into().context("invalid AES key length")?;

        // Convert the second slice to a fixed-size array for ChaCha.
        let chacha_key: &[u8; KEY_SIZE] = split_key.1.try_into().context("invalid ChaCha key length")?;

        // Initialize both cipher contexts.
        // Both are ready for use immediately after construction.
        Ok(Self { aes: AesGcm::new(aes_key)?, chacha: ChaCha20Poly1305::new(chacha_key)? })
    }

    /// Encrypts data using the specified algorithm `A`.
    ///
    /// This is a generic convenience method that delegates to [`CipherAlgorithm::encrypt`].
    #[inline]
    pub fn encrypt<A: CipherAlgorithm>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Dispatch to the trait implementation for the generic type A.
        // This uses static dispatch (monomorphization) for zero runtime overhead.
        A::encrypt(self, plaintext)
    }

    /// Decrypts data using the specified algorithm `A`.
    ///
    /// This is a generic convenience method that delegates to [`CipherAlgorithm::decrypt`].
    #[inline]
    pub fn decrypt<A: CipherAlgorithm>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Dispatch to the trait implementation for the generic type A.
        // The implementation will handle nonce extraction and verification.
        A::decrypt(self, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_new_valid_key() {
        // Use a zeroed key for deterministic testing.
        let key = [0u8; ARGON_KEY_LEN];

        // Ensure the Cipher constructs successfully with a valid key length.
        let cipher = Cipher::new(&key);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        // Setup the cipher with a dummy key.
        let key = [1u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();
        let plaintext = b"Hello AES GCM";

        // Perform encryption using the AES marker type.
        let ciphertext = cipher.encrypt::<algorithm::Aes256Gcm>(plaintext).unwrap();

        // Ciphertext should not match plaintext (basic sanity check).
        assert_ne!(plaintext, &ciphertext[..]);

        // Decrypt and verify we get the original data back.
        let decrypted = cipher.decrypt::<algorithm::Aes256Gcm>(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_chacha_roundtrip() {
        // Setup the cipher with a dummy key.
        let key = [2u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();
        let plaintext = b"Hello ChaCha20";

        // Perform encryption using the ChaCha marker type.
        let ciphertext = cipher.encrypt::<algorithm::XChaCha20Poly1305>(plaintext).unwrap();

        // Ciphertext should not match plaintext.
        assert_ne!(plaintext, &ciphertext[..]);

        // Decrypt and verify we get the original data back.
        let decrypted = cipher.decrypt::<algorithm::XChaCha20Poly1305>(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_cross_algorithm_isolation() {
        // Setup the cipher.
        let key = [3u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();
        let plaintext = b"Sensitive Data";

        // Encrypt with AES.
        let aes_ciphertext = cipher.encrypt::<algorithm::Aes256Gcm>(plaintext).unwrap();

        // Attempt to decrypt AES ciphertext with ChaCha engine.
        // This MUST fail because:
        // 1. Nonce formats are different.
        // 2. Keys are different (split from master key).
        // 3. Algorithms are incompatible.
        let result = cipher.decrypt::<algorithm::XChaCha20Poly1305>(&aes_ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        // Setup the cipher.
        let key = [4u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        // Most AEAD implementations (or our wrapper) should reject empty payloads
        // if that's a policy, or simply encrypt an empty payload.
        // The original test expected an error, so we document that behavior.

        // Try encrypting empty bytes with AES.
        let result_aes = cipher.encrypt::<algorithm::Aes256Gcm>(&[]);
        assert!(result_aes.is_err());

        // Try encrypting empty bytes with ChaCha.
        let result_chacha = cipher.encrypt::<algorithm::XChaCha20Poly1305>(&[]);
        assert!(result_chacha.is_err());
    }
}
