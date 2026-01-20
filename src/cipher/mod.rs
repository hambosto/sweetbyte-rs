use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::Kdf;

use crate::config::{AES_KEY_SIZE, ARGON_KEY_LEN, CHACHA_KEY_SIZE};

/// Type markers for cipher algorithms.
///
/// These structs are used as type parameters to select the encryption
/// algorithm at compile time, enabling zero-cost abstraction.
#[allow(non_snake_case)]
pub mod Algorithm {
    /// Marker type for AES-256-GCM cipher.
    pub struct Aes256Gcm;
    /// Marker type for XChaCha20-Poly1305 cipher.
    pub struct XChaCha20Poly1305;
}

/// Trait defining the cipher algorithm interface.
///
/// Implemented for each supported cipher algorithm, enabling polymorphic
/// encryption/decryption operations through the Cipher struct.
pub trait CipherAlgorithm {
    /// Encrypts plaintext using the specified algorithm.
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts ciphertext using the specified algorithm.
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for Algorithm::Aes256Gcm {
    /// AES-256-GCM encryption implementation.
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.encrypt(plaintext)
    }

    /// AES-256-GCM decryption implementation.
    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for Algorithm::XChaCha20Poly1305 {
    /// XChaCha20-Poly1305 encryption implementation.
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.encrypt(plaintext)
    }

    /// XChaCha20-Poly1305 decryption implementation.
    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.decrypt(ciphertext)
    }
}

/// Unified cipher interface supporting multiple algorithms.
///
/// Contains instances of both AES-256-GCM and XChaCha20-Poly1305,
/// with encryption/decryption delegated to the specified algorithm type.
pub struct Cipher {
    /// AES-256-GCM cipher instance.
    aes: AesGcm,
    /// XChaCha20-Poly1305 cipher instance.
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    /// Creates a new Cipher from a 64-byte derived key.
    ///
    /// The key is split into two 32-byte portions:
    /// - First 32 bytes: AES-256 key
    /// - Next 32 bytes: XChaCha20 key
    ///
    /// # Arguments
    /// * `key` - The 64-byte derived key.
    ///
    /// # Returns
    /// A new Cipher instance, or an error if initialization fails.
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        // Extract the AES-256 key (first 32 bytes).
        let aes_key: [u8; AES_KEY_SIZE] = key[..AES_KEY_SIZE].try_into().context("invalid aes-gcm key")?;
        // Extract the ChaCha20 key (bytes 32-63).
        let chacha_key: [u8; CHACHA_KEY_SIZE] = key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE].try_into().context("invalid chacha20poly1305 key")?;

        Ok(Self { aes: AesGcm::new(&aes_key)?, chacha: ChaCha20Poly1305::new(&chacha_key)? })
    }

    /// Encrypts plaintext using the specified algorithm.
    ///
    /// # Type Parameters
    /// * `A` - The cipher algorithm to use.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    /// The ciphertext with nonce prepended.
    #[inline]
    pub fn encrypt<A: CipherAlgorithm>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        A::encrypt(self, plaintext)
    }

    /// Decrypts ciphertext using the specified algorithm.
    ///
    /// # Type Parameters
    /// * `A` - The cipher algorithm to use.
    ///
    /// # Arguments
    /// * `ciphertext` - The data to decrypt (with nonce prepended).
    ///
    /// # Returns
    /// The decrypted plaintext.
    #[inline]
    pub fn decrypt<A: CipherAlgorithm>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        A::decrypt(self, ciphertext)
    }
}
