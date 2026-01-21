//! AES-256-GCM authenticated encryption.
//!
//! Implements AES-256 in Galois/Counter Mode (GCM), providing both
//! confidentiality and authenticity. GCM is an authenticated encryption
//! scheme that combines counter mode encryption with GHASH authentication.
//!
//! # Parameters
//!
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 96 bits (12 bytes)
//! - **Tag size**: 128 bits (16 bytes, included in ciphertext)
//!
//! # Security Notes
//!
//! - Nonces are generated randomly using OS RNG
//! - Each encryption uses a unique nonce
//! - Same plaintext with same key but different nonce produces different ciphertext

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, ensure};

use crate::config::{AES_KEY_SIZE, AES_NONCE_SIZE};

/// AES-256-GCM cipher instance.
///
/// Provides authenticated encryption and decryption using AES-256-GCM.
/// The nonce is prepended to the ciphertext for storage/transmission.
pub struct AesGcm {
    /// The underlying AES-256-GCM cipher.
    inner: Aes256Gcm,
}

impl AesGcm {
    /// Creates a new AES-256-GCM cipher instance.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid.
    #[inline]
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Result<Self> {
        let inner = Aes256Gcm::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts data using AES-256-GCM.
    ///
    /// Generates a random 12-byte nonce, encrypts the plaintext,
    /// and prepends the nonce to the ciphertext.
    ///
    /// The output format is: [nonce (12 bytes)][encrypted data][auth tag (16 bytes)]
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    ///
    /// The ciphertext with nonce prepended (nonce + ciphertext + auth tag).
    ///
    /// # Errors
    ///
    /// Returns an error if plaintext is empty or encryption fails.
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a random 12-byte nonce using OS randomness.
        // This ensures each encryption uses a unique nonce.
        // AES-GCM uses 96-bit (12-byte) nonces for optimal performance.
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt the plaintext with authentication tag.
        // GCM mode combines CTR encryption with GHASH authentication.
        // The result includes the 16-byte authentication tag.
        let mut result = self.inner.encrypt(&nonce, plaintext).map_err(|e| anyhow!("aes-gcm encryption failed: {e}"))?;

        // Prepend nonce to ciphertext for storage/transmission.
        // This allows the decryptor to know which nonce was used.
        // splice(0..0, ...) inserts at the beginning without replacing data.
        result.splice(0..0, nonce.iter().copied());
        Ok(result)
    }

    /// Decrypts data using AES-256-GCM.
    ///
    /// Expects the nonce as the first 12 bytes of input.
    /// The authentication tag is verified during decryption.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data (nonce + ciphertext + auth tag).
    ///
    /// # Returns
    ///
    /// The original plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Ciphertext is too short (needs at least nonce size)
    /// - Authentication fails (wrong key or tampered data)
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Verify minimum length for nonce (12 bytes) + at least some ciphertext.
        // This prevents buffer underruns and malformed input.
        ensure!(ciphertext.len() >= AES_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", AES_NONCE_SIZE, ciphertext.len());

        // Split nonce (first 12 bytes) from encrypted data (rest).
        // Nonce is used to initialize the GCM counter; data includes ciphertext + tag.
        let (nonce, data) = ciphertext.split_at(AES_NONCE_SIZE);

        // Decrypt and verify authentication tag in one operation.
        // If the tag verification fails (wrong key or tampered data),
        // this returns an error and the plaintext is NOT returned.
        self.inner.decrypt(Nonce::from_slice(nonce), data).map_err(|_| anyhow!("aes-gcm authentication failed"))
    }
}
