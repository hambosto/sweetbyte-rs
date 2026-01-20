use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, ensure};

use crate::config::{AES_KEY_SIZE, AES_NONCE_SIZE};

/// AES-256-GCM authenticated encryption cipher.
///
/// Provides authenticated encryption with associated data (AEAD) using
/// AES in Galois/Counter Mode (GCM) with 256-bit keys.
pub struct AesGcm {
    /// The underlying AES-256-GCM cipher instance.
    inner: Aes256Gcm,
}

impl AesGcm {
    /// Creates a new AesGcm cipher with the given key.
    ///
    /// # Arguments
    /// * `key` - A 32-byte AES-256 key.
    ///
    /// # Returns
    /// A new AesGcm instance, or an error if the key is invalid.
    #[inline]
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Result<Self> {
        let inner = Aes256Gcm::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts plaintext using AES-256-GCM.
    ///
    /// Generates a random nonce for each encryption, which is prepended
    /// to the ciphertext. The nonce is 12 bytes.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt (must not be empty).
    ///
    /// # Returns
    /// The ciphertext with nonce prepended, or an error.
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a random 12-byte nonce.
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        // Encrypt the plaintext with the nonce.
        let mut result = self.inner.encrypt(&nonce, plaintext).map_err(|e| anyhow!("aes-gcm encryption failed: {e}"))?;

        // Prepend the nonce to the ciphertext.
        result.splice(0..0, nonce.iter().copied());
        Ok(result)
    }

    /// Decrypts ciphertext using AES-256-GCM.
    ///
    /// Expects the ciphertext to have a 12-byte nonce prepended.
    /// Authentication failure (wrong key or corrupted data) returns an error.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext with nonce prepended (at least 12 bytes).
    ///
    /// # Returns
    /// The decrypted plaintext, or an error if authentication fails.
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(ciphertext.len() >= AES_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", AES_NONCE_SIZE, ciphertext.len());

        // Split off the nonce.
        let (nonce, data) = ciphertext.split_at(AES_NONCE_SIZE);
        // Decrypt and authenticate.
        self.inner.decrypt(Nonce::from_slice(nonce), data).map_err(|_| anyhow!("aes-gcm authentication failed"))
    }
}
