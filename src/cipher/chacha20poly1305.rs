use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE};

/// XChaCha20-Poly1305 authenticated encryption cipher.
///
/// Provides authenticated encryption with associated data (AEAD) using
/// XChaCha20-Poly1305, an extended nonce variant of ChaCha20-Poly1305.
/// XChaCha20 uses a 256-bit key and 192-bit (24-byte) nonce.
pub struct ChaCha20Poly1305 {
    /// The underlying XChaCha20-Poly1305 cipher instance.
    inner: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    /// Creates a new ChaCha20Poly1305 cipher with the given key.
    ///
    /// # Arguments
    /// * `key` - A 32-byte XChaCha20 key.
    ///
    /// # Returns
    /// A new ChaCha20Poly1305 instance, or an error if the key is invalid.
    #[inline]
    pub fn new(key: &[u8; CHACHA_KEY_SIZE]) -> Result<Self> {
        let inner = XChaCha20Poly1305::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts plaintext using XChaCha20-Poly1305.
    ///
    /// Generates a random 24-byte nonce for each encryption, which is
    /// prepended to the ciphertext.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt (must not be empty).
    ///
    /// # Returns
    /// The ciphertext with nonce prepended, or an error.
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a random 24-byte nonce.
        let nonce_bytes = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        // Encrypt the plaintext with the nonce.
        let mut result = self
            .inner
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("chacha20poly1305 encryption failed: {e}"))?;

        // Prepend the nonce to the ciphertext.
        result.splice(0..0, nonce_bytes.iter().copied());
        Ok(result)
    }

    /// Decrypts ciphertext using XChaCha20-Poly1305.
    ///
    /// Expects the ciphertext to have a 24-byte nonce prepended.
    /// Authentication failure (wrong key or corrupted data) returns an error.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext with nonce prepended (at least 24 bytes).
    ///
    /// # Returns
    /// The decrypted plaintext, or an error if authentication fails.
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(ciphertext.len() >= CHACHA_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", CHACHA_NONCE_SIZE, ciphertext.len());

        // Split off the nonce.
        let (nonce_bytes, data) = ciphertext.split_at(CHACHA_NONCE_SIZE);
        // Decrypt and authenticate.
        self.inner.decrypt(XNonce::from_slice(nonce_bytes), data).map_err(|_| anyhow!("chacha20poly1305 authentication failed"))
    }
}
