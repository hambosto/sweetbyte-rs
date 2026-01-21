//! XChaCha20-Poly1305 authenticated encryption.
//!
//! Implements XChaCha20-Poly1305, combining the ChaCha20 stream cipher
//! with Poly1305 authenticator. This provides authenticated encryption
//! that is resistant to timing attacks and efficient on both software
//! and hardware.
//!
//! # Parameters
//!
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 192 bits (24 bytes)
//! - **Tag size**: 128 bits (16 bytes, included in ciphertext)
//!
//! # Advantages over AES
//!
//! - Constant-time implementation (no cache timing attacks)
//! - Better performance on systems without AES-NI
//! - Simpler implementation, smaller attack surface

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE};

/// XChaCha20-Poly1305 cipher instance.
///
/// Provides authenticated encryption and decryption using extended nonce
/// ChaCha20-Poly1305. The extended nonce (24 bytes) provides more flexibility
/// for high-volume scenarios, though we use random nonces per encryption.
pub struct ChaCha20Poly1305 {
    /// The underlying XChaCha20-Poly1305 cipher.
    inner: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    /// Creates a new XChaCha20-Poly1305 cipher instance.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid.
    #[inline]
    pub fn new(key: &[u8; CHACHA_KEY_SIZE]) -> Result<Self> {
        let inner = XChaCha20Poly1305::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts data using XChaCha20-Poly1305.
    ///
    /// Generates a random 24-byte extended nonce, encrypts the plaintext,
    /// and prepends the nonce to the ciphertext.
    ///
    /// The output format is: [nonce (24 bytes)][encrypted data][auth tag (16 bytes)]
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

        // Generate random 24-byte extended nonce.
        // XChaCha20 uses 192-bit (24-byte) nonces for extended range.
        // This is larger than AES-GCM's 96-bit nonce, providing more
        // headroom for high-volume scenarios.
        let nonce_bytes = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt with authentication tag.
        // XChaCha20 is the extended-nonce variant of ChaCha20-Poly1305.
        // It provides the same security as ChaCha20 but with more nonce bits.
        let mut result = self
            .inner
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("chacha20poly1305 encryption failed: {e}"))?;

        // Prepend nonce to ciphertext for storage.
        // The nonce is needed for decryption to initialize the cipher state.
        result.splice(0..0, nonce_bytes.iter().copied());
        Ok(result)
    }

    /// Decrypts data using XChaCha20-Poly1305.
    ///
    /// Expects the nonce as the first 24 bytes of input.
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
        // Verify minimum length for 24-byte extended nonce.
        // This ensures we have enough data for both nonce and ciphertext.
        ensure!(ciphertext.len() >= CHACHA_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", CHACHA_NONCE_SIZE, ciphertext.len());

        // Split extended nonce (first 24 bytes) from encrypted data (rest).
        let (nonce_bytes, data) = ciphertext.split_at(CHACHA_NONCE_SIZE);

        // Decrypt and verify authentication tag.
        // If authentication fails, this returns an error without plaintext.
        // This is critical for detecting tampering with the ciphertext.
        self.inner.decrypt(XNonce::from_slice(nonce_bytes), data).map_err(|_| anyhow!("chacha20poly1305 authentication failed"))
    }
}
