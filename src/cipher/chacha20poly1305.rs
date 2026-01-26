//! XChaCha20-Poly1305 encryption implementation.
//!
//! This module provides a wrapper around the `chacha20poly1305` crate to implement
//! authenticated encryption with associated data (AEAD) using the XChaCha20 variant.
//!
//! # Implementation Details
//!
//! - **Algorithm**: XChaCha20-Poly1305 (Extended Nonce ChaCha20)
//! - **Key Size**: 256 bits (32 bytes)
//! - **Nonce Size**: 192 bits (24 bytes), randomly generated
//! - **Tag Size**: 128 bits (16 bytes), appended automatically
//! - **Ciphertext Format**: `[Nonce (24 bytes)] || [Ciphertext] || [Auth Tag (16 bytes)]`
//!
//! # Why XChaCha20?
//!
//! We use the XChaCha20 variant because it supports 192-bit nonces. This allows us to
//! safely generate nonces randomly without practically any risk of collision (birthday paradox),
//! unlike standard ChaCha20's 96-bit nonce which requires counter-based management
//! for long-term safety.

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_NONCE_SIZE, KEY_SIZE};

/// A wrapper struct for XChaCha20-Poly1305 encryption operations.
///
/// This struct holds the initialized key state and provides high-level
/// encrypt/decrypt methods that handle extended nonce management.
pub struct ChaCha20Poly1305 {
    /// The inner XChaCha20-Poly1305 state.
    inner: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    /// Initializes a new XChaCha20-Poly1305 context with the provided key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid.
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        // Initialize the inner structure.
        // XChaCha20 uses the same key setup as ChaCha20.
        let inner = XChaCha20Poly1305::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts the plaintext and prepends the random extended nonce.
    ///
    /// # Format
    ///
    /// Returns a vector containing: `[Nonce (24B)][Ciphertext][Tag (16B)]`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The plaintext is empty.
    /// - Encryption fails.
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Enforce that plaintext is not empty.
        // Good practice to avoid edge cases with empty messages.
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a random 192-bit (24-byte) nonce.
        // With 192 bits, the probability of collision is negligible even with
        // billions of files, making random generation safe.
        let nonce_bytes = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Perform the encryption.
        // The inner encrypt method appends the 16-byte Poly1305 tag.
        let mut result = self
            .inner
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("chacha20poly1305 encryption failed: {e}"))?;

        // Prepend the nonce to the result.
        // The recipient needs this nonce to decrypt.
        result.splice(0..0, nonce_bytes.iter().copied());

        Ok(result)
    }

    /// Decrypts the ciphertext using the prepended extended nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is shorter than the nonce size.
    /// - The authentication tag verification fails.
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate minimum length.
        // Must be at least 24 bytes (nonce) + tag.
        ensure!(ciphertext.len() >= CHACHA_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", CHACHA_NONCE_SIZE, ciphertext.len());

        // Extract the nonce (first 24 bytes) and the encrypted payload.
        let (nonce_bytes, data) = ciphertext.split_at(CHACHA_NONCE_SIZE);

        // Perform decryption and authentication.
        // Verifies the Poly1305 tag and decrypts if valid.
        self.inner.decrypt(XNonce::from_slice(nonce_bytes), data).map_err(|_| anyhow!("chacha20poly1305 authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_new() {
        // Verify valid construction.
        let key = [0u8; KEY_SIZE];
        let cipher = ChaCha20Poly1305::new(&key);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Setup cipher.
        let key = [0u8; KEY_SIZE];
        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        let plaintext = b"Hello, XChaCha20!";

        // Encrypt.
        let ciphertext = cipher.encrypt(plaintext).unwrap();

        // Verify output is different.
        assert_ne!(plaintext, &ciphertext[..]);

        // Verify length: 24 (nonce) + 17 (plaintext) + 16 (tag) = 57 bytes.
        assert_eq!(ciphertext.len(), CHACHA_NONCE_SIZE + plaintext.len() + 16);

        // Decrypt and verify.
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        // Verify empty plaintext rejection.
        let key = [0u8; KEY_SIZE];
        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        assert!(cipher.encrypt(&[]).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        // Verify short input rejection.
        let key = [0u8; KEY_SIZE];
        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        let ciphertext = vec![0u8; CHACHA_NONCE_SIZE - 1];
        assert!(cipher.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        // Setup cipher and encrypt.
        let key = [0u8; KEY_SIZE];
        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        let plaintext = b"Secret Message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with ciphertext payload.
        let payload_idx = CHACHA_NONCE_SIZE;
        ciphertext[payload_idx] ^= 0x01;

        // Verify decryption failure.
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "chacha20poly1305 authentication failed");
    }
}
