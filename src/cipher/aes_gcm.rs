//! AES-256-GCM encryption implementation.
//!
//! This module provides a wrapper around the `aes-gcm` crate to implement
//! authenticated encryption with associated data (AEAD) using AES-256 in Galois/Counter Mode.
//!
//! # Implementation Details
//!
//! - **Key Size**: 256 bits (32 bytes)
//! - **Nonce Size**: 96 bits (12 bytes), randomly generated per encryption
//! - **Tag Size**: 128 bits (16 bytes), appended automatically by the underlying library
//! - **Ciphertext Format**: `[Nonce (12 bytes)] || [Ciphertext] || [Auth Tag (16 bytes)]`

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, ensure};

use crate::config::{AES_NONCE_SIZE, KEY_SIZE};

/// A wrapper struct for AES-256-GCM encryption operations.
///
/// This struct holds the initialized key state and provides high-level
/// encrypt/decrypt methods that handle nonce management.
pub struct AesGcm {
    /// The inner AES-GCM state from the `aes-gcm` crate.
    inner: Aes256Gcm,
}

impl AesGcm {
    /// Initializes a new AES-GCM context with the provided key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid (though the type signature enforces 32 bytes).
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        // Initialize the inner AES-GCM structure from the slice.
        // This performs key expansion required for AES.
        let inner = Aes256Gcm::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts the plaintext and prepends the random nonce.
    ///
    /// # Format
    ///
    /// Returns a vector containing: `[Nonce (12B)][Ciphertext][Tag (16B)]`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The plaintext is empty.
    /// - Encryption fails (e.g., memory allocation issue).
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Enforce that plaintext is not empty.
        // Authenticated encryption of empty strings is technically possible but
        // often indicative of a logic error in the application layer.
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a cryptographically secure random nonce.
        // It is CRITICAL that nonces are unique for a given key.
        // Using OsRng ensures we get entropy from the OS kernel.
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Perform the encryption.
        // The `encrypt` method of the `aes-gcm` crate appends the auth tag to the end.
        // Format of `result` here is: [Ciphertext][Tag]
        let mut result = self.inner.encrypt(&nonce, plaintext).map_err(|e| anyhow!("aes-gcm encryption failed: {e}"))?;

        // Prepend the nonce to the result.
        // We use splice to insert at the beginning.
        // This is efficient enough, though strict allocation pre-calculation could optimize it.
        // Final format: [Nonce][Ciphertext][Tag]
        result.splice(0..0, nonce.iter().copied());

        Ok(result)
    }

    /// Decrypts the ciphertext using the prepended nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is shorter than the nonce size.
    /// - The authentication tag verification fails (indicating tampering).
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate minimum length.
        // Must contain at least the nonce (12 bytes) and potentially the tag (16 bytes).
        // The aes-gcm crate handles the tag check, but we must ensure we can extract the nonce.
        ensure!(ciphertext.len() >= AES_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", AES_NONCE_SIZE, ciphertext.len());

        // Split the input into nonce and the actual encrypted payload (ciphertext + tag).
        let (nonce, data) = ciphertext.split_at(AES_NONCE_SIZE);

        // Perform decryption and authentication.
        // The `decrypt` method verifies the MAC tag (suffix of `data`) against the content.
        // If verification fails, it returns an error, ensuring we never process tampered data.
        self.inner.decrypt(Nonce::from_slice(nonce), data).map_err(|_| anyhow!("aes-gcm authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_new() {
        // Verify we can instantiate the cipher with a valid key.
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Setup cipher.
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        // Encrypt.
        let ciphertext = cipher.encrypt(plaintext).unwrap();

        // Ciphertext must differ from plaintext.
        assert_ne!(plaintext, &ciphertext[..]);

        // Verify length: 12 (nonce) + 13 (plaintext) + 16 (tag) = 41 bytes.
        assert_eq!(ciphertext.len(), AES_NONCE_SIZE + plaintext.len() + 16);

        // Decrypt and verify.
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        // Verify empty plaintext rejection.
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        assert!(cipher.encrypt(&[]).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        // Verify handling of data shorter than the nonce.
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let ciphertext = vec![0u8; AES_NONCE_SIZE - 1];
        assert!(cipher.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        // Setup cipher and encrypt data.
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"Secret Message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with a byte in the ciphertext part (after the nonce).
        let payload_idx = AES_NONCE_SIZE;
        ciphertext[payload_idx] ^= 0x01;

        // Decryption must fail due to MAC mismatch.
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "aes-gcm authentication failed");
    }

    #[test]
    fn test_decrypt_tampered_tag() {
        // Setup cipher and encrypt data.
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"Secret Message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with a byte in the auth tag (last 16 bytes).
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        // Decryption must fail.
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "aes-gcm authentication failed");
    }
}
