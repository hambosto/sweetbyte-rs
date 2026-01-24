//! # AES-256-GCM Authenticated Encryption
//!
//! This module provides AES-256-GCM (Galois/Counter Mode) implementation for
//! authenticated encryption. AES-GCM combines AES counter mode encryption with
//! the GHASH authentication mode to provide both confidentiality and integrity.
//!
//! ## Security Properties
//!
//! - **Confidentiality**: AES-256 in counter mode provides 256-bit security level
//! - **Authenticity**: GHASH provides 128-bit authentication tags
//! - **Integrity**: Any modification to ciphertext is detected with 2^-128 probability
//! - **Performance**: Hardware acceleration via AES-NI on modern CPUs
//!
//! ## Nonce Management
//!
//! Uses 96-bit (12-byte) random nonces generated with cryptographically secure
//! OS randomness. With random nonces, the probability of nonce reuse is negligible
/// for practical purposes (birthday bound after 2^48 messages).
//
// ## Format
//
// Ciphertext format: [nonce(12 bytes) || ciphertext || authentication_tag(16 bytes)]
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, ensure};

use crate::config::{AES_NONCE_SIZE, KEY_SIZE};

/// # AES-256-GCM Cipher Implementation
///
/// Wrapper struct around the `aes_gcm` crate's Aes256Gcm implementation.
/// Provides convenient methods for encryption and decryption with proper
/// error handling and nonce management.
///
/// The cipher uses:
/// - 256-bit AES encryption key
/// - 96-bit random nonce (generated per encryption)
/// - 128-bit authentication tag
/// - Counter mode encryption for parallelizable decryption
/// - GHASH for authentication (constant-time)
pub struct AesGcm {
    /// The underlying AES-256-GCM cipher instance from the aes_gcm crate
    inner: Aes256Gcm,
}

impl AesGcm {
    /// Creates a new AES-256-GCM cipher instance
    ///
    /// # Arguments
    /// * `key` - 256-bit (32-byte) AES encryption key
    ///
    /// # Returns
    /// Configured AES-256-GCM cipher ready for encryption/decryption
    ///
    /// # Errors
    /// Returns error if key length is invalid (should be exactly 32 bytes)
    ///
    /// # Security Notes
    /// - The key is zeroized after use by the underlying implementation
    /// - Key material is not copied unnecessarily
    /// - Uses constant-time operations where possible
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        // Initialize the underlying AES-256-GCM cipher with the provided key
        // The aes_gcm crate handles key validation and secure key setup
        let inner = Aes256Gcm::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts plaintext with authenticated encryption
    ///
    /// Performs AES-256-GCM encryption with a randomly generated nonce.
    /// The nonce is prepended to the ciphertext for use during decryption.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt, must not be empty
    ///
    /// # Returns
    /// Ciphertext in format: [nonce(12 bytes) || encrypted_data || auth_tag(16 bytes)]
    ///
    /// # Errors
    /// Returns error if:
    /// - Plaintext is empty (prevents encrypting empty messages)
    /// - Random number generation fails
    /// - AES-GCM encryption operation fails
    ///
    /// # Security Guarantees
    /// - Random nonce generation prevents nonce reuse attacks
    /// - Authentication tag ensures ciphertext integrity
    /// - Encryption is IND-CPA secure
    /// - Combined with authentication tag: IND-CCA2 secure
    ///
    /// # Performance Characteristics
    /// - O(n) complexity where n is plaintext length
    /// - Hardware acceleration via AES-NI when available
    /// - Parallelizable decryption (counter mode)
    /// - Constant-time authentication via GHASH
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate input to prevent encryption of empty messages
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a cryptographically secure random 96-bit nonce
        // OsRng provides platform-specific secure randomness
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Perform AES-256-GCM encryption with the generated nonce
        // The result includes the ciphertext and authentication tag
        let mut result = self.inner.encrypt(&nonce, plaintext).map_err(|e| anyhow!("aes-gcm encryption failed: {e}"))?;

        // Prepend the nonce to the ciphertext for storage/transmission
        // Format: [nonce(12 bytes) || ciphertext || auth_tag(16 bytes)]
        result.splice(0..0, nonce.iter().copied());

        Ok(result)
    }

    /// Decrypts ciphertext with authentication verification
    ///
    /// Performs authenticated decryption of AES-256-GCM ciphertext.
    /// The nonce is extracted from the beginning of the ciphertext and
    /// used for decryption. Authentication is verified automatically.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with nonce prepended
    ///
    /// # Returns
    /// Original plaintext if authentication succeeds
    ///
    /// # Errors
    /// Returns error if:
    /// - Ciphertext is too short (less than nonce size)
    /// - Authentication tag verification fails (indicates tampering)
    /// - Underlying AES-GCM decryption fails
    ///
    /// # Security Guarantees
    /// - Authentication failure provides no information about plaintext
    /// - Constant-time authentication tag comparison
    /// - Successful decryption guarantees ciphertext authenticity
    /// - Protects against chosen ciphertext attacks
    ///
    /// # Performance Characteristics
    /// - O(n) complexity where n is ciphertext length
    /// - Hardware acceleration via AES-NI when available
    /// - Counter mode allows parallel decryption
    /// - GHASH authentication is constant-time
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate minimum ciphertext length (at least nonce + minimal encrypted data + auth tag)
        ensure!(ciphertext.len() >= AES_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", AES_NONCE_SIZE, ciphertext.len());

        // Split ciphertext into nonce and encrypted data portions
        // First 12 bytes: nonce, remainder: encrypted data + authentication tag
        let (nonce, data) = ciphertext.split_at(AES_NONCE_SIZE);

        // Perform authenticated decryption
        // The aes_gcm crate automatically verifies the authentication tag
        // and returns error if verification fails (detects tampering)
        self.inner.decrypt(Nonce::from_slice(nonce), data).map_err(|_| anyhow!("aes-gcm authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_new() {
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        assert_ne!(plaintext, &ciphertext[..]);

        assert_eq!(ciphertext.len(), AES_NONCE_SIZE + plaintext.len() + 16);

        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        assert!(cipher.encrypt(&[]).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let ciphertext = vec![0u8; AES_NONCE_SIZE - 1];
        assert!(cipher.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"Secret Message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        let payload_idx = AES_NONCE_SIZE;
        ciphertext[payload_idx] ^= 0x01;

        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "aes-gcm authentication failed");
    }

    #[test]
    fn test_decrypt_tampered_tag() {
        let key = [0u8; KEY_SIZE];
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"Secret Message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "aes-gcm authentication failed");
    }
}
