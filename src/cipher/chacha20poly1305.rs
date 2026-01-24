//! # XChaCha20-Poly1305 Authenticated Encryption
//!
//! This module provides XChaCha20-Poly1305 implementation for authenticated encryption.
//! XChaCha20 extends ChaCha20 with a longer nonce (192 bits vs 96 bits) to eliminate
//! nonce reuse concerns when using random nonces.
//!
//! ## Security Properties
//!
//! - **Confidentiality**: XChaCha20 provides 256-bit security level
//! - **Authenticity**: Poly1305 provides 128-bit authentication tags
//! - **Integrity**: Any modification to ciphertext is detected with 2^-128 probability
//! - **Nonce Safety**: 192-bit nonces make collision probability negligible
//!
//! ## Advantages over ChaCha20-Poly1305
//!
//! - Extended nonces (24 bytes) prevent reuse even with random generation
//! - Better security bounds for multi-message scenarios
//! - Compatible with ChaCha20-Poly1305 (can decrypt with proper nonce handling)
//!
//! ## Format
/// Ciphertext format: [nonce(24 bytes) || ciphertext || authentication_tag(16 bytes)]
use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_NONCE_SIZE, KEY_SIZE};

/// # XChaCha20-Poly1305 Cipher Implementation
///
/// Wrapper struct around the `chacha20poly1305` crate's XChaCha20Poly1305 implementation.
/// Provides authenticated encryption with extended nonces for enhanced security.
///
/// The cipher uses:
/// - 256-bit ChaCha20 encryption key
/// - 192-bit extended nonce (generated per encryption)
/// - 128-bit Poly1305 authentication tag
/// - Stream cipher encryption (constant-time)
/// - Poly1305 for authentication (constant-time)
pub struct ChaCha20Poly1305 {
    /// The underlying XChaCha20-Poly1305 cipher instance from the chacha20poly1305 crate
    inner: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    /// Creates a new XChaCha20-Poly1305 cipher instance
    ///
    /// # Arguments
    /// * `key` - 256-bit (32-byte) ChaCha20 encryption key
    ///
    /// # Returns
    /// Configured XChaCha20-Poly1305 cipher ready for encryption/decryption
    ///
    /// # Errors
    /// Returns error if key length is invalid (should be exactly 32 bytes)
    ///
    /// # Security Notes
    /// - The key is zeroized after use by the underlying implementation
    /// - XChaCha20 provides better nonce reuse protection than standard ChaCha20
    /// - All operations are constant-time to prevent timing attacks
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        // Initialize the underlying XChaCha20-Poly1305 cipher with the provided key
        // The chacha20poly1305 crate handles key validation and secure key setup
        let inner = XChaCha20Poly1305::new_from_slice(key)?;
        Ok(Self { inner })
    }

    /// Encrypts plaintext with authenticated encryption
    ///
    /// Performs XChaCha20-Poly1305 encryption with a randomly generated extended nonce.
    /// The nonce is prepended to the ciphertext for use during decryption.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt, must not be empty
    ///
    /// # Returns
    /// Ciphertext in format: [nonce(24 bytes) || encrypted_data || auth_tag(16 bytes)]
    ///
    /// # Errors
    /// Returns error if:
    /// - Plaintext is empty (prevents encrypting empty messages)
    /// - Random number generation fails
    /// - XChaCha20-Poly1305 encryption operation fails
    ///
    /// # Security Guarantees
    /// - Extended 192-bit nonces eliminate nonce reuse concerns
    /// - Authentication tag ensures ciphertext integrity
    /// - Encryption is IND-CPA secure
    /// - Combined with authentication tag: IND-CCA2 secure
    ///
    /// # Performance Characteristics
    /// - O(n) complexity where n is plaintext length
    /// - Software implementation (constant-time, no hardware dependencies)
    /// - Stream cipher allows encryption of arbitrarily large data
    /// - Poly1305 authentication is fast and constant-time
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate input to prevent encryption of empty messages
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a cryptographically secure random 192-bit extended nonce
        // XChaCha20 uses 24-byte nonces vs 12-byte for standard ChaCha20
        let nonce_bytes = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        // Perform XChaCha20-Poly1305 encryption with the generated nonce
        // The result includes the ciphertext and 128-bit Poly1305 authentication tag
        let mut result = self
            .inner
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("chacha20poly1305 encryption failed: {e}"))?;
        // Prepend the extended nonce to the ciphertext for storage/transmission
        // Format: [nonce(24 bytes) || ciphertext || auth_tag(16 bytes)]
        result.splice(0..0, nonce_bytes.iter().copied());

        Ok(result)
    }

    /// Decrypts ciphertext with authentication verification
    ///
    /// Performs authenticated decryption of XChaCha20-Poly1305 ciphertext.
    /// The extended nonce is extracted from the beginning of the ciphertext and
    /// used for decryption. Authentication is verified automatically.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with extended nonce prepended
    ///
    /// # Returns
    /// Original plaintext if authentication succeeds
    ///
    /// # Errors
    /// Returns error if:
    /// - Ciphertext is too short (less than extended nonce size)
    /// - Authentication tag verification fails (indicates tampering)
    /// - Underlying XChaCha20-Poly1305 decryption fails
    ///
    /// # Security Guarantees
    /// - Authentication failure provides no information about plaintext
    /// - Constant-time authentication tag comparison via Poly1305
    /// - Successful decryption guarantees ciphertext authenticity
    /// - Extended nonce prevents collision attacks
    /// - Protects against chosen ciphertext attacks
    ///
    /// # Performance Characteristics
    /// - O(n) complexity where n is ciphertext length
    /// - Software implementation (consistent performance across platforms)
    /// - Stream cipher allows parallel processing of ciphertext blocks
    /// - Poly1305 authentication is fast and constant-time
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate minimum ciphertext length (at least extended nonce + minimal encrypted data + auth tag)
        ensure!(ciphertext.len() >= CHACHA_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", CHACHA_NONCE_SIZE, ciphertext.len());
        // Split ciphertext into extended nonce and encrypted data portions
        // First 24 bytes: extended nonce, remainder: encrypted data + authentication tag
        let (nonce_bytes, data) = ciphertext.split_at(CHACHA_NONCE_SIZE);
        // Perform authenticated decryption
        // The chacha20poly1305 crate automatically verifies the Poly1305 authentication tag
        // and returns error if verification fails (detects tampering)
        self.inner.decrypt(XNonce::from_slice(nonce_bytes), data).map_err(|_| anyhow!("chacha20poly1305 authentication failed"))
    }
}
