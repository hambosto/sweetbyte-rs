//! Dual-layer cipher combining AES-256-GCM and XChaCha20-Poly1305.

use anyhow::{Context, Result};

use crate::config::{AES_KEY_SIZE, ARGON_KEY_LEN, CHACHA_KEY_SIZE};
use crate::crypto::aes::AesCipher;
use crate::crypto::chacha::ChachaCipher;

/// Dual-layer cipher that chains AES-256-GCM and XChaCha20-Poly1305.
pub struct Cipher {
    aes: AesCipher,
    chacha: ChachaCipher,
}

impl Cipher {
    /// Creates a new dual-layer cipher.
    ///
    /// # Arguments
    /// * `key` - A 64-byte key (first 32 for AES, last 32 for ChaCha)
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        let aes_key: [u8; AES_KEY_SIZE] =
            key[..AES_KEY_SIZE].try_into().context("invalid AES key")?;

        let chacha_key: [u8; CHACHA_KEY_SIZE] = key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE]
            .try_into()
            .context("invalid ChaCha key")?;

        Ok(Self {
            aes: AesCipher::new(&aes_key),
            chacha: ChachaCipher::new(&chacha_key),
        })
    }

    /// Encrypts plaintext using AES-256-GCM.
    pub fn encrypt_aes(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.aes.encrypt(plaintext)
    }

    /// Decrypts ciphertext using AES-256-GCM.
    pub fn decrypt_aes(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.aes.decrypt(ciphertext)
    }

    /// Encrypts plaintext using XChaCha20-Poly1305.
    pub fn encrypt_chacha(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.chacha.encrypt(plaintext)
    }

    /// Decrypts ciphertext using XChaCha20-Poly1305.
    pub fn decrypt_chacha(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.chacha.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_creation() {
        let key = [0u8; ARGON_KEY_LEN];
        assert!(Cipher::new(&key).is_ok());
    }

    #[test]
    fn test_aes_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = cipher.encrypt_aes(plaintext).unwrap();
        let decrypted = cipher.decrypt_aes(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = cipher.encrypt_chacha(plaintext).unwrap();
        let decrypted = cipher.decrypt_chacha(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dual_layer_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";

        // Encrypt with AES, then ChaCha
        let aes_encrypted = cipher.encrypt_aes(plaintext).unwrap();
        let dual_encrypted = cipher.encrypt_chacha(&aes_encrypted).unwrap();

        // Decrypt with ChaCha, then AES
        let chacha_decrypted = cipher.decrypt_chacha(&dual_encrypted).unwrap();
        let decrypted = cipher.decrypt_aes(&chacha_decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
