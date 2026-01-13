//! XChaCha20-Poly1305 encryption.

use anyhow::{Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use crate::config::{CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE};
use crate::crypto::derive::random_bytes;

/// XChaCha20-Poly1305 cipher.
pub struct ChachaCipher {
    aead: XChaCha20Poly1305,
}

impl ChachaCipher {
    /// Creates a new ChaCha cipher with the given key.
    ///
    /// # Arguments
    /// * `key` - A 32-byte key
    pub fn new(key: &[u8; CHACHA_KEY_SIZE]) -> Self {
        let aead = XChaCha20Poly1305::new_from_slice(key).expect("valid key size");
        Self { aead }
    }

    /// Encrypts plaintext using XChaCha20-Poly1305.
    ///
    /// The nonce is prepended to the ciphertext.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// Nonce + ciphertext + authentication tag
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("plaintext cannot be empty");
        }

        let nonce_bytes: [u8; CHACHA_NONCE_SIZE] = random_bytes()?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .aead
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("ChaCha encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(CHACHA_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts ciphertext using XChaCha20-Poly1305.
    ///
    /// Expects the nonce to be prepended to the ciphertext.
    ///
    /// # Arguments
    /// * `ciphertext` - Nonce + ciphertext + authentication tag
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            bail!("ciphertext cannot be empty");
        }

        if ciphertext.len() < CHACHA_NONCE_SIZE {
            bail!(
                "ciphertext too short, need at least {} bytes, got {}",
                CHACHA_NONCE_SIZE,
                ciphertext.len()
            );
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(CHACHA_NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.aead
            .decrypt(nonce, encrypted)
            .map_err(|_| anyhow::anyhow!("ChaCha authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; CHACHA_KEY_SIZE];
        let cipher = ChachaCipher::new(&key);

        let plaintext = b"Hello, World!";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty() {
        let key = [0u8; CHACHA_KEY_SIZE];
        let cipher = ChachaCipher::new(&key);

        assert!(cipher.encrypt(b"").is_err());
    }

    #[test]
    fn test_decrypt_empty() {
        let key = [0u8; CHACHA_KEY_SIZE];
        let cipher = ChachaCipher::new(&key);

        assert!(cipher.decrypt(&[]).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = [0u8; CHACHA_KEY_SIZE];
        let cipher = ChachaCipher::new(&key);

        assert!(cipher.decrypt(&[0u8; CHACHA_NONCE_SIZE - 1]).is_err());
    }

    #[test]
    fn test_decrypt_tampered() {
        let key = [0u8; CHACHA_KEY_SIZE];
        let cipher = ChachaCipher::new(&key);

        let plaintext = b"Hello, World!";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        if let Some(last) = ciphertext.last_mut() {
            *last ^= 0xFF;
        }

        assert!(cipher.decrypt(&ciphertext).is_err());
    }
}
