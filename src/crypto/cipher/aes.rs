use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};

use crate::crypto::random;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// AesCipher implements AES-256-GCM encryption and decryption.
///
/// This struct provides a high-level interface for encrypting and decrypting data
/// using the AES-256-GCM algorithm. It handles nonce generation and management internally.
///
/// # Examples
///
/// ```
/// use sweetbyte::crypto::cipher::AesCipher;
///
/// let key = vec![0u8; 32]; // In practice, use a proper key derivation function
/// let cipher = AesCipher::new(&key).unwrap();
///
/// let plaintext = b"Hello, World!";
/// let ciphertext = cipher.encrypt(plaintext).unwrap();
/// let decrypted = cipher.decrypt(&ciphertext).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub struct AesCipher {
    cipher: Aes256Gcm,
}

impl AesCipher {
    /// Creates a new `AesCipher` instance with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte key for AES-256.
    ///
    /// # Returns
    ///
    /// Returns a new `AesCipher` instance, or an error if the key length is invalid.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(anyhow!("key must be {} bytes, got {}", KEY_SIZE, key.len()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("failed to create AES cipher: {}", e))?;

        Ok(Self { cipher })
    }

    /// Encrypts the given plaintext.
    ///
    /// This method generates a random nonce, encrypts the plaintext, and prepends
    /// the nonce to the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the nonce followed by the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(anyhow!("plaintext cannot be empty"));
        }

        let nonce_bytes = random::get_random_bytes(NONCE_SIZE)
            .map_err(|e| anyhow!("failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("encryption failed: {}", e))?;

        // Prepend nonce to ciphertext (same as Go implementation)
        let mut result = nonce_bytes;
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts the given ciphertext.
    ///
    /// This method extracts the nonce from the beginning of the ciphertext and
    /// decrypts the remaining data.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The data to decrypt (nonce + encrypted data).
    ///
    /// # Returns
    ///
    /// Returns the decrypted plaintext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            return Err(anyhow!("ciphertext cannot be empty"));
        }

        if ciphertext.len() < NONCE_SIZE {
            return Err(anyhow!(
                "ciphertext too short, need at least {} bytes, got {}",
                NONCE_SIZE,
                ciphertext.len()
            ));
        }

        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("authentication failed: {}", e))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = vec![0u8; 32];
        let cipher = AesCipher::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
