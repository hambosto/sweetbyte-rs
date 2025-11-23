use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use super::derive;

const KEY_SIZE: usize = 32;
const NONCE_SIZE_X: usize = 24;

/// ChaCha20Cipher implements ChaCha20-Poly1305 encryption and decryption.
pub struct ChaCha20Cipher {
    cipher: XChaCha20Poly1305,
}

impl ChaCha20Cipher {
    /// Creates a new `ChaCha20Cipher` instance with the given key.
    ///
    /// The key must be `KEY_SIZE` (32) bytes long.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(anyhow!("key must be {} bytes, got {}", KEY_SIZE, key.len()));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow!("failed to create XChaCha20-Poly1305 cipher: {}", e))?;

        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(anyhow!("plaintext cannot be empty"));
        }

        let nonce_bytes = derive::get_random_bytes(NONCE_SIZE_X)
            .map_err(|e| anyhow!("failed to generate nonce: {}", e))?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("encryption failed: {}", e))?;

        // Prepend nonce to ciphertext (same as Go implementation)
        let mut result = nonce_bytes;
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            return Err(anyhow!("ciphertext cannot be empty"));
        }

        if ciphertext.len() < NONCE_SIZE_X {
            return Err(anyhow!(
                "ciphertext too short, need at least {} bytes, got {}",
                NONCE_SIZE_X,
                ciphertext.len()
            ));
        }

        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_SIZE_X);
        let nonce = XNonce::from_slice(nonce_bytes);

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
        let cipher = ChaCha20Cipher::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
