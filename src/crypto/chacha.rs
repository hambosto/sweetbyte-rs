use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use super::{random_bytes, Cipher};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

/// XChaCha20-Poly1305 authenticated encryption.
#[derive(Clone)]
pub struct ChaCha {
    cipher: XChaCha20Poly1305,
}

impl ChaCha {
    /// Creates a new XChaCha20-Poly1305 cipher from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            anyhow::bail!("ChaCha20 key must be {KEY_SIZE} bytes, got {}", key.len());
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .context("failed to initialize XChaCha20-Poly1305")?;

        Ok(Self { cipher })
    }
}

impl Cipher for ChaCha {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        let nonce_bytes = random_bytes(NONCE_SIZE)?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("ChaCha20 encryption failed: {e}"))?;

        Ok([nonce_bytes, ciphertext].concat())
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(
            data.len() >= NONCE_SIZE,
            "ciphertext too short: need at least {NONCE_SIZE} bytes, got {}",
            data.len()
        );

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("ChaCha20 decryption failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = vec![0u8; KEY_SIZE];
        let cipher = ChaCha::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        assert!(ciphertext.len() > plaintext.len());
    }

    #[test]
    fn test_invalid_key_size() {
        assert!(ChaCha::new(&[0u8; 16]).is_err());
        assert!(ChaCha::new(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = ChaCha::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.encrypt(&[]).is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let cipher = ChaCha::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.decrypt(&[0u8; 5]).is_err());
    }
}
