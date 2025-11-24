use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};

use super::{random_bytes, Cipher};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// AES-256-GCM authenticated encryption.
#[derive(Clone)]
pub struct Aes {
    cipher: Aes256Gcm,
}

impl Aes {
    /// Creates a new AES-256-GCM cipher from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            anyhow::bail!("AES key must be {KEY_SIZE} bytes, got {}", key.len());
        }

        let cipher = Aes256Gcm::new_from_slice(key).context("failed to initialize AES-256-GCM")?;

        Ok(Self { cipher })
    }
}

impl Cipher for Aes {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        let nonce_bytes = random_bytes(NONCE_SIZE)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AES encryption failed: {e}"))?;

        Ok([nonce_bytes, ciphertext].concat())
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(
            data.len() >= NONCE_SIZE,
            "ciphertext too short: need at least {NONCE_SIZE} bytes, got {}",
            data.len()
        );

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = vec![0u8; KEY_SIZE];
        let cipher = Aes::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        assert!(ciphertext.len() > plaintext.len());
    }

    #[test]
    fn test_invalid_key_size() {
        assert!(Aes::new(&[0u8; 16]).is_err());
        assert!(Aes::new(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = Aes::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.encrypt(&[]).is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let cipher = Aes::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.decrypt(&[0u8; 5]).is_err());
    }
}
