use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow, bail};

use crate::{
    config::{AES_KEY_SIZE, AES_NONCE_SIZE},
    crypto::derive::random_bytes,
};

pub struct AesCipher {
    aead: Aes256Gcm,
}

impl AesCipher {
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        let aead = Aes256Gcm::new_from_slice(key).expect("valid key size");
        Self { aead }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("plaintext cannot be empty");
        }

        let nonce_bytes: [u8; AES_NONCE_SIZE] = random_bytes()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .aead
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AES encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            bail!("ciphertext cannot be empty");
        }

        if ciphertext.len() < AES_NONCE_SIZE {
            bail!(
                "ciphertext too short, need at least {} bytes, got {}",
                AES_NONCE_SIZE,
                ciphertext.len()
            );
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.aead
            .decrypt(nonce, encrypted)
            .map_err(|_| anyhow!("AES authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; AES_KEY_SIZE];
        let cipher = AesCipher::new(&key);

        let plaintext = b"Hello, World!";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty() {
        let key = [0u8; AES_KEY_SIZE];
        let cipher = AesCipher::new(&key);

        assert!(cipher.encrypt(b"").is_err());
    }

    #[test]
    fn test_decrypt_empty() {
        let key = [0u8; AES_KEY_SIZE];
        let cipher = AesCipher::new(&key);

        assert!(cipher.decrypt(&[]).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = [0u8; AES_KEY_SIZE];
        let cipher = AesCipher::new(&key);

        assert!(cipher.decrypt(&[0u8; AES_NONCE_SIZE - 1]).is_err());
    }

    #[test]
    fn test_decrypt_tampered() {
        let key = [0u8; AES_KEY_SIZE];
        let cipher = AesCipher::new(&key);

        let plaintext = b"Hello, World!";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        if let Some(last) = ciphertext.last_mut() {
            *last ^= 0xFF;
        }

        assert!(cipher.decrypt(&ciphertext).is_err());
    }
}
