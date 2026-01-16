use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};

use super::random_bytes;
use crate::config::{AES_KEY_SIZE, AES_NONCE_SIZE};

pub struct AesGcm {
    inner: Aes256Gcm,
}

impl AesGcm {
    #[inline]
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        Self { inner: Aes256Gcm::new_from_slice(key).expect("valid key size") }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("plaintext cannot be empty");
        }

        let nonce_bytes: [u8; AES_NONCE_SIZE] = random_bytes()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self.inner.encrypt(nonce, plaintext).map_err(|e| anyhow!("AES encryption failed: {e}"))?;
        let mut result = Vec::with_capacity(AES_NONCE_SIZE + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(encrypted);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < AES_NONCE_SIZE {
            bail!("ciphertext too short: need at least {AES_NONCE_SIZE} bytes, got {}", ciphertext.len());
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.inner.decrypt(nonce, encrypted).map_err(|_| anyhow!("AES authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> AesGcm {
        AesGcm::new(&[0u8; AES_KEY_SIZE])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = test_cipher();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_empty_fails() {
        assert!(test_cipher().encrypt(b"").is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        assert!(test_cipher().decrypt(&[0u8; AES_NONCE_SIZE - 1]).is_err());
    }

    #[test]
    fn decrypt_tampered_fails() {
        let cipher = test_cipher();
        let mut ciphertext = cipher.encrypt(b"Hello, World!").unwrap();

        if let Some(last) = ciphertext.last_mut() {
            *last ^= 0xFF;
        }

        assert!(cipher.decrypt(&ciphertext).is_err());
    }
}
