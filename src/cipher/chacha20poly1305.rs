use anyhow::{Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use super::random_bytes;
use crate::config::{CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE};

pub struct ChaCha20Poly1305 {
    inner: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    #[inline]
    pub fn new(key: &[u8; CHACHA_KEY_SIZE]) -> Self {
        Self { inner: XChaCha20Poly1305::new_from_slice(key).expect("valid key size") }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("plaintext cannot be empty");
        }

        let nonce_bytes: [u8; CHACHA_NONCE_SIZE] = random_bytes()?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let encrypted = self.inner.encrypt(nonce, plaintext).map_err(|e| anyhow!("ChaCha20Poly1305 encryption failed: {e}"))?;
        let mut result = Vec::with_capacity(CHACHA_NONCE_SIZE + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(encrypted);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < CHACHA_NONCE_SIZE {
            bail!("ciphertext too short: need at least {CHACHA_NONCE_SIZE} bytes, got {}", ciphertext.len());
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(CHACHA_NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.inner.decrypt(nonce, encrypted).map_err(|_| anyhow!("ChaCha20Poly1305 authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&[0u8; CHACHA_KEY_SIZE])
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
        assert!(test_cipher().decrypt(&[0u8; CHACHA_NONCE_SIZE - 1]).is_err());
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
