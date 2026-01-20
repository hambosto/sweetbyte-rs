use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, ensure};

use crate::config::{AES_KEY_SIZE, AES_NONCE_SIZE};

pub struct AesGcm {
    inner: Aes256Gcm,
}

impl AesGcm {
    #[inline]
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Result<Self> {
        let inner = Aes256Gcm::new_from_slice(key)?;
        Ok(Self { inner })
    }

    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut result = self.inner.encrypt(&nonce, plaintext).map_err(|e| anyhow!("aes-gcm encryption failed: {e}"))?;

        result.splice(0..0, nonce.iter().copied());
        Ok(result)
    }

    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(ciphertext.len() >= AES_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", AES_NONCE_SIZE, ciphertext.len());

        let (nonce, data) = ciphertext.split_at(AES_NONCE_SIZE);
        self.inner.decrypt(Nonce::from_slice(nonce), data).map_err(|_| anyhow!("aes-gcm authentication failed"))
    }
}
