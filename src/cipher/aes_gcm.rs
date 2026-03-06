use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Context, Result};

use crate::config::AES_NONCE_SIZE;

pub struct AesGcm {
    cipher: Aes256Gcm,
}

impl AesGcm {
    pub fn new(key: &[u8]) -> Result<Self> {
        Ok(Self { cipher: Aes256Gcm::new_from_slice(key)? })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!plaintext.is_empty(), "Cannot encrypt empty plaintext");

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, plaintext).context("AES-GCM encryption failed")?;
        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());

        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= AES_NONCE_SIZE, "Ciphertext too short (minimum {AES_NONCE_SIZE} bytes required)");

        let (nonce, ciphertext) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce);

        self.cipher.decrypt(nonce, ciphertext).context("AES-GCM decryption failed")
    }
}
