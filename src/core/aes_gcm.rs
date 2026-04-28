use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Context, Result};

use crate::config::{AES_NONCE_SIZE, KEY_SIZE};
use crate::secret::SecretBytes;

pub struct AesGcm {
    key: SecretBytes,
}

impl AesGcm {
    pub fn new(key: &[u8]) -> Result<Self> {
        anyhow::ensure!(key.len() == KEY_SIZE, "invalid key length");

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(!plaintext.is_empty(), "empty plaintext");

        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret()).context("cipher init failed")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).context("encryption failed")?;

        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= AES_NONCE_SIZE, "ciphertext too short");

        let (nonce_bytes, ciphertext) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret()).context("cipher init failed")?;

        cipher.decrypt(nonce, ciphertext).context("decryption failed")
    }
}
