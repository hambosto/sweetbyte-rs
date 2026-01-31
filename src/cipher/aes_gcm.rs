use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::Result;

use crate::config::{AES_NONCE_SIZE, KEY_SIZE};

pub struct AesGcm {
    cipher: Aes256Gcm,
}

impl AesGcm {
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        Ok(Self { cipher: Aes256Gcm::new_from_slice(key)? })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            anyhow::bail!("empty plaintext");
        }

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, plaintext).map_err(|error| anyhow::anyhow!("aes-gcm encrypt: {error}"))?;

        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < AES_NONCE_SIZE {
            anyhow::bail!("ciphertext too short");
        }

        let (nonce, ciphertext) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce);

        self.cipher.decrypt(nonce, ciphertext).map_err(|error| anyhow::anyhow!("aes-gcm decrypt: {error}"))
    }
}
