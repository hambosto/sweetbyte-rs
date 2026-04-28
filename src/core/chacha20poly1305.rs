use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_NONCE_SIZE, KEY_SIZE};
use crate::secret::SecretBytes;

pub struct ChaCha20Poly1305 {
    key: SecretBytes,
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            anyhow::bail!("invalid key length: expected {KEY_SIZE} bytes, found {}", key.len());
        }

        Ok(Self { key: SecretBytes::new(key.to_vec()) })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            anyhow::bail!("plaintext must not be empty");
        }

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).context("failed to encrypt")?;

        let mut result = Vec::with_capacity(CHACHA_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < CHACHA_NONCE_SIZE {
            anyhow::bail!("ciphertext too short: minimum {CHACHA_NONCE_SIZE} bytes");
        }

        let (nonce_bytes, ciphertext) = ciphertext.split_at(CHACHA_NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;
        cipher.decrypt(nonce, ciphertext).context("failed to decrypt")
    }
}
