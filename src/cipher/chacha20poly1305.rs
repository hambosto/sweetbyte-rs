use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_NONCE_SIZE, KEY_SIZE};

pub struct ChaCha20Poly1305 {
    cipher: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        Ok(Self { cipher: XChaCha20Poly1305::new_from_slice(key)? })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            anyhow::bail!("empty plaintext");
        }

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, plaintext).map_err(|error| anyhow::anyhow!("chacha20poly1305 encrypt: {error}"))?;
        let mut result = Vec::with_capacity(CHACHA_NONCE_SIZE + ciphertext.len());

        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < CHACHA_NONCE_SIZE {
            anyhow::bail!("ciphertext too short");
        }

        let (nonce, ciphertext) = ciphertext.split_at(CHACHA_NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce);

        self.cipher.decrypt(nonce, ciphertext).map_err(|error| anyhow::anyhow!("chacha20poly1305 decrypt: {error}"))
    }
}
