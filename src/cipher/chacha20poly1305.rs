use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::{CHACHA_NONCE_SIZE, KEY_SIZE};

pub struct ChaCha20Poly1305 {
    inner: XChaCha20Poly1305,
}

impl ChaCha20Poly1305 {
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        let inner = XChaCha20Poly1305::new_from_slice(key)?;
        Ok(Self { inner })
    }

    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        let nonce_bytes = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let mut result = self
            .inner
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow!("chacha20poly1305 encryption failed: {e}"))?;

        result.splice(0..0, nonce_bytes.iter().copied());
        Ok(result)
    }

    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(ciphertext.len() >= CHACHA_NONCE_SIZE, "ciphertext too short: need at least {} bytes, got {}", CHACHA_NONCE_SIZE, ciphertext.len());

        let (nonce_bytes, data) = ciphertext.split_at(CHACHA_NONCE_SIZE);

        self.inner.decrypt(XNonce::from_slice(nonce_bytes), data).map_err(|_| anyhow!("chacha20poly1305 authentication failed"))
    }
}
