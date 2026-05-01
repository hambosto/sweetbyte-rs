use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::config::CHACHA_NONCE_SIZE;
use crate::secret::SecretBytes;
use crate::validation::{IntoSecretBytes, KeyBytes32, NonEmptyBytes};

pub struct ChaCha20Poly1305 {
    key: SecretBytes,
}

impl ChaCha20Poly1305 {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = NonEmptyBytes::try_new(plaintext.to_vec()).context("plaintext must not be empty")?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref().as_slice()).context("failed to encrypt")?;

        let mut result = Vec::with_capacity(CHACHA_NONCE_SIZE.saturating_add(ciphertext.len()));
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = NonEmptyBytes::try_new(ciphertext.to_vec()).context("ciphertext must not be empty")?;
        let (nonce_bytes, ciphertext) = ciphertext.as_ref().split_at(CHACHA_NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;

        cipher.decrypt(nonce, ciphertext).context("failed to decrypt")
    }
}
