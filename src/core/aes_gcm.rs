use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::{Context, Result};

use crate::config::AES_NONCE_SIZE;
use crate::secret::SecretBytes;
use crate::validation::{IntoSecretBytes, KeyBytes32, NonEmptyBytes};

pub struct AesGcm {
    key: SecretBytes,
}

impl AesGcm {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = KeyBytes32::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;

        Ok(Self { key: key.into_secret() })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = NonEmptyBytes::try_new(plaintext.to_vec()).context("plaintext must not be empty")?;
        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref().as_slice()).context("failed to encrypt")?;

        let mut result = Vec::with_capacity(AES_NONCE_SIZE.saturating_add(ciphertext.len()));
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = NonEmptyBytes::try_new(ciphertext.to_vec()).context("ciphertext must not be empty")?;
        let (nonce_bytes, ciphertext) = ciphertext.as_ref().split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret()).context("failed to initialize cipher")?;

        cipher.decrypt(nonce, ciphertext).context("failed to decrypt")
    }
}
