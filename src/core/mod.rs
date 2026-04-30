use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod key;
mod signer;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use key::Key;
pub use signer::Signer;

use crate::config::KEY_LEN;
use crate::secret::SecretBytes;
use crate::validation::{IntoSecretBytes, KeyBytes32, KeyBytes64};

pub enum CipherAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct Cipher {
    first: AesGcm,
    second: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        let key = KeyBytes64::try_new(key.expose_secret().to_vec()).context("key must not be empty")?;
        let key_bytes = key.into_inner();
        let (first_key, second_key) = key_bytes.split_at(KEY_LEN);
        let aes_secret = KeyBytes32::try_new(first_key.to_vec()).context("failed to create AES-256-GCM secret")?;
        let chacha_secret = KeyBytes32::try_new(second_key.to_vec()).context("failed to create ChaCha20Poly1305 secret")?;

        let first = AesGcm::new(&aes_secret.into_secret()).context("failed to initialize AES-256-GCM cipher")?;
        let second = ChaCha20Poly1305::new(&chacha_secret.into_secret()).context("failed to initialize ChaCha20Poly1305 cipher")?;

        Ok(Self { first, second })
    }

    pub fn encrypt(&self, algo: &CipherAlgorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.first.encrypt(plaintext),
            CipherAlgorithm::ChaCha20Poly1305 => self.second.encrypt(plaintext),
        }
    }

    pub fn decrypt(&self, algo: &CipherAlgorithm, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.first.decrypt(ciphertext),
            CipherAlgorithm::ChaCha20Poly1305 => self.second.decrypt(ciphertext),
        }
    }
}
