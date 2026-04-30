use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod key;
mod signer;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use key::Key;
pub use signer::Signer;

use crate::secret::SecretBytes;
use crate::validation::KeyBytes64;

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
        let (aes_secret, chacha_secret) = key.split()?;

        Ok(Self { first: AesGcm::new(&aes_secret.into_secret())?, second: ChaCha20Poly1305::new(&chacha_secret.into_secret())? })
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
