use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;
mod mac;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::Derive;
pub use mac::Mac;

use crate::config::{ARGON_KEY_LEN, KEY_SIZE};
use crate::secret::SecretBytes;

pub enum CipherAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}

pub struct Cipher {
    aes: AesGcm,
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        if key.expose_secret().len() != ARGON_KEY_LEN {
            anyhow::bail!("invalid key length: expected {}, got {}", ARGON_KEY_LEN, key.expose_secret().len());
        }

        let aes_key = Self::extract_key(key.expose_secret(), 0)?;
        let chacha_key = Self::extract_key(key.expose_secret(), KEY_SIZE)?;

        Ok(Self { aes: AesGcm::new(aes_key)?, chacha: ChaCha20Poly1305::new(chacha_key)? })
    }

    pub fn encrypt(&self, algo: CipherAlgorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.aes.encrypt(plaintext),
            CipherAlgorithm::XChaCha20Poly1305 => self.chacha.encrypt(plaintext),
        }
    }

    pub fn decrypt(&self, algo: CipherAlgorithm, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.aes.decrypt(ciphertext),
            CipherAlgorithm::XChaCha20Poly1305 => self.chacha.decrypt(ciphertext),
        }
    }

    fn extract_key(key: &[u8], offset: usize) -> Result<&[u8; KEY_SIZE]> {
        key.get(offset..offset + KEY_SIZE)
            .context("Invalid key offset or length")?
            .try_into()
            .context("Failed to convert to fixed-size key")
    }
}
