use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;
mod mac;

pub use aes_gcm::AesGcm;
pub use algorithm::{Aes256Gcm, XChaCha20Poly1305};
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::Derive;
pub use mac::Mac;

use crate::config::{ARGON_KEY_LEN, KEY_SIZE};

pub mod algorithm {
    pub struct Aes256Gcm;
    pub struct XChaCha20Poly1305;
}

pub trait CipherAlgorithm {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for algorithm::Aes256Gcm {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.encrypt(plaintext)
    }

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for algorithm::XChaCha20Poly1305 {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.encrypt(plaintext)
    }

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.decrypt(ciphertext)
    }
}

pub struct Cipher {
    aes: AesGcm,
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != ARGON_KEY_LEN {
            anyhow::bail!("invalid key length: expected {}, got {}", ARGON_KEY_LEN, key.len());
        }

        let aes_key = Self::extract_key(key, 0)?;
        let chacha_key = Self::extract_key(key, KEY_SIZE)?;

        Ok(Self { aes: AesGcm::new(aes_key)?, chacha: ChaCha20Poly1305::new(chacha_key)? })
    }

    pub fn encrypt<Algo: CipherAlgorithm>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Algo::encrypt(self, plaintext)
    }

    pub fn decrypt<Algo: CipherAlgorithm>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Algo::decrypt(self, ciphertext)
    }

    fn extract_key(key: &[u8], offset: usize) -> Result<&[u8; KEY_SIZE]> {
        key.get(offset..offset + KEY_SIZE)
            .context("Invalid key offset or length")?
            .try_into()
            .context("Failed to convert to fixed-size key")
    }
}
