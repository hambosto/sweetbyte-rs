use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;
mod hash;
mod mac;
mod protected;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::Derive;
pub use hash::Hash;
pub use mac::Mac;
pub use protected::Protected;

use crate::config::{ARGON_KEY_LEN, KEY_SIZE};

pub mod algorithm {
    pub struct Aes256Gcm;

    pub struct XChaCha20Poly1305;
}

pub use algorithm::{Aes256Gcm, XChaCha20Poly1305};

pub trait CipherAlgorithm {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for algorithm::Aes256Gcm {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for algorithm::XChaCha20Poly1305 {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.decrypt(ciphertext)
    }
}

pub struct Cipher {
    aes: AesGcm,

    chacha: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        let split_key = key.split_at(KEY_SIZE);
        let aes_key: &[u8; KEY_SIZE] = split_key.0.try_into().context("invalid AES key length")?;
        let chacha_key: &[u8; KEY_SIZE] = split_key.1.try_into().context("invalid ChaCha key length")?;

        Ok(Self { aes: AesGcm::new(aes_key)?, chacha: ChaCha20Poly1305::new(chacha_key)? })
    }

    #[inline]
    pub fn encrypt<A: CipherAlgorithm>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        A::encrypt(self, plaintext)
    }

    #[inline]
    pub fn decrypt<A: CipherAlgorithm>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        A::decrypt(self, ciphertext)
    }
}
