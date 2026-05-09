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
use crate::validation::KeyBytes32;

pub enum CipherAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct Cipher {
    first_cipher: AesGcm,
    second_cipher: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(first_key: &SecretBytes, second_key: &SecretBytes) -> Result<Self> {
        let first_secret = KeyBytes32::try_new(first_key.expose_secret().to_vec()).context("first key must be 32 bytes")?;
        let second_secret = KeyBytes32::try_new(second_key.expose_secret().to_vec()).context("second key must be 32 bytes")?;

        let first_cipher = AesGcm::new(&first_secret.into_secret()).context("failed to initialize first cipher")?;
        let second_cipher = ChaCha20Poly1305::new(&second_secret.into_secret()).context("failed to initialize second cipher")?;

        Ok(Self { first_cipher, second_cipher })
    }

    pub fn encrypt(&self, algo: &CipherAlgorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.first_cipher.encrypt(plaintext),
            CipherAlgorithm::ChaCha20Poly1305 => self.second_cipher.encrypt(plaintext),
        }
    }

    pub fn decrypt(&self, algo: &CipherAlgorithm, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.first_cipher.decrypt(ciphertext),
            CipherAlgorithm::ChaCha20Poly1305 => self.second_cipher.decrypt(ciphertext),
        }
    }
}
