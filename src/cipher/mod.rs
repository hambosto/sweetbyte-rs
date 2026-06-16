use anyhow::{Context, Result};

mod aes256_gcm;
mod chacha20poly1305;
mod key;
mod signer;

use aes256_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
pub(crate) use key::Key;
pub(crate) use signer::Signer;

use crate::secret::Secret;
use crate::validation::KeyBytes32;

#[non_exhaustive]
pub(crate) enum CipherAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub(crate) struct Cipher {
    primary_cipher: Aes256Gcm,
    secondary_cipher: ChaCha20Poly1305,
}

impl Cipher {
    pub(crate) fn new(primary_key: &Secret, secondary_key: &Secret) -> Result<Self> {
        let primary_secret = KeyBytes32::try_new(primary_key.expose_secret().to_vec()).context("primary key must be 32 bytes")?;
        let secondary_secret = KeyBytes32::try_new(secondary_key.expose_secret().to_vec()).context("secondary key must be 32 bytes")?;
        let primary_cipher = Aes256Gcm::new(&primary_secret.into_secret()).context("failed to initialize primary cipher")?;
        let secondary_cipher = ChaCha20Poly1305::new(&secondary_secret.into_secret()).context("failed to initialize secondary cipher")?;

        Ok(Self { primary_cipher, secondary_cipher })
    }

    #[inline]
    pub(crate) fn encrypt(&self, algo: &CipherAlgorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.primary_cipher.encrypt(plaintext),
            CipherAlgorithm::ChaCha20Poly1305 => self.secondary_cipher.encrypt(plaintext),
        }
    }

    #[inline]
    pub(crate) fn decrypt(&self, algo: &CipherAlgorithm, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.primary_cipher.decrypt(ciphertext),
            CipherAlgorithm::ChaCha20Poly1305 => self.secondary_cipher.decrypt(ciphertext),
        }
    }
}
