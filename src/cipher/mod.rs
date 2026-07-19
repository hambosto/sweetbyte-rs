mod aead;
mod signer;
mod stretch;

use aead::AeadCipher;
use aes_gcm::Aes256Gcm;
use anyhow::{Context, Result};
use chacha20poly1305::XChaCha20Poly1305;
pub(crate) use signer::Signer;
pub(crate) use stretch::Stretch;

use crate::secret::Secret;
use crate::validation::KeyBytes;

pub(crate) enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub(crate) struct Cipher {
    primary_cipher: AeadCipher<Aes256Gcm>,
    secondary_cipher: AeadCipher<XChaCha20Poly1305>,
}

impl Cipher {
    pub(crate) fn new(primary_key: &Secret, secondary_key: &Secret) -> Result<Self> {
        let primary_key = KeyBytes::try_new(primary_key.expose_secret().to_vec()).context("primary key must be 32 bytes")?;
        let secondary_key = KeyBytes::try_new(secondary_key.expose_secret().to_vec()).context("secondary key must be 32 bytes")?;
        let primary_cipher = AeadCipher::<Aes256Gcm>::new(&primary_key.into_secret()).context("failed to initialize primary cipher")?;
        let secondary_cipher = AeadCipher::<XChaCha20Poly1305>::new(&secondary_key.into_secret()).context("failed to initialize secondary cipher")?;

        Ok(Self { primary_cipher, secondary_cipher })
    }

    #[inline]
    pub(crate) fn encrypt(&self, algorithm: &Algorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::Aes256Gcm => self.primary_cipher.encrypt(plaintext),
            Algorithm::ChaCha20Poly1305 => self.secondary_cipher.encrypt(plaintext),
        }
    }

    #[inline]
    pub(crate) fn decrypt(&self, algorithm: &Algorithm, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::Aes256Gcm => self.primary_cipher.decrypt(ciphertext),
            Algorithm::ChaCha20Poly1305 => self.secondary_cipher.decrypt(ciphertext),
        }
    }
}
