use anyhow::Result;

mod aes_gcm;
mod chacha20poly1305;
mod key;
mod signer;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use key::Key;
pub use signer::Signer;

use crate::config::{KEY_SIZE, SCRYPT_KEY_LEN};
use crate::secret::SecretBytes;

pub enum CipherAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct Cipher {
    aes: AesGcm,
    chacha: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &SecretBytes) -> Result<Self> {
        if key.expose_secret().len() != SCRYPT_KEY_LEN {
            anyhow::bail!("invalid key length");
        }

        let (aes_key, chacha_key) = key.expose_secret().split_at(KEY_SIZE);

        Ok(Self { aes: AesGcm::new(aes_key)?, chacha: ChaCha20Poly1305::new(chacha_key)? })
    }

    pub fn encrypt(&self, algo: &CipherAlgorithm, plaintext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.aes.encrypt(plaintext),
            CipherAlgorithm::ChaCha20Poly1305 => self.chacha.encrypt(plaintext),
        }
    }

    pub fn decrypt(&self, algo: &CipherAlgorithm, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match algo {
            CipherAlgorithm::Aes256Gcm => self.aes.decrypt(ciphertext),
            CipherAlgorithm::ChaCha20Poly1305 => self.chacha.decrypt(ciphertext),
        }
    }
}
