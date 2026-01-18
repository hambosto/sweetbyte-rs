use anyhow::{Context, Result};

mod aes_gcm;
mod chacha20poly1305;
mod derive;

pub use aes_gcm::AesGcm;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use derive::{derive_key, random_bytes};

use crate::config::{AES_KEY_SIZE, ARGON_KEY_LEN, CHACHA_KEY_SIZE};

#[allow(non_snake_case)]
pub mod Algorithm {
    pub struct Aes256Gcm;
    pub struct XChaCha20Poly1305;
}

pub trait CipherAlgorithm {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherAlgorithm for Algorithm::Aes256Gcm {
    #[inline]
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.encrypt(plaintext)
    }

    #[inline]
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherAlgorithm for Algorithm::XChaCha20Poly1305 {
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
        let aes_key: [u8; AES_KEY_SIZE] = key[..AES_KEY_SIZE].try_into().context("invalid aes-gcm key")?;
        let chacha_key: [u8; CHACHA_KEY_SIZE] = key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE].try_into().context("invalid chacha20poly1305 key")?;

        Ok(Self { aes: AesGcm::new(&aes_key), chacha: ChaCha20Poly1305::new(&chacha_key) })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; ARGON_KEY_LEN] {
        [0u8; ARGON_KEY_LEN]
    }

    #[test]
    fn cipher_creation() {
        assert!(Cipher::new(&test_key()).is_ok());
    }

    #[test]
    fn aes_roundtrip() {
        let cipher = Cipher::new(&test_key()).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt::<Algorithm::Aes256Gcm>(plaintext).unwrap();
        let decrypted = cipher.decrypt::<Algorithm::Aes256Gcm>(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha_roundtrip() {
        let cipher = Cipher::new(&test_key()).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt::<Algorithm::XChaCha20Poly1305>(plaintext).unwrap();
        let decrypted = cipher.decrypt::<Algorithm::XChaCha20Poly1305>(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn dual_layer_roundtrip() {
        let cipher = Cipher::new(&test_key()).unwrap();
        let plaintext = b"Hello, World!";

        let aes_encrypted = cipher.encrypt::<Algorithm::Aes256Gcm>(plaintext).unwrap();
        let dual_encrypted = cipher.encrypt::<Algorithm::XChaCha20Poly1305>(&aes_encrypted).unwrap();

        let chacha_decrypted = cipher.decrypt::<Algorithm::XChaCha20Poly1305>(&dual_encrypted).unwrap();
        let decrypted = cipher.decrypt::<Algorithm::Aes256Gcm>(&chacha_decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
