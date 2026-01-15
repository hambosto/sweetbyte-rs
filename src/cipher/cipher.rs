use anyhow::{Context, Result};

use crate::cipher::aes_gcm::Aes256GcmCipher;
use crate::cipher::cacha20poly1305::ChaCha20Poly1305Cipher;
use crate::config::{AES_KEY_SIZE, ARGON_KEY_LEN, CHACHA_KEY_SIZE};
#[allow(non_snake_case)]
pub mod Algorithm {
    pub struct AES256Gcm;
    pub struct XChaCha20Poly1305;
}

pub struct Cipher {
    aes_gcm: Aes256GcmCipher,
    chacha20poly1305: ChaCha20Poly1305Cipher,
}

impl Cipher {
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        let aes_key: [u8; AES_KEY_SIZE] =
            key[..AES_KEY_SIZE].try_into().context("invalid AES key")?;

        let chacha_key: [u8; CHACHA_KEY_SIZE] = key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE]
            .try_into()
            .context("invalid ChaCha key")?;

        Ok(Self {
            aes_gcm: Aes256GcmCipher::new(&aes_key),
            chacha20poly1305: ChaCha20Poly1305Cipher::new(&chacha_key),
        })
    }

    pub fn encrypt<T: Selector>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        T::encrypt(self, plaintext)
    }

    pub fn decrypt<T: Selector>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        T::decrypt(self, ciphertext)
    }
}

pub trait Selector {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl Selector for Algorithm::AES256Gcm {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes_gcm.encrypt(plaintext)
    }

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes_gcm.decrypt(ciphertext)
    }
}

impl Selector for Algorithm::XChaCha20Poly1305 {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha20poly1305.encrypt(plaintext)
    }

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha20poly1305.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_creation() {
        let key = [0u8; ARGON_KEY_LEN];
        assert!(Cipher::new(&key).is_ok());
    }

    #[test]
    fn test_aes_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = cipher.encrypt::<Algorithm::AES256Gcm>(plaintext).unwrap();
        let decrypted = cipher.decrypt::<Algorithm::AES256Gcm>(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = cipher
            .encrypt::<Algorithm::XChaCha20Poly1305>(plaintext)
            .unwrap();
        let decrypted = cipher
            .decrypt::<Algorithm::XChaCha20Poly1305>(&ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dual_layer_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";

        let aes_encrypted = cipher.encrypt::<Algorithm::AES256Gcm>(plaintext).unwrap();
        let dual_encrypted = cipher
            .encrypt::<Algorithm::XChaCha20Poly1305>(&aes_encrypted)
            .unwrap();

        let chacha_decrypted = cipher
            .decrypt::<Algorithm::XChaCha20Poly1305>(&dual_encrypted)
            .unwrap();
        let decrypted = cipher
            .decrypt::<Algorithm::AES256Gcm>(&chacha_decrypted)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
