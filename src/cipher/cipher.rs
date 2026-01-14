use anyhow::{Context, Result};

use crate::cipher::aes::AesCipher;
use crate::cipher::chacha::ChachaCipher;
use crate::config::{AES_KEY_SIZE, ARGON_KEY_LEN, CHACHA_KEY_SIZE};

pub mod algorithm {
    pub struct AESGcm;
    pub struct XChaCha20Poly1305;
}

pub struct Cipher {
    aes: AesCipher,
    chacha: ChachaCipher,
}

impl Cipher {
    pub fn new(key: &[u8; ARGON_KEY_LEN]) -> Result<Self> {
        let aes_key: [u8; AES_KEY_SIZE] =
            key[..AES_KEY_SIZE].try_into().context("invalid AES key")?;

        let chacha_key: [u8; CHACHA_KEY_SIZE] = key[AES_KEY_SIZE..AES_KEY_SIZE + CHACHA_KEY_SIZE]
            .try_into()
            .context("invalid ChaCha key")?;

        Ok(Self {
            aes: AesCipher::new(&aes_key),
            chacha: ChachaCipher::new(&chacha_key),
        })
    }

    pub fn encrypt<T: CipherSelector>(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        T::encrypt(self, plaintext)
    }

    pub fn decrypt<T: CipherSelector>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        T::decrypt(self, ciphertext)
    }
}

pub trait CipherSelector {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl CipherSelector for algorithm::AESGcm {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.encrypt(plaintext)
    }

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.aes.decrypt(ciphertext)
    }
}

impl CipherSelector for algorithm::XChaCha20Poly1305 {
    fn encrypt(cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.encrypt(plaintext)
    }

    fn decrypt(cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        cipher.chacha.decrypt(ciphertext)
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
        let ciphertext = cipher.encrypt::<algorithm::AESGcm>(plaintext).unwrap();
        let decrypted = cipher.decrypt::<algorithm::AESGcm>(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = cipher
            .encrypt::<algorithm::XChaCha20Poly1305>(plaintext)
            .unwrap();
        let decrypted = cipher
            .decrypt::<algorithm::XChaCha20Poly1305>(&ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dual_layer_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];
        let cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";

        let aes_encrypted = cipher.encrypt::<algorithm::AESGcm>(plaintext).unwrap();
        let dual_encrypted = cipher
            .encrypt::<algorithm::XChaCha20Poly1305>(&aes_encrypted)
            .unwrap();

        let chacha_decrypted = cipher
            .decrypt::<algorithm::XChaCha20Poly1305>(&dual_encrypted)
            .unwrap();
        let decrypted = cipher
            .decrypt::<algorithm::AESGcm>(&chacha_decrypted)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
