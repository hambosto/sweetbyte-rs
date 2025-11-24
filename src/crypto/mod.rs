//! Cryptographic primitives and utilities.
//!
//! This module provides core cryptographic functionality including:
//! - **AEAD Ciphers**: AES-256-GCM and XChaCha20-Poly1305
//! - **Key Derivation**: Argon2id password hashing
//! - **Random Generation**: Cryptographically secure random bytes

mod aes;
mod chacha;
mod kdf;
mod random;

pub use aes::Aes;
pub use chacha::ChaCha;
pub use kdf::{ARGON_KEY_LEN, ARGON_SALT_LEN, derive_key};
pub use random::random_bytes;

/// Shared trait for authenticated encryption with associated data (AEAD) ciphers.
pub trait Cipher {
    /// Encrypts plaintext and returns nonce + ciphertext.
    fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Decrypts nonce + ciphertext and returns plaintext.
    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>>;
}
