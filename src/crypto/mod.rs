//! Cryptographic primitives and utilities.
//!
//! This module provides the core cryptographic functionality for SweetByte, including:
//!
//! - **Ciphers**: AES-256-GCM and XChaCha20-Poly1305 encryption/decryption.
//! - **KDF**: Argon2id key derivation.
//! - **Random**: Cryptographically secure random number generation.
//!
//! The module is organized into submodules for better separation of concerns,
//! but common types and functions are re-exported for convenience.

pub mod cipher;
pub mod kdf;
pub mod random;

// Re-export for easier migration, but consumers should prefer using submodules
pub use cipher::{AesCipher, ChaCha20Cipher};
pub use kdf::{hash, ARGON_KEY_LEN, ARGON_SALT_LEN};
pub use random::get_random_bytes;

#[allow(dead_code)]
pub const KEY_SIZE: usize = 32;
