//! Cryptographic modules for SweetByte.

pub mod aes;
pub mod chacha;
pub mod cipher;
pub mod derive;

pub use cipher::Cipher;
pub use derive::{derive_key, generate_salt, random_bytes};
