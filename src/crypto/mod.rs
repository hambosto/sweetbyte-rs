pub mod aes_gcm;
pub mod chacha20;
pub mod derive;

pub use aes_gcm::AesCipher;
pub use chacha20::ChaCha20Cipher;
pub use derive::*;

#[allow(dead_code)]
pub const KEY_SIZE: usize = 32;
