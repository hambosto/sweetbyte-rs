pub mod decryptor;
pub mod encryptor;

use anyhow::Result;

pub use decryptor::Decryptor;
pub use encryptor::Encryptor;

/// Processor orchestrates the encryption and decryption processes.
pub struct Processor;

impl Processor {
    /// Creates a new Processor instance.
    pub fn new() -> Self {
        Self
    }

    pub fn encrypt(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        password: &str,
        progress_callback: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()> {
        let encryptor = Encryptor;
        encryptor.encrypt(src_path, dest_path, password, progress_callback)
    }

    pub fn decrypt(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        password: &str,
        progress_callback: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()> {
        let decryptor = Decryptor;
        decryptor.decrypt(src_path, dest_path, password, progress_callback)
    }
}

impl Default for Processor {
    fn default() -> Self {
        Self::new()
    }
}
