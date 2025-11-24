pub mod decryptor;
pub mod encryptor;

use crate::file_manager::FileManager;
use anyhow::Result;

pub use decryptor::Decryptor;
pub use encryptor::Encryptor;

/// Processor orchestrates the encryption and decryption processes.
pub struct Processor {
    file_manager: FileManager,
}

impl Processor {
    /// Creates a new Processor with the given FileManager.
    pub fn new(file_manager: FileManager) -> Self {
        Self { file_manager }
    }

    pub fn encrypt(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        password: &str,
        progress_callback: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()> {
        let encryptor = Encryptor::new(&self.file_manager);
        encryptor.encrypt(src_path, dest_path, password, progress_callback)
    }

    pub fn decrypt(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        password: &str,
        progress_callback: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()> {
        let decryptor = Decryptor::new(&self.file_manager);
        decryptor.decrypt(src_path, dest_path, password, progress_callback)
    }
}

impl Default for Processor {
    fn default() -> Self {
        Self::new(FileManager::default())
    }
}
