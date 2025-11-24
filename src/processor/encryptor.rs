use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

use crate::crypto::{kdf, random};
use crate::file;
use crate::header;
use crate::header::Header;
use crate::stream::Pipeline;
use crate::types::Processing;

pub struct Encryptor;

impl Encryptor {
    pub fn encrypt(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        password: &str,
        progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()> {
        // Get original size using file module function
        let (_, src_info) = file::open_file(src_path)?;
        let original_size = src_info.len();

        if original_size == 0 {
            return Err(anyhow!("cannot encrypt a file with zero size"));
        }

        // Generate salt
        let salt = random::get_random_bytes(kdf::ARGON_SALT_LEN)?;

        // Derive key
        let key = kdf::hash(password.as_bytes(), &salt)?;

        // Create header
        let mut hdr = Header::new()?;
        hdr.set_original_size(original_size);
        hdr.set_protected(true);

        // Marshal header
        let header_bytes = header::marshal::marshal(&hdr, &salt, &key)?;

        // Create runtime for async execution
        let rt = Runtime::new()?;

        rt.block_on(async {
            // Open source file
            let src_file = File::open(src_path).await?;

            // Create destination file
            let mut dest_file = File::create(dest_path).await?;

            // Write header
            dest_file.write_all(&header_bytes).await?;

            // Process file content
            let pipeline = Pipeline::new(&key, Processing::Encryption)?;
            pipeline
                .process(src_file, dest_file, progress_callback)
                .await?;

            Ok(())
        })
    }
}
