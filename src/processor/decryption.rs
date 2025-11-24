use crate::crypto;
use crate::file;
use crate::header;
use crate::header::Header;
use crate::stream::Pipeline;
use crate::types::Processing;
use anyhow::{anyhow, Result};
use std::io::Seek;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncSeekExt;
use tokio::runtime::Runtime;

/// Decrypts a file from source to destination using the provided password.
pub fn decrypt_file(
    src_path: &std::path::Path,
    dest_path: &std::path::Path,
    password: &str,
    progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> Result<()> {
    // Open source file synchronously to read header
    let (mut src_file_sync, _) = file::open_file(src_path)?;

    // Unmarshal header
    let mut hdr = Header::new()?;
    header::marshal::unmarshal(&mut hdr, &mut src_file_sync)?;

    // Get current position (offset after header)
    let offset = src_file_sync.stream_position()?;

    // Drop sync file handle
    drop(src_file_sync);

    // Get salt from header
    let salt = hdr.salt()?;

    // Derive key
    let key = crypto::kdf::hash(password.as_bytes(), &salt)?;

    // Verify header
    header::verification::verify_header(&hdr, &key)?;

    // Check if protected
    if !hdr.is_protected() {
        return Err(anyhow!("file is not protected"));
    }

    // Create runtime for async execution
    let rt = Runtime::new()?;

    rt.block_on(async {
        // Open source file async
        let mut src_file = File::open(src_path).await?;

        // Seek to offset
        src_file.seek(tokio::io::SeekFrom::Start(offset)).await?;

        // Create destination file
        let dest_file = File::create(dest_path).await?;

        // Process file content
        let pipeline = Pipeline::new(&key, Processing::Decryption)?;
        pipeline
            .process(src_file, dest_file, progress_callback)
            .await?;

        Ok(())
    })
}
