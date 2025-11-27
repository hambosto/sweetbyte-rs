use crate::crypto::derive_key;
use crate::file;
use crate::header;
use crate::header::Header;
use crate::stream::Pipeline;
use crate::types::Processing;
use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::{Seek, SeekFrom};

/// Decrypts a file from source to destination using the provided password.
pub fn decrypt_file(
    src_path: &std::path::Path,
    dest_path: &std::path::Path,
    password: &str,
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
    let key = derive_key(password.as_bytes(), &salt)?;

    // Verify header
    header::verification::verify_header(&hdr, &key)?;

    // Check if protected
    if !hdr.is_protected() {
        return Err(anyhow!("file is not protected"));
    }

    // Get original size from header for progress tracking
    let original_size = hdr.original_size;

    // Open source file
    let mut src_file = File::open(src_path)?;

    // Seek to offset
    src_file.seek(SeekFrom::Start(offset))?;

    // Create destination file
    let dest_file = File::create(dest_path)?;

    // Process file content
    let pipeline = Pipeline::new(&key, Processing::Decryption)?;
    pipeline.process(src_file, dest_file, original_size)?;

    Ok(())
}
