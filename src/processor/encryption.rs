use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::Write;

use crate::crypto::{ARGON_SALT_LEN, derive_key, random_bytes};
use crate::file;
use crate::header;
use crate::header::Header;
use crate::stream::Pipeline;
use crate::types::Processing;

/// Encrypts a file from source to destination using the provided password.
pub fn encrypt_file(
    src_path: &std::path::Path,
    dest_path: &std::path::Path,
    password: &str,
) -> Result<()> {
    // Get original size using file module function
    let (_, src_info) = file::open_file(src_path)?;
    let original_size = src_info.len();

    if original_size == 0 {
        return Err(anyhow!("cannot encrypt a file with zero size"));
    }

    // Generate salt
    let salt = random_bytes(ARGON_SALT_LEN)?;

    // Derive key
    let key = derive_key(password.as_bytes(), &salt)?;

    // Create header
    let mut hdr = Header::new()?;
    hdr.set_original_size(original_size);
    hdr.set_protected(true);

    // Marshal header
    let header_bytes = header::marshal::marshal(&hdr, &salt, &key)?;

    // Open source file
    let src_file = File::open(src_path)?;

    // Create destination file
    let mut dest_file = File::create(dest_path)?;

    // Write header
    dest_file.write_all(&header_bytes)?;

    // Process file content
    let processor = Pipeline::new(&key, Processing::Encryption)?;
    processor.process(src_file, dest_file, original_size)?;

    Ok(())
}
