//! High-level file encryption and decryption operations.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::ARGON_KEY_LEN;
use crate::crypto::{derive_key, generate_salt};
use crate::file::{create_file, get_file_info, open_file};
use crate::header::Header;
use crate::stream::Pipeline;
use crate::types::Processing;

/// Encrypts a file.
///
/// # Arguments
/// * `src_path` - Source file path
/// * `dest_path` - Destination file path
/// * `password` - Encryption password
pub fn encrypt(src_path: &Path, dest_path: &Path, password: &str) -> Result<()> {
    let src_file = open_file(src_path)?;

    let src_info = get_file_info(src_path)?.context("source file not found")?;

    let original_size = src_info.size;
    if original_size == 0 {
        bail!("cannot encrypt a file with zero size");
    }

    let salt = generate_salt()?;
    let key = derive_key(password.as_bytes(), &salt)?;

    let mut header = Header::new();
    header.set_original_size(original_size);
    header.set_protected(true);

    let header_bytes = header.marshal(&salt, &key)?;

    let mut dest_file = create_file(dest_path)?;

    // Write header
    std::io::Write::write_all(&mut dest_file, &header_bytes)?;

    // Process file through pipeline
    let key_array: [u8; ARGON_KEY_LEN] = key;
    let pipeline = Pipeline::new(&key_array, Processing::Encryption)?;
    pipeline.process(src_file, dest_file, original_size)?;

    Ok(())
}

/// Decrypts a file.
///
/// # Arguments
/// * `src_path` - Source file path
/// * `dest_path` - Destination file path
/// * `password` - Decryption password
pub fn decrypt(src_path: &Path, dest_path: &Path, password: &str) -> Result<()> {
    let mut src_file = open_file(src_path)?;

    let mut header = Header::new();
    header.unmarshal(&mut src_file)?;

    let salt = header.salt()?;
    let key = derive_key(password.as_bytes(), salt)?;

    header
        .verify(&key)
        .context("incorrect password or corrupt file")?;

    if !header.is_protected() {
        bail!("file is not protected");
    }

    let original_size = header.original_size();
    if original_size == 0 {
        bail!("cannot decrypt a file with zero size");
    }

    let dest_file = create_file(dest_path)?;

    // Process file through pipeline
    let key_array: [u8; ARGON_KEY_LEN] = key;
    let pipeline = Pipeline::new(&key_array, Processing::Decryption)?;
    pipeline.process(src_file, dest_file, original_size)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("source.txt");
        let enc_path = dir.path().join("encrypted.swx");
        let dec_path = dir.path().join("decrypted.txt");

        let original_content = b"Hello, World! This is a test file for encryption.";
        std::fs::write(&src_path, original_content).unwrap();

        // Encrypt
        encrypt(&src_path, &enc_path, "test_password_123").unwrap();
        assert!(enc_path.exists());

        // Decrypt
        decrypt(&enc_path, &dec_path, "test_password_123").unwrap();
        assert!(dec_path.exists());

        // Compare
        let decrypted_content = std::fs::read(&dec_path).unwrap();
        assert_eq!(decrypted_content, original_content);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("source.txt");
        let enc_path = dir.path().join("encrypted.swx");
        let dec_path = dir.path().join("decrypted.txt");

        std::fs::write(&src_path, b"Test content").unwrap();

        encrypt(&src_path, &enc_path, "correct_password").unwrap();

        let result = decrypt(&enc_path, &dec_path, "wrong_password");
        assert!(result.is_err());
    }
}
