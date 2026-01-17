use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cipher::{derive_key, random_bytes};
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN};
use crate::file::{create_file, get_file_info, open_file};
use crate::header::Header;
use crate::stream::Pipeline;
use crate::types::Processing;

pub struct Encryptor {
    password: String,
}

impl Encryptor {
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    pub fn encrypt(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let src_file = open_file(src_path)?;
        let original_size = self.validate_source_file(src_path)?;

        let salt: [u8; ARGON_SALT_LEN] = random_bytes()?;
        let key = derive_key(self.password.as_bytes(), &salt)?;

        let header = self.create_header(original_size, &salt, &key)?;
        self.write_encrypted_file(dest_path, &header, src_file, original_size, &key)?;

        Ok(())
    }

    fn validate_source_file(&self, src_path: &Path) -> Result<u64> {
        let src_info = get_file_info(src_path)?.context("source file not found")?;

        if src_info.size == 0 {
            bail!("cannot encrypt a file with zero size");
        }

        Ok(src_info.size)
    }

    fn create_header(&self, original_size: u64, salt: &[u8; ARGON_SALT_LEN], key: &[u8; ARGON_KEY_LEN]) -> Result<Vec<u8>> {
        let mut header = Header::new();
        header.set_original_size(original_size);
        header.set_protected(true);
        header.marshal(salt, key)
    }

    fn write_encrypted_file(&self, dest_path: &Path, header_bytes: &[u8], src_file: BufReader<File>, original_size: u64, key: &[u8; ARGON_KEY_LEN]) -> Result<()> {
        let mut dest_file = create_file(dest_path)?;
        dest_file.write_all(header_bytes)?;

        let src_file = src_file.into_inner();
        let pipeline = Pipeline::new(key, Processing::Encryption)?;
        pipeline.process(src_file, dest_file, original_size)?;

        Ok(())
    }
}

pub struct Decryptor {
    password: String,
}

impl Decryptor {
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    pub fn decrypt(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let mut src_file = open_file(src_path)?;
        let header = self.read_and_verify_header(&mut src_file)?;

        let original_size = header.original_size();
        if original_size == 0 {
            bail!("cannot decrypt a file with zero size");
        }

        let salt = header.salt()?;
        let key = derive_key(self.password.as_bytes(), salt)?;

        self.write_decrypted_file(dest_path, src_file, original_size, &key)?;

        Ok(())
    }

    fn read_and_verify_header(&self, src_file: &mut BufReader<File>) -> Result<Header> {
        let mut header = Header::new();
        header.unmarshal(src_file.get_mut())?;

        let salt = header.salt()?;
        let key = derive_key(self.password.as_bytes(), salt)?;

        header.verify(&key).context("incorrect password or corrupt file")?;

        if !header.is_protected() {
            bail!("file is not protected");
        }

        Ok(header)
    }

    fn write_decrypted_file(&self, dest_path: &Path, src_file: BufReader<File>, original_size: u64, key: &[u8; ARGON_KEY_LEN]) -> Result<()> {
        let dest_file = create_file(dest_path)?;

        let src_file = src_file.into_inner();
        let pipeline = Pipeline::new(key, Processing::Decryption)?;
        pipeline.process(src_file, dest_file, original_size)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("source.txt");
        let enc_path = dir.path().join("encrypted.swx");
        let dec_path = dir.path().join("decrypted.txt");
        let original_content = b"Hello, World! This is a test file for encryption.";

        fs::write(&src_path, original_content).unwrap();

        let encryptor = Encryptor::new("test_password_123");
        encryptor.encrypt(&src_path, &enc_path).unwrap();
        assert!(enc_path.exists());

        let decryptor = Decryptor::new("test_password_123");
        decryptor.decrypt(&enc_path, &dec_path).unwrap();
        assert!(dec_path.exists());

        let decrypted_content = fs::read(&dec_path).unwrap();
        assert_eq!(decrypted_content, original_content);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("source.txt");
        let enc_path = dir.path().join("encrypted.swx");
        let dec_path = dir.path().join("decrypted.txt");

        fs::write(&src_path, b"Test content").unwrap();

        Encryptor::new("correct_password").encrypt(&src_path, &enc_path).unwrap();

        let result = Decryptor::new("wrong_password").decrypt(&enc_path, &dec_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_zero_size_file() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("empty.txt");
        let enc_path = dir.path().join("encrypted.swx");

        fs::write(&src_path, b"").unwrap();

        let result = Encryptor::new("password").encrypt(&src_path, &enc_path);
        assert!(result.is_err());
    }
}
