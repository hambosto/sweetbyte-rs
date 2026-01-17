use std::io::Write;

use anyhow::{Context, Result, bail};

use crate::cipher::{derive_key, random_bytes};
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN};
use crate::file::File;
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

    pub fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        src.validate(true)?;
        let original_size = src.size()?;

        if original_size == 0 {
            bail!("cannot encrypt a file with zero size");
        }

        let salt: [u8; ARGON_SALT_LEN] = random_bytes()?;
        let key = derive_key(self.password.as_bytes(), &salt)?;

        let header = self.create_header(original_size, &salt, &key)?;
        self.write_encrypted_file(dest, &header, src, original_size, &key)?;

        Ok(())
    }

    fn create_header(&self, original_size: u64, salt: &[u8; ARGON_SALT_LEN], key: &[u8; ARGON_KEY_LEN]) -> Result<Vec<u8>> {
        let mut header = Header::new();
        header.set_original_size(original_size);
        header.set_protected(true);
        header.marshal(salt, key)
    }

    fn write_encrypted_file(&self, dest: &File, header_bytes: &[u8], src: &File, original_size: u64, key: &[u8; ARGON_KEY_LEN]) -> Result<()> {
        let mut dest_writer = dest.writer()?;
        dest_writer.write_all(header_bytes)?;

        let src_reader = src.reader()?.into_inner();
        let dest_writer = dest_writer.into_inner().context("failed to get inner writer")?;

        let pipeline = Pipeline::new(key, Processing::Encryption)?;
        pipeline.process(src_reader, dest_writer, original_size)?;

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

    pub fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        if !src.exists() {
            bail!("source file not found: {}", src.path().display());
        }

        let mut src_reader = src.reader()?;
        let header = self.read_and_verify_header(&mut src_reader)?;

        let original_size = header.original_size();
        if original_size == 0 {
            bail!("cannot decrypt a file with zero size");
        }

        let salt = header.salt()?;
        let key = derive_key(self.password.as_bytes(), salt)?;
        self.write_decrypted_file(dest, src_reader, original_size, &key)?;

        Ok(())
    }

    fn read_and_verify_header(&self, src_reader: &mut std::io::BufReader<std::fs::File>) -> Result<Header> {
        let mut header = Header::new();
        header.unmarshal(src_reader.get_mut())?;

        let salt = header.salt()?;
        let key = derive_key(self.password.as_bytes(), salt)?;

        header.verify(&key).context("incorrect password or corrupt file")?;

        if !header.is_protected() {
            bail!("file is not protected");
        }

        Ok(header)
    }

    fn write_decrypted_file(&self, dest: &File, src_reader: std::io::BufReader<std::fs::File>, original_size: u64, key: &[u8; ARGON_KEY_LEN]) -> Result<()> {
        let dest_writer = dest.writer()?;

        let src_file = src_reader.into_inner();
        let dest_file = dest_writer.into_inner().context("failed to get inner writer")?;

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

        let mut src_file = File::new(&src_path);
        let enc_file = File::new(&enc_path);
        let dec_file = File::new(&dec_path);

        let encryptor = Encryptor::new("test_password_123");
        encryptor.encrypt(&mut src_file, &enc_file).unwrap();
        assert!(enc_file.exists());

        let decryptor = Decryptor::new("test_password_123");
        decryptor.decrypt(&enc_file, &dec_file).unwrap();
        assert!(dec_file.exists());

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

        let mut src_file = File::new(&src_path);
        let enc_file = File::new(&enc_path);
        let dec_file = File::new(&dec_path);

        Encryptor::new("correct_password").encrypt(&mut src_file, &enc_file).unwrap();

        let result = Decryptor::new("wrong_password").decrypt(&enc_file, &dec_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("incorrect password"));
    }

    #[test]
    fn test_encrypt_zero_size_file() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("empty.txt");
        let enc_path = dir.path().join("encrypted.swx");

        fs::write(&src_path, b"").unwrap();

        let mut src_file = File::new(&src_path);
        let enc_file = File::new(&enc_path);

        let result = Encryptor::new("password").encrypt(&mut src_file, &enc_file);
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("file is empty") || error_msg.contains("cannot encrypt a file with zero size"), "Unexpected error: {}", error_msg);
    }

    #[test]
    fn test_encrypt_nonexistent_file() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("nonexistent.txt");
        let enc_path = dir.path().join("encrypted.swx");

        let mut src_file = File::new(&src_path);
        let enc_file = File::new(&enc_path);

        let result = Encryptor::new("password").encrypt(&mut src_file, &enc_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_nonexistent_file() {
        let dir = tempdir().unwrap();
        let enc_path = dir.path().join("nonexistent.swx");
        let dec_path = dir.path().join("decrypted.txt");

        let enc_file = File::new(&enc_path);
        let dec_file = File::new(&dec_path);

        let result = Decryptor::new("password").decrypt(&enc_file, &dec_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("source file not found"));
    }

    #[test]
    fn test_encrypt_large_file() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("large.txt");
        let enc_path = dir.path().join("large.swx");
        let dec_path = dir.path().join("large_dec.txt");

        let large_content = vec![b'A'; 1024 * 1024];
        fs::write(&src_path, &large_content).unwrap();

        let mut src_file = File::new(&src_path);
        let enc_file = File::new(&enc_path);
        let dec_file = File::new(&dec_path);

        Encryptor::new("password").encrypt(&mut src_file, &enc_file).unwrap();
        Decryptor::new("password").decrypt(&enc_file, &dec_file).unwrap();

        let decrypted = fs::read(&dec_path).unwrap();
        assert_eq!(decrypted.len(), large_content.len());
        assert_eq!(decrypted, large_content);
    }
}
