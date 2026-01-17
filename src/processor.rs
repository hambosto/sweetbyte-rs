use std::io::{BufReader, Write};

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
        let size = src.size()?;
        if size == 0 {
            bail!("cannot encrypt a file with zero size");
        }

        let salt: [u8; ARGON_SALT_LEN] = random_bytes()?;
        let key = derive_key(self.password.as_bytes(), &salt)?;

        let header = build_header(size, &salt, &key)?;
        let mut writer = dest.writer()?;
        writer.write_all(&header)?;

        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;

        Pipeline::new(&key, Processing::Encryption)?.process(reader, writer, size)?;
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

        let mut reader = src.reader()?;
        let header = read_and_verify_header(&mut reader, self.password.as_bytes())?;

        let size = header.original_size();
        if size == 0 {
            bail!("cannot decrypt a file with zero size");
        }

        let key = derive_key(self.password.as_bytes(), header.salt()?)?;
        let reader = reader.into_inner();
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;

        Pipeline::new(&key, Processing::Decryption)?.process(reader, writer, size)?;
        Ok(())
    }
}

fn build_header(size: u64, salt: &[u8; ARGON_SALT_LEN], key: &[u8; ARGON_KEY_LEN]) -> Result<Vec<u8>> {
    let mut h = Header::new();
    h.set_original_size(size);
    h.set_protected(true);
    h.marshal(salt, key)
}

fn read_and_verify_header(reader: &mut BufReader<std::fs::File>, password: &[u8]) -> Result<Header> {
    let mut h = Header::new();
    h.unmarshal(reader.get_mut())?;

    let key = derive_key(password, h.salt()?)?;
    h.verify(&key).context("incorrect password or corrupt file")?;

    if !h.is_protected() {
        bail!("file is not protected");
    }

    Ok(h)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let enc = dir.path().join("enc.swx");
        let dec = dir.path().join("dec.txt");
        let data = b"Hello, World! This is a test file for encryption.";

        fs::write(&src, data).unwrap();

        let mut src_file = File::new(&src);
        Encryptor::new("pw").encrypt(&mut src_file, &File::new(&enc)).unwrap();
        Decryptor::new("pw").decrypt(&File::new(&enc), &File::new(&dec)).unwrap();

        assert_eq!(fs::read(&dec).unwrap(), data);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let enc = dir.path().join("enc.swx");

        fs::write(&src, b"data").unwrap();

        let mut src_file = File::new(&src);
        Encryptor::new("correct").encrypt(&mut src_file, &File::new(&enc)).unwrap();

        let err = Decryptor::new("wrong").decrypt(&File::new(&enc), &File::new("out.txt"));
        assert!(err.unwrap_err().to_string().contains("incorrect password"));
    }

    #[test]
    fn test_encrypt_zero_size_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("empty.txt");
        let enc = dir.path().join("enc.swx");

        fs::write(&src, b"").unwrap();

        let mut src_file = File::new(&src);
        assert!(Encryptor::new("pw").encrypt(&mut src_file, &File::new(&enc)).is_err());
    }

    #[test]
    fn test_encrypt_nonexistent_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("nope.txt");
        let enc = dir.path().join("enc.swx");

        let mut src_file = File::new(&src);
        assert!(Encryptor::new("pw").encrypt(&mut src_file, &File::new(&enc)).is_err());
    }

    #[test]
    fn test_decrypt_nonexistent_file() {
        let dir = tempdir().unwrap();
        let enc = dir.path().join("nope.swx");

        let err = Decryptor::new("pw").decrypt(&File::new(&enc), &File::new("out.txt"));
        assert!(err.unwrap_err().to_string().contains("source file not found"));
    }

    #[test]
    fn test_encrypt_large_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("large.txt");
        let enc = dir.path().join("large.swx");
        let dec = dir.path().join("large_dec.txt");

        let data = vec![b'A'; 1024 * 1024];
        fs::write(&src, &data).unwrap();

        let mut src_file = File::new(&src);
        Encryptor::new("pw").encrypt(&mut src_file, &File::new(&enc)).unwrap();
        Decryptor::new("pw").decrypt(&File::new(&enc), &File::new(&dec)).unwrap();

        assert_eq!(fs::read(&dec).unwrap(), data);
    }
}
