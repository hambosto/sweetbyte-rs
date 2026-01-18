use std::io::{BufReader, Write};

use anyhow::{Context, Result, bail};

use crate::cipher::KDF;
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN};
use crate::file::File;
use crate::header::Header;
use crate::types::Processing;
use crate::worker::Worker;

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

        let salt: [u8; ARGON_SALT_LEN] = KDF::generate_salt()?;
        let key = KDF::derive(self.password.as_bytes(), &salt)?;

        let header = build_header(size, &salt, key.as_bytes())?;
        let mut writer = dest.writer()?;
        writer.write_all(&header)?;

        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;

        Worker::new(key.as_bytes(), Processing::Encryption)?.process(reader, writer, size)?;
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

        let key = KDF::derive(self.password.as_bytes(), header.salt()?)?;
        let reader = reader.into_inner();
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;

        Worker::new(key.as_bytes(), Processing::Decryption)?.process(reader, writer, size)?;
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

    let key = KDF::derive(password, h.salt()?)?;
    h.verify(key.as_bytes()).context("incorrect password or corrupt file")?;

    if !h.is_protected() {
        bail!("file is not protected");
    }

    Ok(h)
}
