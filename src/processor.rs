use std::io::{BufReader, Read, Write};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::cipher::Derive;
use crate::config::{ARGON_KEY_LEN, ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME, CONTENT_HASH_SIZE};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::FileMetadata;
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
        ensure!(size != 0, "cannot encrypt a file with zero size");

        let (filename, file_size, created_at, modified_at) = src.file_metadata()?;
        let metadata = FileMetadata::new(filename, file_size, created_at, modified_at);

        let content_hash = compute_content_hash(src)?;

        let salt: [u8; ARGON_SALT_LEN] = Derive::generate_salt()?;

        let key = Derive::new(self.password.as_bytes())?.derive_key(&salt, ARGON_MEMORY, ARGON_TIME, ARGON_THREADS)?;

        let header = write_header(metadata, content_hash, &salt, &key)?;

        let mut writer = dest.writer()?;
        writer.write_all(&header)?;

        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;

        Worker::new(&key, Processing::Encryption)?.process(reader, writer, size)?;
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
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        let mut reader = src.reader()?;
        let (header, key) = read_header(&mut reader, self.password.as_bytes())?;

        let size = header.file_size();
        ensure!(size != 0, "cannot decrypt a file with zero size");

        let reader = reader.into_inner();
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;

        Worker::new(&key, Processing::Decryption)?.process(reader, writer, size)?;
        Ok(())
    }
}

fn compute_content_hash(file: &File) -> Result<[u8; CONTENT_HASH_SIZE]> {
    let mut reader = file.reader()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer).context("failed to read file for hashing")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; CONTENT_HASH_SIZE];
    hash.copy_from_slice(&result);
    Ok(hash)
}

fn write_header(metadata: FileMetadata, content_hash: [u8; CONTENT_HASH_SIZE], salt: &[u8; ARGON_SALT_LEN], key: &[u8; ARGON_KEY_LEN]) -> Result<Vec<u8>> {
    let header = Header::new(metadata, content_hash)?;
    header.serialize(salt, key)
}

fn read_header(reader: &mut BufReader<std::fs::File>, password: &[u8]) -> Result<(Header, [u8; ARGON_KEY_LEN])> {
    let header = Header::deserialize(reader.get_mut())?;

    let salt = header.salt()?;
    let key = Derive::new(password)?.derive_key(salt, header.kdf_memory(), header.kdf_time().into(), header.kdf_parallelism().into())?;

    header.verify(&key).context("incorrect password or corrupt file")?;

    Ok((header, key))
}
