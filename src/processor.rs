use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};

use crate::cipher::{ContentHash, Derive};
use crate::config::{ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::FileMetadata;
use crate::types::Processing;
use crate::worker::Worker;

pub struct Processor {
    password: String,
}

impl Processor {
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    pub fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        src.validate(true)?;
        let size = src.size()?;
        ensure!(size != 0, "cannot encrypt a file with zero size");

        let (filename, file_size, created_at, modified_at) = src.file_metadata()?;
        let metadata = FileMetadata::new(filename, file_size, created_at, modified_at);

        let mut file_content = Vec::new();
        src.reader()?.read_to_end(&mut file_content).context("failed to read file for hashing")?;
        let content_hash = *ContentHash::new(&file_content).as_bytes();

        let salt: [u8; ARGON_SALT_LEN] = Derive::generate_salt()?;

        let key = Derive::new(self.password.as_bytes())?.derive_key(&salt, ARGON_MEMORY, ARGON_TIME, ARGON_THREADS)?;

        let header = Header::new(metadata, content_hash)?;
        let header_bytes = header.serialize(&salt, &key)?;

        let mut writer = dest.writer()?;
        writer.write_all(&header_bytes)?;

        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;

        Worker::new(&key, Processing::Encryption)?.process(reader, writer, size)?;
        Ok(())
    }

    pub fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        let mut reader = src.reader()?;
        let header = Header::deserialize(reader.get_mut())?;

        let salt = header.salt()?;
        let key = Derive::new(self.password.as_bytes())?.derive_key(salt, header.kdf_memory(), header.kdf_time().into(), header.kdf_parallelism().into())?;

        header.verify(&key).context("incorrect password or corrupt file")?;

        let size = header.file_size();
        ensure!(size != 0, "cannot decrypt a file with zero size");

        let expected_hash = header.content_hash().context("content hash not found in header")?;

        let reader = reader.into_inner();
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;

        Worker::new(&key, Processing::Decryption)?.process(reader, writer, size)?;

        let mut decrypted_content = Vec::new();
        dest.reader()?.read_to_end(&mut decrypted_content).context("failed to read decrypted file for verification")?;
        ContentHash::new(&decrypted_content).verify(expected_hash).context("decrypted content integrity check failed")?;

        Ok(())
    }
}
