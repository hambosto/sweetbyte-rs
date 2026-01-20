use std::io::{BufReader, Write};

use anyhow::{Context, Result, ensure};

use crate::cipher::Kdf;
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN, CURRENT_VERSION, FLAG_PROTECTED};
use crate::file::File;
use crate::header::Header;
use crate::types::Processing;
use crate::worker::Worker;

/// Encryptor handles the encryption of files.
///
/// Takes a password, generates a salt and derived key using Argon2id,
/// creates a header with metadata, and processes the file content
/// through the worker pipeline for parallel encryption.
pub struct Encryptor {
    /// The password used for key derivation.
    password: String,
}

impl Encryptor {
    /// Creates a new Encryptor with the given password.
    ///
    /// # Arguments
    /// * `password` - The password, which can be any type implementing `Into<String>`.
    ///
    /// # Returns
    /// A new Encryptor instance.
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Encrypts a source file to a destination file.
    ///
    /// The encryption process:
    /// 1. Validates the source file exists and is not empty.
    /// 2. Generates a random salt.
    /// 3. Derives an encryption key from the password and salt.
    /// 4. Creates a header with metadata (version, flags, original size).
    /// 5. Writes the header to the output file.
    /// 6. Processes the file content through the worker pipeline.
    ///
    /// # Arguments
    /// * `src` - The source file to encrypt.
    /// * `dest` - The destination file for encrypted output.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if encryption failed.
    pub fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        // Validate source file.
        src.validate(true)?;
        let size = src.size()?;
        ensure!(size != 0, "cannot encrypt a file with zero size");

        // Generate salt and derive key using Argon2id.
        let salt: [u8; ARGON_SALT_LEN] = Kdf::generate_salt()?;
        let key = Kdf::derive(self.password.as_bytes(), &salt)?;

        // Build and write header.
        let header = build_header(size, &salt, key.as_bytes())?;
        let mut writer = dest.writer()?;
        writer.write_all(&header)?;

        // Extract raw file handles for the worker.
        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;

        // Process file content through worker pipeline.
        Worker::new(key.as_bytes(), Processing::Encryption)?.process(reader, writer, size)?;
        Ok(())
    }
}

/// Decryptor handles the decryption of encrypted files.
///
/// Reads and verifies the file header, derives the decryption key,
/// and processes the encrypted content through the worker pipeline.
pub struct Decryptor {
    /// The password used for key derivation.
    password: String,
}

impl Decryptor {
    /// Creates a new Decryptor with the given password.
    ///
    /// # Arguments
    /// * `password` - The password, which can be any type implementing `Into<String>`.
    ///
    /// # Returns
    /// A new Decryptor instance.
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Decrypts a source file to a destination file.
    ///
    /// The decryption process:
    /// 1. Verifies the source file exists.
    /// 2. Reads and verifies the header (magic bytes, version, flags).
    /// 3. Derives the decryption key from the password and stored salt.
    /// 4. Verifies the header MAC using the derived key.
    /// 5. Processes the encrypted content through the worker pipeline.
    ///
    /// # Arguments
    /// * `src` - The encrypted source file.
    /// * `dest` - The destination file for decrypted output.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if decryption failed.
    pub fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        // Verify source file exists.
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        // Read and verify the header.
        let mut reader = src.reader()?;
        let header = read_and_verify_header(&mut reader, self.password.as_bytes())?;

        // Get original file size from header.
        let size = header.original_size();
        ensure!(size != 0, "cannot decrypt a file with zero size");

        // Derive key using the salt from the header.
        let key = Kdf::derive(self.password.as_bytes(), header.salt()?)?;
        let reader = reader.into_inner();
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;

        // Process file content through worker pipeline.
        Worker::new(key.as_bytes(), Processing::Decryption)?.process(reader, writer, size)?;
        Ok(())
    }
}

/// Builds a file header with the given parameters.
///
/// The header contains version, flags, original size, salt, and MAC.
///
/// # Arguments
/// * `size` - The original file size in bytes.
/// * `salt` - The salt used for key derivation.
/// * `key` - The derived encryption key.
///
/// # Returns
/// The serialized header as a byte vector.
fn build_header(size: u64, salt: &[u8; ARGON_SALT_LEN], key: &[u8; ARGON_KEY_LEN]) -> Result<Vec<u8>> {
    Header::new(CURRENT_VERSION, size, FLAG_PROTECTED)?.serialize(salt, key)
}

/// Reads and verifies the file header.
///
/// Deserializes the header from the reader and verifies its integrity
/// using HMAC-SHA256 with the derived key.
///
/// # Arguments
/// * `reader` - The buffered reader positioned at the start of the file.
/// * `password` - The password used for key derivation.
///
/// # Returns
/// The verified Header on success, or an error if verification failed.
fn read_and_verify_header(reader: &mut BufReader<std::fs::File>, password: &[u8]) -> Result<Header> {
    // Deserialize header from the file.
    let header = Header::deserialize(reader.get_mut())?;

    // Derive key using the salt from the header.
    let key = Kdf::derive(password, header.salt()?)?;
    // Verify header integrity using HMAC.
    header.verify(key.as_bytes()).context("incorrect password or corrupt file")?;

    Ok(header)
}
