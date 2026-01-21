//! High-level encryption and decryption orchestration.
//!
//! Provides [`Encryptor`] and [`Decryptor`] structs that coordinate
//! the complete encryption/decryption pipeline:
//!
//! - Password-based key derivation via Argon2id
//! - Secure header creation/verification
//! - Worker pipeline execution for chunked processing
//!
//! # Encryption Flow
//!
//! 1. Validate source file
//! 2. Generate random salt
//! 3. Derive 64-byte key from password + salt (Argon2id)
//! 4. Build and write secure header
//! 5. Process file content through Worker pipeline
//!
//! # Decryption Flow
//!
//! 1. Verify source file exists
//! 2. Read and deserialize header
//! 3. Derive key using password + salt from header
//! 4. Verify header HMAC (authenticates password)
//! 5. Process encrypted content through Worker pipeline

use std::io::{BufReader, Write};

use anyhow::{Context, Result, ensure};

use crate::cipher::Derive;
use crate::config::{ARGON_KEY_LEN, ARGON_SALT_LEN, CURRENT_VERSION, FLAG_PROTECTED};
use crate::file::File;
use crate::header::Header;
use crate::types::Processing;
use crate::worker::Worker;

/// High-level encryptor coordinating the complete encryption pipeline.
///
/// Takes a password and source file, produces an encrypted output file
/// with secure header and error-corrected ciphertext.
pub struct Encryptor {
    /// The password for key derivation.
    password: String,
}

impl Encryptor {
    /// Creates a new encryptor with the specified password.
    ///
    /// # Arguments
    ///
    /// * `password` - The encryption password (converted to String).
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Encrypts a source file to a destination file.
    ///
    /// The complete encryption flow:
    /// 1. Validate source file exists and has content
    /// 2. Generate random 32-byte salt for key derivation
    /// 3. Derive 64-byte key from password + salt (Argon2id, 64 MB memory, 3 iterations)
    /// 4. Build secure header with: magic bytes, salt, metadata, HMAC authentication
    /// 5. Write header to output file
    /// 6. Process file content through Worker pipeline (parallel chunk encryption)
    ///
    /// The header provides:
    /// - File format identification (magic bytes)
    /// - Key derivation salt (unique per file)
    /// - File metadata (original size, flags)
    /// - HMAC authentication (verifies correct password)
    ///
    /// # Arguments
    ///
    /// * `src` - The source file to encrypt (must exist and be non-empty).
    /// * `dest` - The destination file for encrypted output.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Source file is invalid or empty
    /// - Key derivation fails
    /// - Header creation fails
    /// - Worker pipeline processing fails
    pub fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        // Validate source file exists and has content
        src.validate(true)?;
        let size = src.size()?;
        ensure!(size != 0, "cannot encrypt a file with zero size");

        // Generate random salt for key derivation.
        // This salt is stored in the header and used during decryption.
        // Each encrypted file has a unique salt, even with the same password.
        let salt: [u8; ARGON_SALT_LEN] = Derive::generate_salt()?;

        // Derive 64-byte cryptographic key from password + salt.
        // First 32 bytes: encryption key (AES + ChaCha20)
        // Last 32 bytes: HMAC key (header authentication)
        let key = Derive::new(self.password.as_bytes())?.derive_with_salt(&salt)?;

        // Build secure header with file metadata and authentication.
        // This includes: version, flags, original size, salt, HMAC.
        let header = build_header(size, &salt, &key)?;

        // Write header to output file.
        // The header must be written first so it can be read during decryption.
        let mut writer = dest.writer()?;
        writer.write_all(&header)?;

        // Extract raw file handles for worker pipeline.
        // The worker needs direct access to the underlying file handles.
        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;

        // Process file content through encryption pipeline.
        // This handles reading, parallel encryption, and writing encrypted chunks.
        Worker::new(&key, Processing::Encryption)?.process(reader, writer, size)?;
        Ok(())
    }
}

/// High-level decryptor coordinating the complete decryption pipeline.
///
/// Takes a password and encrypted source file, produces a decrypted output file.
pub struct Decryptor {
    /// The password for key derivation.
    password: String,
}

impl Decryptor {
    /// Creates a new decryptor with the specified password.
    ///
    /// # Arguments
    ///
    /// * `password` - The decryption password (converted to String).
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Decrypts a source file to a destination file.
    ///
    /// # Arguments
    ///
    /// * `src` - The encrypted source file (must exist).
    /// * `dest` - The destination file for decrypted output.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Source file doesn't exist
    /// - Header deserialization fails
    /// - Key derivation fails
    /// - Header verification fails (wrong password or corrupt file)
    /// - Worker pipeline processing fails
    pub fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        // Read and verify the secure header
        let mut reader = src.reader()?;
        let header = read_and_verify_header(&mut reader, self.password.as_bytes())?;

        // Get original file size from header
        let size = header.original_size();
        ensure!(size != 0, "cannot decrypt a file with zero size");

        // Derive key using password and salt from header
        let key = Derive::new(self.password.as_bytes())?.derive_with_salt(header.salt()?)?;

        // Extract raw file handles for worker pipeline
        let reader = reader.into_inner();
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;

        // Process file content through decryption pipeline
        Worker::new(&key, Processing::Decryption)?.process(reader, writer, size)?;
        Ok(())
    }
}

/// Builds a secure header with file metadata and authentication.
///
/// # Arguments
///
/// * `size` - Original file size in bytes.
/// * `salt` - Random salt for key derivation.
/// * `key` - Derived cryptographic key for HMAC.
///
/// # Errors
///
/// Returns an error if header serialization fails.
fn build_header(size: u64, salt: &[u8; ARGON_SALT_LEN], key: &[u8; ARGON_KEY_LEN]) -> Result<Vec<u8>> {
    let h = Header::new(CURRENT_VERSION, size, FLAG_PROTECTED)?.serialize(salt, key)?;
    Ok(h)
}

/// Reads and verifies a secure header from an encrypted file.
///
/// # Arguments
///
/// * `reader` - Buffered reader positioned at file start.
/// * `password` - User's password for key derivation.
///
/// # Errors
///
/// Returns an error if:
/// - Header deserialization fails
/// - Key derivation fails
/// - HMAC verification fails (wrong password or corrupted file)
fn read_and_verify_header(reader: &mut BufReader<std::fs::File>, password: &[u8]) -> Result<Header> {
    // Deserialize header from file
    let header = Header::deserialize(reader.get_mut())?;

    // Derive key using password and salt from header
    let key = Derive::new(password)?.derive_with_salt(header.salt()?)?;

    // Verify header authenticity using HMAC
    header.verify(&key).context("incorrect password or corrupt file")?;

    Ok(header)
}
