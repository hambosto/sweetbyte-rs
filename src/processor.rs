//! File Encryption/Decryption Processor
//!
//! This module provides the main high-level interface for encrypting and decrypting files
//! using the SweetByte cryptographic format. It orchestrates the entire encryption pipeline
//! including key derivation, metadata handling, header serialization, and secure data processing.
//!
//! # Architecture
//! The Processor acts as the main orchestrator that coordinates between:
//! - Key derivation using Argon2id with configurable parameters
//! - File metadata preservation and integrity verification via BLAKE3 hashing
//! - Header serialization/deserialization with Reed-Solomon error correction
//! - Multi-threaded cryptographic operations via the Worker system
//! - User interface feedback for operation progress
//!
//! # Security Model
//! - Uses Argon2id for password-based key derivation (memory-hard KDF)
//! - Implements authenticated encryption with associated data (AEAD)
//! - Provides integrity verification through BLAKE3 content hashing
//! - Supports constant-time operations to prevent timing attacks
//! - Uses cryptographically secure random salt generation

use std::io::Write;

use anyhow::{Context, Result, ensure};

use crate::cipher::{Derive, Hash};
use crate::config::{ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::Metadata;
use crate::types::Processing;
use crate::worker::Worker;

/// High-level file encryption and decryption processor
///
/// This struct provides the main API for encrypting and decrypting files using
/// the SweetByte format. It handles the complete cryptographic pipeline from
/// password-based key derivation through to final file output.
///
/// # Fields
/// - `password`: The user-provided password used for key derivation
///
/// # Security Considerations
/// - Password is stored as a String and used for Argon2id key derivation
/// - Memory-hard KDF parameters are configurable via config constants
/// - All cryptographic operations are performed by specialized sub-modules
/// - Integrity is verified through multiple layers (header auth + content hash)
///
/// # Usage Pattern
/// ```rust
/// let processor = Processor::new("user_password");
/// processor.encrypt(&mut source_file, &dest_file)?;
/// processor.decrypt(&encrypted_file, &output_file)?;
/// ```
pub struct Processor {
    /// User password for key derivation (stored in memory only)
    password: String,
}

impl Processor {
    /// Creates a new Processor instance with the specified password
    ///
    /// Initializes the processor with a user-provided password that will be
    /// used for Argon2id key derivation during encryption and decryption operations.
    ///
    /// # Arguments
    /// * `password` - Any type convertible to String, typically a string literal
    ///
    /// # Returns
    /// * `Self` - New Processor instance containing the password
    ///
    /// # Security Note
    /// The password is stored in memory as a String. In a production environment,
    /// consider using secure string handling to zero memory after use.
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Encrypts a source file to a destination file using SweetByte format
    ///
    /// Performs the complete encryption pipeline:
    /// 1. Validates source file is non-empty
    /// 2. Extracts file metadata (name, size)
    /// 3. Computes BLAKE3 content hash for integrity verification
    /// 4. Generates cryptographically secure salt
    /// 5. Derives encryption key using Argon2id
    /// 6. Creates and serializes authenticated header
    /// 7. Encrypts file content using multi-threaded worker
    /// 8. Displays operation summary to user
    ///
    /// # Arguments
    /// * `src` - Mutable reference to source file to encrypt
    /// * `dest` - Reference to destination file for encrypted output
    ///
    /// # Returns
    /// * `Result<()>` - Success or error information
    ///
    /// # Errors
    /// * Source file is empty (0 bytes)
    /// * File metadata extraction failures
    /// * Hash computation errors (I/O failures)
    /// * Salt generation failures (CSPRNG errors)
    /// * Key derivation failures (memory allocation, password issues)
    /// * Header serialization failures
    /// * File I/O errors during writing
    /// * Worker thread failures or encryption errors
    ///
    /// # Security Guarantees
    /// - Random 16-byte salt for each encryption (prevents rainbow table attacks)
    /// - Argon2id with configurable memory/time parameters (memory-hard KDF)
    /// - BLAKE3 hash for content integrity verification
    /// - Authenticated header with Reed-Solomon error correction
    /// - Multi-threaded encryption for performance without security compromise
    pub fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        // Prevent encryption of empty files (would be meaningless and vulnerable)
        ensure!(src.size()? != 0, "cannot encrypt a file with zero size");

        // Extract original filename and file size for metadata preservation
        let (filename, file_size) = src.file_metadata()?;

        // Compute BLAKE3 hash of source content for integrity verification during decryption
        // This ensures any corruption or tampering is detected
        let content_hash = Hash::new(src.reader()?, Some(file_size))?;

        // Create metadata object with original file information and content hash
        let metadata = Metadata::new(filename, file_size, *content_hash.as_bytes());

        // Generate cryptographically secure random salt for key derivation
        // 16 bytes provides 128 bits of entropy, sufficient for password-based KDF
        let salt = Derive::generate_salt::<ARGON_SALT_LEN>()?;

        // Derive encryption key from password using Argon2id with configured parameters
        // Argon2id is resistant to GPU/ASIC attacks and combines memory hardness with side-channel
        // resistance
        let key = Derive::new(self.password.as_bytes())?.derive_key(&salt, ARGON_MEMORY, ARGON_TIME, ARGON_THREADS)?;

        // Create authenticated header containing metadata and Reed-Solomon parity
        let header = Header::new(metadata)?;
        // Serialize header with salt and encrypt using derived key for authentication
        let header_bytes = header.serialize(&salt, &key)?;

        // Get fresh reader for source file and writer for destination
        let reader = src.reader()?;
        let mut writer = dest.writer()?;

        // Write authenticated header to start of encrypted file
        writer.write_all(&header_bytes)?;

        // Perform multi-threaded encryption of file content
        // Worker handles chunking, encryption, and parallel processing
        Worker::new(&key, Processing::Encryption)?.process(reader, writer, file_size)?;

        // Display encryption summary to user with original file information
        crate::ui::show_header_info(header.file_name(), header.file_size(), header.file_hash());

        Ok(())
    }

    /// Decrypts a source file to a destination file from SweetByte format
    ///
    /// Performs the complete decryption pipeline with comprehensive verification:
    /// 1. Validates source file existence
    /// 2. Deserializes and authenticates the file header
    /// 3. Derives decryption key using stored Argon2id parameters
    /// 4. Verifies header authenticity (detects wrong password/tampering)
    /// 5. Decrypts file content using multi-threaded worker
    /// 6. Verifies decrypted content integrity against stored hash
    /// 7. Displays operation summary to user
    ///
    /// # Arguments
    /// * `src` - Reference to encrypted source file
    /// * `dest` - Reference to destination file for decrypted output
    ///
    /// # Returns
    /// * `Result<()>` - Success or error information
    ///
    /// # Errors
    /// * Source file does not exist
    /// * Header deserialization failures (corrupt file, format errors)
    /// * Empty file detection (invalid SweetByte file)
    /// * Key derivation failures (wrong password, parameter errors)
    /// * Header authentication failures (wrong password or tampered header)
    /// * Decryption process failures (corrupt ciphertext, worker errors)
    /// * Content integrity verification failures (corrupted decrypted data)
    /// * File I/O errors during writing
    ///
    /// # Security Guarantees
    /// - Header authentication prevents decryption with wrong password
    /// - Reed-Solomon error correction recovers from limited corruption
    /// - Content hash verification ensures data integrity
    /// - Constant-time operations prevent timing attacks
    /// - All verification steps must pass for successful decryption
    pub fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        // Ensure the encrypted source file actually exists
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        // Open file handles for reading encrypted data and writing decrypted output
        let mut reader = src.reader()?;
        let writer = dest.writer()?;

        // Deserialize and authenticate header from the encrypted file
        // This step verifies the file format and extracts metadata
        let header = Header::deserialize(reader.get_mut())?;

        // Prevent decryption of files with zero size (invalid format)
        ensure!(header.file_size() != 0, "cannot decrypt a file with zero size");

        // Derive decryption key using the same Argon2id parameters from the header
        // This ensures only the correct password can decrypt the file
        let key = Derive::new(self.password.as_bytes())?.derive_key(
            header.salt()?,                  // Salt from encrypted file
            header.kdf_memory(),             // Memory cost parameter
            header.kdf_time().into(),        // Time cost parameter
            header.kdf_parallelism().into(), // Thread count
        )?;

        // Verify header authenticity using derived key
        // This detects wrong passwords or header tampering
        header.verify(&key).context("incorrect password or corrupt file")?;

        // Perform multi-threaded decryption of file content
        // Worker handles chunking, decryption, and parallel processing
        Worker::new(&key, Processing::Decryption)?.process(reader, writer, header.file_size())?;

        // Verify decrypted content integrity against original hash
        // This ensures the decrypted data matches what was originally encrypted
        Hash::new(dest.reader()?, Some(header.file_size()))?
            .verify(header.file_hash())
            .context("decrypted content integrity check failed")?;

        // Display decryption summary with recovered file information
        crate::ui::show_header_info(header.file_name(), header.file_size(), header.file_hash());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_processor_integration() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let filename = base_path.join("test_processor_integration.txt");
        let content = b"Integration test content for processor.";

        let enc_filename = base_path.join("test_processor_integration.txt.swx");
        let dec_filename = base_path.join("test_processor_integration_dec.txt");

        fs::write(&filename, content).unwrap();

        let mut src = File::new(&filename);
        let dest_enc = File::new(&enc_filename);
        let dest_dec = File::new(&dec_filename);

        let password = "strong_password";
        let processor = Processor::new(password);

        src.validate(true).unwrap();
        processor.encrypt(&mut src, &dest_enc).unwrap();

        assert!(dest_enc.exists());

        processor.decrypt(&dest_enc, &dest_dec).unwrap();

        assert!(dest_dec.exists());
        let decrypted_content = fs::read(&dec_filename).unwrap();
        assert_eq!(decrypted_content, content);
    }
}
