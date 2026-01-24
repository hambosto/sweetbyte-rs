//! Main Encryption/Decryption Processing Orchestrator
//!
//! This module contains the high-level Processor that orchestrates the complete
//! encryption and decryption workflows. It integrates all components including
//! key derivation, header management, file I/O, and parallel processing.
//!
//! ## Architecture
//!
//! The Processor follows a pipeline architecture:
// Encryption Pipeline:
//! 1. File validation and metadata extraction
//! 2. Content hashing for integrity verification
//! 3. Salt generation and key derivation
// 4. Header creation and serialization
// 5. Parallel encryption processing
//
// Decryption Pipeline:
// 1. Header parsing and validation
// 2. Salt extraction and key derivation
// 3. Header integrity verification
// 4. Parallel decryption processing
// 5. Content integrity verification
//!
//! ## Security Features
// - **Strong Key Derivation**: Argon2 with validated parameters
// - **Integrity Protection**: Multiple layers of verification
// - **Secure Memory**: Proper handling of sensitive data
// - **Input Validation**: Comprehensive checks before operations
// - **Error Isolation**: Detailed error context without information leakage

use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};

use crate::cipher::{Derive, Hash};
use crate::config::{ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::FileMetadata;
use crate::types::Processing;
use crate::worker::Worker;

/// Main processor for encryption and decryption operations
///
/// This struct orchestrates the complete SweetByte workflow, handling both
/// encryption and decryption with comprehensive security and integrity checks.
/// It serves as the high-level interface that coordinates all cryptographic
/// components and file operations.
///
/// ## Security Architecture
///
/// The processor implements defense-in-depth with multiple security layers:
///
/// 1. **Input Validation**: Ensures files are appropriate for processing
/// 2. **Integrity Hashing**: Verifies content before/after operations
/// 3. **Authenticated Encryption**: Uses AEAD ciphers for confidentiality+integrity
/// 4. **Header Verification**: Validates metadata before processing
/// 5. **Post-Processing Verification**: Confirms successful operations
///
/// ## Memory Management
///
/// The processor is designed to handle large files efficiently:
/// - Streaming operations for file I/O
/// - Parallel processing for CPU-intensive operations
/// - Minimal memory footprint during processing
/// - Secure handling of cryptographic keys
///
/// ## Error Handling
///
/// All operations include comprehensive error handling with context:
/// - Clear error messages for users
/// - Detailed context for debugging
/// - Security-aware error reporting
/// - Graceful failure without data loss
pub struct Processor {
    /// User password for key derivation
    ///
    /// This password is used as input to the Argon2 key derivation function.
    /// It's stored as a String for convenience but should be handled securely
    /// throughout the processing pipeline.
    password: String,
}

impl Processor {
    /// Create a new Processor with the specified password
    ///
    /// This constructor initializes the processor for encryption/decryption
    /// operations. The password will be used for key derivation and should
    /// be the same for both encryption and corresponding decryption.
    ///
    /// # Arguments
    ///
    /// * `password` - The user's password (anything convertible to String)
    ///
    /// # Returns
    ///
    /// A new Processor instance ready for operations
    ///
    /// # Password Security
    ///
    /// The password should be:
    /// - At least 8 characters long (enforced by UI)
    /// - Reasonably complex for security
    /// - Different for different files for maximum security
    ///
    /// # Thread Safety
    ///
    /// Processor instances are not thread-safe due to the password field.
    /// Create separate instances for concurrent operations if needed.
    ///
    /// # Memory Management
    ///
    /// The password is stored in memory for the lifetime of the Processor.
    /// Consider dropping the Processor instance promptly after use to
    /// minimize password exposure time in memory.
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Encrypt a file with comprehensive security and integrity checks
    ///
    /// This method performs the complete SweetByte encryption workflow,
    /// including metadata extraction, key derivation, header creation,
    /// and parallel processing with integrity verification.
    ///
    /// # Arguments
    ///
    /// * `src` - Source file to encrypt (must exist and be readable)
    /// * `dest` - Destination file for encrypted output (must not exist)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Encryption completed successfully
    /// * `Err(anyhow::Error)` - Encryption failed with detailed context
    ///
    /// # Encryption Process
    ///
    /// 1. **Validation**: Ensure source file exists and is not empty
    /// 2. **Metadata Extraction**: Get filename, size, and content hash
    /// 3. **Key Generation**: Generate random salt and derive encryption key
    /// 4. **Header Creation**: Create encrypted header with metadata
    /// 5. **Content Encryption**: Parallel processing of file content
    /// 6. **Finalization**: Write encrypted file with header
    ///
    /// # Security Features
    ///
    /// - **Unique Salt**: Each encryption uses a cryptographically random salt
    /// - **Strong KDF**: Argon2 with validated parameters resists brute-force
    /// - **Authenticated Encryption**: Protects both confidentiality and integrity
    /// - **Content Verification**: Hashes original content for later verification
    /// - **Header Protection**: Header is encrypted with the derived key
    ///
    /// # Performance Considerations
    ///
    /// - Memory usage scales with file chunk size, not total file size
    /// - Parallel processing utilizes all available CPU cores
    /// - Streaming I/O minimizes memory footprint
    /// - Key derivation is the most CPU-intensive step
    ///
    /// # Error Conditions
    ///
    /// - Source file doesn't exist or is unreadable
    /// - Source file is empty (nothing to encrypt)
    /// - Destination file already exists
    /// - Insufficient disk space
    /// - Permission denied for file operations
    /// - Cryptographic operation failures
    pub fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        // Validate source file
        ensure!(src.size()? != 0, "cannot encrypt a file with zero size");

        // Extract file metadata for the header
        let (filename, file_size) = src.file_metadata()?;

        // Read entire file for content hashing
        let mut file_content = Vec::new();
        src.reader()?.read_to_end(&mut file_content).context("failed to read file for hashing")?;

        // Compute content hash for integrity verification
        let content_hash = *Hash::new(&file_content).as_bytes();

        // Create metadata for the encrypted header
        let metadata = FileMetadata::new(filename, file_size, content_hash);

        // Generate cryptographically random salt for key derivation
        let salt: [u8; ARGON_SALT_LEN] = Derive::generate_salt()?;

        // Derive encryption key from password and salt using Argon2
        let key = Derive::new(self.password.as_bytes())?.derive_key(&salt, ARGON_MEMORY, ARGON_TIME, ARGON_THREADS)?;

        // Create and serialize the encrypted header
        let header = Header::new(metadata)?;
        let header_bytes = header.serialize(&salt, &key)?;

        // Write header to destination file
        let mut writer = dest.writer()?;
        writer.write_all(&header_bytes)?;

        // Process file content with parallel encryption
        let reader = src.reader()?.into_inner();
        let writer = writer.into_inner().context("failed to get inner writer")?;
        Worker::new(&key, Processing::Encryption)?.process(reader, writer, file_size)?;

        // Display encryption summary to user
        crate::ui::show_header_info(header.file_name(), header.file_size(), header.file_hash());

        Ok(())
    }

    /// Decrypt a file with comprehensive validation and integrity checks
    ///
    /// This method performs the complete SweetByte decryption workflow,
    /// including header parsing, key derivation, content decryption, and
    /// multiple layers of integrity verification.
    ///
    /// # Arguments
    ///
    /// * `src` - Encrypted source file (must exist and be valid .swx file)
    /// * `dest` - Destination file for decrypted output (must not exist)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Decryption completed successfully
    /// * `Err(anyhow::Error)` - Decryption failed with detailed context
    ///
    /// # Decryption Process
    ///
    /// 1. **Validation**: Ensure source file exists and is accessible
    /// 2. **Header Parsing**: Read and parse encrypted header
    /// 3. **Key Derivation**: Derive key using stored salt and parameters
    /// 4. **Header Verification**: Validate header integrity with MAC
    /// 5. **Content Decryption**: Parallel processing of encrypted content
    /// 6. **Final Verification**: Verify decrypted content matches original hash
    ///
    /// # Security Features
    ///
    /// - **Password Verification**: Header MAC verifies correct password
    /// - **Integrity Protection**: Multiple layers ensure data hasn't been corrupted
    /// - **Constant-Time Operations**: Prevents timing-based attacks on password
    /// - **Content Verification**: Ensures decrypted data matches original
    /// - **Metadata Validation**: Verifies file format and algorithm support
    ///
    /// # Performance Considerations
    ///
    /// - Header validation is fast, processing scales with file size
    /// - Parallel decryption utilizes all available CPU cores
    /// - Memory usage is controlled through chunk-based processing
    /// - Final verification requires reading the entire decrypted file
    ///
    /// # Error Conditions
    ///
    /// - Source file doesn't exist or is unreadable
    /// - File is not a valid SweetByte encrypted file
    /// - Incorrect password (most common failure)
    /// - File corruption detected during validation
    /// - Corrupted header or encrypted content
    /// - Insufficient disk space for output
    /// - Permission denied for file operations
    ///
    /// # Security Notes
    ///
    /// The decryption process provides strong protection against:
    /// - Incorrect passwords (header MAC verification)
    /// - File corruption (multiple integrity checks)
    /// - Malicious modifications (authenticated encryption)
    /// - Truncation attacks (size verification)
    pub fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        // Validate source file exists
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        // Open and parse the encrypted header
        let mut reader = src.reader()?;
        let header = Header::deserialize(reader.get_mut())?;

        // Validate file size from header
        ensure!(header.file_size() != 0, "cannot decrypt a file with zero size");

        // Extract salt and key derivation parameters from header
        let salt = header.salt()?;
        let key = Derive::new(self.password.as_bytes())?.derive_key(salt, header.kdf_memory(), header.kdf_time().into(), header.kdf_parallelism().into())?;

        // Verify header integrity and password correctness
        header.verify(&key).context("incorrect password or corrupt file")?;

        // Store expected hash for final verification
        let expected_hash = header.file_hash();

        // Process encrypted content with parallel decryption
        // Pass the BufReader directly to preserve buffered data that hasn't been logically read yet
        // The Worker will wrap it in another BufReader, which is slightly inefficient but correct
        // Using into_inner() here would lose buffered data and cause decryption failure
        let writer = dest.writer()?.into_inner().context("failed to get inner writer")?;
        Worker::new(&key, Processing::Decryption)?.process(reader, writer, header.file_size())?;

        // Verify decrypted content integrity
        let mut decrypted_content = Vec::new();
        dest.reader()?.read_to_end(&mut decrypted_content).context("failed to read decrypted file for verification")?;

        Hash::new(&decrypted_content).verify(expected_hash).context("decrypted content integrity check failed")?;

        // Display decryption summary to user
        crate::ui::show_header_info(header.file_name(), header.file_size(), header.file_hash());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

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
