//! High-level file processing orchestration.
//!
//! This module provides the `Processor` struct, which coordinates the entire encryption/decryption
//! lifecycle. It handles:
//! - File verification
//! - Key derivation (Argon2)
//! - Header creation and parsing
//! - Content hashing (BLAKE3)
//! - Delegating bulk processing to the [`crate::worker::Worker`].

use anyhow::{Context, Result, ensure};
use tokio::io::AsyncWriteExt;

use crate::cipher::{Derive, Hash};
use crate::config::{ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::Metadata;
use crate::types::Processing;
use crate::worker::Worker;

/// The main entry point for processing files.
///
/// Holds the user's password and coordinates operations on files.
pub struct Processor {
    /// The user-provided password used for key derivation.
    password: String,
}

impl Processor {
    /// Creates a new processor with the given password.
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    /// Encrypts a source file to a destination file.
    ///
    /// # Process
    ///
    /// 1. Validate source file.
    /// 2. Hash source content (for integrity verification later).
    /// 3. Derive encryption keys from password + random salt.
    /// 4. Create and serialize the secure header.
    /// 5. Write header to destination.
    /// 6. Process body using the concurrent `Worker`.
    pub async fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        // Ensure source is valid.
        ensure!(src.size().await? != 0, "cannot encrypt a file with zero size");

        // Gather metadata.
        let (filename, file_size) = src.file_metadata().await?;

        // Compute hash of the plaintext.
        // This requires reading the full file once before encryption.
        // While this adds I/O, it guarantees we can verify integrity after decryption.
        let content_hash = Hash::new(src.reader().await?, Some(file_size)).await?;

        // Prepare metadata struct.
        let metadata = Metadata::new(filename, file_size, *content_hash.as_bytes());

        // Generate a new random salt for this file.
        let salt = Derive::generate_salt::<ARGON_SALT_LEN>()?;

        // Derive the master key using Argon2id.
        // This is a CPU-intensive operation.
        let key = Derive::new(self.password.as_bytes())?.derive_key(&salt, ARGON_MEMORY, ARGON_TIME, ARGON_THREADS)?;

        // Construct the file header.
        let header = Header::new(metadata)?;

        // Serialize the header using the derived key (for HMAC).
        let header_bytes = header.serialize(&salt, &key)?;

        // Open streams.
        let reader = src.reader().await?;
        let mut writer = dest.writer().await?;

        // Write the header first.
        writer.write_all(&header_bytes).await?;

        // Delegate bulk encryption to the worker.
        Worker::new(&key, Processing::Encryption)?.process(reader, writer, file_size).await?;

        // Display summary to user.
        crate::ui::show_header_info(header.file_name(), header.file_size(), header.file_hash());

        Ok(())
    }

    /// Decrypts a source file to a destination file.
    ///
    /// # Process
    ///
    /// 1. Read and parse the header.
    /// 2. Derive keys using the salt found in the header.
    /// 3. Verify header integrity (HMAC check).
    /// 4. Process body using the concurrent `Worker`.
    /// 5. Hash the decrypted output and compare with the hash stored in the header.
    pub async fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        ensure!(src.exists(), "source file not found: {}", src.path().display());

        let mut reader = src.reader().await?;
        let writer = dest.writer().await?;

        // Read and deserialize the header.
        // This reads the initial bytes of the file.
        let header = Header::deserialize(reader.get_mut()).await?;

        ensure!(header.file_size() != 0, "cannot decrypt a file with zero size");

        // Derive the key using the salt extracted from the header.
        // We use the KDF parameters stored in the header to ensure future compatibility.
        let key = Derive::new(self.password.as_bytes())?.derive_key(header.salt()?, header.kdf_memory(), header.kdf_time().into(), header.kdf_parallelism().into())?;

        // Verify the header HMAC.
        // This ensures the password is correct AND the header hasn't been tampered with.
        header.verify(&key).context("incorrect password or corrupt file")?;

        // Delegate bulk decryption to the worker.
        Worker::new(&key, Processing::Decryption)?.process(reader, writer, header.file_size()).await?;

        // Verify integrity of the decrypted content.
        // We read the output file we just wrote and hash it.
        Hash::new(dest.reader().await?, Some(header.file_size()))
            .await?
            .verify(header.file_hash())
            .context("decrypted content integrity check failed")?;

        // Display summary.
        crate::ui::show_header_info(header.file_name(), header.file_size(), header.file_hash());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    #[tokio::test]
    async fn test_processor_integration() {
        // Setup temporary directory for file ops.
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let filename = base_path.join("test_processor_integration.txt");
        let content = b"Integration test content for processor.";

        // Paths for encrypted and decrypted files.
        let enc_filename = base_path.join("test_processor_integration.txt.swx");
        let dec_filename = base_path.join("test_processor_integration_dec.txt");

        // Write original file.
        fs::write(&filename, content).await.unwrap();

        let mut src = File::new(&filename);
        let dest_enc = File::new(&enc_filename);
        let dest_dec = File::new(&dec_filename);

        let password = "strong_password";
        let processor = Processor::new(password);

        // 1. Encrypt
        src.validate(true).await.unwrap();
        processor.encrypt(&mut src, &dest_enc).await.unwrap();

        assert!(dest_enc.exists());

        // 2. Decrypt
        processor.decrypt(&dest_enc, &dest_dec).await.unwrap();

        // 3. Verify
        assert!(dest_dec.exists());
        let decrypted_content = fs::read(&dec_filename).await.unwrap();
        assert_eq!(decrypted_content, content);
    }
}
