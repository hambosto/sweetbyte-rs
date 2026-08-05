mod config;
mod core;
mod crypto;
mod format;
mod fs;
mod pipeline;
mod transform;
mod ui;

use anyhow::{Context, Result};
use mimalloc::MiMalloc;
use tokio::io::AsyncWriteExt;

use crate::config::{ARGON2_SALT_LEN, PASSWORD_LEN};
use crate::core::{Metadata, Operation, Secret};
use crate::crypto::{KeyDerivation, validate_hash};
use crate::format::{Deserializer, Serializer};
use crate::fs::{Discover, FileHandle};
use crate::pipeline::Pipeline;
use crate::ui::Input;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    ui::clear()?;
    ui::banner()?;

    let input = Input::new(PASSWORD_LEN, true);
    let (source, target, operation) = select_files(&input).await?;
    let secret = input.password(operation).context("failed to read password")?;

    let metadata = match operation {
        Operation::Encryption => encrypt(&source, &target, &secret).await?,
        Operation::Decryption => decrypt(&source, &target, &secret).await?,
    };

    ui::success(operation, &target)?;
    ui::header(metadata.name(), metadata.size(), metadata.hash())?;

    if input.delete(&source, operation).context("failed to confirm deletion")? {
        source.delete().await.context("failed to delete source file")?;
        ui::deleted(&source)?;
    }

    ui::exit()
}

async fn select_files(input: &Input) -> Result<(FileHandle, FileHandle, Operation)> {
    let operation = input.operation_mode().context("failed to select operation")?;
    let files: Vec<FileHandle> = Discover::new(".", operation).run().into_iter().map(FileHandle::new).collect();

    if files.is_empty() {
        anyhow::bail!("no files available for processing");
    }

    ui::files(&files).await?;

    let source = FileHandle::new(input.file(&files).context("failed to select file")?);
    let target = FileHandle::new(source.output_path(operation));

    if target.exists() && !input.overwrite(&target).context("failed to confirm overwrite")? {
        anyhow::bail!("operation canceled");
    }

    Ok((source, target, operation))
}

async fn encrypt(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<Metadata> {
    let metadata = source.metadata().await.context("failed to read metadata")?;
    let salt = KeyDerivation::generate_salt(ARGON2_SALT_LEN).context("failed to generate salt")?;
    let kdf = KeyDerivation::new(secret).context("failed to initialize key derivation")?;
    let (primary_key, secondary_key, signer_key) = kdf.derive_keys(&salt).context("failed to derive keys")?;

    let serializer = Serializer::new(metadata.name(), metadata.size(), metadata.hash()).context("failed to initialize serializer")?;
    let header = serializer.serialize(salt.expose_secret(), &signer_key).context("failed to serialize header")?;

    let mut writer = target.writer().await.context("failed to create target file")?;
    writer.write_all(&header).await.context("failed to write header")?;

    let reader = source.reader().await.context("failed to open source file")?;
    let pipeline = Pipeline::new(&primary_key, &secondary_key, Operation::Encryption).context("failed to initialize pipeline")?;
    pipeline.process(reader, writer, metadata.size()).await.context("failed to encrypt file")?;

    Ok(metadata)
}

async fn decrypt(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<Metadata> {
    let mut reader = source.reader().await.context("failed to open source file")?;
    let header = Deserializer::from_reader(&mut reader).await.context("failed to deserialize header")?;

    let kdf = KeyDerivation::new(secret).context("failed to initialize key derivation")?;
    let (primary_key, secondary_key, signer_key) = kdf.derive_keys(header.salt()).context("failed to derive keys")?;

    if !header.verify(&signer_key)? {
        anyhow::bail!("incorrect password or corrupted file");
    }

    let writer = target.writer().await.context("failed to create target file")?;
    let pipeline = Pipeline::new(&primary_key, &secondary_key, Operation::Decryption).context("failed to initialize pipeline")?;
    pipeline.process(reader, writer, header.file_size()).await.context("failed to decrypt file")?;

    if !validate_hash(target.path(), header.file_hash())? {
        anyhow::bail!("hash verification failed");
    }

    Metadata::new(header.file_name(), header.file_size(), header.file_hash()).context("failed to build metadata")
}

#[cfg(test)]
mod tests {
    use sha2::Digest;
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    fn secret(password: &[u8]) -> Secret {
        let key = sha2::Sha256::digest(password);
        Secret::new(key.to_vec())
    }

    #[tokio::test]
    async fn roundtrip_preserves_content() {
        // Arrange
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("test.txt");
        let encrypted_path = dir.path().join("test.txt.swx");
        let decrypted_path = dir.path().join("test_dec.txt");
        fs::write(&source_path, b"test content").await.unwrap();

        let secret = secret(b"password");
        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);
        let decrypted = FileHandle::new(&decrypted_path);

        // Act
        encrypt(&source, &encrypted, &secret).await.unwrap();
        decrypt(&encrypted, &decrypted, &secret).await.unwrap();

        // Assert
        assert_eq!(fs::read(&decrypted_path).await.unwrap(), b"test content");
    }

    #[tokio::test]
    async fn encrypt_produces_different_output() {
        // Arrange
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("plain.txt");
        let encrypted_path = dir.path().join("plain.txt.swx");
        fs::write(&source_path, b"sensitive data").await.unwrap();

        let secret = secret(b"pass123");
        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);

        // Act
        encrypt(&source, &encrypted, &secret).await.unwrap();

        // Assert
        let original = fs::read(&source_path).await.unwrap();
        let ciphertext = fs::read(&encrypted_path).await.unwrap();
        assert_ne!(original, ciphertext);
    }

    #[tokio::test]
    async fn decrypt_wrong_password_fails() {
        // Arrange
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("file.txt");
        let encrypted_path = dir.path().join("file.txt.swx");
        let decrypted_path = dir.path().join("file_dec.txt");
        fs::write(&source_path, b"secret").await.unwrap();

        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);
        let decrypted = FileHandle::new(&decrypted_path);
        encrypt(&source, &encrypted, &secret(b"correct")).await.unwrap();

        // Act
        let result = decrypt(&encrypted, &decrypted, &secret(b"wrong")).await;

        // Assert
        assert!(result.is_err());
        assert!(!decrypted.exists());
    }

    #[tokio::test]
    async fn roundtrip_preserves_metadata() {
        // Arrange
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("data.bin");
        let encrypted_path = dir.path().join("data.bin.swx");
        let decrypted_path = dir.path().join("data_dec.bin");
        fs::write(&source_path, vec![42u8; 4096].as_slice()).await.unwrap();

        let secret = secret(b"metadata-test");
        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);
        let decrypted = FileHandle::new(&decrypted_path);
        let original_meta = source.metadata().await.unwrap();

        // Act
        encrypt(&source, &encrypted, &secret).await.unwrap();
        let decrypted_meta = decrypt(&encrypted, &decrypted, &secret).await.unwrap();

        // Assert
        assert_eq!(decrypted_meta.name(), original_meta.name());
        assert_eq!(decrypted_meta.size(), original_meta.size());
        assert_eq!(decrypted_meta.hash(), original_meta.hash());
    }

    #[tokio::test]
    async fn encrypt_empty_file_fails() {
        // Arrange
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("empty.txt");
        let encrypted_path = dir.path().join("empty.txt.swx");
        fs::write(&source_path, b"").await.unwrap();

        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);

        // Act
        let result = encrypt(&source, &encrypted, &secret(b"pass")).await;

        // Assert
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn encrypted_file_has_swx_extension() {
        // Arrange
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("report.pdf");
        let encrypted_path = dir.path().join("report.pdf.swx");
        fs::write(&source_path, b"pdf content").await.unwrap();

        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);

        // Act
        encrypt(&source, &encrypted, &secret(b"pass")).await.unwrap();

        // Assert
        assert_eq!(encrypted_path.extension().unwrap(), "swx");
        assert!(encrypted.exists());
    }
}
