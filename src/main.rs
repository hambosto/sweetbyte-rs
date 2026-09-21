mod config;
mod core;
mod crypto;
mod format;
mod fs;
mod pipeline;
mod transform;
mod ui;

use anyhow::Result;
use tokio::io::AsyncWriteExt;

use crate::config::{ARGON2_SALT_LEN, PASSWORD_LEN};
use crate::core::{ExposeSecret, Metadata, Operation, Secret};
use crate::crypto::{KeyDerivation, validate_hash};
use crate::format::{Deserializer, Serializer};
use crate::fs::{FileHandle, Scanner};
use crate::pipeline::Pipeline;
use crate::ui::Prompt;

#[tokio::main]
async fn main() -> Result<()> {
    ui::clear_screen()?;
    ui::show_banner()?;

    let prompt = Prompt::new(PASSWORD_LEN, true);
    let (source, target, operation) = select_files(&prompt).await?;
    let secret = prompt.read_password(operation)?;

    let metadata = match operation {
        Operation::Encryption => encrypt_file(&source, &target, &secret).await?,
        Operation::Decryption => decrypt_file(&source, &target, &secret).await?,
    };

    ui::show_success(operation, &target)?;
    ui::show_header(metadata.name(), metadata.size(), metadata.hash())?;

    if prompt.confirm_deletion(&source, operation)? {
        source.delete().await?;
        ui::show_deletion(&source)?;
    }

    ui::show_exit()
}

async fn select_files(prompt: &Prompt) -> Result<(FileHandle, FileHandle, Operation)> {
    let operation = prompt.select_operation()?;
    let files: Vec<FileHandle> = Scanner::new(".", operation).scan().into_iter().map(FileHandle::new).collect();

    if files.is_empty() {
        anyhow::bail!("no files found");
    }

    ui::list_files(&files).await?;

    let source = FileHandle::new(prompt.select_file(&files)?);
    let target = FileHandle::new(source.output_path(operation));

    if target.exists() && !prompt.confirm_overwrite(&target)? {
        anyhow::bail!("operation aborted");
    }

    Ok((source, target, operation))
}

async fn encrypt_file(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<Metadata> {
    let metadata = source.metadata().await?;
    let salt = KeyDerivation::generate_salt(ARGON2_SALT_LEN)?;
    let (primary_key, secondary_key, signer_key) = KeyDerivation::new(secret)?.derive_keys(&salt)?;

    let serializer = Serializer::new(metadata.name(), metadata.size(), metadata.hash())?;
    let raw_header = serializer.to_bytes(salt.expose_secret(), &signer_key)?;

    let mut writer = target.open_writer().await?;
    writer.write_all(&raw_header).await?;

    let reader = source.open_reader().await?;
    Pipeline::new(&primary_key, &secondary_key, Operation::Encryption)?.run(reader, writer, metadata.size()).await?;

    Ok(metadata)
}

async fn decrypt_file(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<Metadata> {
    let mut reader = source.open_reader().await?;
    let header = Deserializer::from_reader(&mut reader).await?;
    let (primary_key, secondary_key, signer_key) = KeyDerivation::new(secret)?.derive_keys(header.salt())?;

    if !header.verify_tag(&signer_key)? {
        anyhow::bail!("invalid password or corrupt file");
    }

    let writer = target.open_writer().await?;
    Pipeline::new(&primary_key, &secondary_key, Operation::Decryption)?.run(reader, writer, header.file_size()).await?;

    if !validate_hash(target.path(), header.file_hash())? {
        anyhow::bail!("file hash mismatch");
    }

    Metadata::new(header.file_name(), header.file_size(), header.file_hash())
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
        encrypt_file(&source, &encrypted, &secret).await.unwrap();
        decrypt_file(&encrypted, &decrypted, &secret).await.unwrap();

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
        encrypt_file(&source, &encrypted, &secret).await.unwrap();

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
        encrypt_file(&source, &encrypted, &secret(b"correct")).await.unwrap();

        // Act
        let result = decrypt_file(&encrypted, &decrypted, &secret(b"wrong")).await;

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
        encrypt_file(&source, &encrypted, &secret).await.unwrap();
        let decrypted_meta = decrypt_file(&encrypted, &decrypted, &secret).await.unwrap();

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
        let result = encrypt_file(&source, &encrypted, &secret(b"pass")).await;

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
        encrypt_file(&source, &encrypted, &secret(b"pass")).await.unwrap();

        // Assert
        assert_eq!(encrypted_path.extension().unwrap(), "swx");
        assert!(encrypted.exists());
    }
}
