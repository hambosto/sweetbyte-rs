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
use crate::core::{FileMetadata, Operation, Secret};
use crate::crypto::KeyDerivation;
use crate::format::{Deserializer, Serializer};
use crate::fs::{Discover, FileHandle};
use crate::pipeline::Pipeline;
use crate::ui::Input;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    crate::ui::clear()?;
    crate::ui::banner()?;

    let (source, target, operation) = select_files().await?;
    let secret = Input::new(PASSWORD_LEN, true).password(operation)?;

    let header = match operation {
        Operation::Encryption => encrypt(&source, &target, &secret).await?,
        Operation::Decryption => decrypt(&source, &target, &secret).await?,
    };

    crate::ui::success(operation, &target)?;
    crate::ui::header(header.name(), header.size(), &hex::encode(header.hash()))?;

    finalize_source(&source, operation).await?;

    crate::ui::exit()
}

async fn select_files() -> Result<(FileHandle, FileHandle, Operation)> {
    let input = Input::new(PASSWORD_LEN, true);

    let operation = input.operation_mode()?;
    let discovered = Discover::new(".", operation).run();
    let files: Vec<FileHandle> = discovered.into_iter().map(FileHandle::new).collect();
    if files.is_empty() {
        anyhow::bail!("no files available for processing");
    }

    crate::ui::files(&files).await?;

    let chosen = input.file(&files)?;
    let source = FileHandle::new(chosen);
    let target = FileHandle::new(source.output_path(operation));

    if target.exists() {
        let allowed = input.overwrite(&target)?;
        if !allowed {
            anyhow::bail!("operation canceled");
        }
    }

    Ok((source, target, operation))
}

async fn finalize_source(source: &FileHandle, operation: Operation) -> Result<()> {
    let input = Input::new(PASSWORD_LEN, true);
    let should_delete = input.delete(source, operation)?;
    if should_delete {
        source.delete().await.context("failed to delete source file")?;
        crate::ui::deleted(source)?;
    }

    Ok(())
}

async fn encrypt(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<FileMetadata> {
    let mut writer = target.writer().await.context("failed to create target file")?;
    let reader = source.reader().await.context("failed to open source file")?;
    let metadata = source.metadata().await.context("failed to read metadata")?;

    let salt = KeyDerivation::generate_salt(ARGON2_SALT_LEN)?;
    let key = KeyDerivation::new(secret)?;
    let keys = key.derive_keys(&salt)?;

    let header = Serializer::new(metadata.name(), metadata.size(), metadata.hash().to_vec())?;
    let serialized = header.serialize(salt.expose_secret(), &keys.signer_key).context("failed to serialize header")?;
    writer.write_all(&serialized).await.context("failed to write header")?;

    let engine = Pipeline::new(&keys.primary_key, &keys.secondary_key, Operation::Encryption)?;
    engine.process(reader, writer, metadata.size()).await?;

    FileMetadata::new(header.file_name().to_owned(), header.file_size(), header.file_hash().to_vec())
}

async fn decrypt(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<FileMetadata> {
    let mut reader = source.reader().await.context("failed to open source file")?;
    let writer = target.writer().await.context("failed to create target file")?;
    let header = Deserializer::from_reader(reader.get_mut()).await.context("failed to deserialize header")?;

    let key = KeyDerivation::new(secret)?;
    let keys = key.derive_keys(header.salt())?;
    let valid = header.verify(&keys.signer_key)?;
    if !valid {
        anyhow::bail!("incorrect password or corrupted file");
    }

    let pipeline = Pipeline::new(&keys.primary_key, &keys.secondary_key, Operation::Decryption)?;
    pipeline.process(reader, writer, header.file_size()).await?;

    let hash_ok = crate::crypto::validate_hash(target.path(), header.file_hash())?;
    if !hash_ok {
        anyhow::bail!("hash verification failed");
    }

    FileMetadata::new(header.file_name().to_owned(), header.file_size(), header.file_hash().to_vec())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;
    use crate::core::Secret;
    use crate::fs::FileHandle;

    #[tokio::test]
    async fn roundtrip_preserves_content() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("test.txt");
        let encrypted_path = dir.path().join("test.txt.swx");
        let decrypted_path = dir.path().join("test_dec.txt");

        fs::write(&source_path, b"test content").await.unwrap();

        let secret = Secret::new(b"password".to_vec());

        let source = FileHandle::new(&source_path);
        let encrypted = FileHandle::new(&encrypted_path);
        let decrypted = FileHandle::new(&decrypted_path);

        encrypt(&source, &encrypted, &secret).await.unwrap();
        assert!(encrypted.exists());

        decrypt(&encrypted, &decrypted, &secret).await.unwrap();
        assert!(decrypted.exists());

        assert_eq!(fs::read(&decrypted_path).await.unwrap(), b"test content");
    }
}
