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

    let header = match operation {
        Operation::Encryption => encrypt(&source, &target, &secret).await?,
        Operation::Decryption => decrypt(&source, &target, &secret).await?,
    };

    ui::success(operation, &target)?;
    ui::header(header.name(), header.size(), header.hash())?;

    let should_delete = input.delete(&source, operation).context("failed to confirm deletion")?;
    if should_delete {
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

    let allowed = input.overwrite(&target).context("failed to confirm overwrite")?;
    if target.exists() && !allowed {
        anyhow::bail!("operation canceled");
    }

    Ok((source, target, operation))
}

async fn encrypt(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<Metadata> {
    let metadata = source.metadata().await.context("failed to read metadata")?;
    let salt = KeyDerivation::generate_salt(ARGON2_SALT_LEN).context("failed to generate salt")?;
    let kdf = KeyDerivation::new(secret).context("failed to initialize key derivation")?;
    let keys = kdf.derive_keys(&salt).context("failed to derive keys")?;

    let header = Serializer::new(metadata.name(), metadata.size(), metadata.hash()).context("failed to initialize serializer")?;
    let serialized = header.serialize(salt.expose_secret(), &keys.signer_key).context("failed to serialize header")?;

    let mut writer = target.writer().await.context("failed to create target file")?;
    writer.write_all(&serialized).await.context("failed to write header")?;

    let reader = source.reader().await.context("failed to open source file")?;
    let pipeline = Pipeline::new(&keys.primary_key, &keys.secondary_key, Operation::Encryption).context("failed to initialize pipeline")?;
    pipeline.process(reader, writer, metadata.size()).await?;

    Ok(metadata)
}

async fn decrypt(source: &FileHandle, target: &FileHandle, secret: &Secret) -> Result<Metadata> {
    let mut reader = source.reader().await.context("failed to open source file")?;
    let header = Deserializer::from_reader(&mut reader).await.context("failed to deserialize header")?;

    let kdf = KeyDerivation::new(secret).context("failed to initialize key derivation")?;
    let keys = kdf.derive_keys(header.salt()).context("failed to derive keys")?;
    if !header.verify(&keys.signer_key)? {
        anyhow::bail!("incorrect password or corrupted file");
    }

    let writer = target.writer().await.context("failed to create target file")?;
    let pipeline = Pipeline::new(&keys.primary_key, &keys.secondary_key, Operation::Decryption).context("failed to initialize pipeline")?;
    pipeline.process(reader, writer, header.file_size()).await?;

    if !validate_hash(target.path(), header.file_hash())? {
        anyhow::bail!("hash verification failed");
    }

    Metadata::new(header.file_name(), header.file_size(), header.file_hash()).context("failed to build metadata")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    #[tokio::test]
    async fn roundtrip_preserves_content() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("test.txt");
        let encrypted_path = dir.path().join("test.txt.swx");
        let decrypted_path = dir.path().join("test_dec.txt");

        fs::write(&source_path, b"test content").await.unwrap();

        let secret = Secret::new(b"password".into());

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
