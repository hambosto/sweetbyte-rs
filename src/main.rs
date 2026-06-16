mod cipher;
mod compression;
mod config;
mod encoding;
mod engine;
mod files;
mod header;
mod padding;
mod secret;
mod types;
mod ui;
mod validation;

use anyhow::{Context, Result};
use cipher::Key;
use compression::CompressionLevel;
use config::{ARGON2_SALT_LEN, NAME_MAX_LEN, ORIGINAL_COUNT, PASSWORD_LEN, RECOVERY_COUNT};
use engine::Engine;
use files::Files;
use header::{ReadHeader, WriteHeader};
use padding::BlockSize;
use secret::Secret;
use tokio::io::AsyncWriteExt;
use types::{FileHeader, Processing};
use ui::{Display, Input};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    run(PASSWORD_LEN, NAME_MAX_LEN).await
}

async fn run(password_len: usize, name_max_len: usize) -> Result<()> {
    let input = Input::new(password_len, true);
    let display = Display::new(name_max_len);

    display.clear()?;
    display.banner()?;

    let processing = input.processing_mode()?;
    let files = Files::discover(".", processing);
    if files.is_empty() {
        anyhow::bail!("no files available for processing");
    }

    display.files(&files).await?;

    let source = Files::new(input.file(&files)?);
    let target = Files::new(source.output_path(processing));

    if target.exists() && !input.overwrite(&target)? {
        anyhow::bail!("operation canceled");
    }

    let secret = input.password(processing)?;
    let header = match processing {
        Processing::Encryption => encrypt(&source, &target, &secret).await?,
        Processing::Decryption => decrypt(&source, &target, &secret).await?,
    };

    display.success(processing, &target)?;
    display.header(&header.name, header.size, &header.hash)?;

    if input.delete(&source, processing)? {
        source.delete().await.context("failed to delete source file")?;
        display.deleted(&source)?;
    }

    display.exit()
}

async fn encrypt(source: &Files, target: &Files, secret: &Secret) -> Result<FileHeader> {
    let mut writer = target.writer().await.context("failed to create target file")?;
    let reader = source.reader().await.context("failed to open source file")?;
    let metadata = source.metadata().await.context("failed to read metadata")?;

    let salt = Key::generate_salt(ARGON2_SALT_LEN)?;
    let key = Key::new(secret)?;
    let derived_keys = key.derive_keys(&salt)?;

    let header = WriteHeader::new(metadata.name, metadata.size, metadata.hash)?;
    let serialized = header.serialize(salt.expose_secret(), &derived_keys.signer_key).context("failed to serialize header")?;
    writer.write_all(&serialized).await.context("failed to write header")?;

    let engine = Engine::new(&derived_keys.primary_key, &derived_keys.secondary_key, Processing::Encryption, CompressionLevel::Fast, BlockSize::B128, ORIGINAL_COUNT, RECOVERY_COUNT)?;
    engine.process(reader, writer, metadata.size).await?;

    Ok(FileHeader { name: header.name().to_owned(), size: header.size(), hash: hex::encode(header.hash()) })
}

async fn decrypt(source: &Files, target: &Files, secret: &Secret) -> Result<FileHeader> {
    let mut reader = source.reader().await.context("failed to open source file")?;
    let writer = target.writer().await.context("failed to create target file")?;
    let header = ReadHeader::from_reader(reader.get_mut()).await.context("failed to deserialize header")?;

    let key = Key::new(secret)?;
    let derived_keys = key.derive_keys(header.salt())?;
    if !header.verify(&derived_keys.signer_key)? {
        anyhow::bail!("incorrect password");
    }

    let engine = Engine::new(&derived_keys.primary_key, &derived_keys.secondary_key, Processing::Decryption, CompressionLevel::Fast, BlockSize::B128, ORIGINAL_COUNT, RECOVERY_COUNT)?;
    engine.process(reader, writer, header.size()).await?;

    if !target.validate_hash(header.hash())? {
        anyhow::bail!("hash verification failed");
    }

    Ok(FileHeader { name: header.name().to_owned(), size: header.size(), hash: hex::encode(header.hash()) })
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

        let secret = Secret::new(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"password").as_ref().to_vec());

        let source = Files::new(&source_path);
        let encrypted = Files::new(&encrypted_path);
        let decrypted = Files::new(&decrypted_path);

        encrypt(&source, &encrypted, &secret).await.unwrap();
        assert!(encrypted.exists());

        decrypt(&encrypted, &decrypted, &secret).await.unwrap();
        assert!(decrypted.exists());

        assert_eq!(fs::read(&decrypted_path).await.unwrap(), b"test content");
    }
}
