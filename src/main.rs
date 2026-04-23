mod allocator;
mod cipher;
mod compression;
mod config;
mod encoding;
mod files;
mod header;
mod padding;
mod secret;
mod types;
mod ui;
mod worker;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::io::AsyncWriteExt;

use crate::cipher::Derive;
use crate::config::{ARGON_SALT_LEN, NAME_MAX_LEN, PASSWORD_LEN};
use crate::files::Files;
use crate::header::{Deserializer, Metadata, Serializer};
use crate::secret::{SecretBytes, SecretString};
use crate::types::{FileHeader, Processing};
use crate::ui::display::Display;
use crate::ui::prompt::Prompt;
use crate::worker::Worker;

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    Interactive,
}

#[tokio::main]
async fn main() -> Result<()> {
    let prompt = Prompt::new(PASSWORD_LEN);
    let display = Display::new(NAME_MAX_LEN);

    match Cli::parse().command {
        Some(Cmd::Interactive) | None => run_interactive(&prompt, &display).await,
    }
}

async fn run_interactive(prompt: &Prompt, display: &Display) -> Result<()> {
    display.clear()?;
    display.banner()?;

    let processing = prompt.processing_mode()?;
    let mut files = Files::discover(".", processing);
    anyhow::ensure!(!files.is_empty(), "no eligible files");

    display.files(&mut files).await?;
    let source = Files::new(prompt.file(&files)?);
    let target = Files::new(source.output_path(processing));
    if target.exists() && !prompt.overwrite(target.path())? {
        anyhow::bail!("operation cancelled");
    }

    let secret = SecretString::new(prompt.password(processing)?);
    let process = match processing {
        Processing::Encryption => encrypt_file(&source, &target, &secret).await?,
        Processing::Decryption => decrypt_file(&source, &target, &secret).await?,
    };

    display.success(processing, target.path())?;
    display.header(&process.name, process.size, &process.hash)?;

    if prompt.delete(source.path(), processing)? {
        source.delete().await?;
        display.deleted(source.path())?;
    }

    Ok(())
}

async fn encrypt_file(source: &Files, target: &Files, secret: &SecretString) -> Result<FileHeader> {
    let metadata = source.file_metadata().await?;
    let salt = Derive::generate_salt(ARGON_SALT_LEN)?;
    let key = derive_key(secret, &salt)?;
    let filename = metadata.filename.clone();
    let header = Serializer::new(Metadata::new(metadata.filename, metadata.size, metadata.hash)?)?;

    let mut writer = target.writer().await?;
    writer.write_all(&header.serialize(&salt, &key)?).await?;

    Worker::new(&key, Processing::Encryption)?.process(source.reader().await?, writer, metadata.size).await?;

    Ok(FileHeader { name: filename, size: metadata.size, hash: hex::encode(header.file_hash()) })
}

async fn decrypt_file(source: &Files, target: &Files, secret: &SecretString) -> Result<FileHeader> {
    let mut reader = source.reader().await?;
    let header = Deserializer::deserialize(reader.get_mut()).await?;

    let key = derive_key(secret, header.salt())?;
    anyhow::ensure!(header.verify(&key)?, "invalid password");

    Worker::new(&key, Processing::Decryption)?.process(reader, target.writer().await?, header.file_size()).await?;
    anyhow::ensure!(target.validate_hash(header.file_hash()).await?, "hash mismatch");

    Ok(FileHeader { name: header.file_name().to_owned(), size: header.file_size(), hash: hex::encode(header.file_hash()) })
}

fn derive_key(secret: &SecretString, salt: &[u8]) -> Result<SecretBytes> {
    Derive::new(secret.expose_secret().as_bytes())?.derive_key(salt)
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

        let source = Files::new(&source_path);
        let encrypted = Files::new(&encrypted_path);
        let decrypted = Files::new(&decrypted_path);
        let secret = SecretString::new("password123".into());

        encrypt_file(&source, &encrypted, &secret).await.unwrap();
        assert!(encrypted.exists());

        decrypt_file(&encrypted, &decrypted, &secret).await.unwrap();
        assert!(decrypted.exists());

        assert_eq!(fs::read(&decrypted_path).await.unwrap(), b"test content");
    }
}
