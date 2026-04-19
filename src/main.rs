mod allocator;
mod cipher;
mod compression;
mod config;
mod encoding;
mod file;
mod header;
mod padding;
mod secret;
mod types;
mod ui;
mod worker;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::AsyncWriteExt;

use cipher::Derive;
use config::{ARGON_SALT_LEN, PASSWORD_MIN_LENGTH};
use file::File;
use header::{HeaderReader, HeaderWriter, Metadata};
use secret::SecretString;
use types::{Processing, ProcessorMode};
use ui::display::Display;
use ui::prompt::Prompt;
use worker::Worker;

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    Encrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
    },
    Decrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
    },
    Interactive,
}

#[tokio::main]
async fn main() -> Result<()> {
    let prompt = Prompt::new(PASSWORD_MIN_LENGTH);
    let display = Display::new(35);

    match Cli::parse().command {
        Some(Cmd::Encrypt { input, output, password }) => run_cli(&input, output, password, Processing::Encryption, &prompt, &display).await,
        Some(Cmd::Decrypt { input, output, password }) => run_cli(&input, output, password, Processing::Decryption, &prompt, &display).await,
        Some(Cmd::Interactive) | None => run_interactive(&prompt, &display).await,
    }
}

async fn run_cli(input: &str, output: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt, display: &Display) -> Result<()> {
    let mut src = File::new(input);
    let mode = ProcessorMode::from(processing);
    let dest = File::new(output.map_or_else(|| src.output_path(mode), PathBuf::from));
    let secret = resolve_secret(password, processing, prompt)?;

    let info = process(&mut src, &dest, &secret, processing).await?;
    display.success(mode, dest.path())?;
    display.header(&info.name, info.size, &info.hash)
}

async fn run_interactive(prompt: &Prompt, display: &Display) -> Result<()> {
    display.clear()?;
    display.banner()?;

    let mode = Prompt::mode()?;
    let processing = Processing::from(mode);

    let mut files = File::discover(".", mode);
    anyhow::ensure!(!files.is_empty(), "no eligible files found");
    display.files(&mut files).await?;

    let path = Prompt::file(&files)?;
    let mut src = File::new(&path);
    let dest = File::new(src.output_path(mode));

    if dest.exists() && !Prompt::overwrite(dest.path())? {
        anyhow::bail!("operation cancelled");
    }

    let secret = resolve_secret(None, processing, prompt)?;
    let info = process(&mut src, &dest, &secret, processing).await?;

    display.success(mode, dest.path())?;
    display.header(&info.name, info.size, &info.hash)?;

    let label = match mode {
        ProcessorMode::Encrypt => "original",
        ProcessorMode::Decrypt => "encrypted",
    };

    if Prompt::delete(src.path(), label)? {
        src.delete().await?;
        display.deleted(src.path())?;
    }

    Ok(())
}

struct FileInfo {
    name: String,
    size: u64,
    hash: String,
}

async fn process(src: &mut File, dest: &File, secret: &SecretString, processing: Processing) -> Result<FileInfo> {
    anyhow::ensure!(src.exists(), "source file not found: {}", src.path().display());
    anyhow::ensure!(!src.path().is_dir(), "source is a directory: {}", src.path().display());

    match processing {
        Processing::Encryption => encrypt(src, dest, secret).await,
        Processing::Decryption => decrypt(src, dest, secret).await,
    }
    .with_context(|| format!("{processing} failed: {}", src.path().display()))
}

async fn encrypt(src: &mut File, dest: &File, secret: &SecretString) -> Result<FileInfo> {
    let metadata = src.file_metadata().await?;
    let salt = Derive::generate_salt(ARGON_SALT_LEN)?;
    let key = Derive::new(secret.expose_secret().as_bytes())?.derive_key(&salt)?;
    let filename = metadata.filename.clone();

    let header = HeaderWriter::new(Metadata::new(metadata.filename, metadata.size, metadata.hash)?)?;
    let mut writer = dest.writer().await?;
    writer.write_all(&header.serialize(&salt, &key)?).await?;
    Worker::new(&key, Processing::Encryption)?.process(src.reader().await?, writer, metadata.size).await?;

    Ok(FileInfo { name: filename, size: metadata.size, hash: hex::encode(header.file_hash()) })
}

async fn decrypt(src: &File, dest: &File, secret: &SecretString) -> Result<FileInfo> {
    let mut reader = src.reader().await?;
    let header = HeaderReader::read(reader.get_mut()).await?;
    anyhow::ensure!(header.file_size() != 0, "cannot decrypt a file with zero size");

    let key = Derive::new(secret.expose_secret().as_bytes())?.derive_key(header.salt())?;
    anyhow::ensure!(header.verify(&key)?, "invalid password or corrupted data");

    Worker::new(&key, Processing::Decryption)?.process(reader, dest.writer().await?, header.file_size()).await?;
    anyhow::ensure!(dest.validate_hash(header.file_hash()).await?, "hash mismatch");

    Ok(FileInfo { name: header.file_name().to_owned(), size: header.file_size(), hash: hex::encode(header.file_hash()) })
}

fn resolve_secret(password: Option<String>, processing: Processing, prompt: &Prompt) -> Result<SecretString> {
    match password {
        Some(password) => Ok(SecretString::from_str(&password)),
        None => match processing {
            Processing::Encryption => Ok(SecretString::new(prompt.encrypt_password()?)),
            Processing::Decryption => Ok(SecretString::new(prompt.decrypt_password()?)),
        },
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let src_path = base.join("test.txt");
        let enc_path = base.join("test.txt.swx");
        let dec_path = base.join("test_dec.txt");

        fs::write(&src_path, b"test content").await.unwrap();

        let mut src = File::new(&src_path);
        let enc = File::new(&enc_path);
        let dec = File::new(&dec_path);
        let secret = SecretString::new("password123".to_owned());

        encrypt(&mut src, &enc, &secret).await.unwrap();
        assert!(enc.exists(), "encrypted file should exist");

        decrypt(&enc, &dec, &secret).await.unwrap();
        assert!(dec.exists(), "decrypted file should exist");

        assert_eq!(fs::read(&dec_path).await.unwrap(), b"test content", "roundtrip content must match");
    }
}
