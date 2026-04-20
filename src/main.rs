use anyhow::Result;
use tokio::io::AsyncWriteExt;

use sweetbyte_rs::cipher::Derive;
use sweetbyte_rs::config::{ARGON_SALT_LEN, PASSWORD_MIN_LENGTH};
use sweetbyte_rs::file::File;
use sweetbyte_rs::header::{HeaderReader, HeaderWriter, Metadata};
use sweetbyte_rs::secret::SecretString;
use sweetbyte_rs::types::{FileInfo, Processing};
use sweetbyte_rs::ui::display::Display;
use sweetbyte_rs::ui::prompt::Prompt;
use sweetbyte_rs::worker::Worker;
use sweetbyte_rs::cli::{Cli, Cmd};

#[tokio::main]
async fn main() -> Result<()> {
    let prompt = Prompt::new(PASSWORD_MIN_LENGTH);
    let display = Display::new(35);

    match Cli::parse_args().command {
        Some(Cmd::Interactive) | None => run(&prompt, &display).await,
    }
}

async fn run(prompt: &Prompt, display: &Display) -> Result<()> {
    display.clear()?;
    display.banner()?;

    let mode = prompt.mode()?;
    let processing = Processing::from(mode);

    let mut files = File::discover(".", mode);
    anyhow::ensure!(!files.is_empty(), "no eligible files found");

    display.files(&mut files).await?;

    let path = prompt.file(&files)?;
    let mut src = File::new(&path);
    let dest = File::new(src.output_path(mode));

    if dest.exists() && !prompt.overwrite(dest.path())? {
        anyhow::bail!("operation cancelled");
    }

    let secret = SecretString::new(prompt.password(&processing)?);
    anyhow::ensure!(src.exists(), "source file not found: {}", src.path().display());
    anyhow::ensure!(!src.path().is_dir(), "source is a directory: {}", src.path().display());

    let info = match processing {
        Processing::Encryption => encrypt(&mut src, &dest, &secret).await,
        Processing::Decryption => decrypt(&src, &dest, &secret).await,
    }?;

    display.success(mode, dest.path())?;
    display.header(&info.name, info.size, &info.hash)?;

    let label = match processing {
        Processing::Encryption => "original",
        Processing::Decryption => "encrypted",
    };

    if prompt.delete(src.path(), label)? {
        src.delete().await?;
        display.deleted(src.path())?;
    }

    Ok(())
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
