use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use tokio::io::AsyncWriteExt;

use crate::cipher::Derive;
use crate::config::{ARGON_SALT_LEN, PASSWORD_MIN_LENGTH};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::Metadata;
use crate::secret::SecretString;
use crate::types::{Processing, ProcessorMode};
use crate::ui::display::Display;
use crate::ui::prompt::Prompt;
use crate::worker::Worker;

#[derive(Subcommand)]
enum Command {
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

#[derive(Parser)]
#[command(name = "sweetbyte-rs", version = "26.1.0", about = "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction.")]
pub struct App {
    #[command(subcommand)]
    command: Option<Command>,
}

pub struct HeaderInfo {
    name: String,
    size: u64,
    hash: String,
}

impl App {
    pub fn init() -> Result<Self> {
        let subscriber = tracing_subscriber::fmt().with_file(true).with_line_number(true).finish();
        tracing::subscriber::set_global_default(subscriber)?;
        Ok(Self::parse())
    }

    pub async fn execute(mut self) -> Result<()> {
        let prompt = Prompt::new(PASSWORD_MIN_LENGTH);
        let display = Display::default();

        match self.command.take() {
            Some(Command::Encrypt { input, output, password }) => self.run_cli(&input, output, password, Processing::Encryption, &prompt, &display).await,
            Some(Command::Decrypt { input, output, password }) => self.run_cli(&input, output, password, Processing::Decryption, &prompt, &display).await,
            Some(Command::Interactive) | None => self.interactive(&prompt, &display).await,
        }
    }

    async fn run_cli(&self, input: &str, output: Option<String>, password: Option<String>, processing: Processing, prompt: &Prompt, display: &Display) -> Result<()> {
        let src = File::new(input);
        let dest = File::new(output.map_or_else(|| src.output_path(processing.mode()), |s| PathBuf::from(s)));
        let secret = password.map_or_else(|| Self::password(prompt, processing), |p| Ok(SecretString::from_str(&p)))?;

        let info = self.process(&src, &dest, &secret, processing).await?;
        display.success(processing.mode(), dest.path());
        display.header(&info.name, info.size, &info.hash);
        Ok(())
    }

    async fn interactive(&self, prompt: &Prompt, display: &Display) -> Result<()> {
        display.clear()?;
        display.banner()?;

        let mode = Prompt::mode()?;
        let processing = Processing::from(mode);

        let mut files = File::discover(mode);
        if files.is_empty() {
            return Err(anyhow!("no eligible files found"));
        }

        display.files(&mut files).await?;

        let path = Prompt::file(&files)?;
        let mut src = File::new(&path);

        if !src.validate().await {
            return Err(anyhow!("invalid input file: {}", path.display()));
        }

        let dest = File::new(src.output_path(mode));
        if dest.exists() && !Prompt::overwrite(dest.path())? {
            return Err(anyhow!("operation canceled"));
        }

        let secret = Self::password(prompt, processing)?;
        let info = self.process(&src, &dest, &secret, processing).await?;

        display.success(mode, dest.path());
        display.header(&info.name, info.size, &info.hash);

        let label = match mode {
            ProcessorMode::Encrypt => "original",
            ProcessorMode::Decrypt => "encrypted",
        };
        if Prompt::delete(src.path(), label)? {
            src.delete().await?;
            display.deleted(src.path());
        }

        Ok(())
    }

    async fn process(&self, src: &File, dest: &File, secret: &SecretString, processing: Processing) -> Result<HeaderInfo> {
        match processing {
            Processing::Encryption => self.encrypt(src, dest, secret).await,
            Processing::Decryption => self.decrypt(src, dest, secret).await,
        }
        .with_context(|| format!("{processing} failed: {}", src.path().display()))
    }

    async fn encrypt(&self, src: &File, dest: &File, secret: &SecretString) -> Result<HeaderInfo> {
        let (name, size, hash) = src.file_metadata().await?;
        let salt = Derive::generate_salt(ARGON_SALT_LEN)?;
        let key = Derive::new(secret.expose_secret().as_bytes())?.derive_key(&salt)?;
        let header = Header::new(Metadata::new(name.clone(), size, hash))?;

        let mut writer = dest.writer().await?;
        writer.write_all(&header.serialize(&salt, &key)?).await?;

        Worker::new(&key, Processing::Encryption)?.process(src.reader().await?, writer, size).await?;

        Ok(HeaderInfo { name, size, hash: header.file_hash() })
    }

    async fn decrypt(&self, src: &File, dest: &File, secret: &SecretString) -> Result<HeaderInfo> {
        let mut reader = src.reader().await?;
        let header = Header::deserialize(reader.get_mut()).await?;

        if header.file_size() == 0 {
            return Err(anyhow!("cannot decrypt a file with zero size"));
        }

        let key = Derive::new(secret.expose_secret().as_bytes())?.derive_key(header.salt()?)?;
        if !header.verify(&key) {
            return Err(anyhow!("invalid password or corrupted data"));
        }

        Worker::new(&key, Processing::Decryption)?.process(reader, dest.writer().await?, header.file_size()).await?;

        if !dest.validate_hash(header.file_hash()).await? {
            return Err(anyhow!("hash mismatch"));
        }

        Ok(HeaderInfo { name: header.file_name().to_owned(), size: header.file_size(), hash: header.file_hash() })
    }

    fn password(prompt: &Prompt, processing: Processing) -> Result<SecretString> {
        let pw = match processing {
            Processing::Encryption => prompt.encrypt_password()?,
            Processing::Decryption => prompt.decrypt_password()?,
        };
        Ok(SecretString::new(pw))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let src_path = base.join("test.txt");
        let enc_path = base.join("test.txt.swx");
        let dec_path = base.join("test_dec.txt");
        let content = b"test content";

        fs::write(&src_path, content).await.unwrap();

        let mut src = File::new(&src_path);
        let enc = File::new(&enc_path);
        let dec = File::new(&dec_path);
        let secret = SecretString::new("password123".to_owned());

        assert!(src.validate().await);

        let app = App { command: None };
        app.encrypt(&src, &enc, &secret).await.unwrap();
        assert!(enc.exists());

        app.decrypt(&enc, &dec, &secret).await.unwrap();
        assert!(dec.exists());

        assert_eq!(fs::read(&dec_path).await.unwrap(), content);
    }
}
