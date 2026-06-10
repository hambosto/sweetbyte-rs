use anyhow::{Context, Result};
use sweetbyte_rs::config::{ARGON2_SALT_LEN, NAME_MAX_LEN, PASSWORD_LEN};
use sweetbyte_rs::core::Key;
use sweetbyte_rs::engine::Engine;
use sweetbyte_rs::files::Files;
use sweetbyte_rs::header::{Deserializer, Serializer};
use sweetbyte_rs::secret::Secret;
use sweetbyte_rs::types::{FileHeader, Processing};
use sweetbyte_rs::ui::{Display, Input};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<()> {
    App::new(Input::new(PASSWORD_LEN, true), Display::new(NAME_MAX_LEN)).run().await
}

struct App {
    input: Input,
    display: Display,
}

impl App {
    fn new(input: Input, display: Display) -> Self {
        Self { input, display }
    }

    async fn run(&self) -> Result<()> {
        self.display.clear()?;
        self.display.banner()?;

        let processing = self.input.processing_mode()?;
        let files = Files::discover(".", processing);
        if files.is_empty() {
            anyhow::bail!("no files available for processing");
        }

        self.display.files(&files).await?;

        let source = Files::new(self.input.file(&files)?);
        let target = Files::new(source.output_path(processing));

        if target.exists() && !self.input.overwrite(&target)? {
            anyhow::bail!("operation canceled");
        }

        let secret = self.input.password(processing)?;
        let header = match processing {
            Processing::Encryption => self.encrypt(&source, &target, &secret).await?,
            Processing::Decryption => self.decrypt(&source, &target, &secret).await?,
            _ => anyhow::bail!("unsupported processing mode"),
        };

        self.display.success(processing, &target)?;
        self.display.header(&header.name, header.size, &header.hash)?;

        if self.input.delete(&source, processing)? {
            source.delete().await.context("failed to delete source file")?;
            self.display.deleted(&source)?;
        }

        self.display.exit()
    }

    async fn encrypt(&self, source: &Files, target: &Files, secret: &Secret) -> Result<FileHeader> {
        let mut writer = target.writer().await.context("failed to create target file")?;
        let reader = source.reader().await.context("failed to open source file")?;
        let metadata = source.metadata().await.context("failed to read metadata")?;

        let salt = Key::generate_salt(ARGON2_SALT_LEN)?;
        let key = Key::new(secret)?;
        let derived_keys = key.derive_keys(salt.expose_secret())?;

        let header = Serializer::new(metadata.name, metadata.size, metadata.hash)?;
        let serialized = header.serialize(salt.expose_secret(), &derived_keys.signer_key).context("failed to serialize header")?;
        writer.write_all(&serialized).await.context("failed to write header")?;

        let engine = Engine::new(&derived_keys.primary_key, &derived_keys.secondary_key, Processing::Encryption)?;
        engine.process(reader, writer, metadata.size).await?;

        Ok(FileHeader { name: header.file_name().to_owned(), size: header.file_size(), hash: hex::encode(header.file_hash()) })
    }

    async fn decrypt(&self, source: &Files, target: &Files, secret: &Secret) -> Result<FileHeader> {
        let mut reader = source.reader().await.context("failed to open source file")?;
        let writer = target.writer().await.context("failed to create target file")?;
        let header = Deserializer::deserialize(reader.get_mut()).await.context("failed to deserialize header")?;

        let key = Key::new(secret)?;
        let derived_keys = key.derive_keys(header.salt().expose_secret())?;
        if !header.verify(&derived_keys.signer_key)? {
            anyhow::bail!("incorrect password");
        }

        let engine = Engine::new(&derived_keys.primary_key, &derived_keys.secondary_key, Processing::Decryption)?;
        engine.process(reader, writer, header.file_size()).await?;

        if !target.validate_hash(header.file_hash())? {
            anyhow::bail!("hash verification failed");
        }

        Ok(FileHeader { name: header.file_name().to_owned(), size: header.file_size(), hash: hex::encode(header.file_hash()) })
    }
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
        let app = App::new(Input::new(PASSWORD_LEN, true), Display::new(NAME_MAX_LEN));

        let source = Files::new(&source_path);
        let encrypted = Files::new(&encrypted_path);
        let decrypted = Files::new(&decrypted_path);

        app.encrypt(&source, &encrypted, &secret).await.unwrap();
        assert!(encrypted.exists());

        app.decrypt(&encrypted, &decrypted, &secret).await.unwrap();
        assert!(decrypted.exists());

        assert_eq!(fs::read(&decrypted_path).await.unwrap(), b"test content");
    }
}
