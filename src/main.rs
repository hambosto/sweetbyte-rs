use anyhow::Result;
use sweetbyte_rs::config::{NAME_MAX_LEN, PASSWORD_LEN, SCRYPT_SALT_LEN};
use sweetbyte_rs::core::Key;
use sweetbyte_rs::files::Files;
use sweetbyte_rs::header::{Deserializer, Metadata, Serializer};
use sweetbyte_rs::secret::{SecretBytes, SecretString};
use sweetbyte_rs::types::{FileHeader, Processing};
use sweetbyte_rs::ui::{Display, Input};
use sweetbyte_rs::worker::Worker;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<()> {
    let input = Input::new(PASSWORD_LEN, true);
    let display = Display::new(NAME_MAX_LEN);

    run_interactive(&input, &display).await
}

async fn run_interactive(input: &Input, display: &Display) -> Result<()> {
    display.clear()?;
    display.banner()?;

    let processing = input.processing_mode()?;
    let mut files = Files::discover(".", processing);
    if files.is_empty() {
        anyhow::bail!("no files available for processing");
    }

    display.files(&mut files).await?;
    let source = Files::new(input.file(&files)?);
    let target = Files::new(source.output_path(processing));
    if target.exists() && !input.overwrite(&target)? {
        anyhow::bail!("operation canceled");
    }

    let secret = SecretString::new(input.password(processing)?);
    let process = match processing {
        Processing::Encryption => encrypt_file(&source, &target, &secret).await?,
        Processing::Decryption => decrypt_file(&source, &target, &secret).await?,
    };

    display.success(processing, &target)?;
    display.header(&process.name, process.size, &process.hash)?;

    if input.delete(&source, processing)? {
        source.delete().await?;
        display.deleted(&source)?;
    }

    display.exit()?;

    Ok(())
}

async fn encrypt_file(source: &Files, target: &Files, secret: &SecretString) -> Result<FileHeader> {
    let metadata = source.file_metadata().await?;
    let salt = Key::generate_salt(SCRYPT_SALT_LEN)?;
    let key = derive_key(secret, &salt)?;
    let header = Serializer::new(Metadata::new(metadata.file_name, metadata.size, metadata.hash)?)?;

    let mut writer = target.writer().await?;
    writer.write_all(&header.serialize(&salt, &key)?).await?;

    Worker::new(&key, Processing::Encryption)?.process(source.reader().await?, writer, metadata.size).await?;

    Ok(FileHeader { name: header.file_name(), size: header.file_size(), hash: hex::encode(header.file_hash()) })
}

async fn decrypt_file(source: &Files, target: &Files, secret: &SecretString) -> Result<FileHeader> {
    let mut reader = source.reader().await?;
    let header = Deserializer::deserialize(reader.get_mut()).await?;

    let key = derive_key(secret, header.salt())?;
    if !header.verify(&key)? {
        anyhow::bail!("incorrect password");
    }

    Worker::new(&key, Processing::Decryption)?.process(reader, target.writer().await?, header.file_size()).await?;
    if !target.validate_hash(header.file_hash()).await? {
        anyhow::bail!("hash verification failed");
    }

    Ok(FileHeader { name: header.file_name().to_owned(), size: header.file_size(), hash: hex::encode(header.file_hash()) })
}

fn derive_key(secret: &SecretString, salt: &[u8]) -> Result<SecretBytes> {
    Key::new(secret.expose_secret().as_bytes())?.derive_key(salt)
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
