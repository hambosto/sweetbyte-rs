use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;

use crate::cipher::Derive;
use crate::config::{ARGON_MEMORY, ARGON_SALT_LEN, ARGON_THREADS, ARGON_TIME};
use crate::file::File;
use crate::header::Header;
use crate::header::metadata::Metadata;
use crate::types::Processing;
use crate::worker::Worker;

pub struct Processor {
    password: String,
}

impl Processor {
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    pub async fn encrypt(&self, src: &mut File, dest: &File) -> Result<()> {
        if src.size().await? == 0 {
            anyhow::bail!("zero-size file");
        }

        let (filename, file_size, content_hash) = src.file_metadata().await?;
        let metadata = Metadata::new(filename, file_size, content_hash);
        let salt = Derive::generate_salt::<ARGON_SALT_LEN>()?;
        let key = Derive::new(self.password.as_bytes())?.derive_key(&salt, ARGON_MEMORY, ARGON_TIME, ARGON_THREADS)?;
        let header = Header::new(metadata)?;
        let header_bytes = header.serialize(&salt, &key)?;
        let reader = src.reader().await?;

        let mut writer = dest.writer().await?;
        writer.write_all(&header_bytes).await?;

        Worker::new(&key, Processing::Encryption)?.process(reader, writer, file_size).await?;

        crate::ui::show_header_info(header.file_name(), header.file_size(), &header.file_hash());

        Ok(())
    }

    pub async fn decrypt(&self, src: &File, dest: &File) -> Result<()> {
        if !src.exists() {
            anyhow::bail!("source file not found: {}", src.path().display());
        }

        let mut reader = src.reader().await?;
        let writer = dest.writer().await?;

        let header = Header::deserialize(reader.get_mut()).await?;
        if header.file_size() == 0 {
            anyhow::bail!("cannot decrypt a file with zero size");
        }

        let key = Derive::new(self.password.as_bytes())?.derive_key(header.salt()?, header.kdf_memory(), header.kdf_time().into(), header.kdf_parallelism().into())?;
        header.verify(&key).context("invalid password or corrupted data")?;

        Worker::new(&key, Processing::Decryption)?.process(reader, writer, header.file_size()).await?;

        if !dest.validate_hash(header.file_hash())? {
            anyhow::bail!("hash mismatch")
        }

        crate::ui::show_header_info(header.file_name(), header.file_size(), &header.file_hash());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    #[tokio::test]
    async fn test_processor_integration() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let filename = base_path.join("test_processor_integration.txt");
        let content = b"Integration test content for processor.";

        let enc_filename = base_path.join("test_processor_integration.txt.swx");
        let dec_filename = base_path.join("test_processor_integration_dec.txt");

        fs::write(&filename, content).await.unwrap();

        let mut src = File::new(&filename);
        let dest_enc = File::new(&enc_filename);
        let dest_dec = File::new(&dec_filename);

        let password = "strong_password";
        let processor = Processor::new(password);

        src.validate(true).await.unwrap();
        processor.encrypt(&mut src, &dest_enc).await.unwrap();

        assert!(dest_enc.exists());

        processor.decrypt(&dest_enc, &dest_dec).await.unwrap();

        assert!(dest_dec.exists());
        let decrypted_content = fs::read(&dec_filename).await.unwrap();
        assert_eq!(decrypted_content, content);
    }
}
