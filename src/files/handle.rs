use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs::File;
use tokio::io::{BufReader, BufWriter};

use crate::config::FILE_EXTENSION;
use crate::pipeline::Processing;

pub(crate) struct Metadata {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) hash: Vec<u8>,
}

pub(crate) struct Files {
    path: PathBuf,
}

impl Files {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn name(&self) -> &str {
        self.path.file_name().and_then(|n| n.to_str()).unwrap_or_default()
    }

    pub(crate) fn exists(&self) -> bool {
        self.path.exists()
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        self.path.extension().and_then(|e| e.to_str()).is_some_and(|e| e == FILE_EXTENSION)
    }

    pub(crate) fn output_path(&self, processing: Processing) -> PathBuf {
        match processing {
            Processing::Encryption => self.path.with_added_extension(FILE_EXTENSION),
            Processing::Decryption => self.path.with_extension(""),
        }
    }

    pub(crate) async fn reader(&self) -> Result<BufReader<File>> {
        File::open(&self.path).await.map(BufReader::new).context("failed to open file")
    }

    pub(crate) async fn writer(&self) -> Result<BufWriter<File>> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.context("failed to create directory")?;
        }

        tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .await
            .map(BufWriter::new)
            .context("failed to create file")
    }

    pub(crate) async fn delete(&self) -> Result<()> {
        if !self.exists() {
            anyhow::bail!("file does not exist: {}", self.path.display());
        }

        tokio::fs::remove_file(&self.path).await.context("failed to delete file")
    }

    pub(crate) async fn size(&self) -> Result<u64> {
        tokio::fs::metadata(&self.path).await.map(|m| m.len()).context("failed to read metadata")
    }

    pub(crate) async fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata { name: self.name().to_owned(), size: self.size().await?, hash: super::hash::hash(self)? })
    }
}
