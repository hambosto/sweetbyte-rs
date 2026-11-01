use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs::{File, OpenOptions};

use crate::config::FILE_EXTENSION;
use crate::core::{Metadata, Operation};
use crate::crypto::Hash;

pub(crate) struct FileEntry {
    path: PathBuf,
}

impl FileEntry {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn name(&self) -> String {
        self.path.file_name().map_or_default(|name| name.to_string_lossy().into_owned())
    }

    pub(crate) fn exists(&self) -> bool {
        self.path.exists()
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        self.path.extension().is_some_and(|extension| extension == FILE_EXTENSION)
    }

    pub(crate) fn output_path(&self, operation: Operation) -> PathBuf {
        match operation {
            Operation::Encryption => self.path.with_added_extension(FILE_EXTENSION),
            Operation::Decryption => self.path.with_extension(""),
        }
    }

    pub(crate) async fn reader(&self) -> Result<File> {
        File::open(&self.path).await.context("failed to open source file")
    }

    pub(crate) async fn writer(&self) -> Result<File> {
        if let Some(parent) = self.path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.context("failed to create output directory")?;
        }

        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .await
            .context("failed to create output file")
    }

    pub(crate) async fn delete(&self) -> Result<()> {
        tokio::fs::remove_file(&self.path).await.context("failed to remove source file")
    }

    pub(crate) async fn size(&self) -> Result<u64> {
        tokio::fs::metadata(&self.path).await.map(|metadata| metadata.len()).context("failed to stat source file")
    }

    pub(crate) async fn metadata(&self) -> Result<Metadata> {
        let file_hash = Hash::new(self.path()).compute().context("failed to hash source file")?;
        let file_name = self.name();
        let file_size = self.size().await.context("failed to read source size")?;

        Metadata::new(file_name, file_size, &file_hash)
    }
}
