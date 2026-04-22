use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader, BufWriter};
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::Processing;

pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
    pub hash: Vec<u8>,
}

pub struct Files {
    path: PathBuf,
}

impl Files {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn is_encrypted(&self) -> bool {
        self.path.extension().and_then(|e| e.to_str()) == Some(FILE_EXTENSION)
    }

    pub fn is_hidden(&self) -> bool {
        self.path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.'))
    }

    pub fn is_excluded(&self) -> bool {
        let parts: Vec<&str> = self.path.to_str().into_iter().chain(self.path.iter().filter_map(|c| c.to_str())).collect();

        EXCLUDED_PATTERNS.iter().any(|pat| parts.iter().any(|part| fast_glob::glob_match(pat, part)))
    }

    pub fn is_eligible(&self, processing: Processing) -> bool {
        if self.is_hidden() {
            return false;
        }

        if self.is_excluded() {
            return false;
        }

        match processing {
            Processing::Encryption => !self.is_encrypted(),
            Processing::Decryption => self.is_encrypted(),
        }
    }

    pub fn output_path(&self, processing: Processing) -> PathBuf {
        match processing {
            Processing::Encryption => self.path.with_added_extension(FILE_EXTENSION),
            Processing::Decryption => self.path.with_extension(""),
        }
    }

    pub async fn reader(&self) -> Result<BufReader<File>> {
        tokio::fs::File::open(&self.path).await.map(BufReader::new).context("failed to open file")
    }

    pub async fn writer(&self) -> Result<BufWriter<File>> {
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

    pub async fn delete(&self) -> Result<()> {
        anyhow::ensure!(self.exists(), "file not found {}", self.path.display());

        tokio::fs::remove_file(&self.path).await.context("failed to delete file")
    }

    pub async fn size(&self) -> Result<u64> {
        tokio::fs::metadata(&self.path).await.map(|m| m.len()).context("failed to read metadata")
    }

    pub async fn hash(&self) -> Result<Vec<u8>> {
        let mut reader = self.reader().await?;
        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];

        loop {
            let n = reader.read(&mut buffer).await.context("failed to hash file")?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(hasher.finalize().as_bytes().to_vec())
    }

    pub async fn validate_hash(&self, expected: &[u8]) -> Result<bool> {
        let actual = self.hash().await?;

        Ok(bool::from(actual.as_slice().ct_eq(expected)))
    }

    pub async fn file_metadata(&self) -> Result<FileMetadata> {
        let filename = self.path.file_name().context("invalid path")?.to_string_lossy().into();
        let size = self.size().await?;
        let hash = self.hash().await?;

        Ok(FileMetadata { filename, size, hash })
    }

    pub fn discover(root: impl AsRef<Path>, processing: Processing) -> Vec<Self> {
        WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| Self::new(e.into_path()))
            .filter(|f| f.is_eligible(processing))
            .collect()
    }
}
