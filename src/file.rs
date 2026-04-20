use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, BufReader, BufWriter};
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
    pub hash: Vec<u8>,
}

pub struct File {
    path: PathBuf,
}

impl File {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use] 
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use] 
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    #[must_use] 
    pub fn is_encrypted(&self) -> bool {
        self.path.extension().is_some_and(|ext| ext == FILE_EXTENSION.trim_start_matches('.'))
    }

    #[must_use] 
    pub fn is_hidden(&self) -> bool {
        self.path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'))
    }

    #[must_use] 
    pub fn is_excluded(&self) -> bool {
        let path = self.path.to_str().unwrap_or("");

        EXCLUDED_PATTERNS
            .iter()
            .any(|pattern| fast_glob::glob_match(pattern, path) || self.path.components().any(|comp| fast_glob::glob_match(pattern, comp.as_os_str().to_str().unwrap_or(""))))
    }

    #[must_use] 
    pub fn is_eligible(&self, mode: ProcessorMode) -> bool {
        if self.is_hidden() || self.is_excluded() {
            return false;
        }

        match mode {
            ProcessorMode::Encrypt => !self.is_encrypted(),
            ProcessorMode::Decrypt => self.is_encrypted(),
        }
    }

    #[must_use] 
    pub fn output_path(&self, mode: ProcessorMode) -> PathBuf {
        match mode {
            ProcessorMode::Encrypt => {
                let mut p = self.path.clone().into_os_string();
                p.push(FILE_EXTENSION);
                PathBuf::from(p)
            }
            ProcessorMode::Decrypt => self.path.with_extension(""),
        }
    }

    pub async fn reader(&self) -> Result<BufReader<tokio::fs::File>> {
        tokio::fs::File::open(&self.path)
            .await
            .map(BufReader::new)
            .with_context(|| format!("Failed to open file: {}", self.path.display()))
    }

    pub async fn writer(&self) -> Result<BufWriter<tokio::fs::File>> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .await
            .map(BufWriter::new)
            .with_context(|| format!("Failed to create file: {}", self.path.display()))
    }

    pub async fn delete(&self) -> Result<()> {
        anyhow::ensure!(self.exists(), "File not found: {}", self.path.display());
        tokio::fs::remove_file(&self.path).await.context("Failed to delete file")
    }

    pub async fn size(&self) -> Result<u64> {
        tokio::fs::metadata(&self.path)
            .await
            .map(|m| m.len())
            .with_context(|| format!("Failed to read metadata: {}", self.path.display()))
    }

    pub async fn hash(&self) -> Result<Vec<u8>> {
        let mut reader = self.reader().await?;
        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];

        loop {
            let n = reader.read(&mut buffer).await.context("Failed to read file for hashing")?;
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
        let filename = self.path.file_name().map_or_else(|| "unknown".to_owned(), |n| n.to_string_lossy().into_owned());

        let size = self.size().await?;
        let hash = self.hash().await?;

        Ok(FileMetadata { filename, size, hash })
    }

    pub fn discover(root: impl AsRef<Path>, mode: ProcessorMode) -> Vec<Self> {
        WalkDir::new(root)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| Self::new(e.into_path()))
            .filter(|f| f.is_eligible(mode))
            .collect()
    }
}
