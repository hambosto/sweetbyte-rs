use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, BufReader, BufWriter};
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

pub struct File {
    path: PathBuf,
    size: Option<u64>,
}

impl File {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), size: None }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn hash(&self) -> Result<Vec<u8>> {
        let mut reader = self.reader().await?;
        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let bytes_read = reader.read(&mut buffer).await.context("read for hash")?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize().as_bytes().to_vec())
    }

    pub async fn size(&mut self) -> Result<u64> {
        if let Some(size) = self.size {
            return Ok(size);
        }

        let meta = tokio::fs::metadata(&self.path).await.with_context(|| format!("metadata read error: {}", self.path.display()))?;
        self.size = Some(meta.len());

        Ok(meta.len())
    }

    pub async fn file_metadata(&self) -> Result<(String, u64, Vec<u8>)> {
        let meta = tokio::fs::metadata(&self.path).await.with_context(|| format!("read metadata: {}", self.path.display()))?;
        let filename = self.path.file_name().map_or_else(|| "unknown".to_owned(), |n| n.to_string_lossy().into_owned());
        let size = meta.len();
        let hash = self.hash().await?;

        Ok((filename, size, hash))
    }

    pub fn is_encrypted(&self) -> bool {
        self.path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
    }

    pub fn is_hidden(&self) -> bool {
        self.path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'))
    }

    pub fn is_excluded(&self) -> bool {
        let path_str = self.path.to_str().unwrap_or("");

        EXCLUDED_PATTERNS.iter().any(|pattern| {
            let full_match = fast_glob::glob_match(pattern, path_str);
            if full_match {
                return true;
            }

            self.path.components().any(|comp| fast_glob::glob_match(pattern, comp.as_os_str().to_str().unwrap_or("")))
        })
    }

    pub fn is_eligible(&self, mode: ProcessorMode) -> bool {
        if self.is_hidden() || self.is_excluded() {
            return false;
        }

        match mode {
            ProcessorMode::Encrypt => !self.is_encrypted(),
            ProcessorMode::Decrypt => self.is_encrypted(),
        }
    }

    pub fn output_path(&self, mode: ProcessorMode) -> PathBuf {
        match mode {
            ProcessorMode::Encrypt => {
                if let Some(name) = self.path.to_str() {
                    PathBuf::from(format!("{name}{FILE_EXTENSION}"))
                } else {
                    self.path.clone()
                }
            }
            ProcessorMode::Decrypt => {
                if let Some(stripped) = self.path.to_string_lossy().strip_suffix(FILE_EXTENSION) {
                    PathBuf::from(stripped)
                } else {
                    self.path.clone()
                }
            }
        }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    pub async fn reader(&self) -> Result<BufReader<tokio::fs::File>> {
        let file = tokio::fs::File::open(&self.path).await.with_context(|| format!("open file: {}", self.path.display()))?;

        Ok(BufReader::new(file))
    }

    pub async fn writer(&self) -> Result<BufWriter<tokio::fs::File>> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.with_context(|| format!("create dir: {}", parent.display()))?;
        }

        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .await
            .with_context(|| format!("create file: {}", self.path.display()))?;

        Ok(BufWriter::new(file))
    }

    pub async fn delete(&self) -> Result<()> {
        if !self.exists() {
            anyhow::bail!("file not found: {}", self.path.display());
        }

        tokio::fs::remove_file(&self.path).await.with_context(|| format!("delete file: {}", self.path.display()))
    }

    pub async fn validate(&mut self) -> bool {
        if !self.exists() {
            tracing::error!("file not found: {}", self.path().display());
            return false;
        }

        if self.is_dir() {
            tracing::error!("path is a directory: {}", self.path().display());
            return false;
        }

        if self.size().await.unwrap_or(0) == 0 {
            tracing::error!("file is empty: {}", self.path().display());
            return false;
        }

        true
    }

    pub async fn validate_hash(&self, expected_hash: &[u8]) -> Result<bool> {
        let file_hash = self.hash().await?;
        let result = bool::from(file_hash.as_slice().ct_eq(expected_hash));

        Ok(result)
    }

    pub fn discover(mode: ProcessorMode) -> Vec<Self> {
        WalkDir::new(".")
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| Self::new(entry.into_path()))
            .filter(|file| file.is_eligible(mode))
            .collect()
    }
}
