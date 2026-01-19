use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use fast_glob::glob_match;
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

static EXCLUSION_MATCHERS: LazyLock<Vec<String>> = LazyLock::new(|| EXCLUDED_PATTERNS.iter().map(|s| (*s).to_string()).collect());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    path: PathBuf,
    size: Option<u64>,
    is_selected: bool,
}

impl File {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), size: None, is_selected: true }
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&mut self) -> Result<u64> {
        if let Some(size) = self.size {
            return Ok(size);
        }

        let meta = fs::metadata(&self.path).with_context(|| format!("failed to get metadata: {}", self.path.display()))?;
        self.size = Some(meta.len());
        Ok(meta.len())
    }

    #[inline]
    pub fn size_if_loaded(&self) -> Option<u64> {
        self.size
    }

    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
    }

    #[inline]
    pub fn is_hidden(&self) -> bool {
        self.path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'))
    }

    pub fn is_excluded(&self) -> bool {
        let path_str = self.path.to_str().unwrap_or("");

        EXCLUSION_MATCHERS
            .iter()
            .any(|pattern| glob_match(pattern, path_str) || self.path.components().any(|comp| glob_match(pattern, comp.as_os_str().to_str().unwrap_or(""))))
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
                let mut name = self.path.as_os_str().to_os_string();
                name.push(FILE_EXTENSION);
                PathBuf::from(name)
            }
            ProcessorMode::Decrypt => self.path.to_string_lossy().strip_suffix(FILE_EXTENSION).map_or_else(|| self.path.clone(), PathBuf::from),
        }
    }

    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    pub fn reader(&self) -> Result<BufReader<fs::File>> {
        let file = fs::File::open(&self.path).with_context(|| format!("failed to open file: {}", self.path.display()))?;
        Ok(BufReader::new(file))
    }

    pub fn writer(&self) -> Result<BufWriter<fs::File>> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .with_context(|| format!("failed to create file: {}", self.path.display()))?;

        Ok(BufWriter::new(file))
    }

    pub fn delete(&self) -> Result<()> {
        if !self.exists() {
            bail!("file not found: {}", self.path.display());
        }

        fs::remove_file(&self.path).with_context(|| format!("failed to delete file: {}", self.path.display()))
    }

    pub fn validate(&mut self, must_exist: bool) -> Result<()> {
        if must_exist {
            if !self.exists() {
                bail!("file not found: {}", self.path.display());
            }

            if self.is_dir() {
                bail!("path is a directory: {}", self.path.display());
            }

            let size = self.size()?;
            if size == 0 {
                bail!("file is empty: {}", self.path.display());
            }
        } else if self.exists() {
            bail!("file already exists: {}", self.path.display());
        }

        Ok(())
    }

    pub fn discover(mode: ProcessorMode) -> Result<Vec<Self>> {
        Ok(WalkDir::new(".")
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| File::new(entry.into_path()))
            .filter(|file| file.is_eligible(mode))
            .collect::<Vec<File>>())
    }
}
