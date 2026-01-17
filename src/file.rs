use std::fs;
use std::io::{BufReader, BufWriter, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, anyhow, bail};
use fast_glob::glob_match;
use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::types::ProcessorMode;

static EXCLUSION_MATCHERS: LazyLock<Vec<String>> = LazyLock::new(|| EXCLUDED_PATTERNS.iter().map(|s| s.to_string()).collect());

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

    pub fn with_metadata(path: impl Into<PathBuf>) -> Result<Option<Self>> {
        let path = path.into();
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("stat failed: {}", path.display())),
        };

        Ok(Some(Self { path, size: Some(meta.len()), is_selected: true }))
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
    pub fn is_selected(&self) -> bool {
        self.is_selected
    }

    #[inline]
    pub fn set_selected(&mut self, selected: bool) {
        self.is_selected = selected;
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
        WalkDir::new(".")
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| File::new(entry.into_path()))
            .filter(|file| file.is_eligible(mode))
            .collect::<Vec<_>>()
            .pipe(Ok)
    }

    pub fn load_metadata(paths: &[PathBuf]) -> Result<Vec<Self>> {
        paths
            .iter()
            .map(|path| File::with_metadata(path)?.ok_or_else(|| anyhow!("file not found: {}", path.display())))
            .collect()
    }
}

trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_new() {
        let file = File::new("test.txt");
        assert_eq!(file.path(), Path::new("test.txt"));
        assert!(file.is_selected());
        assert_eq!(file.size_if_loaded(), None);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(File::new("file.swx").is_encrypted());
        assert!(!File::new("file.txt").is_encrypted());
        assert!(!File::new("file").is_encrypted());
    }

    #[test]
    fn test_is_hidden() {
        assert!(File::new(".hidden").is_hidden());
        assert!(File::new(".gitignore").is_hidden());
        assert!(!File::new("visible.txt").is_hidden());
    }

    #[test]
    fn test_is_eligible_encrypt() {
        assert!(File::new("document.txt").is_eligible(ProcessorMode::Encrypt));
        assert!(!File::new("document.swx").is_eligible(ProcessorMode::Encrypt));
        assert!(!File::new(".hidden").is_eligible(ProcessorMode::Encrypt));
    }

    #[test]
    fn test_is_eligible_decrypt() {
        assert!(File::new("document.swx").is_eligible(ProcessorMode::Decrypt));
        assert!(!File::new("document.txt").is_eligible(ProcessorMode::Decrypt));
    }

    #[test]
    fn test_is_not_excluded() {
        assert!(!File::new("document.txt").is_excluded());
        assert!(!File::new("image.png").is_excluded());
        assert!(!File::new("data.json").is_excluded());
        assert!(!File::new("photo.jpg").is_excluded());
        assert!(!File::new("video.mp4").is_excluded());
        assert!(!File::new("music.mp3").is_excluded());
        assert!(!File::new("spreadsheet.xlsx").is_excluded());
    }

    #[test]
    fn test_output_path_encrypt() {
        let file = File::new("document.txt");
        assert_eq!(file.output_path(ProcessorMode::Encrypt), PathBuf::from("document.txt.swx"));
    }

    #[test]
    fn test_output_path_decrypt() {
        let file = File::new("document.txt.swx");
        assert_eq!(file.output_path(ProcessorMode::Decrypt), PathBuf::from("document.txt"));
    }

    #[test]
    fn test_reader_writer() {
        let dir = tempdir().unwrap();
        let file = File::new(dir.path().join("test.txt"));

        // Write data
        {
            let mut writer = file.writer().unwrap();
            writer.write_all(b"Hello, World!").unwrap();
        }

        // Read data
        let mut reader = file.reader().unwrap();
        let mut content = Vec::new();
        reader.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"Hello, World!");
    }

    #[test]
    fn test_exists_and_delete() {
        let dir = tempdir().unwrap();
        let file = File::new(dir.path().join("test.txt"));

        assert!(!file.exists());

        // Create file
        file.writer().unwrap();
        assert!(file.exists());

        // Delete file
        file.delete().unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_validate_must_exist() {
        let dir = tempdir().unwrap();
        let mut file = File::new(dir.path().join("test.txt"));

        // Should fail - doesn't exist
        assert!(file.validate(true).is_err());

        // Create file
        file.writer().unwrap().write_all(b"content").unwrap();

        // Should pass - exists and not empty
        assert!(file.validate(true).is_ok());
    }

    #[test]
    fn test_validate_must_not_exist() {
        let dir = tempdir().unwrap();
        let mut file = File::new(dir.path().join("test.txt"));

        // Should pass - doesn't exist
        assert!(file.validate(false).is_ok());

        // Create file
        file.writer().unwrap();

        // Should fail - exists
        assert!(file.validate(false).is_err());
    }

    #[test]
    fn test_selection() {
        let mut file = File::new("test.txt");
        assert!(file.is_selected());

        file.set_selected(false);
        assert!(!file.is_selected());

        file.set_selected(true);
        assert!(file.is_selected());
    }

    #[test]
    fn test_with_metadata() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");

        // File doesn't exist
        assert!(File::with_metadata(&path).unwrap().is_none());

        // Create file
        fs::write(&path, b"Hello").unwrap();

        // File exists
        let file = File::with_metadata(&path).unwrap().unwrap();
        assert_eq!(file.path(), path);
        assert_eq!(file.size_if_loaded(), Some(5));
    }
}
