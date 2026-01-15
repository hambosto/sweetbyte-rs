use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::FILE_EXTENSION;
use crate::types::{FileInfo, ProcessorMode};

#[must_use = "the returned BufReader should be used to read the file"]
pub fn open_file(path: &Path) -> Result<BufReader<File>> {
    let file = File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;
    Ok(BufReader::new(file))
}

#[must_use = "the returned BufWriter should be used to write to the file"]
pub fn create_file(path: &Path) -> Result<BufWriter<File>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to create file: {}", path.display()))?;

    Ok(BufWriter::new(file))
}

pub fn delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("not found: {}", path.display());
    }

    fs::remove_file(path).with_context(|| format!("cannot remove: {}", path.display()))
}

#[must_use = "the returned FileInfo should be used"]
pub fn get_file_info(path: &Path) -> Result<Option<FileInfo>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat failed: {}", path.display())),
    };

    Ok(Some(FileInfo { path: path.to_path_buf(), size: meta.len(), is_encrypted: is_encrypted_file(path), is_selected: true }))
}

#[inline]
#[must_use]
pub fn get_output_path(input: &Path, mode: ProcessorMode) -> PathBuf {
    match mode {
        ProcessorMode::Encrypt => {
            let mut name = input.as_os_str().to_os_string();
            name.push(FILE_EXTENSION);
            PathBuf::from(name)
        }
        ProcessorMode::Decrypt => input.to_string_lossy().strip_suffix(FILE_EXTENSION).map_or_else(|| input.to_path_buf(), PathBuf::from),
    }
}

#[inline]
#[must_use]
pub fn is_encrypted_file(path: &Path) -> bool {
    path.as_os_str().to_string_lossy().ends_with(FILE_EXTENSION)
}

pub fn get_file_info_list(paths: &[PathBuf]) -> Result<Vec<FileInfo>> {
    paths.iter().map(|path| get_file_info(path)?.ok_or_else(|| anyhow!("file not found: {}", path.display()))).collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_create_and_open_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");

        {
            let mut writer = create_file(&path).unwrap();
            Write::write_all(&mut writer, b"Hello, World!").unwrap();
        }

        let reader = open_file(&path).unwrap();
        let content: Vec<u8> = Read::bytes(reader).map(|b| b.unwrap()).collect();
        assert_eq!(content, b"Hello, World!");
    }

    #[test]
    fn test_get_output_path_encrypt() {
        let input = Path::new("document.txt");
        let output = get_output_path(input, ProcessorMode::Encrypt);
        assert_eq!(output, PathBuf::from("document.txt.swx"));
    }

    #[test]
    fn test_get_output_path_decrypt() {
        let input = Path::new("document.txt.swx");
        let output = get_output_path(input, ProcessorMode::Decrypt);
        assert_eq!(output, PathBuf::from("document.txt"));
    }

    #[test]
    fn test_is_encrypted_file() {
        assert!(is_encrypted_file(Path::new("file.swx")));
        assert!(!is_encrypted_file(Path::new("file.txt")));
        assert!(!is_encrypted_file(Path::new("file")));
    }
}
