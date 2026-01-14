use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

use crate::file::operations::is_encrypted_file;
use crate::file::validation::is_excluded;
use crate::types::ProcessorMode;

pub fn find_eligible_files(mode: ProcessorMode) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    walk_directory(".", |path| {
        if is_eligible(path, mode) {
            files.push(path.to_path_buf());
        }
    })?;

    Ok(files)
}

fn walk_directory<F>(dir: &str, mut callback: F) -> Result<()>
where
    F: FnMut(&Path),
{
    fn walk_inner<F>(dir: &Path, callback: &mut F) -> Result<()>
    where
        F: FnMut(&Path),
    {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_inner(&path, callback)?;
            } else {
                callback(&path);
            }
        }

        Ok(())
    }

    walk_inner(Path::new(dir), &mut callback)
}

fn is_eligible(path: &Path, mode: ProcessorMode) -> bool {
    if let Some(name) = path.file_name()
        && name.to_string_lossy().starts_with('.')
    {
        return false;
    }

    if is_excluded(path) {
        return false;
    }

    let is_encrypted = is_encrypted_file(path);
    match mode {
        ProcessorMode::Encrypt => !is_encrypted,
        ProcessorMode::Decrypt => is_encrypted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_eligible_encrypt() {
        assert!(is_eligible(
            Path::new("document.txt"),
            ProcessorMode::Encrypt
        ));
        assert!(!is_eligible(
            Path::new("document.swx"),
            ProcessorMode::Encrypt
        ));
        assert!(!is_eligible(Path::new(".hidden"), ProcessorMode::Encrypt));
    }

    #[test]
    fn test_is_eligible_decrypt() {
        assert!(is_eligible(
            Path::new("document.swx"),
            ProcessorMode::Decrypt
        ));
        assert!(!is_eligible(
            Path::new("document.txt"),
            ProcessorMode::Decrypt
        ));
    }
}
