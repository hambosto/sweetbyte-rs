use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use crate::file::operations::is_encrypted_file;
use crate::file::validation::is_excluded;
use crate::types::ProcessorMode;

pub fn find_eligible_files(mode: ProcessorMode) -> Result<Vec<PathBuf>> {
    let files = WalkDir::new(".")
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_eligible(path, mode))
        .collect();

    Ok(files)
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
