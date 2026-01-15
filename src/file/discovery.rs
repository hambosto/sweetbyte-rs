use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use crate::file::operations::is_encrypted_file;
use crate::file::validation::is_excluded;
use crate::types::ProcessorMode;

pub fn find_eligible_files(mode: ProcessorMode) -> Result<Vec<PathBuf>> {
    let files = WalkDir::new(".")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_eligible(path, mode))
        .collect();

    Ok(files)
}

#[inline]
fn is_eligible(path: &Path, mode: ProcessorMode) -> bool {
    let is_hidden = path.file_name().is_some_and(|name| name.to_string_lossy().starts_with('.'));

    if is_hidden || is_excluded(path) {
        return false;
    }

    match mode {
        ProcessorMode::Encrypt => !is_encrypted_file(path),
        ProcessorMode::Decrypt => is_encrypted_file(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_eligible_encrypt() {
        assert!(is_eligible(Path::new("document.txt"), ProcessorMode::Encrypt));
        assert!(!is_eligible(Path::new("document.swx"), ProcessorMode::Encrypt));
        assert!(!is_eligible(Path::new(".hidden"), ProcessorMode::Encrypt));
    }

    #[test]
    fn test_is_eligible_decrypt() {
        assert!(is_eligible(Path::new("document.swx"), ProcessorMode::Decrypt));
        assert!(!is_eligible(Path::new("document.txt"), ProcessorMode::Decrypt));
    }
}
