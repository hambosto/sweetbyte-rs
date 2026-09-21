use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::core::Operation;

pub(crate) struct Scanner {
    root: PathBuf,
    operation: Operation,
}

impl Scanner {
    pub(crate) fn new(root: impl Into<PathBuf>, operation: Operation) -> Self {
        Self { root: root.into(), operation }
    }

    pub(crate) fn scan(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        for entry in WalkDir::new(&self.root).min_depth(1).same_file_system(true).sort_by_file_name() {
            let Ok(entry) = entry else {
                continue;
            };

            let path = entry.into_path();
            if self.is_eligible(&path) {
                paths.push(path);
            }
        }

        paths
    }

    fn is_eligible(&self, path: &Path) -> bool {
        if !path.is_file() {
            return false;
        }

        if Self::is_hidden(path) {
            return false;
        }

        if Self::is_excluded(path) {
            return false;
        }

        match self.operation {
            Operation::Encryption => !Self::is_encrypted(path),
            Operation::Decryption => Self::is_encrypted(path),
        }
    }

    fn is_hidden(path: &Path) -> bool {
        let Some(raw) = path.file_name() else {
            return false;
        };

        let Some(name) = raw.to_str() else {
            return false;
        };

        name.starts_with('.')
    }

    fn is_excluded(path: &Path) -> bool {
        for component in path {
            let Some(segment) = component.to_str() else {
                continue;
            };

            for pattern in EXCLUDED_PATTERNS {
                if fast_glob::glob_match(pattern, segment) {
                    return true;
                }
            }
        }

        false
    }

    fn is_encrypted(path: &Path) -> bool {
        let Some(extension) = path.extension() else {
            return false;
        };

        let Some(name) = extension.to_str() else {
            return false;
        };

        name == FILE_EXTENSION
    }
}
