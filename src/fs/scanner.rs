use std::path::PathBuf;

use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::core::Operation;

pub(crate) struct FileScanner {
    root: PathBuf,
    operation: Operation,
}

impl FileScanner {
    pub(crate) fn new(root: impl Into<PathBuf>, operation: Operation) -> Self {
        Self { root: root.into(), operation }
    }

    pub(crate) fn scan(&self) -> Vec<PathBuf> {
        let walker = WalkDir::new(&self.root).same_file_system(true).sort_by_file_name().into_iter().filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }

            let name = entry.file_name().to_string_lossy();
            if name.starts_with('.') {
                return false;
            }

            for pattern in EXCLUDED_PATTERNS.iter() {
                if fast_glob::glob_match(*pattern, name.as_bytes()) {
                    return false;
                }
            }

            true
        });

        let mut entries = Vec::new();

        for entry in walker {
            let Ok(entry) = entry else {
                continue;
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let is_encrypted = entry.path().extension().is_some_and(|extension| extension == FILE_EXTENSION);
            let wanted = match self.operation {
                Operation::Encryption => !is_encrypted,
                Operation::Decryption => is_encrypted,
            };
            if !wanted {
                continue;
            }

            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.len() == 0 {
                continue;
            }

            entries.push(entry.into_path());
        }

        entries
    }
}
