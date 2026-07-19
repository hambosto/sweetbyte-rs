use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::config::{EXCLUDED_PATTERNS, FILE_EXTENSION};
use crate::pipeline::Processing;

pub(crate) struct Discover {
    root: String,
    processing: Processing,
}

impl Discover {
    pub(crate) fn new(root: impl Into<String>, processing: Processing) -> Self {
        Self { root: root.into(), processing }
    }

    pub(crate) fn run(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        for entry in WalkDir::new(&self.root).follow_links(false) {
            let Ok(entry) = entry else {
                continue;
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.into_path();
            if self.is_eligible(&path) {
                paths.push(path);
            }
        }

        paths
    }

    fn is_eligible(&self, path: &Path) -> bool {
        if Self::is_hidden(path) {
            return false;
        }

        if Self::is_excluded(path) {
            return false;
        }

        match self.processing {
            Processing::Encryption => !Self::is_encrypted(path),
            Processing::Decryption => Self::is_encrypted(path),
        }
    }

    fn is_hidden(path: &Path) -> bool {
        let Some(file_name) = path.file_name() else {
            return false;
        };

        let Some(file_name) = file_name.to_str() else {
            return false;
        };

        file_name.starts_with('.')
    }

    fn is_excluded(path: &Path) -> bool {
        for component in path {
            let Some(part) = component.to_str() else {
                continue;
            };

            for pattern in EXCLUDED_PATTERNS {
                if fast_glob::glob_match(pattern, part) {
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

        let Some(extension) = extension.to_str() else {
            return false;
        };

        extension == FILE_EXTENSION
    }
}
