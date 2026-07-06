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
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
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
        let file_name = match path.file_name() {
            Some(file_name) => file_name,
            None => return false,
        };

        let file_name = match file_name.to_str() {
            Some(file_name) => file_name,
            None => return false,
        };

        file_name.starts_with('.')
    }

    fn is_excluded(path: &Path) -> bool {
        for component in path.iter() {
            let part = match component.to_str() {
                Some(part) => part,
                None => continue,
            };

            for pattern in EXCLUDED_PATTERNS.iter() {
                if fast_glob::glob_match(pattern, part) {
                    return true;
                }
            }
        }

        false
    }

    fn is_encrypted(path: &Path) -> bool {
        let extension = match path.extension() {
            Some(extension) => extension,
            None => return false,
        };

        let extension = match extension.to_str() {
            Some(extension) => extension,
            None => return false,
        };

        extension == FILE_EXTENSION
    }
}
