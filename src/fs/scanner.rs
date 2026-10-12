use std::path::PathBuf;

use walkdir::WalkDir;

use crate::core::Operation;

use super::entry::Entry;

pub(crate) struct Scanner {
    root: PathBuf,
    operation: Operation,
}

impl Scanner {
    pub(crate) fn new(root: impl Into<PathBuf>, operation: Operation) -> Self {
        Self { root: root.into(), operation }
    }

    pub(crate) fn scan(&self) -> Vec<Entry> {
        let mut entries = Vec::new();

        for entry in WalkDir::new(&self.root).min_depth(1).same_file_system(true).sort_by_file_name() {
            let Ok(entry) = entry else {
                continue;
            };

            let entry = Entry::new(entry.into_path());
            if self.is_eligible(&entry) {
                entries.push(entry);
            }
        }

        entries
    }

    fn is_eligible(&self, entry: &Entry) -> bool {
        if !entry.path().is_file() {
            return false;
        }

        if entry.is_empty() {
            return false;
        }

        if entry.is_hidden() {
            return false;
        }

        if entry.is_excluded() {
            return false;
        }

        match self.operation {
            Operation::Encryption => !entry.is_encrypted(),
            Operation::Decryption => entry.is_encrypted(),
        }
    }
}
