use std::path::Path;

use walkdir::WalkDir;

use crate::config::EXCLUDED_PATTERNS;
use crate::pipeline::Processing;

use super::handle::Files;

impl Files {
    pub(crate) fn is_hidden(&self) -> bool {
        self.path().file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.'))
    }

    pub(crate) fn is_excluded(&self) -> bool {
        self.path()
            .iter()
            .filter_map(|c| c.to_str())
            .any(|part| EXCLUDED_PATTERNS.iter().any(|pattern| fast_glob::glob_match(pattern, part)))
    }

    pub(crate) fn is_eligible(&self, processing: Processing) -> bool {
        !self.is_hidden()
            && !self.is_excluded()
            && match processing {
                Processing::Encryption => !self.is_encrypted(),
                Processing::Decryption => self.is_encrypted(),
            }
    }

    pub(crate) fn discover(root: impl AsRef<Path>, processing: Processing) -> Vec<Self> {
        let mut files = Vec::new();

        for entry in WalkDir::new(root).follow_links(false).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            let file = Self::new(entry.into_path());
            if file.is_eligible(processing) {
                files.push(file);
            }
        }

        files
    }
}
