use crate::config::{EXCLUDED_DIRS, EXCLUDED_EXTS};
use std::path::Path;

/// Configuration for file discovery and processing.
#[derive(Debug, Clone)]
pub struct FileConfig {
    pub excluded_dirs: Vec<String>,
    pub excluded_exts: Vec<String>,
}

impl FileConfig {
    /// Creates a new FileConfig with default values.
    pub fn new() -> Self {
        Self {
            excluded_dirs: EXCLUDED_DIRS.iter().map(|s| s.to_string()).collect(),
            excluded_exts: EXCLUDED_EXTS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Checks if a directory should be excluded.
    pub fn is_excluded_dir(&self, path: &Path) -> bool {
        path.components().any(|component| {
            if let Some(name) = component.as_os_str().to_str() {
                self.excluded_dirs
                    .iter()
                    .any(|dir| dir.trim_end_matches('/') == name)
            } else {
                false
            }
        })
    }

    /// Checks if a file extension should be excluded.
    pub fn is_excluded_ext(&self, path: &str) -> bool {
        self.excluded_exts.iter().any(|ext| path.ends_with(ext))
    }
}

impl Default for FileConfig {
    fn default() -> Self {
        Self::new()
    }
}
