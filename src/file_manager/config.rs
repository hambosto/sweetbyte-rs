use crate::config::{EXCLUDED_DIRS, EXCLUDED_EXTS};
use std::path::Path;

/// Configuration for file discovery and processing.
///
/// This struct holds references to static configuration data rather than
/// owning the data, making it more efficient and idiomatic.
#[derive(Debug, Clone, Copy)]
pub struct FileConfig {
    pub excluded_dirs: &'static [&'static str],
    pub excluded_exts: &'static [&'static str],
}

impl FileConfig {
    /// Creates a new FileConfig with default values.
    pub const fn new() -> Self {
        Self {
            excluded_dirs: EXCLUDED_DIRS,
            excluded_exts: EXCLUDED_EXTS,
        }
    }

    /// Checks if a directory should be excluded.
    ///
    /// This walks through all path components and checks if any component
    /// matches an excluded directory name.
    pub fn is_excluded_dir(&self, path: &Path) -> bool {
        path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .map(|name| {
                    self.excluded_dirs
                        .iter()
                        .any(|dir| dir.trim_end_matches('/') == name)
                })
                .unwrap_or(false)
        })
    }

    /// Checks if a file should be excluded based on its extension or filename.
    ///
    /// Checks against both file extensions (e.g., ".rs") and full filename
    /// patterns (e.g., "go.mod").
    pub fn is_excluded_ext(&self, path: &Path) -> bool {
        path.to_str()
            .map(|path_str| self.excluded_exts.iter().any(|ext| path_str.ends_with(ext)))
            .unwrap_or(false)
    }
}

impl Default for FileConfig {
    fn default() -> Self {
        Self::new()
    }
}
