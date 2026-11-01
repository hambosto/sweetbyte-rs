use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct FileItem {
    path: PathBuf,
    name: String,
    size: u64,
    is_encrypted: bool,
}

impl FileItem {
    pub(crate) fn new(path: impl Into<PathBuf>, name: String, size: u64, is_encrypted: bool) -> Self {
        Self { path: path.into(), name, size, is_encrypted }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }
}
