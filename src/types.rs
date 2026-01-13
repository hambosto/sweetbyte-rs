//! Common types used throughout SweetByte.

use std::path::PathBuf;

/// Processing mode for the file processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorMode {
    Encrypt,
    Decrypt,
}

impl ProcessorMode {
    /// Returns the display name for the mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl std::fmt::Display for ProcessorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Processing type for stream operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Processing {
    Encryption,
    Decryption,
}

impl Processing {
    /// Returns a description string for progress display.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }
}

impl std::fmt::Display for Processing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// A task to be processed by the worker pool.
#[derive(Debug)]
pub struct Task {
    /// The data to process.
    pub data: Vec<u8>,
    /// The task index for ordering.
    pub index: u64,
}

/// Result of processing a task.
#[derive(Debug)]
pub struct TaskResult {
    /// The task index for ordering.
    pub index: u64,
    /// The processed data.
    pub data: Vec<u8>,
    /// Size used for progress tracking.
    pub size: usize,
    /// Error message if processing failed.
    pub error: Option<String>,
}

impl TaskResult {
    /// Creates a successful task result.
    pub fn success(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self {
            index,
            data,
            size,
            error: None,
        }
    }

    /// Creates a failed task result.
    pub fn failure(index: u64, error: anyhow::Error) -> Self {
        Self {
            index,
            data: Vec::new(),
            size: 0,
            error: Some(error.to_string()),
        }
    }

    /// Returns true if the task succeeded.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// File information for display.
#[derive(Debug)]
pub struct FileInfo {
    /// File path.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Whether the file is encrypted.
    pub is_encrypted: bool,
}
