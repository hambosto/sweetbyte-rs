use std::fmt::{Display, Formatter, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorMode {
    Encrypt,
    Decrypt,
}

impl ProcessorMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Processing {
    Encryption,
    Decryption,
}

impl Processing {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }
}

impl Display for Processing {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.description())
    }
}

#[derive(Debug)]
pub struct Task {
    pub data: Vec<u8>,
    pub index: u64,
}

#[derive(Debug)]
pub struct TaskResult {
    pub data: Vec<u8>,
    pub error: Option<Box<str>>,
    pub index: u64,
    pub size: usize,
}

impl TaskResult {
    pub fn success(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    pub fn failure(index: u64, error: anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

#[derive(Debug)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub is_encrypted: bool,
}
