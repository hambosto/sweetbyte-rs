use std::{
    fmt::{Display, Formatter, Result},
    path::PathBuf,
};

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
    pub index: u64,
    pub data: Vec<u8>,
    pub size: usize,
    pub error: Option<String>,
}

impl TaskResult {
    pub fn success(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self {
            index,
            data,
            size,
            error: None,
        }
    }

    pub fn failure(index: u64, error: anyhow::Error) -> Self {
        Self {
            index,
            data: Vec::new(),
            size: 0,
            error: Some(error.to_string()),
        }
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
