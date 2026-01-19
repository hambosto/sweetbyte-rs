use std::fmt::{Display, Formatter, Result};

#[derive(Clone, Copy, PartialEq)]
pub enum ProcessorMode {
    Encrypt,
    Decrypt,
}

impl ProcessorMode {
    pub const ALL: &'static [Self] = &[Self::Encrypt, Self::Decrypt];

    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

impl Display for ProcessorMode {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

#[derive(Clone, Copy)]
pub enum Processing {
    Encryption,
    Decryption,
}

impl Processing {
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encryption => "Encrypting...",
            Self::Decryption => "Decrypting...",
        }
    }

    pub fn mode(&self) -> ProcessorMode {
        match self {
            Self::Encryption => ProcessorMode::Encrypt,
            Self::Decryption => ProcessorMode::Decrypt,
        }
    }
}

impl Display for Processing {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(self.label())
    }
}

pub struct Task {
    pub data: Vec<u8>,
    pub index: u64,
}

pub struct TaskResult {
    pub data: Vec<u8>,
    pub error: Option<Box<str>>,
    pub index: u64,
    pub size: usize,
}

impl TaskResult {
    #[inline]
    pub fn ok(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { data, error: None, index, size }
    }

    #[inline]
    pub fn err(index: u64, error: anyhow::Error) -> Self {
        Self { data: Vec::new(), error: Some(error.to_string().into_boxed_str()), index, size: 0 }
    }
}
