//! SweetByte - Multi-layered file encryption with error correction.
//!
//! A resilient, secure, and efficient file encryption tool that uses:
//! - AES-256-GCM and XChaCha20-Poly1305 for dual-layer encryption
//! - Argon2id for key derivation
//! - Reed-Solomon for error correction
//! - Zlib for compression
//! - PKCS7 for padding

pub mod cli;
pub mod compression;
pub mod config;
pub mod crypto;
pub mod encoding;
pub mod file;
pub mod header;
pub mod interactive;
pub mod padding;
pub mod processor;
pub mod stream;
pub mod types;
pub mod ui;

// pub use anyhow::{Context, Result, anyhow, bail};
