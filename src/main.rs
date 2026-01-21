//! Main entry point and module organization for SweetByte.
//!
//! SweetByte is a resilient, secure, and efficient file encryption tool that provides
//! multi-layered encryption using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon
//! error correction codes for data resilience.
//!
//! # Architecture
//!
//! The application is organized into the following modules:
//!
//! - [`cipher`]: Cryptographic primitives (AES-256-GCM, XChaCha20-Poly1305, Argon2id)
//! - [`cli`]: Command-line interface and interactive mode
//! - [`compression`]: Zlib compression/decompression
//! - [`config`]: Application constants and configuration
//! - [`encoding`]: Reed-Solomon error correction encoding
//! - [`mod@file`]: File discovery and operations
//! - [`header`]: Secure file header serialization/deserialization
//! - [`padding`]: PKCS7 padding for block ciphers
//! - [`processor`]: High-level encryption/decryption orchestration
//! - [`types`]: Common type definitions
//! - [`ui`]: User interface components
//! - [`worker`]: Concurrent file processing pipeline
//!
//! # Encryption Pipeline
//!
//! When encrypting a file, data passes through the following stages:
//!
//! 1. **Zlib Compression** - Reduces file size before encryption
//! 2. **PKCS7 Padding** - Aligns data to block boundaries
//! 3. **AES-256-GCM Encryption** - First layer of authenticated encryption
//! 4. **XChaCha20-Poly1305 Encryption** - Second layer of authenticated encryption
//! 5. **Reed-Solomon Encoding** - Adds error correction redundancy
//!
//! # Security Features
//!
//! - **Defense in Depth**: Dual encryption layers with distinct algorithms
//! - **Strong Key Derivation**: Argon2id with configurable parameters
//! - **Tamper Detection**: HMAC-SHA256 authentication with constant-time comparison
//! - **Resilient Format**: Reed-Solomon codes allow recovery from partial corruption

mod cipher;
mod cli;
mod compression;
mod config;
mod encoding;
mod file;
mod header;
mod padding;
mod processor;
mod types;
mod ui;
mod worker;

use std::process;

use cli::Cli;

/// Entry point for the SweetByte encryption tool.
///
/// Initializes the CLI parser and executes the requested operation.
/// Errors are printed to stderr with contextual information and
/// the process exits with a non-zero status code on failure.
fn main() {
    if let Err(e) = Cli::init().execute() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}
