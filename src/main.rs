//! SweetByte - A resilient, secure, and efficient file encryption tool.
//!
//! SweetByte protects your files using a multi-layered cryptographic pipeline with:
//! - **Dual-algorithm encryption**: AES-256-GCM layered with XChaCha20-Poly1305 for
//!   defense-in-depth.
//! - **Strong key derivation**: Argon2id password hashing to resist brute-force attacks.
//! - **Error correction**: Reed-Solomon encoding enables recovery from partial data corruption.
//! - **Content integrity**: BLAKE3 hashing ensures 100% data integrity after decryption.
//! - **Tamper-proof headers**: HMAC-SHA256 authentication prevents header tampering.
//!
//! # Architecture
//!
//! The system uses a three-stage concurrent processing pipeline:
//! 1. **Reader thread** - Reads input file in chunks and sends tasks via channels.
//! 2. **Executor pool** - Processes tasks in parallel using Rayon's work-stealing scheduler.
//! 3. **Writer thread** - Receives results, reorders them sequentially, and writes to output.
//!
//! # Encryption Pipeline
//!
//! Data flows through these stages during encryption:
//! 1. Zlib compression (reduces file size).
//! 2. PKCS7 padding (aligns to 128-byte blocks).
//! 3. AES-256-GCM encryption (industry-standard authenticated encryption).
//! 4. XChaCha20-Poly1305 encryption (modern stream cipher with extended nonce).
//! 5. Reed-Solomon encoding (adds resilience to corruption).
//!
//! Decryption reverses this pipeline.
//!
//! # Usage
//!
//! ## Command-Line Mode
//!
//! ```ignore
//! # Encrypt a file (prompts for password)
//! sweetbyte-rs encrypt -i document.txt -o document.swx
//!
//! # Decrypt a file (prompts for password)
//! sweetbyte-rs decrypt -i document.swx -o document.txt
//!
//! # Auto-derive output paths
//! sweetbyte-rs encrypt -i document.txt  # Creates document.txt.swx
//! sweetbyte-rs decrypt -i document.txt.swx  # Creates document.txt
//! ```
//!
//! ## Interactive Mode
//!
//! ```ignore
//! # Launch guided wizard
//! sweetbyte-rs
//! ```
//!
//! # File Format
//!
//! Encrypted files (`.swx`) contain:
//! - **Secure header** (variable size): magic bytes, salt, parameters, metadata, MAC.
//!   - All header sections are Reed-Solomon encoded for corruption resilience.
//! - **Data chunks**: encrypted blocks with length prefixes.
//!
//! # Modules
//!
//! - [`allocator`] - Global mimalloc allocator for efficient memory management.
//! - [`cipher`] - Dual-algorithm encryption, key derivation, hashing, and MAC.
//! - [`cli`] - Command-line interface using clap and dialoguer.
//! - [`compression`] - Zlib compression/decompression.
//! - [`config`] - Application constants and cryptographic parameters.
//! - [`encoding`] - Reed-Solomon error correction.
//! - [`mod@file`] - File discovery, validation, and I/O operations.
//! - [`header`] - Secure header management with Reed-Solomon protection.
//! - [`padding`] - PKCS7 padding for block cipher alignment.
//! - [`processor`] - Encryption/decryption workflow orchestration.
//! - [`types`] - Core type definitions (enums, task types).
//! - [`ui`] - User interface components (progress bars, prompts, tables).
//! - [`worker`] - Concurrent processing pipeline (reader, executor, writer, buffer).

mod allocator;
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

use anyhow::Result;
use cli::Cli;

/// Application entry point.
///
/// Initializes the runtime and hands off control to the CLI handler.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the command-line interface logic.
    // This parses arguments (env::args) to determine if we are in interactive mode
    // or specific command mode (encrypt/decrypt).
    // The `init()` call uses `clap` to handle parsing.
    // The `execute()` call runs the async business logic.
    Cli::init().execute().await
}
