// SweetByte - A secure file encryption tool
//
// Encryption: AES-256-GCM + XChaCha20-Poly1305 + Reed-Solomon error correction
// Key Derivation: Argon2id
// File Format: Custom header + encrypted data chunks with length prefixes

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
/// Parses command-line arguments or enters interactive mode,
/// then processes the specified file with encryption or decryption.
///
/// # Exit Codes
/// * 0 - Success
/// * 1 - Error (message printed to stderr)
fn main() {
    if let Err(e) = Cli::init().execute() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}
