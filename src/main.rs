//! SweetByte - Secure File Encryption Tool
//!
//! SweetByte is a command-line tool for secure file encryption using modern
//! cryptographic algorithms and error correction. It provides both direct
//! command execution and interactive modes for user convenience.
//!
//! ## Features
//!
//! - **Strong Encryption**: AES-256-GCM and XChaCha20-Poly1305 algorithms
//! - **Error Correction**: Reed-Solomon coding for data corruption resistance
//! - **Memory Safety**: Rust's memory safety prevents common security vulnerabilities
//! - **Performance Optimized**: Parallel processing and efficient memory management
//! - **User Friendly**: Interactive mode with guided file selection
//!
//! ## Security Architecture
//!
//! The application follows defense-in-depth principles:
//!
//! 1. **Key Derivation**: Argon2 with configurable parameters for brute-force resistance
//! 2. **Authenticated Encryption**: Both confidentiality and integrity protection
//! 3. **Error Correction**: Recover from data corruption without cryptographic compromise
//! 4. **Secure Memory**: Proper handling of sensitive data in memory
//! 5. **Input Validation**: Comprehensive validation prevents injection and traversal attacks
//!
//! ## Module Organization
//!
//! The codebase is organized into logical modules:
//!
//! - `allocator`: Custom memory allocator for performance and security
//! - `cipher`: Cryptographic primitives and algorithms
//! - `cli`: Command-line interface and argument parsing
//! - `compression`: ZLIB compression for size optimization
//! - `config`: Global configuration constants and parameters
//! - `encoding`: Reed-Solomon error correction implementation
//! - `file`: Secure file operations and management
//! - `header`: File format header handling
//! - `padding`: PKCS#7 padding implementation
//! - `processor`: Main encryption/decryption orchestration
//! - `types`: Core type definitions and error handling
//! - `ui`: User interface components and interactive elements
//! - `worker`: Parallel processing workers
//!
//! ## Build Configuration
//!
//! The application uses custom memory allocation and optimized build settings
//! for security and performance. See `Cargo.toml` for build configuration.
//!
//! ## Error Handling
//!
//! All operations use comprehensive error handling with the `anyhow` crate
//! to provide clear error messages with context for debugging and user feedback.

// === Core Modules ===

// Custom memory allocator for improved performance and security
mod allocator;

// Cryptographic algorithms and implementations
mod cipher;

// Command-line interface and argument processing
mod cli;

// Data compression functionality
mod compression;

// Global configuration constants
mod config;

// Error correction coding
mod encoding;

// File system operations and management
mod file;

// File format header handling
mod header;

// Padding schemes for block alignment
mod padding;

// Main processing orchestration
mod processor;

// Core type definitions and error types
mod types;

// User interface components
mod ui;

// Parallel processing workers
mod worker;

// === External Dependencies ===

use anyhow::Result;
use cli::Cli;

/// Application entry point
///
/// This function serves as the main entry point for the SweetByte application.
/// It initializes the command-line interface and delegates all processing
/// to the appropriate handlers based on user input.
///
/// # Functionality
///
/// 1. Parse command-line arguments using clap
/// 2. Route to appropriate command handler
/// 3. Provide error handling and user feedback
/// 4. Return appropriate exit codes
///
/// # Error Handling
///
/// The function returns `Result<()>` which allows the Rust runtime to:
/// - Print error messages to stderr on failure
/// - Exit with non-zero status code on errors
/// - Provide clean error output for users
///
/// # Performance
///
/// The main function is intentionally lightweight - all heavy lifting
/// is delegated to specialized modules for better code organization
/// and maintainability.
///
/// # Security
///
/// - No sensitive data is stored in static variables
/// - Command-line arguments are validated before processing
/// - Memory allocation is properly managed through custom allocator
/// - Error messages are sanitized to avoid information leakage
///
/// # Usage
///
/// ```bash
/// # Direct encryption
/// sweetbyte-rs encrypt -i input.txt -o encrypted.swx
///
/// # Direct decryption
/// sweetbyte-rs decrypt -i encrypted.swx -o decrypted.txt
///
/// # Interactive mode
/// sweetbyte-rs
/// ```
///
/// # Exit Codes
///
/// - `0`: Successful execution
/// - `1`: Error occurred (details printed to stderr)
/// - `2`: Invalid command-line arguments (handled by clap)
fn main() -> Result<()> {
    // Initialize CLI and execute the requested operation
    Cli::init().execute()
}
