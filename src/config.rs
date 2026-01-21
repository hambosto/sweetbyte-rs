//! Application configuration constants.
//!
//! Defines all cryptographic parameters, file format specifications,
//! and operational constraints used throughout SweetByte.
//!
//! # Cryptographic Parameters
//!
//! - **Argon2id**: Memory-hard key derivation with 64KB memory, 3 iterations, 4 threads
//! - **AES-256-GCM**: 256-bit key, 96-bit (12-byte) nonce
//! - **XChaCha20-Poly1305**: 256-bit key, 192-bit (24-byte) nonce
//! - **HMAC-SHA256**: 256-bit authentication tag
//!
//! # File Format Constants
//!
//! - **Magic Bytes**: `0xCAFEBABE` - Identifies SweetByte encrypted files
//! - **Reed-Solomon**: 4 data shards + 10 parity shards for error correction
//! - **Chunk Size**: 256KB for streaming processing
//!
//! # Security Considerations
//!
//! These constants represent carefully chosen values that balance security,
//! performance, and compatibility. Changing them may break compatibility
//! with files encrypted using different parameters.

/// Application name displayed in CLI help and banners.
pub const APP_NAME: &str = "SweetByte";

/// File extension for encrypted files (`.swx`).
pub const FILE_EXTENSION: &str = ".swx";

/// Argon2id time cost parameter (number of iterations).
///
/// Higher values increase computational cost for brute-force attacks.
pub const ARGON_TIME: u32 = 3;

/// Argon2id memory cost in bytes (64 KB).
///
/// Memory-hard parameter that increases attacker's memory requirements.
pub const ARGON_MEMORY: u32 = 64 * 1024;

/// Argon2id parallelism parameter (number of lanes).
///
/// Controls parallel execution of the hash function.
pub const ARGON_THREADS: u32 = 4;

/// Length of the derived key in bytes.
///
/// The 64-byte key is split: 32 bytes for AES-256-GCM and 32 bytes for XChaCha20-Poly1305.
pub const ARGON_KEY_LEN: usize = 64;

/// Length of the random salt in bytes.
///
/// Used to prevent rainbow table attacks on password derivation.
pub const ARGON_SALT_LEN: usize = 32;

/// Number of data shards for Reed-Solomon encoding.
///
/// Data is split into this many shards before adding parity.
pub const DATA_SHARDS: usize = 4;

/// Number of parity shards for Reed-Solomon encoding.
///
/// These provide redundancy for error correction.
/// The ratio (10 parity / 4 data = 2.5x overhead) allows recovery
/// from up to 10 corrupted shards.
pub const PARITY_SHARDS: usize = 10;

/// Block size for PKCS7 padding.
///
/// Must match the block size of the block cipher (AES uses 128-bit/16-byte blocks,
/// but we use 128 bytes internally for efficiency).
pub const BLOCK_SIZE: usize = 128;

/// Chunk size for streaming file processing in bytes (256 KB).
///
/// Files are processed in chunks to support efficient streaming
/// and low memory usage for large files.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Magic bytes identifying a SweetByte encrypted file.
///
/// Value: `0xCAFEBABE` (little-endian representation).
pub const MAGIC_BYTES: u32 = 0xCAFE_BABE;

/// Size of magic bytes field in the header (4 bytes).
pub const MAGIC_SIZE: usize = 4;

/// Size of HMAC-SHA256 authentication tag (32 bytes).
pub const MAC_SIZE: usize = 32;

/// Size of header metadata in bytes.
///
/// Contains version (2 bytes), flags (4 bytes), and original size (8 bytes).
pub const HEADER_DATA_SIZE: usize = 14;

/// Current file format version.
///
/// Used for forward/backward compatibility. Version 1 (0x0001) is current.
pub const CURRENT_VERSION: u16 = 0x0001;

/// Flag indicating the file is protected/encrypted.
///
/// Bit 0 of the flags field. Must be set for valid encrypted files.
pub const FLAG_PROTECTED: u32 = 1;

/// AES-256-GCM key size (32 bytes / 256 bits).
pub const AES_KEY_SIZE: usize = 32;

/// AES-256-GCM nonce size (12 bytes / 96 bits).
pub const AES_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 key size (32 bytes / 256 bits).
pub const CHACHA_KEY_SIZE: usize = 32;

/// XChaCha20-Poly1305 nonce size (24 bytes / 192 bits).
pub const CHACHA_NONCE_SIZE: usize = 24;

/// Minimum password length in characters.
///
/// Enforced to prevent weak passwords.
pub const PASSWORD_MIN_LENGTH: usize = 8;

/// Patterns for excluding files/directories from discovery.
///
/// These patterns prevent accidentally encrypting sensitive data
/// or source code files.
pub const EXCLUDED_PATTERNS: &[&str] = &[
    "target",       // Build artifacts
    "vendor",       // Dependency directories
    "node_modules", // Node.js dependencies
    ".git",         // Git repositories
    ".github",      // GitHub configuration
    ".config",      // User configuration
    ".local",       // User data
    ".cache",       // Cached data
    ".ssh",         // SSH keys (sensitive!)
    ".gnupg",       // GPG keys (sensitive!)
    "*.rs",         // Rust source files
    "*.go",         // Go source files
];
