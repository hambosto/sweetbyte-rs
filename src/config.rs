//! Application configuration and cryptographic constants.
//!
//! This module defines the core constants used throughout the application, including:
//! - Cryptographic parameters (key sizes, nonce sizes, iteration counts)
//! - Application limits (buffer sizes, filename lengths)
//! - Feature flags and magic bytes
//! - Default configuration values
//!
//! These constants ensure consistency across the codebase and serve as the single
//! source of truth for the file format specification.

/// The application name used in user-facing output and prompts.
pub const APP_NAME: &str = "SweetByte";

/// The default file extension appended to encrypted files.
pub const FILE_EXTENSION: &str = ".swx";

/// Argon2id time cost (number of passes).
///
/// We use 3 passes to balance security and usability. This provides
/// substantial resistance to GPU-based cracking while keeping the
/// derivation time reasonable for the user (typically < 1 second).
pub const ARGON_TIME: u32 = 3;

/// Argon2id memory cost in KiB.
///
/// Set to 64 MiB (64 * 1024). This memory hardness requirement makes
/// ASIC/FPGA attacks significantly more expensive by requiring
/// dedicated RAM per candidate password tester.
pub const ARGON_MEMORY: u32 = 64 * 1024;

/// Argon2id parallelism factor (number of threads).
///
/// Set to 4 threads. This utilizes modern multi-core CPUs to compute
/// the hash faster for the legitimate user, while forcing an attacker
/// to replicate this parallelism (increasing silicon area cost).
pub const ARGON_THREADS: u32 = 4;

/// Length of the derived master key in bytes.
///
/// We derive a 64-byte key to support our dual-cipher architecture
/// (potentially splitting into two 32-byte keys) or for future extensibility.
pub const ARGON_KEY_LEN: usize = 64;

/// Length of the random salt used for key derivation in bytes.
///
/// 32 bytes (256 bits) provides complete protection against pre-computation
/// attacks (rainbow tables) and ensures uniqueness per file.
pub const ARGON_SALT_LEN: usize = 32;

/// Number of data shards for Reed-Solomon erasure coding.
///
/// This is the "k" parameter in the (n, k) RS code. We split data into
/// 4 original data shards.
pub const DATA_SHARDS: usize = 4;

/// Number of parity shards for Reed-Solomon erasure coding.
///
/// This is the "m" parameter. We generate 10 parity shards, allowing
/// recovery from the loss of any 10 shards (total 14). This provides
/// extremely high resilience to data corruption.
pub const PARITY_SHARDS: usize = 10;

/// The block size for operations requiring alignment, in bytes.
///
/// 128 bytes allows for alignment with cache lines and SIMD registers,
/// optimizing memory access patterns during processing.
pub const BLOCK_SIZE: usize = 128;

/// Size of data chunks read from the file in bytes.
///
/// Set to 256 KiB. This size is chosen to:
/// 1. Amortize the overhead of channel passing and thread synchronization.
/// 2. Fit comfortably in CPU L2/L3 caches.
/// 3. Keep memory usage proportional to thread count.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Magic bytes identifying a SweetByte encrypted file.
///
/// `0xDEAD_BEEF` is a recognizable pattern used in the file header
/// to quickly verify file type before attempting expensive decryption.
pub const MAGIC_BYTES: u32 = 0xDEAD_BEEF;

/// Size of the HMAC-SHA256 authentication tag in bytes.
pub const MAC_SIZE: usize = 32;

/// The current file format version.
///
/// Version 2 (`0x0002`) supports the latest header features including
/// Reed-Solomon protected headers and metadata.
pub const CURRENT_VERSION: u16 = 0x0002;

/// Algorithm identifier for AES-256-GCM.
pub const ALGORITHM_AES_256_GCM: u8 = 0x01;

/// Algorithm identifier for XChaCha20-Poly1305.
pub const ALGORITHM_CHACHA20_POLY1305: u8 = 0x02;

/// Size of the generic hash output (BLAKE3) in bytes.
pub const HASH_SIZE: usize = 32;

/// Compression method identifier for Zlib.
pub const COMPRESSION_ZLIB: u8 = 0x01;

/// Encoding method identifier for Reed-Solomon.
pub const ENCODING_REED_SOLOMON: u8 = 0x01;

/// Key Derivation Function identifier for Argon2id.
pub const KDF_ARGON2: u8 = 0x01;

/// Maximum allowed length for filenames preserved in metadata.
///
/// 256 bytes covers most filesystem limits (e.g., ext4 is 255 bytes).
pub const MAX_FILENAME_LENGTH: usize = 256;

/// Size of the nonce for AES-GCM in bytes.
///
/// Standard 12 bytes (96 bits) as recommended by NIST SP 800-38D.
pub const AES_NONCE_SIZE: usize = 12;

/// Size of the raw encryption key in bytes.
///
/// 32 bytes (256 bits) for AES-256 and XChaCha20.
pub const KEY_SIZE: usize = 32;

/// Size of the extended nonce for XChaCha20 in bytes.
///
/// 24 bytes (192 bits) allows for random nonces without risk of collision,
/// unlike standard ChaCha20's 12-byte nonce.
pub const CHACHA_NONCE_SIZE: usize = 24;

/// Minimum required password length.
///
/// Enforces a basic level of entropy for user passwords.
pub const PASSWORD_MIN_LENGTH: usize = 8;

/// List of file and directory patterns to exclude during recursive directory scanning.
///
/// Includes version control directories, build artifacts, and system caches
/// to prevent encrypting unnecessary or temporary files.
pub const EXCLUDED_PATTERNS: &[&str] = &["target", "vendor", "node_modules", ".git", ".github", ".config", ".local", ".cache", ".ssh", ".gnupg", "*.rs", "*.go"];
