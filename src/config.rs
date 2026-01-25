//! Global Configuration Constants
//!
//! This module contains all configuration parameters used throughout the SweetByte
//! application. These constants define cryptographic parameters, file formats,
//! performance settings, and security policies.
//!
//! ## Design Philosophy
//!
//! The configuration follows these principles:
//! - **Security First**: All cryptographic parameters use conservative, well-vetted values
//! - **Performance Aware**: Parameters balance security with reasonable performance
//! - **Future Proof**: Version numbers and algorithm identifiers support format evolution
//! - **Cross Platform**: Values work consistently across different operating systems
//!
//! ## Security Considerations
//!
//! - Argon2 parameters are chosen to resist GPU/ASIC attacks
//! - Nonce sizes provide sufficient collision resistance
//! - Key sizes meet current security standards (128+ bits of security)
//! - Reed-Solomon parameters provide strong error correction without excessive overhead

/// Application name used in user interfaces and file metadata
pub const APP_NAME: &str = "SweetByte";

/// File extension for encrypted files
///
/// This extension identifies files encrypted by SweetByte. It should be
/// unique enough to avoid conflicts with other applications while being
/// memorable and easy to type.
pub const FILE_EXTENSION: &str = ".swx";

// === Argon2 Key Derivation Parameters ===
// These parameters control the computational cost of password-based key derivation.
// They are chosen to provide strong resistance against brute-force attacks while
// remaining usable on typical modern hardware.

/// Argon2 time cost parameter (number of iterations)
///
/// This value determines how many passes the algorithm makes over memory.
/// Higher values increase resistance to brute-force attacks but also increase
/// processing time. Three iterations provide a good security/performance balance.
///
/// Security Impact: Each additional iteration doubles the attack cost
/// Performance Impact: Linear increase in processing time
pub const ARGON_TIME: u32 = 3;

/// Argon2 memory cost parameter in kilobytes
///
/// This controls how much memory the algorithm uses, which is critical for
/// resisting GPU and ASIC attacks that have limited memory. 64MB provides
/// strong protection while remaining accessible on most systems.
///
/// Security Impact: Higher memory requirements make parallel attacks more expensive
/// Performance Impact: Linear increase in memory usage, minimal CPU impact
pub const ARGON_MEMORY: u32 = 64 * 1024;

/// Argon2 parallelism parameter (number of threads)
///
/// Controls how many parallel lanes the algorithm uses. Four threads provide
/// good parallelism on modern multi-core processors while maintaining compatibility
/// with systems that have fewer cores.
///
/// Security Impact: Parallelism increases resistance to certain attack vectors
/// Performance Impact: Utilizes multiple CPU cores for faster processing
pub const ARGON_THREADS: u32 = 4;

/// Length of derived keys in bytes
///
/// 64 bytes (512 bits) provides sufficient length to derive both encryption
/// and MAC keys while maintaining a security margin. This exceeds the minimum
/// requirements for AES-256 and other supported algorithms.
pub const ARGON_KEY_LEN: usize = 64;

/// Length of Argon2 salt in bytes
///
/// 32 bytes provides 256 bits of randomness, which is more than sufficient
/// to prevent salt collision attacks. Each encryption operation uses a unique
/// salt to ensure identical passwords produce different keys.
///
/// Security Impact: Prevents pre-computation attacks and rainbow table attacks
/// Storage Cost: 32 bytes per encrypted file is negligible
pub const ARGON_SALT_LEN: usize = 32;

// === Reed-Solomon Error Correction Parameters ===
// These parameters control the resilience of the encoding against data corruption.
// The chosen values provide strong protection while keeping overhead reasonable.

/// Number of data shards in Reed-Solomon encoding
///
/// Data shards contain the original file data. Four shards provide a good
/// balance between error correction capability and computational overhead.
///
/// Performance Impact: More shards increase parallel processing potential
/// Storage Impact: No storage overhead for data shards
pub const DATA_SHARDS: usize = 4;

/// Number of parity shards in Reed-Solomon encoding
///
/// Parity shards provide error correction capability. Ten parity shards allow
/// recovery from up to 10 corrupted shards out of 14 total (4 data + 10 parity),
/// providing approximately 71% error tolerance.
///
/// Error Tolerance: Can recover from any 10 corrupted shards
/// Storage Overhead: Increases file size by 250% (10/4 parity ratio)
pub const PARITY_SHARDS: usize = 10;

// === Processing and Buffering Parameters ===
// These parameters control how data is processed in chunks for memory efficiency.

/// Block size for padding and cryptographic operations
///
/// 128 bytes aligns well with modern CPU cache lines and cryptographic block sizes.
/// This size provides good performance for both small and large files.
///
/// Performance Impact: Optimized for cache efficiency and SIMD operations
/// Memory Impact: Minimal per-operation memory overhead
pub const BLOCK_SIZE: usize = 128;

/// Chunk size for file processing operations
///
/// 256KB chunks provide a good balance between memory usage and I/O efficiency.
/// This size allows streaming processing of large files while keeping memory
/// usage reasonable on constrained systems.
///
/// Memory Impact: Peak memory usage is approximately this size
/// I/O Impact: Optimized for modern storage devices
pub const CHUNK_SIZE: usize = 256 * 1024;

// === File Format and Protocol Constants ===
// These constants define the binary format of encrypted files and protocol identifiers.

/// Magic bytes for file format identification
///
/// This 4-byte value identifies files created by SweetByte. It's checked
/// during decryption to verify file format compatibility and to prevent
/// processing of unrelated files.
///
/// Choice Criteria: Easy to recognize but unlikely to appear in random data
pub const MAGIC_BYTES: u32 = 0xDEAD_BEEF;

/// Size of authentication tag (MAC) in bytes
///
/// 32 bytes (256 bits) provides strong integrity protection for authenticated
/// encryption algorithms. This size is compatible with both AES-GCM and
/// ChaCha20-Poly1305 security requirements.
///
/// Security Impact: 2^256 probability of successful forgery attack
/// Storage Impact: 32 bytes per file
pub const MAC_SIZE: usize = 32;

/// Current file format version
///
/// Version 2 includes all current features while maintaining compatibility
/// with future extensions. The version number allows the application to
/// handle different file formats gracefully.
///
/// Format Evolution: Future versions will maintain backward compatibility
/// where possible, or provide clear upgrade paths.
pub const CURRENT_VERSION: u16 = 0x0002;

// === Algorithm Identifiers ===
// These constants identify the algorithms used in the encrypted file format.

/// Identifier for AES-256-GCM encryption algorithm
///
/// AES with 256-bit key in Galois/Counter Mode provides:
/// - Strong encryption (256-bit security level)
/// - Authenticated encryption (integrity protection)
/// - Hardware acceleration support on most modern CPUs
pub const ALGORITHM_AES_256_GCM: u8 = 0x01;

/// Identifier for XChaCha20-Poly1305 encryption algorithm
///
/// XChaCha20 with Poly1305 provides:
/// - Strong encryption (256-bit security level)
/// - Authenticated encryption (integrity protection)
/// - Excellent performance on all platforms, even without AES hardware
/// - Extended nonce for better collision resistance
pub const ALGORITHM_CHACHA20_POLY1305: u8 = 0x02;

/// Size of hash digests used throughout the application
///
/// 32 bytes (256 bits) is used for SHA-256 hashes, providing:
/// - Strong collision resistance
/// - Compatibility with existing standards
/// - Efficient computation on modern hardware
pub const HASH_SIZE: usize = 32;

/// Identifier for ZLIB compression algorithm
///
/// ZLIB (DEFLATE) provides good compression with reasonable speed
/// and is widely supported across platforms and languages.
pub const COMPRESSION_ZLIB: u8 = 0x01;

/// Identifier for Reed-Solomon error correction encoding
///
/// Reed-Solomon provides protection against data corruption and can
/// recover from multiple shard failures simultaneously.
pub const ENCODING_REED_SOLOMON: u8 = 0x01;

/// Identifier for Argon2 key derivation function
///
/// Argon2 is the winner of the Password Hashing Competition and provides
/// strong resistance against GPU/ASIC attacks.
pub const KDF_ARGON2: u8 = 0x01;

// === File and User Interface Limits ===
// These constants define limits and constraints for safe operation.

/// Maximum filename length that can be stored in metadata
///
/// 256 bytes accommodates most filename conventions across operating systems
/// while preventing excessive metadata size. This includes UTF-8 encoding,
/// so it supports international filenames.
pub const MAX_FILENAME_LENGTH: usize = 256;

/// Size of AES-GCM nonce in bytes
///
/// 12 bytes (96 bits) is the recommended size for AES-GCM. This provides
/// sufficient randomness while keeping the nonce size reasonable and
/// maintaining good performance characteristics.
pub const AES_NONCE_SIZE: usize = 12;

/// Size of encryption keys in bytes
///
/// 32 bytes (256 bits) provides strong security for both AES-256 and
/// ChaCha20. This meets current security recommendations and provides
/// a comfortable security margin against future cryptanalytic advances.
pub const KEY_SIZE: usize = 32;

/// Size of XChaCha20 nonce in bytes
///
/// 24 bytes (192 bits) is the standard size for XChaCha20. The extended
/// nonce size provides excellent collision resistance while maintaining
/// compatibility with the ChaCha20 specification.
pub const CHACHA_NONCE_SIZE: usize = 24;

/// Minimum password length for user passwords
///
/// 8 characters provides a reasonable balance between security and usability.
/// Shorter passwords are vulnerable to brute-force attacks, while longer
/// requirements may discourage users from using strong passwords.
///
/// Security Impact: Prevents obviously weak passwords
/// Usability Impact: Reasonable minimum that most users accept
pub const PASSWORD_MIN_LENGTH: usize = 8;

// === File Discovery and Exclusion Patterns ===
// These patterns define which files and directories are automatically excluded
// from the interactive file browser to prevent accidental encryption of system
// files and improve user experience.

/// File and directory patterns to exclude from file discovery
///
/// These patterns prevent accidental encryption of:
/// - Build artifacts and dependencies (target, vendor, node_modules)
/// - Version control metadata (.git, .github)
/// - Configuration and cache directories (.config, .local, .cache)
/// - Security-sensitive files (.ssh, .gnupg)
/// - Source code files that typically don't need encryption (*.rs, *.go)
///
/// This improves user experience by focusing on relevant files and preventing
/// accidental system file encryption that could cause boot or functionality issues.
pub const EXCLUDED_PATTERNS: &[&str] = &[
    "target",       // Rust build artifacts
    "vendor",       // Go/Cargo dependencies
    "node_modules", // Node.js dependencies
    ".git",         // Git repository metadata
    ".github",      // GitHub workflows and metadata
    ".config",      // User configuration files
    ".local",       // Local user data
    ".cache",       // Application cache files
    ".ssh",         // SSH keys and configuration
    ".gnupg",       // GPG keys and configuration
    "*.rs",         // Rust source files
    "*.go",         // Go source files
];
