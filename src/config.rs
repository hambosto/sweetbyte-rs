//! Application configuration constants.

/// Application name.
pub const APP_NAME: &str = "SweetByte";

/// Application version.
pub const APP_VERSION: &str = "1.0";

/// Encrypted file extension.
pub const FILE_EXTENSION: &str = ".swx";

// Argon2id parameters
/// Argon2id time cost (iterations).
pub const ARGON_TIME: u32 = 3;

/// Argon2id memory cost in KiB.
pub const ARGON_MEMORY: u32 = 64 * 1024;

/// Argon2id parallelism (threads).
pub const ARGON_THREADS: u32 = 4;

/// Derived key length in bytes.
pub const ARGON_KEY_LEN: usize = 64;

/// Salt length in bytes.
pub const ARGON_SALT_LEN: usize = 32;

// Reed-Solomon parameters
/// Number of data shards.
pub const DATA_SHARDS: usize = 4;

/// Number of parity shards.
pub const PARITY_SHARDS: usize = 10;

/// Total number of shards.
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

// Padding parameters
/// PKCS7 block size.
pub const BLOCK_SIZE: u8 = 128;

// Streaming parameters
/// Default chunk size for streaming (256 KB).
pub const CHUNK_SIZE: usize = 256 * 1024;

// Header constants
/// Magic bytes identifying SweetByte files.
pub const MAGIC_BYTES: u32 = 0xCAFE_BABE;

/// Magic size in bytes.
pub const MAGIC_SIZE: usize = 4;

/// MAC size in bytes (HMAC-SHA256).
pub const MAC_SIZE: usize = 32;

/// Header data size in bytes.
pub const HEADER_DATA_SIZE: usize = 14;

/// Current file format version.
pub const CURRENT_VERSION: u16 = 0x0001;

/// Flag indicating file is protected.
pub const FLAG_PROTECTED: u32 = 1;

// Cipher parameters
/// AES-256-GCM key size.
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM nonce size.
pub const AES_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 key size.
pub const CHACHA_KEY_SIZE: usize = 32;

/// XChaCha20-Poly1305 nonce size.
pub const CHACHA_NONCE_SIZE: usize = 24;

/// Minimum password length.
pub const PASSWORD_MIN_LENGTH: usize = 8;

/// Excluded patterns for file discovery.
pub const EXCLUDED_PATTERNS: &[&str] = &[
    "vendor/**",
    "node_modules/**",
    ".git/**",
    ".github/**",
    ".vscode/**",
    ".idea/**",
    ".vs/**",
    "build/**",
    "dist/**",
    "target/**",
    "bin/**",
    "obj/**",
    "out/**",
    ".config/**",
    ".local/**",
    ".cache/**",
    ".ssh/**",
    ".gnupg/**",
    ".npm/**",
    ".yarn/**",
    ".gradle/**",
    ".maven/**",
    "__pycache__/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".tox/**",
    ".eggs/**",
    "*.egg-info/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "coverage/**",
    ".coverage/**",
    ".next/**",
    ".nuxt/**",
    ".svelte-kit/**",
    "tmp/**",
    "temp/**",
    "logs/**",
    "*.log",
    "**/*.go",
    "**/go.mod",
    "**/go.sum",
    "**/*.nix",
    "**/.gitignore",
    "**/.gitattributes",
    "**/.dockerignore",
    "**/.editorconfig",
    "**/*.exe",
    "**/*.dll",
    "**/*.so",
    "**/*.dylib",
    "**/*.rs",
    "**/*.o",
    "**/*.a",
    "**/*.lib",
    "**/*.obj",
    "**/*.pyc",
    "**/*.pyo",
    "**/*.pyd",
    "**/*.class",
    "**/*.jar",
    "**/*.war",
    "**/*.ear",
    "**/*.zip",
    "**/*.tar",
    "**/*.gz",
    "**/*.rar",
    "**/*.7z",
    "**/*.iso",
    "**/*.dmg",
    "**/*.pkg",
    "**/*.deb",
    "**/*.rpm",
    "*.go",
    "*.mod",
    "*.sum",
    "*.nix",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "Pipfile.lock",
    "poetry.lock",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
];
