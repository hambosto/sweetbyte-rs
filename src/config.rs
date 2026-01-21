pub const APP_NAME: &str = "SweetByte";

pub const FILE_EXTENSION: &str = ".swx";

pub const ARGON_TIME: u32 = 3;

pub const ARGON_MEMORY: u32 = 64 * 1024;

pub const ARGON_THREADS: u32 = 4;

pub const ARGON_KEY_LEN: usize = 64;

pub const ARGON_SALT_LEN: usize = 32;

pub const DATA_SHARDS: usize = 4;

pub const PARITY_SHARDS: usize = 10;

pub const BLOCK_SIZE: usize = 128;

pub const CHUNK_SIZE: usize = 256 * 1024;

pub const MAGIC_BYTES: u32 = 0xCAFE_BABE;

pub const MAGIC_SIZE: usize = 4;

pub const MAC_SIZE: usize = 32;

pub const HEADER_DATA_SIZE: usize = 14;

pub const CURRENT_VERSION: u16 = 0x0001;

pub const FLAG_PROTECTED: u32 = 1;

pub const AES_KEY_SIZE: usize = 32;

pub const AES_NONCE_SIZE: usize = 12;

pub const CHACHA_KEY_SIZE: usize = 32;

pub const CHACHA_NONCE_SIZE: usize = 24;

pub const PASSWORD_MIN_LENGTH: usize = 8;

pub const EXCLUDED_PATTERNS: &[&str] = &["target", "vendor", "node_modules", ".git", ".github", ".config", ".local", ".cache", ".ssh", ".gnupg", "*.rs", "*.go"];
