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

pub const MAGIC_BYTES: u32 = 0xDEAD_BEEF;

pub const MAC_SIZE: usize = 32;

pub const CURRENT_VERSION: u16 = 0x0002;

pub const ALGORITHM_AES_256_GCM: u8 = 0x01;

pub const ALGORITHM_CHACHA20_POLY1305: u8 = 0x02;

pub const HASH_SIZE: usize = 20;

pub const COMPRESSION_ZLIB: u8 = 0x01;

pub const ENCODING_REED_SOLOMON: u8 = 0x01;

pub const KDF_ARGON2: u8 = 0x01;

pub const MAX_FILENAME_LENGTH: usize = 256;

pub const AES_NONCE_SIZE: usize = 12;

pub const KEY_SIZE: usize = 32;

pub const CHACHA_NONCE_SIZE: usize = 24;

pub const PASSWORD_MIN_LENGTH: usize = 8;

pub const EXCLUDED_PATTERNS: &[&str] = &["target", "vendor", "node_modules", ".git", ".github", ".config", ".local", ".cache", ".ssh", ".gnupg", "*.rs", "*.go"];
