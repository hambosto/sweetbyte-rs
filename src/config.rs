pub const APP_NAME: &str = "SweetByte";

pub const FILE_EXTENSION: &str = "swx";

pub const ARGON2_M_COST: u32 = 65536;

pub const ARGON2_T_COST: u32 = 3;

pub const ARGON2_P_COST: u32 = 4;

pub const ARGON2_KEY_LEN: usize = 64;

pub const ARGON2_SALT_LEN: usize = 32;

pub const CHACHA_NONCE_SIZE: usize = 24;

pub const AES_NONCE_SIZE: usize = 12;

pub const KEY_LEN: usize = 32;

pub const DATA_SHARDS: usize = 4;

pub const PARITY_SHARDS: usize = 10;

pub const CHUNK_SIZE: usize = 256 * 1024;

pub const MAGIC_BYTES: u32 = 0xDEAD_BEEF;

pub const CURRENT_VERSION: u16 = 0x0002;

pub const MAX_FILENAME_LEN: usize = 256;

pub const PASSWORD_LEN: usize = 8;

pub const NAME_MAX_LEN: usize = 35;

pub const EXCLUDED_PATTERNS: &[&str] = &["target", "vendor", "node_modules", ".git", ".github", ".config", ".local", ".cache", ".ssh", ".gnupg", "*.rs", "*.go", "*.nix", "*.toml", "*.lock"];
