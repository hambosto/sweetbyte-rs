use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use std::io;

// Argon2id parameters matching Go implementation
pub const ARGON_TIME: u32 = 3;
pub const ARGON_MEMORY: u32 = 64 * 1024; // 64 KB
pub const ARGON_THREADS: u32 = 4;
pub const ARGON_KEY_LEN: usize = 64;
pub const ARGON_SALT_LEN: usize = 32;

/// Derives a 64-byte key from password and salt using Argon2id
pub fn hash(password: &[u8], salt: &[u8]) -> anyhow::Result<[u8; ARGON_KEY_LEN]> {
    if password.is_empty() {
        return Err(anyhow::anyhow!("password cannot be empty"));
    }

    if salt.len() != ARGON_SALT_LEN {
        return Err(anyhow::anyhow!(
            "expected {} bytes, got {}",
            ARGON_SALT_LEN,
            salt.len()
        ));
    }

    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, Some(ARGON_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("failed to create Argon2 params: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("failed to encode salt: {}", e))?;

    let hash = argon2
        .hash_password(password, &salt_string)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {}", e))?;

    let hash_bytes = hash
        .hash
        .ok_or_else(|| anyhow::anyhow!("no hash produced"))?;

    let mut key = [0u8; ARGON_KEY_LEN];
    let bytes = hash_bytes.as_bytes();
    if bytes.len() < ARGON_KEY_LEN {
        return Err(anyhow::anyhow!(
            "hash too short: got {} bytes, expected {}",
            bytes.len(),
            ARGON_KEY_LEN
        ));
    }
    key.copy_from_slice(&bytes[..ARGON_KEY_LEN]);

    Ok(key)
}

/// Generates cryptographically secure random bytes
pub fn get_random_bytes(size: usize) -> io::Result<Vec<u8>> {
    use rand::RngCore;
    let mut bytes = vec![0u8; size];
    rand::rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let password = b"testpassword";
        let salt = get_random_bytes(ARGON_SALT_LEN).unwrap();
        let key = hash(password, &salt).unwrap();
        assert_eq!(key.len(), ARGON_KEY_LEN);
    }

    #[test]
    fn test_hash_deterministic() {
        let password = b"testpassword";
        let salt = vec![0u8; ARGON_SALT_LEN];
        let key1 = hash(password, &salt).unwrap();
        let key2 = hash(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_get_random_bytes() {
        let bytes1 = get_random_bytes(32).unwrap();
        let bytes2 = get_random_bytes(32).unwrap();
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }
}
