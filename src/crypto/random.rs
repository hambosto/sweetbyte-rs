//! Cryptographically secure random number generation.

use anyhow::Result;
use rand::RngCore;

/// Generates cryptographically secure random bytes.
///
/// Uses the operating system's CSPRNG.
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    rand::rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_bytes_zero_size() {
        let bytes = random_bytes(0).unwrap();
        assert_eq!(bytes.len(), 0);
    }
}
