//! Cryptographically secure random number generation.
//!
//! This module provides a simple interface for generating random bytes using the system's
//! cryptographically secure random number generator (CSPRNG).

use rand::RngCore;
use std::io;

/// Generates cryptographically secure random bytes.
///
/// This function uses the operating system's CSPRNG to generate the requested number of bytes.
///
/// # Arguments
///
/// * `size` - The number of random bytes to generate.
///
/// # Returns
///
/// Returns a `Vec<u8>` containing the random bytes, or an `io::Error` if the RNG fails.
///
/// # Examples
///
/// ```
/// use sweetbyte::crypto::random::get_random_bytes;
///
/// let bytes = get_random_bytes(32).unwrap();
/// assert_eq!(bytes.len(), 32);
/// ```
pub fn get_random_bytes(size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    rand::rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_random_bytes() {
        let bytes1 = get_random_bytes(32).unwrap();
        let bytes2 = get_random_bytes(32).unwrap();
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }
}
