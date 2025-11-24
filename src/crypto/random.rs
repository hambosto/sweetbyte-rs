//! Cryptographically secure random number generation.

use anyhow::Result;
use rand::RngCore;

/// Generates cryptographically secure random bytes.
///
/// This function uses the operating system's Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
/// to produce a random sequence of bytes. The bytes generated are suitable for cryptographic operations
/// such as key generation, salting, and nonces.
///
/// # Arguments
/// * `size` - The number of random bytes to generate.
///
/// # Returns
/// A result containing:
/// * `Ok(Vec<u8>)` with the generated random bytes,
/// * `Err` if an error occurs during random byte generation.
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    // Create a vector to store the generated random bytes
    let mut bytes = vec![0u8; size];

    // Fill the vector with random bytes from the CSPRNG
    rand::rng().fill_bytes(&mut bytes);

    // Return the vector containing the random bytes
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the random_bytes function to ensure it generates random bytes correctly.
    /// It checks that the length of the returned vector matches the requested size
    /// and that consecutive calls produce different results.
    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap(); // Generate 32 random bytes
        let bytes2 = random_bytes(32).unwrap(); // Generate another 32 random bytes

        assert_eq!(bytes1.len(), 32); // Ensure the length of the first byte vector is 32
        assert_eq!(bytes2.len(), 32); // Ensure the length of the second byte vector is 32
        assert_ne!(bytes1, bytes2); // Ensure the two byte vectors are different (randomness)
    }

    /// Test the random_bytes function with zero size to ensure it returns an empty vector.
    #[test]
    fn test_random_bytes_zero_size() {
        let bytes = random_bytes(0).unwrap(); // Generate 0 random bytes
        assert_eq!(bytes.len(), 0); // Ensure the result is an empty vector
    }
}
