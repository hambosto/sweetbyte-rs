use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};

use super::{Cipher, random_bytes};

// Constants defining the key and nonce sizes
const KEY_SIZE: usize = 32; // AES-256 requires a 32-byte key
const NONCE_SIZE: usize = 12; // AES-GCM typically uses a 12-byte nonce

/// AES-256-GCM authenticated encryption.
///
/// This struct wraps the `Aes256Gcm` implementation from the `aes-gcm` crate, providing
/// encryption and decryption functionality using the AES-256-GCM algorithm.
/// It ensures that both the encryption and decryption processes are authenticated.
/// The encryption algorithm uses a 32-byte key and a 12-byte nonce (random value).
///
/// AES-256-GCM is a modern encryption algorithm that provides both confidentiality
/// and integrity verification, ensuring that ciphertexts cannot be tampered with
/// without detection.
///
/// # Note
/// - The nonce is a random value generated during encryption and prepended to the ciphertext.
/// - The key must be exactly 32 bytes in length to match the AES-256 specification.
#[derive(Clone)]
pub struct Aes {
    cipher: Aes256Gcm, // The underlying AES-256-GCM cipher instance
}

impl Aes {
    /// Creates a new AES-256-GCM cipher from a 32-byte key.
    ///
    /// This function initializes the AES-256-GCM cipher using the provided key.
    /// It checks that the key length is exactly 32 bytes, which is required for AES-256.
    ///
    /// # Arguments
    /// * `key` - A slice of bytes that must be 32 bytes in length.
    ///
    /// # Returns
    /// A result containing either:
    /// * `Ok(Self)` if the cipher is successfully initialized,
    /// * `Err` if the key length is invalid or the initialization fails.
    pub fn new(key: &[u8]) -> Result<Self> {
        // Ensure that the key is of the correct size (32 bytes for AES-256)
        if key.len() != KEY_SIZE {
            anyhow::bail!("AES key must be {KEY_SIZE} bytes, got {}", key.len());
        }

        // Initialize the cipher using the provided key
        let cipher = Aes256Gcm::new_from_slice(key).context("failed to initialize AES-256-GCM")?;

        Ok(Self { cipher })
    }
}

impl Cipher for Aes {
    /// Encrypts the provided plaintext using AES-256-GCM.
    ///
    /// This function generates a random 12-byte nonce, performs the AES encryption on the
    /// provided plaintext, and appends the nonce to the resulting ciphertext.
    /// The output is a concatenation of the nonce and the ciphertext.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt, must not be empty.
    ///
    /// # Returns
    /// A result containing:
    /// * `Ok(Vec<u8>)` with the encrypted ciphertext (nonce + ciphertext),
    /// * `Err` if encryption fails (e.g., empty plaintext).
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Ensure the plaintext is not empty
        anyhow::ensure!(!plaintext.is_empty(), "plaintext cannot be empty");

        // Generate a random nonce of NONCE_SIZE bytes
        let nonce_bytes = random_bytes(NONCE_SIZE)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext using the AES cipher and the generated nonce
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AES encryption failed: {e}"))?;

        // Concatenate the nonce and the ciphertext before returning
        Ok([nonce_bytes, ciphertext].concat())
    }

    /// Decrypts the provided ciphertext using AES-256-GCM.
    ///
    /// This function extracts the nonce from the first 12 bytes of the input ciphertext,
    /// and uses it to decrypt the rest of the ciphertext. The output is the decrypted plaintext.
    ///
    /// # Arguments
    /// * `data` - The ciphertext (nonce + encrypted data).
    ///
    /// # Returns
    /// A result containing:
    /// * `Ok(Vec<u8>)` with the decrypted plaintext,
    /// * `Err` if decryption fails (e.g., invalid ciphertext format).
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Ensure the input data contains at least the nonce size
        anyhow::ensure!(
            data.len() >= NONCE_SIZE,
            "ciphertext too short: need at least {NONCE_SIZE} bytes, got {}",
            data.len()
        );

        // Split the input data into the nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the ciphertext using the AES cipher and the extracted nonce
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the encrypt and decrypt methods to ensure they work correctly.
    /// It checks that after encryption and decryption, the original plaintext is restored.
    #[test]
    fn test_encrypt_decrypt() {
        let key = vec![0u8; KEY_SIZE]; // Example 32-byte key
        let cipher = Aes::new(&key).unwrap();
        let plaintext = b"Hello, World!";

        // Encrypt the plaintext
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        // Decrypt the ciphertext
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        // Ensure the decrypted data matches the original plaintext
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        // Ensure that the ciphertext is longer than the plaintext (due to nonce)
        assert!(ciphertext.len() > plaintext.len());
    }

    /// Test that invalid key sizes (not 32 bytes) result in an error.
    #[test]
    fn test_invalid_key_size() {
        // Test with keys that are not 32 bytes
        assert!(Aes::new(&[0u8; 16]).is_err()); // Too short
        assert!(Aes::new(&[0u8; 64]).is_err()); // Too long
    }

    /// Test that attempting to encrypt an empty plaintext results in an error.
    #[test]
    fn test_empty_plaintext() {
        let cipher = Aes::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.encrypt(&[]).is_err()); // Should fail due to empty plaintext
    }

    /// Test that attempting to decrypt invalid ciphertext (too short) results in an error.
    #[test]
    fn test_invalid_ciphertext() {
        let cipher = Aes::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.decrypt(&[0u8; 5]).is_err()); // Should fail due to invalid length
    }
}
