use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use super::{Cipher, random_bytes};

// Constants defining the key and nonce sizes
const KEY_SIZE: usize = 32; // XChaCha20 uses a 32-byte key
const NONCE_SIZE: usize = 24; // XChaCha20 typically uses a 24-byte nonce

/// XChaCha20-Poly1305 authenticated encryption.
///
/// This struct wraps the `XChaCha20Poly1305` implementation from the `chacha20poly1305` crate,
/// providing encryption and decryption functionality using the XChaCha20-Poly1305 algorithm.
/// It ensures both confidentiality and integrity of the data, preventing tampering during transmission.
///
/// XChaCha20 is a variant of the ChaCha20 cipher that uses an extended nonce size (24 bytes),
/// which provides additional security and makes it less vulnerable to nonce reuse.
#[derive(Clone)]
pub struct ChaCha {
    cipher: XChaCha20Poly1305, // The underlying XChaCha20-Poly1305 cipher instance
}

impl ChaCha {
    /// Creates a new XChaCha20-Poly1305 cipher from a 32-byte key.
    ///
    /// This function initializes the XChaCha20-Poly1305 cipher using the provided key.
    /// It ensures that the key is exactly 32 bytes in length, which is required for the algorithm.
    ///
    /// # Arguments
    /// * `key` - A slice of bytes that must be 32 bytes in length.
    ///
    /// # Returns
    /// A result containing either:
    /// * `Ok(Self)` if the cipher is successfully initialized,
    /// * `Err` if the key length is invalid or initialization fails.
    pub fn new(key: &[u8]) -> Result<Self> {
        // Ensure the key is of the correct size (32 bytes for XChaCha20)
        if key.len() != KEY_SIZE {
            anyhow::bail!("ChaCha20 key must be {KEY_SIZE} bytes, got {}", key.len());
        }

        // Initialize the cipher using the provided key
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .context("failed to initialize XChaCha20-Poly1305")?;

        Ok(Self { cipher })
    }
}

impl Cipher for ChaCha {
    /// Encrypts the provided plaintext using XChaCha20-Poly1305.
    ///
    /// This function generates a random 24-byte nonce, performs the XChaCha20 encryption on the
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
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext using the XChaCha20 cipher and the generated nonce
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("ChaCha20 encryption failed: {e}"))?;

        // Concatenate the nonce and the ciphertext before returning
        Ok([nonce_bytes, ciphertext].concat())
    }

    /// Decrypts the provided ciphertext using XChaCha20-Poly1305.
    ///
    /// This function extracts the nonce from the first 24 bytes of the input ciphertext,
    /// and uses it to decrypt the remaining ciphertext. The output is the decrypted plaintext.
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
        let nonce = XNonce::from_slice(nonce_bytes);

        // Decrypt the ciphertext using the XChaCha20 cipher and the extracted nonce
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("ChaCha20 decryption failed: {e}"))
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
        let cipher = ChaCha::new(&key).unwrap();
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
        assert!(ChaCha::new(&[0u8; 16]).is_err()); // Too short
        assert!(ChaCha::new(&[0u8; 64]).is_err()); // Too long
    }

    /// Test that attempting to encrypt an empty plaintext results in an error.
    #[test]
    fn test_empty_plaintext() {
        let cipher = ChaCha::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.encrypt(&[]).is_err()); // Should fail due to empty plaintext
    }

    /// Test that attempting to decrypt invalid ciphertext (too short) results in an error.
    #[test]
    fn test_invalid_ciphertext() {
        let cipher = ChaCha::new(&[0u8; KEY_SIZE]).unwrap();
        assert!(cipher.decrypt(&[0u8; 5]).is_err()); // Should fail due to invalid length
    }
}
