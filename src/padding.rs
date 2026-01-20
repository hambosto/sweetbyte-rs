use anyhow::{Result, anyhow, ensure};

/// Padding handler implementing PKCS#7 padding for block ciphers.
///
/// Ensures data is aligned to block boundaries for encryption operations.
/// PKCS#7 padding appends bytes equal to the padding length to the data.
pub struct Padding {
    /// The block size in bytes for padding calculations.
    block_size: usize,
}

impl Padding {
    /// Creates a new Padding instance with the specified block size.
    ///
    /// # Arguments
    /// * `block_size` - The block size in bytes (must be greater than 0).
    ///
    /// # Returns
    /// A new Padding instance, or an error if block_size is invalid.
    pub fn new(block_size: usize) -> Result<Self> {
        ensure!(block_size > 0, "block size must be greater than 0");
        Ok(Self { block_size })
    }

    /// Pads data using PKCS#7 padding.
    ///
    /// Appends padding bytes such that the total length is a multiple of block_size.
    /// Each padding byte has a value equal to the number of padding bytes.
    ///
    /// # Arguments
    /// * `data` - The data to pad (must not be empty).
    ///
    /// # Returns
    /// The padded data, or an error if input validation fails.
    pub fn pad(&self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(!data.is_empty(), "data cannot be empty");

        // Calculate padding length: block_size - (data_length mod block_size).
        // If already aligned, padding_len equals block_size.
        let padding_len = self.block_size - (data.len() % self.block_size);

        // Append padding bytes (each with value equal to padding_len).
        let padded = data.iter().copied().chain(std::iter::repeat_n(padding_len as u8, padding_len)).collect();

        Ok(padded)
    }

    /// Removes PKCS#7 padding from data.
    ///
    /// Validates that the padding is well-formed and removes it.
    ///
    /// # Arguments
    /// * `data` - The padded data to unpad (must not be empty).
    ///
    /// # Returns
    /// The unpadded data, or an error if padding validation fails.
    pub fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Get the last byte, which contains the padding length.
        let padding_len = data.last().copied().ok_or_else(|| anyhow!("cannot unpad empty data"))?;

        // Validate padding length is within valid range.
        ensure!(padding_len > 0 && padding_len <= self.block_size as u8, "invalid padding length: {padding_len}");

        let padding_len = padding_len as usize;
        // Ensure data is long enough to contain the padding.
        ensure!(data.len() >= padding_len, "data too short for padding length");

        // Split data into content and padding portions.
        let (content, padding_bytes) = data.split_at(data.len() - padding_len);

        // Validate that all padding bytes have the correct value.
        ensure!(padding_bytes.iter().all(|&b| b == padding_len as u8), "invalid PKCS#7 padding bytes");

        Ok(content.to_vec())
    }
}
