use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::stream::pool::BufferPool;
use crate::types::Processing;
use crate::utils::UintType;

/// Default chunk size: 256KB (matching Go implementation)
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Maximum allowed chunk size for safety (10MB)
const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024;

/// Reads data in chunks from an input stream.
///
/// The reader handles two modes:
/// - **Encryption**: Reads fixed-size chunks (`CHUNK_SIZE`) of plaintext.
/// - **Decryption**: Reads length-prefixed encrypted chunks.
pub struct StreamReader {
    mode: Processing, // The processing mode: Encryption or Decryption
    pool: BufferPool, // The buffer pool to reuse buffers efficiently
}

impl StreamReader {
    /// Creates a new chunk reader for the specified processing mode.
    ///
    /// # Arguments
    ///
    /// * `mode` - Processing mode (Encryption or Decryption).
    /// * `pool` - Buffer pool for allocating chunk buffers.
    ///
    /// # Returns
    ///
    /// A new `StreamReader` instance.
    pub fn new(mode: Processing, pool: BufferPool) -> Self {
        Self { mode, pool }
    }

    /// Reads the next chunk from the stream based on the current mode.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input stream to read from (must implement `AsyncRead`).
    /// * `index` - The expected chunk index (used for error reporting).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` - Successfully read a chunk.
    /// - `Ok(None)` - End of stream reached.
    /// - `Err(_)` - I/O or format error.
    pub async fn read_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        index: u64,
    ) -> Result<Option<Vec<u8>>> {
        match self.mode {
            Processing::Encryption => self.read_plaintext_chunk(reader).await, // Encryption: Read fixed-size plaintext chunk
            Processing::Decryption => self.read_encrypted_chunk(reader, index).await, // Decryption: Read length-prefixed encrypted chunk
        }
    }

    /// Reads a fixed-size chunk of plaintext (for encryption).
    ///
    /// Attempts to fill the buffer up to `CHUNK_SIZE`.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input stream to read from.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` - Successfully read a chunk of plaintext.
    /// - `Ok(None)` - End of stream reached.
    /// - `Err(_)` - I/O error.
    async fn read_plaintext_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let mut buffer = self.pool.get(); // Get a buffer from the pool

        // Ensure buffer has enough capacity
        if buffer.capacity() < CHUNK_SIZE {
            buffer.reserve(CHUNK_SIZE - buffer.len());
        }

        // Resize the buffer to the target chunk size (CHUNK_SIZE)
        buffer.resize(CHUNK_SIZE, 0);

        match reader.read(&mut buffer).await {
            Ok(0) => {
                // EOF reached, return buffer to pool
                self.pool.return_buffer(buffer);
                Ok(None)
            }
            Ok(n) => {
                // Truncate the buffer to the actual number of bytes read
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            Err(e) => {
                // In case of an error, return the buffer and propagate the error
                self.pool.return_buffer(buffer);
                Err(anyhow!("Failed to read chunk: {}", e))
            }
        }
    }

    /// Reads a length-prefixed encrypted chunk (for decryption).
    ///
    /// Format: `[Length (4 bytes)] [Data (Length bytes)]`
    ///
    /// # Arguments
    ///
    /// * `reader` - The input stream to read from.
    /// * `index` - The expected chunk index (used for error reporting).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` - Successfully read an encrypted chunk.
    /// - `Ok(None)` - End of stream reached.
    /// - `Err(_)` - I/O error or invalid chunk format.
    async fn read_encrypted_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        index: u64,
    ) -> Result<Option<Vec<u8>>> {
        // 1. Read the 4-byte length prefix
        let mut length_buf = [0u8; 4];

        match reader.read_exact(&mut length_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None); // EOF: No more chunks to read
            }
            Err(e) => {
                return Err(anyhow!("Failed to read chunk {} length: {}", index, e));
            }
        }

        // Convert the length bytes to a `usize` chunk length
        let chunk_len = u32::from_bytes(&length_buf) as usize;

        // Validate chunk size
        if chunk_len == 0 {
            return Ok(None); // Empty chunk, treat as EOF
        }

        if chunk_len > MAX_CHUNK_SIZE {
            return Err(anyhow!(
                "Invalid chunk {} size: {} bytes exceeds maximum of {} bytes",
                index,
                chunk_len,
                MAX_CHUNK_SIZE
            ));
        }

        // 2. Read the chunk data based on the length prefix
        let mut chunk_data = self.pool.get();
        if chunk_data.capacity() < chunk_len {
            chunk_data.reserve(chunk_len - chunk_data.len());
        }
        chunk_data.resize(chunk_len, 0);

        match reader.read_exact(&mut chunk_data).await {
            Ok(_) => Ok(Some(chunk_data)), // Successfully read the chunk
            Err(e) => {
                // Return the buffer if an error occurs
                self.pool.return_buffer(chunk_data);
                Err(anyhow!("Failed to read chunk {} data: {}", index, e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_plaintext_chunk() {
        let data = vec![1u8; 100]; // 100-byte plaintext
        let mut cursor = Cursor::new(data);

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Encryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().len(), 100); // Ensure chunk size matches the data length
    }

    #[tokio::test]
    async fn test_read_plaintext_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new()); // Empty stream

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Encryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert!(chunk.is_none()); // No data to read, should return None
    }

    #[tokio::test]
    async fn test_read_encrypted_chunk() {
        let mut data = vec![];
        data.extend_from_slice(&5u32.to_be_bytes()); // 5-byte chunk length
        data.extend_from_slice(&[1, 2, 3, 4, 5]); // 5-byte chunk data

        let mut cursor = Cursor::new(data);
        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Decryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert_eq!(chunk.unwrap(), vec![1, 2, 3, 4, 5]); // Ensure chunk data matches
    }
}
