use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::types::Processing;
use crate::utils::UintType;

/// Default chunk size: 256KB (matching Go implementation)
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Maximum allowed chunk size for safety (10MB)
const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024;

/// Reads data in chunks from an input stream.
///
/// For encryption: reads fixed-size chunks of plaintext
/// For decryption: reads length-prefixed encrypted chunks
use crate::stream::pool::BufferPool;

/// Reads data in chunks from an input stream.
///
/// The reader handles two modes:
/// -   **Encryption**: Reads fixed-size chunks (`CHUNK_SIZE`) of plaintext.
/// -   **Decryption**: Reads length-prefixed encrypted chunks.
pub struct StreamReader {
    mode: Processing,
    pool: BufferPool,
}

impl StreamReader {
    /// Creates a new chunk reader for the specified processing mode.
    ///
    /// # Arguments
    ///
    /// * `mode` - Processing mode (Encryption/Decryption).
    /// * `pool` - Buffer pool for allocating chunk buffers.
    pub fn new(mode: Processing, pool: BufferPool) -> Self {
        Self { mode, pool }
    }

    /// Reads the next chunk from the stream.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input stream to read from.
    /// * `index` - The expected chunk index (used for error reporting).
    ///
    /// # Returns
    ///
    /// * `Ok(Some(data))` - Successfully read a chunk.
    /// * `Ok(None)` - End of stream reached.
    /// * `Err(_)` - I/O or format error.
    pub async fn read_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        index: u64,
    ) -> Result<Option<Vec<u8>>> {
        match self.mode {
            Processing::Encryption => self.read_plaintext_chunk(reader).await,
            Processing::Decryption => self.read_encrypted_chunk(reader, index).await,
        }
    }

    /// Reads a fixed-size chunk of plaintext (for encryption).
    ///
    /// Attempts to fill the buffer up to `CHUNK_SIZE`.
    async fn read_plaintext_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let mut buffer = self.pool.get();

        // Ensure buffer has the required capacity
        if buffer.capacity() < CHUNK_SIZE {
            buffer.reserve(CHUNK_SIZE - buffer.len());
        }
        // Resize to target size. Modern allocators zero memory efficiently.
        buffer.resize(CHUNK_SIZE, 0);

        match reader.read(&mut buffer).await {
            Ok(0) => {
                // EOF, return buffer to pool
                self.pool.return_buffer(buffer);
                Ok(None)
            }
            Ok(n) => {
                // Truncate to actual bytes read
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            Err(e) => {
                self.pool.return_buffer(buffer);
                Err(anyhow!("Failed to read chunk: {}", e))
            }
        }
    }

    /// Reads a length-prefixed encrypted chunk (for decryption).
    ///
    /// Format: `[Length (4 bytes)] [Data (Length bytes)]`
    async fn read_encrypted_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        index: u64,
    ) -> Result<Option<Vec<u8>>> {
        // 1. Read 4-byte length prefix (uint32)
        let mut length_buf = [0u8; 4];

        match reader.read_exact(&mut length_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None); // EOF
            }
            Err(e) => {
                return Err(anyhow!("Failed to read chunk {} length: {}", index, e));
            }
        }

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

        // 2. Read chunk data based on length
        let mut chunk_data = self.pool.get();
        if chunk_data.capacity() < chunk_len {
            chunk_data.reserve(chunk_len - chunk_data.len());
        }
        chunk_data.resize(chunk_len, 0);

        match reader.read_exact(&mut chunk_data).await {
            Ok(_) => Ok(Some(chunk_data)),
            Err(e) => {
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
        let data = vec![1u8; 100];
        let mut cursor = Cursor::new(data);

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Encryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().len(), 100);
    }

    #[tokio::test]
    async fn test_read_plaintext_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new());

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Encryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert!(chunk.is_none());
    }

    #[tokio::test]
    async fn test_read_encrypted_chunk() {
        let mut data = vec![];
        data.extend_from_slice(&5u32.to_be_bytes()); // length (Big Endian)
        data.extend_from_slice(&[1, 2, 3, 4, 5]); // data

        let mut cursor = Cursor::new(data);
        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Decryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert_eq!(chunk.unwrap(), vec![1, 2, 3, 4, 5]);
    }
}
