use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::stream::pool::BufferPool;
use crate::types::Processing;
use crate::utils::UintType;

/// Default chunk size: 256KB (matching Go implementation)
pub const CHUNK_SIZE: usize = 256 * 1024;

const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024;
const LENGTH_PREFIX_SIZE: usize = 4;

/// Reads data in chunks from an input stream.
///
/// Handles two modes:
/// - **Encryption**: Fixed-size chunks of plaintext
/// - **Decryption**: Length-prefixed encrypted chunks
pub struct StreamReader {
    mode: Processing,
    pool: BufferPool,
}

impl StreamReader {
    pub fn new(mode: Processing, pool: BufferPool) -> Self {
        Self { mode, pool }
    }

    /// Reads the next chunk based on the processing mode.
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

    async fn read_plaintext_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let mut buffer = self.pool.get();
        buffer.resize(CHUNK_SIZE, 0);

        match reader.read(&mut buffer).await {
            Ok(0) => {
                self.pool.recycle(buffer);
                Ok(None)
            }
            Ok(n) => {
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            Err(e) => {
                self.pool.recycle(buffer);
                Err(anyhow!("Failed to read chunk: {}", e))
            }
        }
    }

    async fn read_encrypted_chunk<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        index: u64,
    ) -> Result<Option<Vec<u8>>> {
        let chunk_len = match self.read_chunk_length(reader, index).await? {
            Some(len) => len,
            None => return Ok(None),
        };

        self.validate_chunk_size(chunk_len, index)?;

        let mut chunk_data = self.pool.get();
        chunk_data.resize(chunk_len, 0);

        match reader.read_exact(&mut chunk_data).await {
            Ok(_) => Ok(Some(chunk_data)),
            Err(e) => {
                self.pool.recycle(chunk_data);
                Err(anyhow!("Failed to read chunk {} data: {}", index, e))
            }
        }
    }

    async fn read_chunk_length<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        index: u64,
    ) -> Result<Option<usize>> {
        let mut length_buf = [0u8; LENGTH_PREFIX_SIZE];

        match reader.read_exact(&mut length_buf).await {
            Ok(_) => {
                let len = u32::from_bytes(&length_buf) as usize;
                if len == 0 { Ok(None) } else { Ok(Some(len)) }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(anyhow!("Failed to read chunk {} length: {}", index, e)),
        }
    }

    fn validate_chunk_size(&self, chunk_len: usize, index: u64) -> Result<()> {
        if chunk_len > MAX_CHUNK_SIZE {
            Err(anyhow!(
                "Invalid chunk {} size: {} bytes exceeds maximum of {} bytes",
                index,
                chunk_len,
                MAX_CHUNK_SIZE
            ))
        } else {
            Ok(())
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
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3, 4, 5]);

        let mut cursor = Cursor::new(data);
        let pool = BufferPool::new(10, CHUNK_SIZE);
        let reader = StreamReader::new(Processing::Decryption, pool);
        let chunk = reader.read_chunk(&mut cursor, 0).await.unwrap();

        assert_eq!(chunk.unwrap(), vec![1, 2, 3, 4, 5]);
    }
}
