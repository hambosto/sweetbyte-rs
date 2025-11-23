use anyhow::Result;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::buffer::ReorderBuffer;
use crate::types::Processing;
use crate::utils::UintType;

/// Writes chunks to output stream, maintaining correct order.
///
/// Uses ReorderBuffer to handle out-of-order chunk completion from parallel workers.
use crate::stream::pool::BufferPool;

/// Writes chunks to output stream, maintaining correct order.
///
/// Uses ReorderBuffer to handle out-of-order chunk completion from parallel workers.
pub struct StreamWriter {
    mode: Processing,
    buffer: ReorderBuffer,
    pool: BufferPool,
}

impl StreamWriter {
    /// Creates a new chunk writer for the specified processing mode
    pub fn new(mode: Processing, pool: BufferPool) -> Self {
        Self {
            mode,
            buffer: ReorderBuffer::new(),
            pool,
        }
    }

    /// Writes a chunk, buffering if necessary to maintain order.
    ///
    /// This method:
    /// 1. Adds the chunk to the ordered buffer
    /// 2. Retrieves all consecutive now-ready chunks
    /// 3. Batches them together and writes in one operation (reduces syscalls)
    ///
    /// # Arguments
    /// * `writer` - Output stream
    /// * `index` - Chunk sequence number
    /// * `data` - Chunk data to write
    pub async fn write_chunk<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        index: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        // Add to buffer and get all ready consecutive chunks
        let ready_chunks = self.buffer.add(index, data);

        if ready_chunks.is_empty() {
            return Ok(());
        }

        // Batch write all ready chunks to reduce syscalls
        match self.mode {
            Processing::Encryption => {
                // For encryption: write length prefix + data for each chunk
                // Collect into a single buffer for batched write
                let mut batch_buffer = Vec::new();

                for chunk in &ready_chunks {
                    let length = (chunk.len() as u32).to_bytes();
                    batch_buffer.extend_from_slice(&length);
                    batch_buffer.extend_from_slice(chunk);
                }

                writer.write_all(&batch_buffer).await?;
            }
            Processing::Decryption => {
                // For decryption: write data only (no length prefix)
                // Collect into a single buffer for batched write
                let mut batch_buffer = Vec::new();

                for chunk in &ready_chunks {
                    batch_buffer.extend_from_slice(chunk);
                }

                writer.write_all(&batch_buffer).await?;
            }
        }

        // Return all buffers to pool
        for chunk in ready_chunks {
            self.pool.return_buffer(chunk);
        }

        Ok(())
    }

    /// Flushes any remaining buffered chunks to the output stream.
    ///
    /// Should be called at the end of processing to ensure all data is written.
    pub async fn flush<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<()> {
        let remaining = self.buffer.flush();

        if !remaining.is_empty() {
            // Use batched writing for flush as well
            match self.mode {
                Processing::Encryption => {
                    let mut batch_buffer = Vec::new();
                    for chunk in &remaining {
                        let length = (chunk.len() as u32).to_bytes();
                        batch_buffer.extend_from_slice(&length);
                        batch_buffer.extend_from_slice(chunk);
                    }
                    writer.write_all(&batch_buffer).await?;
                }
                Processing::Decryption => {
                    let mut batch_buffer = Vec::new();
                    for chunk in &remaining {
                        batch_buffer.extend_from_slice(chunk);
                    }
                    writer.write_all(&batch_buffer).await?;
                }
            }

            // Return all buffers to pool
            for chunk in remaining {
                self.pool.return_buffer(chunk);
            }
        }

        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::reader::CHUNK_SIZE;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_write_in_order() {
        let mut writer_buf = Vec::new();
        let mut cursor = Cursor::new(&mut writer_buf);

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let mut chunk_writer = StreamWriter::new(Processing::Encryption, pool);
        chunk_writer
            .write_chunk(&mut cursor, 0, vec![1, 2, 3])
            .await
            .unwrap();
        chunk_writer
            .write_chunk(&mut cursor, 1, vec![4, 5, 6])
            .await
            .unwrap();
        chunk_writer.flush(&mut cursor).await.unwrap();

        // Should have length prefixes + data
        // 4 bytes len + 3 bytes data + 4 bytes len + 3 bytes data = 14 bytes
        assert_eq!(writer_buf.len(), 14);
    }

    #[tokio::test]
    async fn test_write_out_of_order() {
        let mut writer_buf = Vec::new();
        let mut cursor = Cursor::new(&mut writer_buf);

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let mut chunk_writer = StreamWriter::new(Processing::Decryption, pool);

        // Write chunks out of order
        chunk_writer
            .write_chunk(&mut cursor, 2, vec![7, 8, 9])
            .await
            .unwrap();
        chunk_writer
            .write_chunk(&mut cursor, 0, vec![1, 2, 3])
            .await
            .unwrap();
        chunk_writer
            .write_chunk(&mut cursor, 1, vec![4, 5, 6])
            .await
            .unwrap();
        chunk_writer.flush(&mut cursor).await.unwrap();

        // Should be ordered correctly
        assert_eq!(writer_buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
