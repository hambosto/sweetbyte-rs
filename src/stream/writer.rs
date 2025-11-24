use anyhow::Result;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::buffer::ReorderBuffer;
use crate::types::Processing;
use crate::utils::UintType;

use crate::stream::pool::BufferPool;

/// `StreamWriter` writes chunks to the output stream while maintaining the correct order.
///
/// Since chunks are processed in parallel, they may complete out of order. The `StreamWriter` handles this
/// by using a `ReorderBuffer` to buffer out-of-order chunks and write them in sequential order.
pub struct StreamWriter {
    mode: Processing,
    buffer: ReorderBuffer, // Buffer to reorder out-of-order chunks
    pool: BufferPool,      // Buffer pool to return used buffers
}

impl StreamWriter {
    /// Creates a new chunk writer for the specified processing mode.
    ///
    /// This constructor initializes the `StreamWriter` with a specified mode (either Encryption or Decryption)
    /// and a buffer pool for memory management.
    ///
    /// # Arguments
    ///
    /// * `mode` - Processing mode (Encryption or Decryption).
    /// * `pool` - Buffer pool for returning used buffers.
    ///
    /// # Returns
    ///
    /// Returns an instance of `StreamWriter` configured with the provided mode and buffer pool.
    pub fn new(mode: Processing, pool: BufferPool) -> Self {
        Self {
            mode,
            buffer: ReorderBuffer::new(), // Initialize the reorder buffer
            pool,
        }
    }

    /// Writes a chunk of data to the output stream, buffering it to maintain the correct order.
    ///
    /// This method does the following:
    /// 1. Adds the chunk to the reorder buffer.
    /// 2. Retrieves all ready consecutive chunks.
    /// 3. Batches the chunks together and writes them in one operation to reduce system calls.
    ///
    /// # Arguments
    ///
    /// * `writer` - The output stream to write the data to.
    /// * `index` - The sequence number of the chunk.
    /// * `data` - The chunk data to be written.
    ///
    /// # Returns
    ///
    /// Returns a `Result<()>`. If writing fails, an error is returned.
    pub async fn write_chunk<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        index: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        // Add the chunk to the reorder buffer and get all ready consecutive chunks
        let ready_chunks = self.buffer.add(index, data);

        // If no chunks are ready, return early (nothing to write)
        if ready_chunks.is_empty() {
            return Ok(());
        }

        // Prepare the batch buffer for writing
        match self.mode {
            Processing::Encryption => {
                // For encryption: write length prefix + data for each chunk
                let mut batch_buffer = Vec::new();

                for chunk in &ready_chunks {
                    // Add the length prefix (4 bytes) followed by the chunk data
                    let length = (chunk.len() as u32).to_bytes();
                    batch_buffer.extend_from_slice(&length); // Add length prefix
                    batch_buffer.extend_from_slice(chunk); // Add chunk data
                }

                // Write the entire batch buffer at once (reduces syscalls)
                writer.write_all(&batch_buffer).await?;
            }
            Processing::Decryption => {
                // For decryption: write data only (no length prefix)
                let mut batch_buffer = Vec::new();

                for chunk in &ready_chunks {
                    // Add chunk data to the batch buffer
                    batch_buffer.extend_from_slice(chunk);
                }

                // Write the entire batch buffer at once
                writer.write_all(&batch_buffer).await?;
            }
        }

        // Return all buffers to the pool for reuse
        for chunk in ready_chunks {
            self.pool.return_buffer(chunk);
        }

        Ok(())
    }

    /// Flushes any remaining buffered chunks to the output stream.
    ///
    /// This method ensures that all chunks are written out, even if they were not part of the main flow,
    /// and it should be called at the end of processing to ensure all data is written out.
    /// This is important in scenarios where some chunks may have been processed but are still waiting
    /// for others to be completed.
    ///
    /// # Arguments
    ///
    /// * `writer` - The output stream to write the data to.
    ///
    /// # Returns
    ///
    /// Returns a `Result<()>`. If the flush fails, an error is returned.
    pub async fn flush<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<()> {
        // Get all remaining chunks from the reorder buffer
        let remaining = self.buffer.flush();

        // If there are remaining chunks, write them to the output stream
        if !remaining.is_empty() {
            match self.mode {
                Processing::Encryption => {
                    // For encryption: write length prefix + data for each chunk
                    let mut batch_buffer = Vec::new();
                    for chunk in &remaining {
                        let length = (chunk.len() as u32).to_bytes();
                        batch_buffer.extend_from_slice(&length);
                        batch_buffer.extend_from_slice(chunk);
                    }
                    // Write the entire batch buffer
                    writer.write_all(&batch_buffer).await?;
                }
                Processing::Decryption => {
                    // For decryption: write data only (no length prefix)
                    let mut batch_buffer = Vec::new();
                    for chunk in &remaining {
                        batch_buffer.extend_from_slice(chunk);
                    }
                    // Write the entire batch buffer
                    writer.write_all(&batch_buffer).await?;
                }
            }

            // Return all buffers to the pool
            for chunk in remaining {
                self.pool.return_buffer(chunk);
            }
        }

        // Ensure the writer's internal buffer is flushed
        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::reader::CHUNK_SIZE;
    use std::io::Cursor;

    /// Test case to check that chunks are written in order for encryption mode.
    #[tokio::test]
    async fn test_write_in_order() {
        let mut writer_buf = Vec::new();
        let mut cursor = Cursor::new(&mut writer_buf);

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let mut chunk_writer = StreamWriter::new(Processing::Encryption, pool);

        // Write chunks in order
        chunk_writer
            .write_chunk(&mut cursor, 0, vec![1, 2, 3])
            .await
            .unwrap();
        chunk_writer
            .write_chunk(&mut cursor, 1, vec![4, 5, 6])
            .await
            .unwrap();
        chunk_writer.flush(&mut cursor).await.unwrap();

        // Expect the writer buffer to have length prefixes + data
        // 4 bytes for length prefix + 3 bytes data, repeated for both chunks
        assert_eq!(writer_buf.len(), 14);
    }

    /// Test case to check that out-of-order chunks are written in the correct order for decryption mode.
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

        // The chunks should be ordered correctly in the output buffer
        assert_eq!(writer_buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
