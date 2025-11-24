use anyhow::Result;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::buffer::ReorderBuffer;
use crate::types::Processing;
use crate::utils::UintType;

use crate::stream::pool::BufferPool;

const LENGTH_PREFIX_SIZE: usize = 4;

/// Writes chunks to the output stream while maintaining correct order.
///
/// Uses a `ReorderBuffer` to handle out-of-order chunks from parallel processing.
pub struct StreamWriter {
    mode: Processing,
    buffer: ReorderBuffer,
    pool: BufferPool,
}

impl StreamWriter {
    pub fn new(mode: Processing, pool: BufferPool) -> Self {
        Self {
            mode,
            buffer: ReorderBuffer::new(),
            pool,
        }
    }

    /// Writes a chunk, buffering as needed to maintain correct order.
    ///
    /// Batches consecutive ready chunks together to reduce system calls.
    pub async fn write_chunk<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        index: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let ready_chunks = self.buffer.add(index, data);

        if ready_chunks.is_empty() {
            return Ok(());
        }

        self.write_batch(writer, &ready_chunks).await?;
        self.recycle_chunks(ready_chunks);

        Ok(())
    }

    /// Flushes any remaining buffered chunks.
    pub async fn flush<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<()> {
        let remaining = self.buffer.flush();

        if !remaining.is_empty() {
            self.write_batch(writer, &remaining).await?;
            self.recycle_chunks(remaining);
        }

        writer.flush().await?;
        Ok(())
    }

    async fn write_batch<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        chunks: &[Vec<u8>],
    ) -> Result<()> {
        let batch = self.create_batch_buffer(chunks);
        writer.write_all(&batch).await?;
        Ok(())
    }

    fn create_batch_buffer(&self, chunks: &[Vec<u8>]) -> Vec<u8> {
        match self.mode {
            Processing::Encryption => self.create_encrypted_batch(chunks),
            Processing::Decryption => self.create_decrypted_batch(chunks),
        }
    }

    fn create_encrypted_batch(&self, chunks: &[Vec<u8>]) -> Vec<u8> {
        let total_size: usize = chunks.iter().map(|c| c.len() + LENGTH_PREFIX_SIZE).sum();
        let mut batch = Vec::with_capacity(total_size);

        for chunk in chunks {
            let length = (chunk.len() as u32).to_bytes();
            batch.extend_from_slice(&length);
            batch.extend_from_slice(chunk);
        }

        batch
    }

    fn create_decrypted_batch(&self, chunks: &[Vec<u8>]) -> Vec<u8> {
        let total_size: usize = chunks.iter().map(|c| c.len()).sum();
        let mut batch = Vec::with_capacity(total_size);

        for chunk in chunks {
            batch.extend_from_slice(chunk);
        }

        batch
    }

    fn recycle_chunks(&self, chunks: Vec<Vec<u8>>) {
        for chunk in chunks {
            self.pool.recycle(chunk);
        }
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

        assert_eq!(writer_buf.len(), 14);
    }

    #[tokio::test]
    async fn test_write_out_of_order() {
        let mut writer_buf = Vec::new();
        let mut cursor = Cursor::new(&mut writer_buf);

        let pool = BufferPool::new(10, CHUNK_SIZE);
        let mut chunk_writer = StreamWriter::new(Processing::Decryption, pool);

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

        assert_eq!(writer_buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
