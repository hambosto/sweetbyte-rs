//! Asynchronous file reading and chunking.
//!
//! This module handles reading the input file and splitting it into manageable `Task` chunks
//! for parallel processing. It supports two modes:
//! - **Fixed Chunks** (Encryption): Reads exactly `N` bytes.
//! - **Variable Chunks** (Decryption): Reads a length header, then the payload (reversing the write
//!   format).

use anyhow::{Context, Result, anyhow, ensure};
use flume::Sender;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use crate::types::{Processing, Task};

/// Minimum allowed chunk size (256 KiB) to ensure efficiency.
pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

/// Handles reading input streams and generating tasks.
pub struct Reader {
    /// The processing mode (Encrypt/Decrypt).
    mode: Processing,

    /// The target size for chunks (for encryption).
    chunk_size: usize,
}

impl Reader {
    /// Creates a new reader configuration.
    ///
    /// # Arguments
    ///
    /// * `mode` - Whether we are encrypting or decrypting.
    /// * `chunk_size` - Size of chunks to read (encryption only).
    ///
    /// # Errors
    ///
    /// Returns an error if `chunk_size` is too small.
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        ensure!(chunk_size >= MIN_CHUNK_SIZE, "chunk size must be at least {MIN_CHUNK_SIZE} bytes, got {chunk_size}");
        Ok(Self { mode, chunk_size })
    }

    /// Reads the entire stream and sends chunks to the worker channel.
    ///
    /// This runs asynchronously and blocks only on I/O or backpressure from the channel.
    pub async fn read_all<R: AsyncRead + Unpin>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        let mut reader = BufReader::new(input);

        // Dispatch based on mode.
        // Encryption uses fixed block sizes.
        // Decryption respects the encoded chunk boundaries.
        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender).await,
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender).await,
        }
    }

    /// Reads fixed-size chunks for encryption.
    async fn read_fixed_chunks<R: AsyncRead + Unpin>(&self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        // Reuse buffer allocation?
        // Actually we allocate new vectors for each task to send ownership.
        // To optimize, we could use a buffer pool, but simple allocation is fine for now.
        let mut buffer = vec![0u8; self.chunk_size];

        let mut index = 0u64;

        loop {
            // Read up to chunk_size bytes.
            // Note: read() might return fewer bytes if EOF is reached.
            // We don't use read_exact here because the last chunk will be short.
            let bytes_read = reader.read(&mut buffer).await.context("failed to read chunk")?;

            if bytes_read == 0 {
                // EOF reached.
                break;
            }

            // Create task with the actual data read.
            // We slice `buffer[..bytes_read]` and convert to Vec, which copies the data.
            sender.send_async(Task { data: buffer[..bytes_read].to_vec(), index }).await.map_err(|_| anyhow!("channel closed"))?;

            index += 1;
        }

        Ok(())
    }

    /// Reads length-prefixed chunks for decryption.
    ///
    /// The format assumed is: `[Length: u32][Data: bytes]...`
    async fn read_length_prefixed<R: AsyncRead + Unpin>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            // Step 1: Read the 4-byte length prefix.
            let mut buffer_len = [0u8; 4];

            // If we can't read 4 bytes (EOF), we stop.
            if reader.read_exact(&mut buffer_len).await.is_err() {
                break;
            }

            // Parse length (Big Endian).
            let chunk_len = u32::from_be_bytes(buffer_len) as usize;

            if chunk_len == 0 {
                // Should not happen in valid streams, but handle gracefully.
                continue;
            }

            // Step 2: Read the actual payload.
            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).await.context("failed to read chunk data")?;

            // Send to worker.
            sender.send_async(Task { data, index }).await.map_err(|_| anyhow!("channel closed"))?;

            index += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use flume::unbounded;

    use super::*;

    #[tokio::test]
    async fn test_read_fixed_chunks() {
        let chunk_size = MIN_CHUNK_SIZE;
        let reader = Reader::new(Processing::Encryption, chunk_size).unwrap();

        // Create data: 1 full chunk + 100 bytes.
        let data = vec![1u8; chunk_size + 100];
        let input = Cursor::new(&data);
        let (tx, rx) = unbounded();

        reader.read_all(input, &tx).await.unwrap();
        drop(tx); // Close sender to finish stream

        // First task: full chunk.
        let task1 = rx.recv_async().await.unwrap();
        assert_eq!(task1.index, 0);
        assert_eq!(task1.data.len(), chunk_size);

        // Second task: remainder.
        let task2 = rx.recv_async().await.unwrap();
        assert_eq!(task2.index, 1);
        assert_eq!(task2.data.len(), 100);

        // No more tasks.
        assert!(rx.recv_async().await.is_err());
    }

    #[tokio::test]
    async fn test_read_length_prefixed() {
        let reader = Reader::new(Processing::Decryption, MIN_CHUNK_SIZE).unwrap();

        let mut data = Vec::new();
        // Chunk 1: "hello"
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"hello");
        // Chunk 2: "world"
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"world");

        let input = Cursor::new(&data);
        let (tx, rx) = unbounded();

        reader.read_all(input, &tx).await.unwrap();
        drop(tx);

        let task1 = rx.recv_async().await.unwrap();
        assert_eq!(task1.index, 0);
        assert_eq!(task1.data, b"hello");

        let task2 = rx.recv_async().await.unwrap();
        assert_eq!(task2.index, 1);
        assert_eq!(task2.data, b"world");

        assert!(rx.recv_async().await.is_err());
    }
}
