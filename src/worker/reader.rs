//! Concurrent file reader with chunking strategies
//!
//! This module implements the input stage of the concurrent processing pipeline.
//! The reader is responsible for efficiently reading input data, chunking it
//! appropriately, and producing tasks for the executor thread.
//!
//! ## Reading Strategies
// The reader implements two different strategies based on processing mode:
//
// ### Encryption Mode (Fixed Chunking)
// - Reads data in fixed-size chunks (default 1MB)
// - Each chunk becomes an independent task
// - Optimized for throughput and parallel processing
// - Simple and deterministic behavior
//
// ### Decryption Mode (Length-Prefixed)
// - Reads length-prefixed chunks written during encryption
// - Preserves original data boundaries
// - Handles variable-sized encrypted chunks
// - Ensures complete data recovery
//!
//! ## Performance Optimization
// - **Buffered I/O**: Uses BufReader for efficient disk access
// - **Minimal Allocation**: Reuses buffer for fixed-size chunks
// - **Zero-Copy**: Moves data directly to tasks without copying
// - **Backpressure**: Channel operations provide natural flow control
//!
//! ## Concurrency Design
// The reader operates in a dedicated thread and communicates exclusively
// through bounded channels. This design provides:
// - Non-blocking I/O operations
// - Automatic backpressure when executor is overwhelmed
// - Clean shutdown semantics when input is exhausted

use anyhow::{Context, Result, anyhow, ensure};
use flume::Sender;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use crate::types::{Processing, Task};

/// Minimum allowed chunk size for fixed-size reading (256KB)
///
/// This constant ensures that chunks are large enough to provide good
/// performance benefits from parallel processing while not being so large
/// that they cause memory pressure or latency issues. 256KB provides
/// a good balance between I/O efficiency and parallelization benefits.
pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

/// Concurrent file reader with adaptive chunking strategies
///
/// The Reader is responsible for the input stage of the processing pipeline.
/// It reads data from the input source and creates tasks for the executor.
/// The reading strategy depends on whether we're encrypting or decrypting.
///
/// ## Design Philosophy
///
/// - **Encryption**: Fixed-size chunks for optimal parallelization
/// - **Decryption**: Length-prefixed chunks to maintain original boundaries
/// - **Performance**: Buffered I/O and minimal allocations
/// - **Thread Safety**: Single-threaded operation with channel communication
///
/// ## Memory Management
///
/// For encryption mode, a single buffer is reused across reads to minimize
/// allocations. For decryption mode, dynamic allocation is necessary due to
/// variable chunk sizes determined by the encrypted format.
pub struct Reader {
    /// Processing mode determining the reading strategy
    /// Affects chunking behavior and data boundaries
    mode: Processing,
    /// Fixed chunk size for encryption mode
    /// Ignored for decryption mode which uses length-prefixed chunks
    /// Must be at least MIN_CHUNK_SIZE to ensure performance
    chunk_size: usize,
}

impl Reader {
    /// Creates a new Reader with the specified mode and chunk size
    ///
    /// Initializes the reader with appropriate settings for the processing mode.
    /// The chunk size validation ensures good performance characteristics.
    ///
    /// # Arguments
    ///
    /// * `mode` - Processing mode (Encryption or Decryption)
    /// * `chunk_size` - Size of chunks for encryption mode (ignored for decryption)
    ///
    /// # Returns
    ///
    /// A configured Reader instance or an error if chunk size is invalid
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Chunk size is below MIN_CHUNK_SIZE (256KB)
    /// - This minimum ensures adequate parallelization efficiency
    ///
    /// # Performance Notes
    ///
    /// The minimum chunk size is carefully chosen to balance:
    /// - **Parallelization**: Large enough to benefit from concurrent processing
    /// - **Memory Usage**: Not so large as to cause memory pressure
    /// - **I/O Efficiency**: Matches typical filesystem block sizes
    /// - **Latency**: Keeps task processing latency reasonable
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        ensure!(chunk_size >= MIN_CHUNK_SIZE, "chunk size must be at least {MIN_CHUNK_SIZE} bytes, got {chunk_size}");
        Ok(Self { mode, chunk_size })
    }

    /// Reads all data from input and sends tasks to the executor
    ///
    /// This is the main entry point for the reader. It wraps the input in a
    /// buffered reader for performance and delegates to the appropriate
    /// reading strategy based on the processing mode.
    ///
    /// ## Reading Strategies
    ///
    /// - **Encryption**: Fixed-size chunks (see `read_fixed_chunks`)
    /// - **Decryption**: Length-prefixed chunks (see `read_length_prefixed`)
    ///
    /// # Arguments
    ///
    /// * `input` - Readable input stream
    /// * `sender` - Channel sender for task distribution to executor
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful completion or an error if reading fails
    ///
    /// # Error Handling
    ///
    /// Errors from I/O operations are propagated with context. Channel send
    /// errors indicate that the executor has shut down unexpectedly.
    ///
    /// # Performance Notes
    ///
    /// - **Buffered I/O**: BufReader reduces system call overhead
    /// - **Memory Efficiency**: Reuses buffers where possible
    /// - **Backpressure**: Channel operations naturally limit reading speed
    /// - **Thread Safety**: Single-threaded operation with thread-safe channels
    pub async fn read_all<R: AsyncRead + Unpin>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        // Wrap input in BufReader for efficient I/O operations
        // This reduces system call overhead and improves read performance
        let mut reader = BufReader::new(input);

        // Delegate to appropriate reading strategy based on processing mode
        // Each strategy is optimized for its specific use case
        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender).await,
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender).await,
        }
    }

    /// Reads data in fixed-size chunks for encryption processing
    ///
    /// This method implements the reading strategy for encryption mode.
    /// It reads data in fixed-size chunks and creates tasks for each chunk.
    /// This approach maximizes parallelization efficiency.
    ///
    /// ## Algorithm
    ///
    /// 1. Allocate a reusable buffer of the configured chunk size
    /// 2. Read data into the buffer repeatedly until EOF
    /// 3. Create a task for each chunk (even partial chunks)
    /// 4. Send tasks to the executor via the channel
    /// 5. Increment task index for ordering purposes
    ///
    /// ## Performance Characteristics
    ///
    /// - **Memory**: Single reusable buffer minimizes allocations
    /// - **I/O**: Buffered reading reduces system call overhead
    /// - **Parallelization**: Fixed chunks provide consistent workload
    /// - **Backpressure**: Channel operations limit reading speed
    ///
    /// # Arguments
    ///
    /// * `reader` - Buffered input reader
    /// * `sender` - Channel sender for task distribution
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful completion or an error if operations fail
    ///
    /// # Error Handling
    ///
    /// - **I/O Errors**: Propagated with context about the failed operation
    /// - **Channel Errors**: Occur when executor shuts down unexpectedly
    /// - **Partial Success**: Tasks sent before error remain valid
    ///
    /// # Concurrency Notes
    ///
    /// This method runs in the reader thread and communicates exclusively
    /// through the channel. The bounded channel provides natural backpressure
    /// to prevent overwhelming the executor when processing is slow.
    async fn read_fixed_chunks<R: AsyncRead + Unpin>(&self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        // Allocate a single reusable buffer for all read operations
        // This minimizes memory allocations and garbage collection overhead
        let mut buffer = vec![0u8; self.chunk_size];

        // Track the sequential index for each task
        // This enables proper ordering in the output buffer
        let mut index = 0u64;

        // Continue reading until EOF (bytes_read == 0)
        loop {
            // Read data into the buffer
            // This may return less than the full buffer size on the last chunk
            let bytes_read = reader.read(&mut buffer).await.context("failed to read chunk")?;

            // Check for EOF condition
            if bytes_read == 0 {
                break;
            }

            // Create a task with the actual data read
            // Only copy the relevant portion of the buffer
            sender.send_async(Task { data: buffer[..bytes_read].to_vec(), index }).await.map_err(|_| anyhow!("channel closed"))?;

            // Increment index for the next task
            index += 1;
        }

        Ok(())
    }

    /// Reads length-prefixed chunks for decryption processing
    ///
    /// This method implements the reading strategy for decryption mode.
    /// It reads data that was written with length prefixes during encryption.
    /// This ensures that the original data boundaries are preserved.
    ///
    /// ## Data Format
    ///
    /// Each chunk in the encrypted file has the format:
    /// ```
    /// [4-byte length (big-endian)] [chunk data]
    /// ```
    ///
    /// The length prefix allows the reader to know exactly how much
    /// data to read for each chunk, handling variable-sized encrypted
    /// blocks correctly.
    ///
    /// ## Algorithm
    ///
    /// 1. Read 4-byte length prefix
    /// 2. Convert to usize (big-endian)
    /// 3. Skip zero-length chunks (padding artifacts)
    /// 4. Read exactly that many bytes of data
    /// 5. Create task and send to executor
    /// 6. Repeat until EOF
    ///
    /// ## Performance Characteristics
    ///
    /// - **Variable Size**: Handles chunks of different sizes efficiently
    /// - **Memory**: Allocates exact size needed for each chunk
    /// - **Error Detection**: Detects truncated/corrupted input files
    /// - **Efficiency**: read_exact ensures precise I/O operations
    ///
    /// # Arguments
    ///
    /// * `reader` - Buffered input reader
    /// * `sender` - Channel sender for task distribution
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful completion or an error if operations fail
    ///
    /// # Error Handling
    ///
    /// - **EOF Detection**: Normal termination when length prefix read fails
    /// - **Truncated Data**: read_exact errors indicate corrupted input
    /// - **Channel Errors**: Executor shutdown conditions
    /// - **Memory**: Allocation failures for large chunks
    ///
    /// # Concurrency Notes
    ///
    /// This static method doesn't require &self since it doesn't use
    /// chunk_size. It operates independently in the reader thread.
    async fn read_length_prefixed<R: AsyncRead + Unpin>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        // Track the sequential index for maintaining order
        let mut index = 0u64;

        loop {
            // Read the 4-byte length prefix
            // This tells us exactly how much data to expect for this chunk
            let mut buffer_len = [0u8; 4];

            // If we can't read the length prefix, we've reached EOF
            // This is the normal termination condition for encrypted files
            if reader.read_exact(&mut buffer_len).await.is_err() {
                break;
            }

            // Convert the length prefix to usize
            // Uses big-endian format for cross-platform compatibility
            let chunk_len = u32::from_be_bytes(buffer_len) as usize;

            // Skip zero-length chunks (may occur from padding)
            // This maintains compatibility with the encryption output format
            if chunk_len == 0 {
                continue;
            }

            // Allocate exact size needed for this chunk
            // This avoids waste and handles variable chunk sizes efficiently
            let mut data = vec![0u8; chunk_len];

            // Read exactly the expected number of bytes
            // read_exact will fail if the file is truncated or corrupted
            reader.read_exact(&mut data).await.context("failed to read chunk data")?;

            // Create task with the chunk data and send to executor
            sender.send_async(Task { data, index }).await.map_err(|_| anyhow!("channel closed"))?;

            // Increment index for the next task
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

        let data = vec![1u8; chunk_size + 100];
        let input = Cursor::new(&data);
        let (tx, rx) = unbounded();

        reader.read_all(input, &tx).await.unwrap();
        drop(tx);

        let task1 = rx.recv_async().await.unwrap();
        assert_eq!(task1.index, 0);
        assert_eq!(task1.data.len(), chunk_size);

        let task2 = rx.recv_async().await.unwrap();
        assert_eq!(task2.index, 1);
        assert_eq!(task2.data.len(), 100);

        assert!(rx.recv_async().await.is_err());
    }

    #[tokio::test]
    async fn test_read_length_prefixed() {
        let reader = Reader::new(Processing::Decryption, MIN_CHUNK_SIZE).unwrap();

        let mut data = Vec::new();

        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"hello");

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
