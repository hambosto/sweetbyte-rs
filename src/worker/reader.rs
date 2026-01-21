//! File reading and chunking.
//!
//! Reads input data and produces tasks for the processing pipeline.
//! Uses different strategies for encryption vs decryption.
//!
//! # Reading Strategies
//!
//! - **Encryption**: Fixed-size chunks (256 KB) for efficient batching
//! - **Decryption**: Length-prefixed chunks to match encrypted format

use std::io::{BufReader, Read};

use anyhow::{Context, Result, anyhow, ensure};
use flume::Sender;

use crate::types::{Processing, Task};

/// Minimum chunk size for processing (256 KB).
pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

/// Reads input and produces tasks for the processing pipeline.
///
/// Reads from an input source, splits into chunks, and sends tasks
/// through a channel for parallel processing.
pub struct Reader {
    /// Processing mode (affects reading strategy).
    mode: Processing,

    /// Target chunk size for encryption.
    chunk_size: usize,
}

impl Reader {
    /// Creates a new reader with the specified chunk size.
    ///
    /// # Arguments
    ///
    /// * `mode` - Processing mode (encryption or decryption).
    /// * `chunk_size` - Target chunk size in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if chunk size is below minimum.
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        ensure!(chunk_size >= MIN_CHUNK_SIZE, "chunk size must be at least {MIN_CHUNK_SIZE} bytes, got {chunk_size}");
        Ok(Self { mode, chunk_size })
    }

    /// Reads all input and produces tasks.
    ///
    /// Uses fixed-chunk reading for encryption, length-prefixed for decryption.
    ///
    /// # Type Parameters
    ///
    /// * `R` - A readable type implementing [`Read`].
    ///
    /// # Arguments
    ///
    /// * `input` - The input data source.
    /// * `sender` - Channel sender for produced tasks.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn read_all<R: Read>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        let mut reader = BufReader::new(input);

        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender),
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender),
        }
    }

    /// Reads input in fixed-size chunks for encryption.
    ///
    /// Encryption uses fixed-size chunks because:
    /// 1. The original file size is known from file metadata
    /// 2. Fixed chunks enable efficient parallel processing
    /// 3. The output uses length prefixes to mark chunk boundaries
    ///
    /// Each chunk is sent as a task. The final chunk may be smaller
    /// if the file size isn't a multiple of chunk_size.
    fn read_fixed_chunks<R: Read>(&self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        // Allocate reusable buffer to avoid repeated allocations.
        // This buffer is reused for each chunk, with data copied to the task.
        let mut buffer = vec![0u8; self.chunk_size];
        let mut index = 0u64;

        loop {
            // Read up to chunk_size bytes into the buffer.
            // read() returns the actual number of bytes read.
            let bytes_read = reader.read(&mut buffer).context("failed to read chunk")?;

            // Zero bytes read indicates EOF (end of file reached).
            if bytes_read == 0 {
                break;
            }

            // Create a task with exactly the bytes that were read.
            // buffer[..bytes_read] slices the buffer to the actual data.
            // to_vec() copies the data into the task (buffer is reused).
            sender.send(Task { data: buffer[..bytes_read].to_vec(), index }).map_err(|_| anyhow!("channel closed"))?;
            index += 1;
        }

        Ok(())
    }

    /// Reads length-prefixed chunks for decryption.
    ///
    /// Decryption uses length-prefixed chunks because:
    /// 1. Encrypted chunks may differ in size (due to compression + padding)
    /// 2. The encryption writer prepends each chunk with its length
    /// 3. We must read the length first to know how much to read
    ///
    /// Format: [4-byte length][chunk data][4-byte length][chunk data]...
    fn read_length_prefixed<R: Read>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            // Read 4-byte length prefix using read_exact.
            // read_exact will fail if we can't get all 4 bytes (EOF or error).
            let mut buffer_len = [0u8; 4];
            let read_result = reader.read_exact(&mut buffer_len);

            // If read_exact fails, we've reached EOF or encountered an error.
            // Either way, there are no more chunks to process.
            if read_result.is_err() {
                break;
            }

            // Parse chunk length from big-endian u32.
            // This tells us how many bytes of encrypted data follow.
            let chunk_len = u32::from_be_bytes(buffer_len) as usize;

            // Skip zero-length chunks (shouldn't happen in valid files).
            // This handles any edge cases gracefully.
            if chunk_len == 0 {
                continue;
            }

            // Read exactly chunk_len bytes of encrypted data.
            // read_exact ensures we get all bytes or fail.
            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).context("failed to read chunk data")?;

            // Send the task to the executor for decryption.
            // Tasks are processed in parallel by the executor pool.
            sender.send(Task { data, index }).map_err(|_| anyhow!("channel closed"))?;
            index += 1;
        }

        Ok(())
    }
}
