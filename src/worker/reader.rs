use std::io::{BufReader, Read};

use anyhow::{Context, Result, anyhow, ensure};
use crossbeam_channel::Sender;

use crate::types::{Processing, Task};

/// Minimum allowed chunk size (256 KiB).
pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

/// File reader that chunks input data for parallel processing.
///
/// Reads from an input stream and creates tasks for the executor pool.
/// Uses different strategies for encryption (fixed chunks) and
/// decryption (length-prefixed chunks).
pub struct Reader {
    /// Processing mode affecting read strategy.
    mode: Processing,
    /// Target chunk size in bytes.
    chunk_size: usize,
}

impl Reader {
    /// Creates a new Reader with the given mode and chunk size.
    ///
    /// # Arguments
    /// * `mode` - The processing mode (encryption or decryption).
    /// * `chunk_size` - Target chunk size in bytes (must be >= MIN_CHUNK_SIZE).
    ///
    /// # Returns
    /// A new Reader instance.
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        ensure!(chunk_size >= MIN_CHUNK_SIZE, "chunk size must be at least {MIN_CHUNK_SIZE} bytes, got {chunk_size}");

        Ok(Self { mode, chunk_size })
    }

    /// Reads all data from the input and sends tasks to the channel.
    ///
    /// Dispatches to the appropriate read method based on mode.
    ///
    /// # Arguments
    /// * `input` - The input data source.
    /// * `sender` - Channel sender for sending tasks.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if reading failed.
    pub fn read_all<R: Read>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        let mut reader = BufReader::new(input);

        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender),
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender),
        }
    }

    /// Reads data in fixed-size chunks for encryption.
    ///
    /// Reads up to chunk_size bytes per task, using a reusable buffer.
    /// The final chunk may be smaller than the chunk size.
    ///
    /// # Arguments
    /// * `reader` - The buffered reader.
    /// * `sender` - Channel sender for sending tasks.
    ///
    /// # Returns
    /// Ok(()) on success.
    fn read_fixed_chunks<R: Read>(&self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        // Reusable buffer to avoid allocations per chunk.
        let mut buffer = vec![0u8; self.chunk_size];
        let mut index = 0u64;

        loop {
            // Read up to chunk_size bytes.
            let bytes_read = reader.read(&mut buffer).context("failed to read chunk")?;
            // EOF reached when bytes_read is 0.
            if bytes_read == 0 {
                break;
            }

            // Send task with the data read.
            sender.send(Task { data: buffer[..bytes_read].to_vec(), index }).map_err(|_| anyhow!("channel closed"))?;
            index += 1;
        }

        Ok(())
    }

    /// Reads length-prefixed chunks for decryption.
    ///
    /// Each chunk is preceded by a 4-byte big-endian length prefix.
    /// This allows the writer to reconstruct the original chunk boundaries.
    ///
    /// # Arguments
    /// * `reader` - The buffered reader.
    /// * `sender` - Channel sender for sending tasks.
    ///
    /// # Returns
    /// Ok(()) on success.
    fn read_length_prefixed<R: Read>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            // Read the 4-byte length prefix.
            let mut buffer_len = [0u8; 4];
            let read_result = reader.read_exact(&mut buffer_len);

            // read_exact returns error on EOF.
            if read_result.is_err() {
                break;
            }

            // Parse chunk length as big-endian u32.
            let chunk_len = u32::from_be_bytes(buffer_len) as usize;
            // Skip zero-length chunks.
            if chunk_len == 0 {
                continue;
            }

            // Read the chunk data.
            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).context("failed to read chunk data")?;

            // Send task to the channel.
            sender.send(Task { data, index }).map_err(|_| anyhow!("channel closed"))?;
            index += 1;
        }

        Ok(())
    }
}
