use anyhow::{Context, Result, anyhow};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::types::{Processing, Task};
use crate::utils::UintType;

/// Default chunk size: 256KB (matching Go implementation)
pub const CHUNK_SIZE: usize = 256 * 1024;

const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024;
const LENGTH_PREFIX_SIZE: usize = 4;

/// Reads data in chunks from an input stream and emits tasks via channels.
///
/// Spawns a dedicated reader thread that handles two modes:
/// - **Encryption**: Fixed-size chunks of plaintext
/// - **Decryption**: Length-prefixed encrypted chunks
///
/// Matches Go's ChunkReader architecture with goroutine-based reading.
#[derive(Debug)]
pub struct ChunkReader {
    processing: Processing,
    chunk_size: usize,
    concurrency: usize,
}

impl ChunkReader {
    /// Creates a new chunk reader.
    pub fn new(processing: Processing, chunk_size: usize, concurrency: usize) -> Self {
        Self {
            processing,
            chunk_size,
            concurrency,
        }
    }

    /// Returns the processing mode.
    pub fn processing(&self) -> Processing {
        self.processing
    }

    /// Reads chunks from the input reader in a dedicated thread.
    ///
    /// Returns a tuple of (task_receiver, error_receiver).
    /// The reader thread sends tasks through task_channel and any errors through error_channel.
    /// Respects the cancellation flag to stop early.
    pub fn read_chunks<R>(
        &self,
        mut reader: R,
        cancel: Arc<AtomicBool>,
    ) -> (Receiver<Task>, Receiver<anyhow::Error>)
    where
        R: Read + Send + 'static,
    {
        let (task_tx, task_rx) = bounded(self.concurrency);
        let (err_tx, err_rx) = bounded(1);

        let processing = self.processing;
        let chunk_size = self.chunk_size;

        thread::spawn(move || {
            let result = match processing {
                Processing::Encryption => {
                    Self::read_for_encryption(&mut reader, &task_tx, chunk_size, &cancel)
                }
                Processing::Decryption => Self::read_for_decryption(&mut reader, &task_tx, &cancel),
            };

            // Send error if one occurred (ignore if channel is closed)
            match result {
                Err(e) if !cancel.load(Ordering::SeqCst) => {
                    let _ = err_tx.send(e);
                }
                _ => {}
            }
        });

        (task_rx, err_rx)
    }

    /// Reads fixed-size chunks for encryption.
    #[inline]
    fn read_for_encryption<R>(
        reader: &mut R,
        tasks: &Sender<Task>,
        chunk_size: usize,
        cancel: &Arc<AtomicBool>,
    ) -> Result<()>
    where
        R: Read,
    {
        // Use two buffers to avoid cloning on every iteration
        let mut read_buffer = vec![0u8; chunk_size];
        let mut send_buffer = Vec::with_capacity(chunk_size);
        let mut index = 0u64;

        loop {
            // Check for cancellation
            if cancel.load(Ordering::SeqCst) {
                return Err(anyhow!("operation cancelled"));
            }

            match reader.read(&mut read_buffer) {
                Ok(0) => return Ok(()), // EOF
                Ok(n) => {
                    // Swap buffers to avoid cloning the data
                    std::mem::swap(&mut read_buffer, &mut send_buffer);
                    send_buffer.truncate(n);

                    let task = Task {
                        data: send_buffer,
                        index,
                    };

                    // Check cancellation before blocking send
                    if cancel.load(Ordering::SeqCst) {
                        return Err(anyhow!("operation cancelled"));
                    }

                    tasks
                        .send(task)
                        .map_err(|_| anyhow!("task channel closed"))?;

                    // Recreate send_buffer for next iteration
                    send_buffer = Vec::with_capacity(chunk_size);
                    read_buffer.clear();
                    read_buffer.resize(chunk_size, 0);
                    index += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("failed to read from input stream"),
            }
        }
    }

    /// Reads length-prefixed chunks for decryption.
    #[inline]
    fn read_for_decryption<R>(
        reader: &mut R,
        tasks: &Sender<Task>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<()>
    where
        R: Read,
    {
        let mut index = 0u64;

        loop {
            // Check for cancellation
            if cancel.load(Ordering::SeqCst) {
                return Err(anyhow!("operation cancelled"));
            }

            // Read 4-byte length prefix
            let chunk_len = match Self::read_chunk_length(reader, index)? {
                Some(len) => len,
                None => return Ok(()), // EOF
            };

            if chunk_len == 0 {
                continue;
            }

            // Validate chunk size
            if chunk_len > MAX_CHUNK_SIZE {
                return Err(anyhow!(
                    "chunk {} size ({} bytes) exceeds maximum ({} bytes)",
                    index,
                    chunk_len,
                    MAX_CHUNK_SIZE
                ));
            }

            // Read chunk data
            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).with_context(|| {
                format!("failed to read chunk {} data ({} bytes)", index, chunk_len)
            })?;

            let task = Task { data, index };

            // Check cancellation before blocking send
            if cancel.load(Ordering::SeqCst) {
                return Err(anyhow!("operation cancelled"));
            }

            tasks
                .send(task)
                .map_err(|_| anyhow!("task channel closed"))?;

            index += 1;
        }
    }

    /// Reads the 4-byte length prefix for encrypted chunks.
    #[inline]
    fn read_chunk_length<R>(reader: &mut R, index: u64) -> Result<Option<usize>>
    where
        R: Read,
    {
        let mut length_buf = [0u8; LENGTH_PREFIX_SIZE];

        match reader.read_exact(&mut length_buf) {
            Ok(_) => {
                let len = u32::from_bytes(&length_buf) as usize;
                Ok(Some(len))
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("failed to read chunk {} length prefix", index))
            }
        }
    }
}
