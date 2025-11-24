use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use super::reader::StreamReader;
use super::worker::ChunkWorker;
use super::writer::StreamWriter;
use crate::types::{Processing, Task};

use crate::stream::pool::BufferPool;
use crate::stream::reader::CHUNK_SIZE;

/// Buffer multiplier for pipeline depth (reduced from 4 to 2 for memory efficiency)
const BUFFER_MULTIPLIER: usize = 2;

/// High-performance stream processor using a concurrent pipeline architecture.
///
/// The `Pipeline` orchestrates the entire streaming process, managing:
/// - A pool of worker threads for CPU-bound tasks (encryption/decryption).
/// - Async I/O for reading and writing operations.
/// - Flow control to prevent memory exhaustion when handling large streams.
/// - Optional progress reporting during the processing.
///
/// # Concurrency Model
/// The pipeline utilizes a semaphore to limit the number of active chunks in flight at a given time.
/// This ensures we do not overwhelm memory by reading too many chunks while the writer is processing them.
/// The flow of data follows this sequence: `Reader -> [Channel] -> Worker (CPU) -> [Channel] -> Writer`.
#[derive(Clone)]
pub struct Pipeline {
    worker: Arc<ChunkWorker>, // Worker for processing chunks (encryption, decryption)
    mode: Processing,         // Mode for processing (Encryption/Decryption)
    concurrency: usize,       // Number of concurrent tasks (usually CPU threads)
    pool: BufferPool,         // Pool for buffering chunks
}

impl Pipeline {
    /// Creates a new stream processor with the given key and processing mode.
    ///
    /// This method initializes the pipeline with a pool of worker threads and sets up the required buffers.
    ///
    /// # Arguments
    ///
    /// * `key` - The 64-byte key used for encryption or decryption (32 bytes for AES and 32 bytes for ChaCha20).
    /// * `mode` - The processing mode, either `Encryption` or `Decryption`.
    ///
    /// # Returns
    ///
    /// Returns a new `Pipeline` instance, or an error if initialization fails.
    pub fn new(key: &[u8], mode: Processing) -> Result<Self> {
        let concurrency = num_cpus::get(); // Get the number of CPU cores
        // Calculate pool capacity: enough for reader, writer, and in-flight chunks.
        let pool_capacity = concurrency * BUFFER_MULTIPLIER * 3;
        let pool = BufferPool::new(pool_capacity, CHUNK_SIZE);

        Ok(Self {
            worker: Arc::new(ChunkWorker::new(key, mode, pool.clone())?),
            mode,
            concurrency,
            pool,
        })
    }

    /// Process data from reader to writer with optional progress callback.
    ///
    /// This method processes the data through the pipeline, performing reading, chunk processing, and writing.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input stream to read data from (must implement `AsyncRead`).
    /// * `writer` - The output stream to write data to (must implement `AsyncWrite`).
    /// * `progress_callback` - Optional callback function to report progress (in bytes processed).
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the processing.
    pub async fn process<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let chunk_reader = StreamReader::new(self.mode, self.pool.clone());

        // Channel for sending results to the writer (with flow control)
        let buffer_size = (self.concurrency * BUFFER_MULTIPLIER).max(8); // Ensure minimum buffer size
        let (tx, mut rx) = mpsc::channel::<crate::types::TaskResult>(buffer_size);

        // Spawn a writer task to handle the async writing of processed chunks
        let mode = self.mode;
        let pool = self.pool.clone();
        let writer_handle = tokio::spawn(async move {
            let mut chunk_writer = StreamWriter::new(mode, pool);

            while let Some(result) = rx.recv().await {
                if let Some(err) = result.err {
                    return Err(err); // Return early if there's an error in processing
                }

                // Write chunk (handles reordering internally)
                chunk_writer
                    .write_chunk(&mut writer, result.index, result.data)
                    .await?;

                // Report progress if a callback is provided
                if let Some(ref cb) = progress_callback {
                    cb(result.size as u64);
                }
            }

            // Ensure all remaining buffered chunks are written
            chunk_writer.flush(&mut writer).await?;
            Ok::<_, anyhow::Error>(())
        });

        // Reader Loop & Worker Task Spawning
        let mut join_set = JoinSet::new(); // For managing multiple async tasks
        let semaphore = Arc::new(Semaphore::new(self.concurrency)); // Control concurrency with a semaphore
        let mut index = 0u64;

        loop {
            // Acquire a permit to control concurrency
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    // If the semaphore is full, wait until a permit becomes available
                    semaphore.clone().acquire_owned().await?
                }
            };

            // Read the next chunk from the input stream
            match chunk_reader.read_chunk(&mut reader, index).await? {
                Some(data) => {
                    let tx = tx.clone(); // Clone sender for worker task

                    // Spawn a worker task to process the chunk in a blocking thread
                    let worker = self.worker.clone();
                    join_set.spawn(async move {
                        let _permit = permit; // Drop the permit once the task finishes

                        // Run CPU-bound work in a blocking thread to prevent blocking async runtime
                        let result = tokio::task::spawn_blocking(move || {
                            worker.process(Task { index, data })
                        })
                        .await?;

                        // Send the processed chunk result to the writer
                        tx.send(result).await?;
                        Ok::<_, anyhow::Error>(())
                    });

                    index += 1; // Increment index for the next chunk
                }
                _ => {
                    // End of file reached
                    break;
                }
            }
        }

        // Wait for all worker tasks to complete
        while let Some(res) = join_set.join_next().await {
            res??; // Propagate errors from worker tasks
        }

        // Close the sender to signal the writer to stop
        drop(tx);

        // Wait for the writer to finish processing all chunks and handle any errors
        writer_handle.await??;

        Ok(())
    }
}
