use anyhow::{Context, Result, anyhow};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use super::pool::WorkerPool;
use super::reader::ChunkReader;
use super::worker::ChunkWorker;
use super::writer::ChunkWriter;
use crate::types::Processing;

/// Default chunk size: 256KB (matching Go implementation)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// High-performance stream processor using concurrent pipeline architecture.
///
/// Orchestrates parallel processing through multiple stages:
/// - **ChunkReader**: Reads input in chunks, outputs indexed tasks
/// - **WorkerPool**: Processes chunks concurrently using thread pool
/// - **OrderedBuffer**: Thread-safe buffer that reorders completed chunks
/// - **ChunkWriter**: Writes ordered results with progress tracking
///
/// This matches Go's Pipeline architecture with goroutine-based concurrency.
///
/// # Architecture
///
/// ```text
/// Input → ChunkReader → [Task Channel] → WorkerPool → [Result Channel] → ChunkWriter → Output
///          (thread)                      (N threads)                        (thread)
/// ```
///
/// All components use crossbeam channels for communication and respect a shared
/// cancellation flag for coordinated shutdown.
pub struct Pipeline {
    reader: ChunkReader,
    writer: ChunkWriter,
    pool: WorkerPool,
}

impl Pipeline {
    /// Creates a new stream processor.
    ///
    /// # Arguments
    ///
    /// * `key` - 64-byte encryption key (32 for AES + 32 for ChaCha20)
    /// * `processing` - Processing mode (Encryption or Decryption)
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid or cipher initialization fails.
    pub fn new(key: &[u8], processing: Processing) -> Result<Self> {
        if key.len() < 64 {
            return Err(anyhow!("key must be at least 64 bytes long"));
        }

        let concurrency = num_cpus::get();
        let task_processor = ChunkWorker::new(key, processing)?;

        Ok(Self {
            reader: ChunkReader::new(processing, DEFAULT_CHUNK_SIZE, concurrency),
            writer: ChunkWriter::new(processing),
            pool: WorkerPool::new(task_processor, concurrency),
        })
    }

    /// Processes data from reader to writer with progress tracking.
    ///
    /// This orchestrates the entire pipeline:
    /// 1. Starts reader thread to emit tasks
    /// 2. Starts worker pool to process tasks
    /// 3. Starts writer thread to write results
    /// 4. Waits for completion or errors
    /// 5. Handles cancellation and cleanup
    ///
    /// # Arguments
    ///
    /// * `reader` - Input data source
    /// * `writer` - Output data sink
    /// * `total_size` - Total size for progress tracking
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading fails
    /// - Processing fails
    /// - Writing fails
    /// - Operation is cancelled
    pub fn process<R, W>(&self, reader: R, writer: W, total_size: u64) -> Result<()>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        if total_size == 0 {
            return Err(anyhow!("input stream must not be empty"));
        }

        let progress = Arc::new(crate::tui::Bar::new(total_size, self.reader.processing()));
        self.run_pipeline(reader, writer, progress)
    }

    /// Runs the complete processing pipeline.
    fn run_pipeline<R, W>(&self, reader: R, writer: W, progress: Arc<crate::tui::Bar>) -> Result<()>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        // Shared cancellation flag
        let cancel = Arc::new(AtomicBool::new(false));

        // Stage 1: Start reader thread → tasks channel
        let (tasks_rx, reader_err_rx) = self.reader.read_chunks(reader, cancel.clone());

        // Stage 2: Start worker pool → results channel
        let results_rx = self.pool.process(tasks_rx, cancel.clone());

        // Stage 3: Start writer thread
        let writer_handle = {
            let writer_clone = self.writer.clone();
            let progress_clone = progress.clone();
            let cancel_clone = cancel.clone();

            thread::spawn(move || {
                writer_clone.write_chunks(writer, results_rx, progress_clone, cancel_clone)
            })
        };

        // Wait for writer to complete
        let writer_result = writer_handle
            .join()
            .map_err(|_| anyhow!("writer thread panicked"))?;

        // Check for reader errors
        if let Ok(err) = reader_err_rx.try_recv() {
            cancel.store(true, Ordering::SeqCst);
            return Err(err).context("reader failed");
        }

        // Check writer result
        writer_result.context("writer failed")?;

        // Finish progress bar
        progress.finish();

        Ok(())
    }
}
