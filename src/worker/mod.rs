//! Concurrent file processing with multi-threaded pipeline.
//!
//! Orchestrates reading, processing, and writing of file chunks
//! using multiple threads and channels for inter-thread communication.
//!
//! # Architecture
//!
//! The worker uses a three-stage pipeline:
//!
//! 1. **Reader Thread**: Reads file in chunks and sends to task channel
//! 2. **Executor Pool**: Parallel processing of chunks via Rayon
//! 3. **Writer Thread**: Receives results, reorders, and writes to output
//!
//! # Concurrency Model
//!
//! - Channels: Flume bounded channels for task/result passing
//! - Parallelism: Rayon for parallel chunk processing
//! - Ordering: Buffer reorders out-of-sequence results

use std::io::{Read, Write};
use std::thread;

use anyhow::{Context, Result, anyhow};
use flume::bounded;

use crate::config::{ARGON_KEY_LEN, CHUNK_SIZE};
use crate::types::Processing;
use crate::ui::progress::ProgressBar;
use crate::worker::executor::Executor;
use crate::worker::pipeline::Pipeline;
use crate::worker::reader::Reader;
use crate::worker::writer::Writer;

pub mod buffer;
pub mod executor;
pub mod pipeline;
pub mod reader;
pub mod writer;

/// Main worker orchestrating concurrent file processing.
///
/// Creates a three-thread pipeline: reader → executor → writer.
/// Each thread handles one stage of the processing pipeline.
pub struct Worker {
    /// The processing pipeline for encryption/decryption.
    pipeline: Pipeline,

    /// Whether processing or decrypting.
    mode: Processing,
}

impl Worker {
    /// Creates a new worker with the given key and mode.
    ///
    /// # Arguments
    ///
    /// * `key` - The 64-byte derived cryptographic key.
    /// * `mode` - Encryption or decryption mode.
    ///
    /// # Errors
    ///
    /// Returns an error if pipeline initialization fails.
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode)?;
        Ok(Self { pipeline, mode })
    }

    /// Processes input to output through the pipeline.
    ///
    /// Spawns three threads for reading, executing, and writing.
    ///
    /// Thread architecture:
    /// 1. Reader thread: Reads file → produces tasks → sends to executor
    /// 2. Executor thread: Receives tasks → processes in parallel → sends results
    /// 3. Main thread (writer): Receives results → reorders → writes to output
    ///
    /// The executor uses Rayon's thread pool internally for parallel processing.
    /// This creates a total of: 1 reader + N executor threads + 1 writer thread.
    ///
    /// # Type Parameters
    ///
    /// * `R` - Readable input source.
    /// * `W` - Writable output destination.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data source.
    /// * `output` - The output data destination.
    /// * `total_size` - Total bytes to process (for progress bar).
    ///
    /// # Errors
    ///
    /// Returns an error if any stage fails or threads panic.
    pub fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        // Create progress bar for user feedback during long operations.
        // The progress bar shows bytes processed and estimated time remaining.
        let progress = ProgressBar::new(total_size, self.mode.label())?;

        // Calculate concurrency based on available CPU cores.
        // More cores = more parallel processing capability.
        // Channel size is set to 2x concurrency for pipeline buffering.
        let concurrency = thread::available_parallelism().map(|p| p.get()).unwrap_or(4);
        let channel_size = concurrency * 2;

        // Create bounded channels for task and result passing.
        // Bounded channels prevent unbounded memory growth if one stage stalls.
        // task_sender → task_receiver: raw chunks to process
        // result_sender → result_receiver: processed chunks ready for output
        let (task_sender, task_receiver) = bounded(channel_size);
        let (result_sender, result_receiver) = bounded(channel_size);

        // Create reader and writer for this mode.
        // Reader handles different formats for encryption vs decryption.
        // Writer adds length prefixes for encryption output.
        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = Writer::new(self.mode);

        // Spawn reader thread: reads input, produces tasks.
        // The reader closure takes ownership of input and task_sender.
        let reader_handle = thread::spawn(move || reader.read_all(input, &task_sender));

        // Create executor with shared pipeline (Arc for thread safety).
        // The pipeline is wrapped in Arc so all executor threads can access it.
        let executor = Executor::new(self.pipeline);
        let executor_handle = thread::spawn(move || {
            executor.process(&task_receiver, result_sender);
        });

        // Main thread: write results as they arrive.
        // This blocks until all results are written.
        // The progress bar is updated as each batch completes.
        let write_result = writer.write_all(output, result_receiver, Some(&progress));

        // Wait for all threads to complete and check for panics.
        // join() returns Ok(()) if thread completed normally, Err if panicked.
        let read_result = reader_handle.join().map_err(|_| anyhow!("reader thread panicked"))?;
        executor_handle.join().map_err(|_| anyhow!("executor thread panicked"))?;

        // Finalize progress display (show 100% complete).
        progress.finish();

        // Check for errors from each stage.
        // These context messages help identify which stage failed.
        read_result.context("reading failed")?;
        write_result.context("writing failed")?;

        Ok(())
    }
}
