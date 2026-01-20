use std::io::{Read, Write};
use std::thread;

use anyhow::{Context, Result, anyhow};
use crossbeam_channel::bounded;

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

/// Parallel file processing worker.
///
/// Orchestrates the multi-threaded file processing pipeline with:
/// - A reader thread that reads and chunks input data
/// - Multiple executor threads that process chunks in parallel
/// - A writer thread that writes results in order
pub struct Worker {
    /// The processing pipeline (encryption or decryption).
    pipeline: Pipeline,
    /// Number of concurrent executor threads.
    concurrency: usize,
    /// The processing mode (encryption or decryption).
    mode: Processing,
}

impl Worker {
    /// Creates a new Worker with the given key and mode.
    ///
    /// Automatically determines the concurrency level from available parallelism.
    ///
    /// # Arguments
    /// * `key` - The 64-byte derived encryption key.
    /// * `mode` - The processing mode (encryption or decryption).
    ///
    /// # Returns
    /// A new Worker instance.
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode)?;
        // Use available CPU cores, defaulting to 4 if detection fails.
        let concurrency = thread::available_parallelism().map(|p| p.get()).unwrap_or(4);

        Ok(Self { pipeline, concurrency, mode })
    }

    /// Processes a file using the multi-threaded pipeline.
    ///
    /// Spawns reader, executor, and writer threads that communicate via channels.
    /// Results are written in order despite parallel processing.
    ///
    /// # Type Parameters
    /// * `R` - The input reader type.
    /// * `W` - The output writer type.
    ///
    /// # Arguments
    /// * `input` - The input data source.
    /// * `output` - The output data destination.
    /// * `total_size` - Total bytes to process for progress tracking.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if processing failed.
    pub fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        // Create a progress bar for the operation.
        let progress = ProgressBar::new(total_size, self.mode.label())?;

        // Calculate channel capacity based on concurrency.
        let channel_size = self.concurrency * 2;
        // Create channels for task distribution and result collection.
        let (task_sender, task_receiver) = bounded(channel_size);
        let (result_sender, result_receiver) = bounded(channel_size);

        // Create reader and writer.
        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = Writer::new(self.mode);

        // Spawn the reader thread.
        let reader_handle = thread::spawn(move || reader.read_all(input, &task_sender));

        // Create executor and spawn its thread.
        let executor = Executor::new(self.pipeline, self.concurrency);
        let executor_handle = thread::spawn(move || {
            executor.process(&task_receiver, result_sender);
        });

        // Write results and wait for threads to complete.
        let write_result = writer.write_all(output, result_receiver, Some(&progress));
        let read_result = reader_handle.join().map_err(|_| anyhow!("reader thread panicked"))?;
        executor_handle.join().map_err(|_| anyhow!("executor thread panicked"))?;

        // Finalize progress bar.
        progress.finish();

        // Check for errors from reader and writer.
        read_result.context("reading failed")?;
        write_result.context("writing failed")?;

        Ok(())
    }
}
