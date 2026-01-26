//! Concurrent processing engine.
//!
//! This module orchestrates the multi-threaded processing pipeline, tying together:
//! - **Reader**: Asynchronous input reading.
//! - **Executor**: Parallel CPU-bound processing (via Rayon).
//! - **Writer**: Asynchronous output writing and reordering.
//!
//! # Architecture
//!
//! ```text
//! [Disk] -> Reader(Async) -> [Channel A] -> Executor(Rayon Pool) -> [Channel B] -> Writer(Async) -> [Disk]
//! ```
//!
//! This design allows I/O and CPU operations to overlap perfectly, maximizing throughput.

use std::thread;

use anyhow::{Context, Result, anyhow};
use flume::bounded;
use tokio::io::{AsyncRead, AsyncWrite};

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

/// The main worker struct that manages the lifecycle of a processing job.
pub struct Worker {
    /// The processing pipeline configuration.
    pipeline: Pipeline,

    /// The operation mode.
    mode: Processing,
}

impl Worker {
    /// Initializes a new worker with the derived key and mode.
    ///
    /// # Errors
    ///
    /// Returns an error if pipeline initialization fails (e.g., key/params issue).
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode)?;
        Ok(Self { pipeline, mode })
    }

    /// Executes the processing job from start to finish.
    ///
    /// This spawns the necessary async tasks and blocking threads to handle the workload.
    ///
    /// # Arguments
    ///
    /// * `input` - The source stream.
    /// * `output` - The destination stream.
    /// * `total_size` - Total bytes to process (for progress bar).
    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        // Initialize UI progress bar.
        let progress = ProgressBar::new(total_size, self.mode.label())?;

        // Determine concurrency level.
        // We use logical cores to size our channels to avoid excessive memory usage
        // while maintaining enough buffer for smooth pipeline flow.
        let concurrency = thread::available_parallelism().map(|p| p.get()).unwrap_or(4);
        let channel_size = concurrency * 2;

        // Create channels connecting the stages.
        // Reader -> [task_sender/receiver] -> Executor
        // Executor -> [result_sender/receiver] -> Writer
        let (task_sender, task_receiver) = bounded(channel_size);
        let (result_sender, result_receiver) = bounded(channel_size);

        // Initialize components.
        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = Writer::new(self.mode);

        // Spawn Reader task (Async I/O).
        // This runs on the Tokio runtime.
        let reader_handle = tokio::spawn(async move { reader.read_all(input, &task_sender).await });

        // Spawn Executor task (CPU Bound).
        // We use spawn_blocking because Rayon operations would block the async runtime.
        // The executor consumes tasks and sends results.
        let executor = Executor::new(self.pipeline);
        let executor_handle = tokio::task::spawn_blocking(move || {
            executor.process(&task_receiver, &result_sender);
        });

        // Run Writer task (Async I/O) on the current thread.
        // This consumes results and writes to disk.
        let write_result = writer.write_all(output, result_receiver, Some(&progress)).await;

        // Await handles to ensure all tasks completed cleanly and propagate panics/errors.
        let read_result = reader_handle.await.map_err(|_| anyhow!("reader task panicked"))?;
        executor_handle.await.map_err(|_| anyhow!("executor task panicked"))?;

        // Finish the progress bar.
        progress.finish();

        // Check for errors in the individual stages.
        read_result.context("reading failed")?;
        write_result.context("writing failed")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_worker_lifecycle() {
        let key = [0u8; ARGON_KEY_LEN];
        let worker = Worker::new(&key, Processing::Encryption);
        assert!(worker.is_ok());
    }

    #[tokio::test]
    async fn test_worker_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];

        // 1. Encrypt
        let enc_worker = Worker::new(&key, Processing::Encryption).unwrap();
        let data = vec![0x42u8; 5000]; // Random data
        let input_len = data.len() as u64;
        let mut encrypted = Vec::new();

        enc_worker.process(Cursor::new(data.clone()), &mut encrypted, input_len).await.unwrap();

        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, data);

        // 2. Decrypt
        let dec_worker = Worker::new(&key, Processing::Decryption).unwrap();
        let mut decrypted = Vec::new();

        dec_worker.process(Cursor::new(encrypted), &mut decrypted, input_len).await.unwrap();

        // 3. Verify
        assert_eq!(decrypted, data);
    }
}
