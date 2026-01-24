//! Worker module for concurrent file processing
//!
//! This module implements a high-performance concurrent processing architecture using a
//! producer-consumer pattern with multiple specialized workers. The design prioritizes
//! throughput while maintaining data integrity and proper ordering.
//!
//! ## Architecture Overview
//!
//! The worker system consists of four main components operating in parallel:
//!
//! 1. **Reader**: Reads input data in chunks and creates tasks
//! 2. **Executor**: Processes tasks using a thread pool with Rayon parallelization
//! 3. **Writer**: Writes processed results while maintaining order via buffering
//! 4. **Pipeline**: Handles the actual data transformation (encryption/decryption)
//!
//! ## Concurrency Model
//!
//! The system uses a bounded channel approach with backpressure:
//! - Tasks flow through channels with configurable buffer sizes
//! - Channel size is calculated as `concurrency * 2` for optimal throughput
//! - Automatic detection of CPU cores for thread pool sizing
//! - Separate threads for each major operation to prevent blocking
//!
//! ## Performance Characteristics
//!
//! - **Throughput**: Maximizes I/O and CPU utilization through parallelization
//! - **Memory**: Bounded channels prevent unbounded memory growth
//! - **Latency**: Minimal copying and efficient thread synchronization
//! - **Scalability**: Automatically adapts to available CPU cores

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

/// Main worker orchestrator for concurrent file processing
///
/// The `Worker` struct coordinates the entire processing pipeline, managing
/// the interaction between reader, executor, and writer components. It handles
/// thread creation, channel setup, and ensures proper resource cleanup.
///
/// ## Threading Model
///
/// The worker creates three main threads:
/// - **Reader thread**: Continuously reads input and produces tasks
/// - **Executor thread**: Manages the thread pool for task processing
/// - **Main thread**: Handles writing and progress tracking
///
/// This separation allows I/O operations to run concurrently with CPU-intensive
/// cryptographic operations, maximizing system utilization.
pub struct Worker {
    /// The processing pipeline containing cryptographic and compression components
    /// Shared across threads via Arc wrapping in the executor
    pipeline: Pipeline,
    /// Processing mode determining whether to encrypt or decrypt
    /// Affects the entire processing pipeline behavior
    mode: Processing,
}

impl Worker {
    /// Creates a new Worker instance with the given encryption key and processing mode
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Argon2-derived key for cryptographic operations
    /// * `mode` - Processing mode (Encryption or Decryption)
    ///
    /// # Returns
    ///
    /// Returns a configured Worker instance or an error if pipeline initialization fails
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The cryptographic pipeline fails to initialize
    /// - The Reed-Solomon encoder cannot be created
    /// - The compression algorithm setup fails
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        // Initialize the processing pipeline with cryptographic components
        // This pipeline will be shared across threads via Arc wrapping
        let pipeline = Pipeline::new(key, mode)?;
        Ok(Self { pipeline, mode })
    }

    /// Processes data concurrently from input to output with progress tracking
    ///
    /// This is the main entry point for concurrent file processing. It sets up
    /// the entire producer-consumer pipeline with proper backpressure handling
    /// and thread management.
    ///
    /// # Concurrency Design
    ///
    /// The function implements a three-stage pipeline:
    /// 1. Reader produces tasks and sends to executor channel
    /// 2. Executor processes tasks using Rayon thread pool
    /// 3. Writer consumes results while maintaining order
    ///
    /// Channel sizes are calculated as `concurrency * 2` to provide optimal
    /// buffering between stages while preventing memory bloat.
    ///
    /// # Arguments
    ///
    /// * `input` - Readable input stream (must be Send + 'static for thread safety)
    /// * `output` - Writable output stream (must be Send + 'static for thread safety)
    /// * `total_size` - Total input size for progress tracking (bytes)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful processing or an error if any stage fails
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Reader thread panics or encounters I/O errors
    /// - Executor thread panics during processing
    /// - Writer encounters I/O errors or task processing failures
    /// - Progress bar operations fail
    ///
    /// # Thread Safety
    ///
    /// All I/O objects are moved into their respective threads, ensuring
    /// no data races. Communication happens exclusively through thread-safe
    /// bounded channels with proper error propagation.
    pub fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        // Initialize progress tracking with total file size
        let progress = ProgressBar::new(total_size, self.mode.label())?;

        // Determine optimal concurrency level based on available CPU cores
        // Falls back to 4 if system doesn't provide parallelism info
        let concurrency = thread::available_parallelism().map(|p| p.get()).unwrap_or(4);

        // Channel size set to 2x concurrency for optimal buffering
        // This provides enough buffer to keep all workers busy while
        // preventing unbounded memory growth
        let channel_size = concurrency * 2;

        // Create bounded channels for task and result flow
        // Bounded channels provide backpressure to prevent memory exhaustion
        let (task_sender, task_receiver) = bounded(channel_size);
        let (result_sender, result_receiver) = bounded(channel_size);

        // Initialize reader and writer components
        // Reader handles chunking based on processing mode
        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = Writer::new(self.mode);

        // Spawn reader thread in the background
        // This thread reads input data and produces tasks for the executor
        let reader_handle = thread::spawn(move || reader.read_all(input, &task_sender));

        // Create executor and spawn processing thread
        // Executor manages the thread pool for cryptographic operations
        let executor = Executor::new(self.pipeline);
        let executor_handle = thread::spawn(move || {
            executor.process(&task_receiver, &result_sender);
        });

        // Run writer on main thread while background threads process
        // This allows progress tracking and immediate error detection
        let write_result = writer.write_all(output, result_receiver, Some(&progress));

        // Wait for background threads to complete and collect results
        // This ensures all resources are properly cleaned up
        let read_result = reader_handle.join().map_err(|_| anyhow!("reader thread panicked"))?;
        executor_handle.join().map_err(|_| anyhow!("executor thread panicked"))?;

        // Finalize progress tracking
        progress.finish();

        // Propagate any errors from the pipeline stages
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

    #[test]
    fn test_worker_roundtrip() {
        let key = [0u8; ARGON_KEY_LEN];

        let enc_worker = Worker::new(&key, Processing::Encryption).unwrap();
        let data = vec![0x42u8; 5000];
        let input_len = data.len() as u64;
        let mut encrypted = Vec::new();

        enc_worker.process(Cursor::new(data.clone()), &mut encrypted, input_len).unwrap();
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, data);

        let dec_worker = Worker::new(&key, Processing::Decryption).unwrap();
        let mut decrypted = Vec::new();

        dec_worker.process(Cursor::new(encrypted), &mut decrypted, input_len).unwrap();

        assert_eq!(decrypted, data);
    }
}
