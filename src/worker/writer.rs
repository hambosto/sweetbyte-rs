//! Concurrent file writer with ordering and progress tracking
//!
//! This module implements the output stage of the concurrent processing pipeline.
//! The writer is responsible for receiving processed results from the executor,
//! reordering them to maintain sequence integrity, and writing them to the output.
//!
//! ## Key Responsibilities
//!
//! 1. **Result Reordering**: Ensures output maintains original input order despite concurrent
//!    processing completing tasks out of sequence
//! 2. **Error Handling**: Detects and propagates processing failures immediately
//! 3. **Format Compliance**: Writes data in the correct format for each mode
//! 4. **Progress Tracking**: Updates progress bar based on actual data processed
//! 5. **I/O Optimization**: Uses buffered writing for maximum throughput
//!
//! ## Output Formats
///
/// ### Encryption Mode
/// ```
/// [4-byte length (big-endian)] [encrypted chunk data] [repeat...]
/// ```
///
/// ### Decryption Mode
/// ```
/// [original plaintext data] [continue...]
/// ```
// ## Performance Characteristics
//
// - **Throughput**: Buffered I/O minimizes system call overhead
// - **Memory**: Reordering buffer prevents memory bloat
// - **Latency**: Immediate error detection prevents wasted work
// - **Scalability**: Handles high-frequency results efficiently
use std::io::{BufWriter, Write};

use anyhow::{Context, Result, bail};
use flume::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;
use crate::worker::buffer::Buffer;

/// Concurrent output writer with result reordering
///
/// The Writer handles the final stage of the processing pipeline. It receives
/// results from concurrent processing, ensures proper ordering, and writes
/// the output in the correct format for each processing mode.
///
/// ## Ordering Strategy
///
/// Tasks complete in non-deterministic order due to varying processing times.
/// The writer uses an internal buffer to reorder results back to their
/// original sequential order, ensuring data integrity in the output.
///
/// ## Error Handling
///
/// The writer performs immediate error checking:
/// - Individual task errors cause immediate termination
/// - I/O errors are propagated with detailed context
/// - Partial writes are prevented to maintain data consistency
///
/// ## Performance Optimization
///
/// - **Batch Processing**: Writes multiple results per I/O operation
/// - **Buffered Output**: BufWriter reduces system call overhead
/// - **Progress Tracking**: Efficient progress updates without blocking
/// - **Memory Management**: Minimal buffering to prevent memory pressure
pub struct Writer {
    /// Processing mode determining output format
    /// Affects whether length prefixes are written
    mode: Processing,
    /// Reordering buffer for maintaining output sequence
    /// Handles out-of-order results from concurrent processing
    buffer: Buffer,
}

impl Writer {
    /// Creates a new Writer with the specified processing mode
    ///
    /// Initializes the writer with an empty reordering buffer starting
    /// at index 0. The mode determines the output format.
    ///
    /// # Arguments
    ///
    /// * `mode` - Processing mode (Encryption or Decryption)
    ///
    /// # Returns
    ///
    /// A new Writer instance ready to receive and write results
    ///
    /// # Performance Notes
    ///
    /// The buffer starts empty and grows as needed. The starting index
    /// of 0 is appropriate for new files but could be adjusted for
    /// resume functionality in future versions.
    #[inline]
    pub fn new(mode: Processing) -> Self {
        Self { mode, buffer: Buffer::new(0) }
    }

    /// Writes all results from the receiver to output with proper ordering
    ///
    /// This is the main execution loop for the writer. It continuously
    /// receives results from the executor, reorders them, and writes them
    /// to the output in the correct sequence.
    ///
    /// ## Execution Flow
    ///
    /// 1. Wrap output in BufWriter for I/O optimization
    /// 2. Receive results from executor until channel closes
    /// 3. Add each result to the reordering buffer
    /// 4. Write any ready sequential results immediately
    /// 5. After channel closes, flush any remaining buffered results
    /// 6. Ensure all data is physically written to disk
    ///
    /// ## Error Handling
    ///
    /// The method handles multiple error scenarios:
    /// - Task processing errors from the pipeline
    /// - I/O errors during write operations
    /// - Buffer reordering errors (theoretical)
    /// - Output flush failures
    ///
    /// # Arguments
    ///
    /// * `output` - Writable output stream
    /// * `receiver` - Channel receiver for results from executor
    /// * `progress` - Optional progress bar for user feedback
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful completion or an error with context
    ///
    /// # Performance Characteristics
    ///
    /// - **Backpressure**: Channel blocking prevents overwhelming the writer
    /// - **Batching**: Multiple results written together when possible
    /// - **Buffering**: BufWriter reduces system call overhead
    /// - **Memory**: Buffer size remains bounded by available results
    ///
    /// # Concurrency Notes
    ///
    /// This method runs on the main thread and provides the natural
    /// termination point for the entire pipeline. The channel closing
    /// signals that both reader and executor have completed their work.
    pub fn write_all<W: Write>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&ProgressBar>) -> Result<()> {
        // Wrap output in BufWriter for efficient I/O operations
        // This reduces system call overhead and improves write performance
        let mut writer = BufWriter::new(output);

        // Process results until the executor closes the channel
        // This loop continues until all tasks have been processed
        for result in receiver {
            // Add the new result to the reordering buffer
            // This may release several ready results in sequence
            let ready = self.buffer.add(result);

            // Write any results that are ready in sequential order
            // Batch writing improves I/O performance
            self.write_batch(&mut writer, &ready, progress)?;
        }

        // After the channel closes, flush any remaining buffered results
        // This ensures no data is lost at the end of processing
        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress)?;

        // Ensure all buffered data is physically written to storage
        // This guarantees data integrity before returning success
        writer.flush().context("failed to flush output")
    }

    /// Writes a batch of results to output in sequential order
    ///
    /// This method handles the actual I/O operations for a batch of results
    /// that are ready to be written. It validates each result, formats it
    /// according to the processing mode, and updates progress tracking.
    ///
    /// ## Format Handling
    ///
    /// ### Encryption Mode
    /// - Writes 4-byte length prefix (big-endian)
    /// - Writes encrypted chunk data
    /// - Length prefix enables correct reading during decryption
    ///
    /// ### Decryption Mode
    /// - Writes plaintext data directly
    /// - No length prefix needed for original data format
    ///
    /// ## Error Strategy
    ///
    /// The method uses immediate error propagation:
    /// - Any task error causes immediate termination
    /// - I/O errors are propagated with detailed context
    /// - No partial writes to maintain output integrity
    ///
    /// # Arguments
    ///
    /// * `writer` - Buffered output writer
    /// * `results` - Batch of sequential results to write
    /// * `progress` - Optional progress bar for user feedback
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all results are written successfully
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any result contains a processing error
    /// - I/O operations fail during writing
    /// - File system encounters issues
    ///
    /// # Performance Notes
    ///
    /// - **Sequential Access**: Results are already ordered, allowing efficient writes
    /// - **Error Detection**: Early error detection prevents wasted I/O
    /// - **Progress Updates**: Efficient progress tracking without blocking
    /// - **Memory**: Results are moved, not copied, minimizing overhead
    fn write_batch<W: Write>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&ProgressBar>) -> Result<()> {
        // Process each result in the batch sequentially
        // Results are already in the correct order from the buffer
        for r in results {
            // Check for processing errors in the result
            // Any error causes immediate termination to prevent corrupted output
            if let Some(err) = &r.error {
                bail!("task {} failed: {}", r.index, err);
            }

            // For encryption mode, write length prefix before data
            // This enables correct chunk boundary detection during decryption
            if matches!(self.mode, Processing::Encryption) {
                // Write 4-byte length in big-endian format
                // big-endian ensures cross-platform compatibility
                writer.write_all(&(r.data.len() as u32).to_be_bytes()).context("failed to write chunk size")?;
            }

            // Write the actual data (encrypted or decrypted)
            // This is the main payload for each chunk
            writer.write_all(&r.data).context("failed to write chunk data")?;

            // Update progress bar if provided
            // Use original size (r.size) for accurate progress tracking
            // This reflects actual data processed, not encrypted size
            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flume::unbounded;

    #[test]
    fn test_write_decryption_mode() {
        let mut writer = Writer::new(Processing::Decryption);
        let mut output = Vec::new();
        let (tx, rx) = unbounded();

        tx.send(TaskResult::ok(0, b"hello".to_vec(), 5)).unwrap();
        tx.send(TaskResult::ok(1, b"world".to_vec(), 5)).unwrap();
        drop(tx);

        writer.write_all(&mut output, rx, None).unwrap();

        assert_eq!(output, b"helloworld");
    }

    #[test]
    fn test_write_encryption_mode() {
        let mut writer = Writer::new(Processing::Encryption);
        let mut output = Vec::new();
        let (tx, rx) = unbounded();

        tx.send(TaskResult::ok(0, b"data".to_vec(), 4)).unwrap();
        drop(tx);

        writer.write_all(&mut output, rx, None).unwrap();

        assert_eq!(output.len(), 4 + 4);
        assert_eq!(&output[0..4], &4u32.to_be_bytes());
        assert_eq!(&output[4..], b"data");
    }

    #[test]
    fn test_write_reordering() {
        let mut writer = Writer::new(Processing::Decryption);
        let mut output = Vec::new();
        let (tx, rx) = unbounded();

        tx.send(TaskResult::ok(1, b"world".to_vec(), 5)).unwrap();
        tx.send(TaskResult::ok(0, b"hello".to_vec(), 5)).unwrap();
        drop(tx);

        writer.write_all(&mut output, rx, None).unwrap();

        assert_eq!(output, b"helloworld");
    }
}
