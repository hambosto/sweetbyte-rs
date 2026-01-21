//! Result writing and output formatting.
//!
//! Receives processed results, reorders them for sequential output,
//! and writes to the destination file. Adds length prefixes for encryption.

use std::io::{BufWriter, Write};

use anyhow::{Context, Result, bail};
use flume::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;
use crate::worker::buffer::Buffer;

/// Writes processed results to output.
///
/// Receives results from the executor, reorders them using a buffer,
/// and writes to the output file. For encryption, prepends each chunk
/// with its length.
pub struct Writer {
    /// Processing mode (affects output format).
    mode: Processing,

    /// Buffer for reordering out-of-sequence results.
    buffer: Buffer,
}

impl Writer {
    /// Creates a new writer for the given mode.
    #[inline]
    pub fn new(mode: Processing) -> Self {
        Self { mode, buffer: Buffer::new(0) }
    }

    /// Writes all results from the channel to output.
    ///
    /// Processes results in order as they arrive, using the buffer
    /// to handle out-of-sequence completion from parallel processing.
    ///
    /// The loop reads results from the channel as they arrive.
    /// Results may be out of order due to parallel processing.
    /// The buffer reorders them and returns consecutive batches.
    ///
    /// # Type Parameters
    ///
    /// * `W` - A writable type implementing [`Write`].
    ///
    /// # Arguments
    ///
    /// * `output` - The output destination.
    /// * `receiver` - Channel receiver for processed results.
    /// * `progress` - Optional progress bar to update.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or a task errors.
    pub fn write_all<W: Write>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&ProgressBar>) -> Result<()> {
        let mut writer = BufWriter::new(output);

        // Process results as they arrive from the executor.
        // receiver is an iterator that blocks until results are available.
        for result in receiver {
            // Add to buffer and get any consecutive results ready for output.
            // The buffer handles reordering of out-of-sequence results.
            let ready = self.buffer.add(result);
            self.write_batch(&mut writer, &ready, progress)?;
        }

        // Flush any remaining buffered results.
        // This handles the last few chunks that were waiting for predecessors.
        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress)?;

        // Ensure all data is written to disk.
        // BufWriter may have buffered data that needs flushing.
        writer.flush().context("failed to flush output")
    }

    /// Writes a batch of results to output.
    ///
    /// For encryption: writes a 4-byte length prefix before each chunk.
    /// For decryption: writes chunks directly (no length prefix).
    ///
    /// The length prefix format allows the decryptor to know chunk boundaries
    /// since encrypted chunks may vary in size due to compression and padding.
    fn write_batch<W: Write>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&ProgressBar>) -> Result<()> {
        for r in results {
            // Check for processing errors from the encryption/decryption pipeline.
            // If a task failed, we propagate the error immediately.
            if let Some(err) = &r.error {
                bail!("task {} failed: {}", r.index, err);
            }

            // For encryption: write 4-byte length prefix (big-endian).
            // This tells the decryptor how many bytes to read for this chunk.
            // The format is: [4-byte length][chunk data][4-byte length][chunk data]...
            if matches!(self.mode, Processing::Encryption) {
                writer.write_all(&(r.data.len() as u32).to_be_bytes()).context("failed to write chunk size")?;
            }

            // Write the actual chunk data.
            // This is the encrypted or decrypted bytes for this chunk.
            writer.write_all(&r.data).context("failed to write chunk data")?;

            // Update progress bar with original input size.
            // r.size tracks the original (uncompressed) data size.
            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }

        Ok(())
    }
}
