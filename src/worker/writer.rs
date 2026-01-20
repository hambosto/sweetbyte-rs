use std::io::{BufWriter, Write};

use anyhow::{Context, Result, bail};
use crossbeam_channel::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;
use crate::worker::buffer::Buffer;

/// Result writer that maintains ordering despite parallel processing.
///
/// Receives results from the executor pool, reorders them by index,
/// and writes them to the output. Uses a Buffer to hold out-of-order
/// results until they can be written in sequence.
pub struct Writer {
    /// Processing mode affecting write format.
    mode: Processing,
    /// Buffer for reordering results.
    buffer: Buffer,
}

impl Writer {
    /// Creates a new Writer with the given mode.
    ///
    /// # Arguments
    /// * `mode` - The processing mode.
    ///
    /// # Returns
    /// A new Writer instance.
    #[inline]
    pub fn new(mode: Processing) -> Self {
        Self { mode, buffer: Buffer::new(0) }
    }

    /// Writes all results to the output in order.
    ///
    /// Reads results from the channel, buffers them for ordering,
    /// and writes sequentially to the output.
    ///
    /// # Type Parameters
    /// * `W` - The output writer type.
    ///
    /// # Arguments
    /// * `output` - The output destination.
    /// * `receiver` - Channel receiver for results.
    /// * `progress` - Optional progress bar to update.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if writing failed.
    pub fn write_all<W: Write>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&ProgressBar>) -> Result<()> {
        let mut writer = BufWriter::new(output);

        // Process results as they arrive.
        for result in receiver {
            // Add to buffer and get any ready (in-order) results.
            let ready = self.buffer.add(result);
            // Write the ready results.
            self.write_batch(&mut writer, &ready, progress)?;
        }

        // Write any remaining buffered results.
        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress)?;

        // Ensure all data is flushed to disk.
        writer.flush().context("failed to flush output")
    }

    /// Writes a batch of results to the output.
    ///
    /// For encryption, writes a 4-byte length prefix before each chunk.
    ///
    /// # Arguments
    /// * `writer` - The buffered writer.
    /// * `results` - Results to write (already in order).
    /// * `progress` - Optional progress bar to update.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if a task failed.
    fn write_batch<W: Write>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&ProgressBar>) -> Result<()> {
        for r in results {
            // Check for errors from processing.
            if let Some(err) = &r.error {
                bail!("task {} failed: {}", r.index, err);
            }

            // For encryption, write a length prefix.
            if matches!(self.mode, Processing::Encryption) {
                writer.write_all(&(r.data.len() as u32).to_be_bytes()).context("failed to write chunk size")?;
            }

            // Write the actual data.
            writer.write_all(&r.data).context("failed to write chunk data")?;

            // Update progress bar.
            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }

        Ok(())
    }
}
