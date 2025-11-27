use anyhow::{Context, Result, anyhow};
use crossbeam_channel::Receiver;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::buffer::OrderedBuffer;
use crate::types::{Processing, TaskResult};
use crate::utils::UintType;

/// Writes processed chunks to the output stream while maintaining correct order.
///
/// Uses an OrderedBuffer to handle out-of-order results from parallel processing.
/// Matches Go's ChunkWriter architecture with synchronized buffering.
#[derive(Debug)]
pub struct ChunkWriter {
    processing: Processing,
    buffer: Arc<OrderedBuffer>,
}

impl Clone for ChunkWriter {
    fn clone(&self) -> Self {
        Self {
            processing: self.processing,
            buffer: Arc::clone(&self.buffer),
        }
    }
}

impl ChunkWriter {
    /// Creates a new chunk writer.
    pub fn new(processing: Processing) -> Self {
        Self {
            processing,
            buffer: Arc::new(OrderedBuffer::new()),
        }
    }

    /// Writes chunks from the results channel to the output writer.
    ///
    /// This is a blocking operation that:
    /// 1. Receives results from the channel
    /// 2. Adds them to the OrderedBuffer
    /// 3. Writes ready chunks immediately in the correct order
    /// 4. Updates the progress bar
    /// 5. Handles errors and cancellation
    /// 6. Flushes remaining chunks at the end
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer
    /// * `results` - Channel of task results
    /// * `progress` - Progress bar for tracking
    /// * `cancel` - Cancellation flag
    pub fn write_chunks<W>(
        &self,
        writer: W,
        results: Receiver<TaskResult>,
        progress: Arc<crate::tui::Bar>,
        cancel: Arc<AtomicBool>,
    ) -> Result<()>
    where
        W: Write,
    {
        // Wrap in BufWriter for better I/O performance
        let mut writer = std::io::BufWriter::new(writer);

        loop {
            // Check for cancellation
            if cancel.load(Ordering::SeqCst) {
                return Err(anyhow!("operation cancelled"));
            }

            // Receive next result
            let result = match results.recv() {
                Ok(result) => result,
                Err(_) => {
                    // Channel closed, flush remaining results
                    let remaining = self.buffer.flush();
                    self.write_results(&mut writer, &remaining, &progress)?;
                    writer.flush()?;
                    return Ok(());
                }
            };

            // Check for processing error
            if let Some(err) = result.err {
                cancel.store(true, Ordering::SeqCst);
                return Err(err)
                    .with_context(|| format!("chunk {} processing failed", result.index));
            }

            // Add to buffer and get ready chunks
            let ready_chunks = self.buffer.add(result);

            // Write ready chunks
            if !ready_chunks.is_empty() {
                self.write_results(&mut writer, &ready_chunks, &progress)?;
            }
        }
    }

    /// Writes a batch of results to the output.
    #[inline]
    fn write_results<W>(
        &self,
        writer: &mut W,
        results: &[TaskResult],
        progress: &crate::tui::Bar,
    ) -> Result<()>
    where
        W: Write,
    {
        for result in results {
            // For encryption, write 4-byte length prefix first
            if self.processing == Processing::Encryption {
                let size = result.data.len();
                if size > u32::MAX as usize {
                    return Err(anyhow!(
                        "chunk {} size ({} bytes) exceeds u32::MAX",
                        result.index,
                        size
                    ));
                }

                let length_bytes = (size as u32).to_bytes();
                writer
                    .write_all(&length_bytes)
                    .context("failed to write chunk length prefix")?;
            }

            // Write chunk data
            writer
                .write_all(&result.data)
                .with_context(|| format!("failed to write chunk {} data", result.index))?;

            // Update progress
            progress.add(result.size as u64);
        }

        Ok(())
    }
}
