//! Chunk writer for streaming file processing.

use std::io::Write;

use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, WriteBytesExt};
use crossbeam_channel::Receiver;

use crate::stream::buffer::SequentialBuffer;
use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;

/// Writes processed chunks to output in sequential order.
pub struct ChunkWriter {
    mode: Processing,
    buffer: SequentialBuffer,
}

impl ChunkWriter {
    /// Creates a new chunk writer.
    ///
    /// # Arguments
    /// * `mode` - The processing mode
    pub fn new(mode: Processing) -> Self {
        Self {
            mode,
            buffer: SequentialBuffer::new(0),
        }
    }

    /// Writes all results from the channel to the output.
    ///
    /// # Arguments
    /// * `output` - The output writer
    /// * `receiver` - The channel receiver for results
    /// * `progress` - Optional progress bar
    pub fn write_all<W: Write>(
        &mut self,
        mut output: W,
        receiver: Receiver<TaskResult>,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        for result in receiver {
            if let Some(ref err) = result.error {
                bail!("task {} failed: {}", result.index, err);
            }

            let ready = self.buffer.add(result);
            self.write_ordered(&mut output, &ready, progress)?;
        }

        // Flush remaining buffered results
        let remaining = self.buffer.flush();
        self.write_ordered(&mut output, &remaining, progress)?;

        Ok(())
    }

    fn write_ordered<W: Write>(
        &self,
        output: &mut W,
        results: &[TaskResult],
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        match self.mode {
            Processing::Encryption => {
                for result in results {
                    // Write chunk size prefix
                    output
                        .write_u32::<BigEndian>(result.data.len() as u32)
                        .context("failed to write chunk size")?;

                    // Write chunk data
                    output
                        .write_all(&result.data)
                        .context("failed to write chunk data")?;

                    if let Some(bar) = progress {
                        bar.add(result.size as u64);
                    }
                }
            }
            Processing::Decryption => {
                for result in results {
                    output
                        .write_all(&result.data)
                        .context("failed to write chunk data")?;

                    if let Some(bar) = progress {
                        bar.add(result.size as u64);
                    }
                }
            }
        }

        Ok(())
    }
}
