use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, WriteBytesExt};
use crossbeam_channel::Receiver;
use std::io::Write;

use crate::stream::buffer::SequentialBuffer;
use crate::types::{Processing, TaskResult};
use crate::ui::progress::Bar;

pub struct ChunkWriter {
    mode: Processing,
    buffer: SequentialBuffer,
}

impl ChunkWriter {
    pub fn new(mode: Processing) -> Self {
        Self {
            mode,
            buffer: SequentialBuffer::new(0),
        }
    }

    pub fn write_all<W: Write>(
        &mut self,
        mut output: W,
        receiver: Receiver<TaskResult>,
        progress: Option<&Bar>,
    ) -> Result<()> {
        for result in receiver {
            if let Some(ref err) = result.error {
                bail!("task {} failed: {}", result.index, err);
            }

            let ready = self.buffer.add(result);
            self.write_ordered(&mut output, &ready, progress)?;
        }

        let remaining = self.buffer.flush();
        self.write_ordered(&mut output, &remaining, progress)?;

        Ok(())
    }

    fn write_ordered<W: Write>(
        &self,
        output: &mut W,
        results: &[TaskResult],
        progress: Option<&Bar>,
    ) -> Result<()> {
        match self.mode {
            Processing::Encryption => {
                for result in results {
                    output
                        .write_u32::<BigEndian>(result.data.len() as u32)
                        .context("failed to write chunk size")?;

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
