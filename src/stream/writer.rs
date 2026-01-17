use std::io::{BufWriter, Write};

use anyhow::{Context, Result, bail};
use crossbeam_channel::Receiver;

use crate::stream::buffer::Buffer;
use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;

pub struct ChunkWriter {
    mode: Processing,
    buffer: Buffer,
}

impl ChunkWriter {
    #[inline]
    pub fn new(mode: Processing) -> Self {
        Self { mode, buffer: Buffer::new(0) }
    }

    pub fn write_all<W: Write>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&ProgressBar>) -> Result<()> {
        let mut writer = BufWriter::new(output);

        for result in receiver {
            if let Some(err) = result.error {
                bail!("task {} failed: {}", result.index, err);
            }

            let ready = self.buffer.add(result);
            self.write_results(&mut writer, &ready, progress)?;
        }

        let remaining = self.buffer.flush();
        self.write_results(&mut writer, &remaining, progress)?;

        writer.flush().context("failed to flush output")?;
        Ok(())
    }

    fn write_results<W: Write>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&ProgressBar>) -> Result<()> {
        for result in results {
            self.write_single(writer, result)?;

            if let Some(bar) = progress {
                bar.add(result.size as u64);
            }
        }
        Ok(())
    }

    #[inline]
    fn write_single<W: Write>(&self, writer: &mut W, result: &TaskResult) -> Result<()> {
        match self.mode {
            Processing::Encryption => {
                let size_bytes = (result.data.len() as u32).to_be_bytes();
                writer.write_all(&size_bytes).context("failed to write chunk size")?;
            }
            Processing::Decryption => {}
        }

        writer.write_all(&result.data).context("failed to write chunk data")
    }
}
