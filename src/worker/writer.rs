use std::io::{BufWriter, Write};

use anyhow::{Context, Result, bail};
use crossbeam_channel::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;
use crate::worker::buffer::Buffer;

pub struct Writer {
    mode: Processing,
    buffer: Buffer,
}

impl Writer {
    #[inline]
    pub fn new(mode: Processing) -> Self {
        Self { mode, buffer: Buffer::new(0) }
    }

    pub fn write_all<W: Write>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&ProgressBar>) -> Result<()> {
        let mut writer = BufWriter::new(output);

        for result in receiver {
            let ready = self.buffer.add(result);
            self.write_batch(&mut writer, &ready, progress)?;
        }

        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress)?;

        writer.flush().context("failed to flush output")
    }

    fn write_batch<W: Write>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&ProgressBar>) -> Result<()> {
        for r in results {
            if let Some(err) = &r.error {
                bail!("task {} failed: {}", r.index, err);
            }

            if matches!(self.mode, Processing::Encryption) {
                writer.write_all(&(r.data.len() as u32).to_be_bytes()).context("failed to write chunk size")?;
            }

            writer.write_all(&r.data).context("failed to write chunk data")?;

            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }
        Ok(())
    }
}
