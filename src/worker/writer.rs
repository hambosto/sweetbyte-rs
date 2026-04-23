use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::progress::Progress;
use crate::worker::buffer::Buffer;

pub struct Writer {
    buffer: Buffer,
    processing: Processing,
}

impl Writer {
    pub fn new(processing: Processing) -> Self {
        Self { buffer: Buffer::new(0), processing }
    }

    pub async fn write_all<W: AsyncWrite + Unpin>(&mut self, output: W, mut receiver: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
        let mut writer = BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            let ready = self.buffer.add(result);
            self.write_batch(&mut writer, &ready, progress).await?;
        }

        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress).await?;

        writer.flush().await.context("flush failed")
    }

    async fn write_batch<W: AsyncWrite + Unpin>(&self, writer: &mut W, results: &[TaskResult], progress: &Progress) -> Result<()> {
        for result in results {
            if matches!(self.processing, Processing::Encryption) {
                writer.write_all(&u32::try_from(result.data.len())?.to_be_bytes()).await.context("chunk write failed")?;
            }

            writer.write_all(&result.data).await.context("chunk write failed")?;
            progress.add(result.size as u64);
        }

        Ok(())
    }
}
