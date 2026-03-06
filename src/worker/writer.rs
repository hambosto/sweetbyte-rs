use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::progress::Progress;
use crate::worker::buffer::Buffer;

pub struct Writer {
    mode: Processing,
    buffer: Buffer,
}

impl Writer {
    pub fn new(mode: Processing) -> Self {
        Self { mode, buffer: Buffer::new(0) }
    }

    pub async fn write_all<W: AsyncWrite + Unpin>(&mut self, output: W, mut receiver: Receiver<TaskResult>, progress: Option<&Progress>) -> Result<()> {
        let mut writer = tokio::io::BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            let ready = self.buffer.add(result);
            self.write_batch(&mut writer, &ready, progress).await?;
        }

        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress).await?;

        writer.flush().await.context("Failed to flush writer")
    }

    async fn write_batch<W: AsyncWrite + Unpin>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&Progress>) -> Result<()> {
        for r in results {
            if let Some(error) = &r.error {
                anyhow::bail!("Processing error in chunk {}: {}", r.index, error)
            }

            if matches!(self.mode, Processing::Encryption) {
                writer.write_all(&u32::try_from(r.data.len())?.to_be_bytes()).await.context("Failed to write chunk length")?;
            }

            writer.write_all(&r.data).await.context("Failed to write chunk data")?;
            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }

        Ok(())
    }
}
