use anyhow::{Context, Result};
use flume::Receiver;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};

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

    pub async fn write_all<W: AsyncWrite + Unpin>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&Progress>) -> Result<()> {
        let mut writer = BufWriter::new(output);

        while let Ok(result) = receiver.recv_async().await {
            let ready = self.buffer.add(result);
            self.write_batch(&mut writer, &ready, progress).await?;
        }

        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress).await?;

        writer.flush().await.context("flush")
    }

    async fn write_batch<W: AsyncWrite + Unpin>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&Progress>) -> Result<()> {
        for r in results {
            if let Some(error) = &r.error {
                anyhow::bail!("task {} error: {}", r.index, error)
            }

            if matches!(self.mode, Processing::Encryption) {
                writer.write_all(&(r.data.len() as u32).to_be_bytes()).await.context("write")?;
            }

            writer.write_all(&r.data).await.context("write")?;
            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }

        Ok(())
    }
}
