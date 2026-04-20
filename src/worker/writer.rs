use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use crate::types::{ProcessorMode, TaskResult};
use crate::ui::progress::Progress;
use crate::worker::buffer::Buffer;

pub struct Writer {
    mode: ProcessorMode,
}

impl Writer {
    pub fn new(mode: ProcessorMode) -> Self {
        Self { mode }
    }

    pub async fn write_all<W: AsyncWrite + Unpin>(self, output: W, mut receiver: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
        let mut buffer = Buffer::new(0);
        let mut writer = BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            let ready = buffer.add(result);
            self.write_batch(&mut writer, &ready, progress).await?;
        }

        let remaining = buffer.flush();
        self.write_batch(&mut writer, &remaining, progress).await?;

        writer.flush().await.context("Failed to flush writer")
    }

    async fn write_batch<W: AsyncWrite + Unpin>(&self, writer: &mut W, results: &[TaskResult], progress: &Progress) -> Result<()> {
        for result in results {
            if matches!(self.mode, ProcessorMode::Encryption) {
                writer.write_all(&u32::try_from(result.data.len())?.to_be_bytes()).await.context("Failed to write chunk length")?;
            }

            writer.write_all(&result.data).await.context("Failed to write chunk data")?;

            progress.add(result.size as u64);
        }

        Ok(())
    }
}
