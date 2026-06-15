use std::collections::HashMap;

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use crate::types::{Processing, TaskResult};
use crate::ui::Progress;

pub(super) struct Writer {
    processing: Processing,
}

impl Writer {
    pub(super) fn new(processing: Processing) -> Self {
        Self { processing }
    }

    pub(super) async fn write_all<W: AsyncWrite + Unpin>(&self, output: W, mut receiver: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
        let mut index = 0u64;
        let mut pending = HashMap::<u64, TaskResult>::new();
        let mut writer = BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            pending.insert(result.index, result);

            while let Some(result) = pending.remove(&index) {
                self.write_result(&mut writer, &result, progress).await?;
                index = index.saturating_add(1);
            }
        }

        writer.flush().await.context("failed to flush")
    }

    async fn write_result<W: AsyncWrite + Unpin>(&self, writer: &mut W, result: &TaskResult, progress: &Progress) -> Result<()> {
        if matches!(self.processing, Processing::Encryption) {
            writer.write_all(&u32::try_from(result.data.len())?.to_le_bytes()).await.context("failed to write chunk")?;
        }
        writer.write_all(&result.data).await.context("failed to write chunk")?;
        progress.add(result.size as u64);

        Ok(())
    }
}
