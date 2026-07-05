use std::collections::VecDeque;

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use super::processing::Processing;
use super::task::TaskResult;
use crate::ui::Progress;

pub(super) struct Writer {
    processing: Processing,
}

impl Writer {
    pub(super) fn new(processing: Processing) -> Self {
        Self { processing }
    }

    pub(super) async fn write_all<W: AsyncWrite + Unpin>(&self, output: W, mut receiver: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
        let mut next_index = 0u64;
        let mut pending: VecDeque<Option<TaskResult>> = VecDeque::new();
        let mut writer = BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            let delta = result.index.checked_sub(next_index).context("chunk index behind writer")?;
            let offset = usize::try_from(delta).context("chunk index overflow")?;
            if offset >= pending.len() {
                pending.resize_with(offset.saturating_add(1), || None);
            }

            let slot = pending.get_mut(offset).context("chunk slot missing")?;
            *slot = Some(result);

            while let Some(slot) = pending.front_mut() {
                let Some(result) = slot.take() else { break };
                pending.pop_front();

                self.write_result(&mut writer, &result, progress).await?;
                next_index = next_index.saturating_add(1);
            }
        }

        writer.flush().await.context("failed to flush")
    }

    async fn write_result<W: AsyncWrite + Unpin>(&self, writer: &mut W, result: &TaskResult, progress: &Progress) -> Result<()> {
        if self.processing.is_encryption() {
            let data_len = u32::try_from(result.data.len()).context("chunk length overflow")?;
            writer.write_all(&data_len.to_le_bytes()).await.context("failed to write chunk")?;
        }

        writer.write_all(&result.data).await.context("failed to write chunk")?;
        progress.add(u64::try_from(result.size).context("size overflow")?);

        Ok(())
    }
}
