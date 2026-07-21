use std::collections::VecDeque;

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use super::types::{Operation, TaskResult};
use crate::ui::Progress;

pub(super) struct Writer {
    index: u64,
    pending: VecDeque<Option<TaskResult>>,
    operation: Operation,
}

impl Writer {
    pub(super) fn new(operation: Operation) -> Self {
        Self { index: 0, pending: VecDeque::new(), operation }
    }

    pub(super) async fn write_all<W: AsyncWrite + Unpin>(&mut self, output: W, mut receiver: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
        self.index = 0;
        self.pending.clear();
        let mut writer = BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            let delta = result.index.checked_sub(self.index).context("chunk index behind writer")?;
            let offset = usize::try_from(delta).context("chunk index overflow")?;
            if offset >= self.pending.len() {
                self.pending.resize_with(offset.saturating_add(1), || None);
            }

            let slot = self.pending.get_mut(offset).context("chunk slot missing")?;
            *slot = Some(result);

            while let Some(slot) = self.pending.front_mut() {
                let Some(result) = slot.take() else { break };
                self.pending.pop_front();

                self.write_result(&mut writer, &result, progress).await?;
                self.index = self.index.saturating_add(1);
            }
        }

        writer.flush().await.context("failed to flush")
    }

    async fn write_result<W: AsyncWrite + Unpin>(&self, writer: &mut W, result: &TaskResult, progress_bar: &Progress) -> Result<()> {
        if self.operation.is_encryption() {
            let data_len = u32::try_from(result.data.len()).context("chunk length overflow")?;
            writer.write_all(&data_len.to_le_bytes()).await.context("failed to write chunk")?;
        }

        writer.write_all(&result.data).await.context("failed to write chunk")?;
        progress_bar.add(u64::try_from(result.size).context("size overflow")?);

        Ok(())
    }
}
