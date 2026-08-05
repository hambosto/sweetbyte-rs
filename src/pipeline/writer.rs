use std::collections::VecDeque;

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use crate::config::MAX_CHUNK_SIZE;
use crate::core::{Operation, TaskResult};
use crate::ui::Progress;

pub(super) struct Writer {
    index: u64,
    operation: Operation,
}

impl Writer {
    pub(super) fn new(operation: Operation) -> Self {
        Self { index: 0, operation }
    }

    pub(super) async fn write_all<W: AsyncWrite + Unpin>(&mut self, output: W, mut receiver: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
        let mut pending: VecDeque<Option<TaskResult>> = VecDeque::new();
        let mut writer = BufWriter::new(output);

        while let Some(result) = receiver.recv().await {
            let delta = result.index.checked_sub(self.index).context("chunk index behind writer")?;
            let offset = usize::try_from(delta).context("chunk index exceeded usize")?;
            let required_len = offset.checked_add(1).context("chunk offset overflow")?;

            if required_len > pending.len() {
                pending.resize_with(required_len, || None);
            }

            let slot = pending.get_mut(offset).context("chunk slot missing")?;
            *slot = Some(result);

            while let Some(slot) = pending.front_mut() {
                let Some(result) = slot.take() else { break };
                pending.pop_front();

                self.write_result(&mut writer, &result, progress).await?;
                self.index = self.index.checked_add(1).context("chunk index overflowed u64")?;
            }
        }

        if !pending.is_empty() {
            anyhow::bail!("incomplete chunk stream: {} chunk(s) never arrived starting at index {}", pending.len(), self.index);
        }

        writer.flush().await.context("failed to flush")
    }

    async fn write_result<W: AsyncWrite + Unpin>(&self, writer: &mut W, result: &TaskResult, progress_bar: &Progress) -> Result<()> {
        if self.operation.is_encryption() {
            let data_len = u32::try_from(result.data.len()).context("chunk length overflow")?;

            if data_len > MAX_CHUNK_SIZE {
                anyhow::bail!("encrypted chunk size {data_len} exceeds maximum {MAX_CHUNK_SIZE}");
            }

            writer.write_all(&data_len.to_le_bytes()).await.context("failed to write chunk")?;
        }

        writer.write_all(&result.data).await.context("failed to write chunk")?;
        progress_bar.add(u64::try_from(result.size).context("failed to convert chunk size to u64")?);

        Ok(())
    }
}
