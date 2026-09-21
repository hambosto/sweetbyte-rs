use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use crate::config::MAX_CHUNK_SIZE;
use crate::core::{Operation, TaskResult};
use crate::ui::Progress;

pub(super) async fn write_all<W: AsyncWrite + Unpin>(operation: Operation, output: W, mut result_rx: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
    let buffer_capacity = usize::try_from(MAX_CHUNK_SIZE).context("invalid max chunk limit")?;
    let mut writer = BufWriter::with_capacity(buffer_capacity, output);

    let mut pending: BTreeMap<u64, TaskResult> = BTreeMap::new();
    let mut next = u64::MIN;

    while let Some(task_result) = result_rx.recv().await {
        let chunk_index = task_result.index;
        if chunk_index < next {
            anyhow::bail!("chunk out of order");
        }

        let existing = pending.insert(chunk_index, task_result);
        if existing.is_some() {
            anyhow::bail!("duplicate chunk detected");
        }

        while let Some(ready) = pending.remove(&next) {
            write_result(&mut writer, operation, &ready, progress).await?;
            next = next.checked_add(1).context("chunk counter overflow")?;
        }
    }

    if !pending.is_empty() {
        anyhow::bail!("incomplete chunk stream");
    }

    writer.flush().await.context("failed to flush output file")
}

async fn write_result<W: AsyncWrite + Unpin>(writer: &mut W, operation: Operation, task_result: &TaskResult, progress: &Progress) -> Result<()> {
    if operation.is_encryption() {
        let chunk_len = u32::try_from(task_result.data.len()).context("chunk length overflow")?;
        if chunk_len > MAX_CHUNK_SIZE {
            anyhow::bail!("encrypted chunk exceeds limit");
        }

        writer.write_all(&chunk_len.to_le_bytes()).await.context("failed to write chunk length")?;
    }

    writer.write_all(&task_result.data).await.context("failed to write chunk data")?;

    let written = u64::try_from(task_result.size).context("invalid chunk byte count")?;
    progress.increment(written);

    Ok(())
}
