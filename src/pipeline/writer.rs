use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;

use crate::config::MAX_CHUNK_SIZE;
use crate::core::{Operation, TaskResult};
use crate::ui::Progress;

pub(super) async fn write_all<W: AsyncWrite + Unpin>(operation: Operation, output: W, mut results: Receiver<TaskResult>, progress: &Progress) -> Result<()> {
    let capacity = usize::try_from(MAX_CHUNK_SIZE).context("maximum chunk size exceeds usize")?;
    let mut writer = BufWriter::with_capacity(capacity, output);

    let mut pending: BTreeMap<u64, TaskResult> = BTreeMap::new();
    let mut next = 0_u64;

    while let Some(result) = results.recv().await {
        let index = result.index;
        if index < next {
            anyhow::bail!("chunk index {index} is behind writer index {next}");
        }

        let replaced = pending.insert(index, result);
        if replaced.is_some() {
            anyhow::bail!("duplicate chunk index {index}");
        }

        while let Some(ready) = pending.remove(&next) {
            write_result(&mut writer, operation, &ready, progress).await?;
            next = next.checked_add(1).context("chunk index overflowed u64")?;
        }
    }

    if !pending.is_empty() {
        anyhow::bail!("incomplete chunk stream: {} chunk(s) never arrived starting at index {next}", pending.len());
    }

    writer.flush().await.context("failed to flush output")
}

async fn write_result<W: AsyncWrite + Unpin>(writer: &mut W, operation: Operation, result: &TaskResult, progress: &Progress) -> Result<()> {
    if operation.is_encryption() {
        let chunk_len = u32::try_from(result.data.len()).context("chunk length overflow")?;
        if chunk_len > MAX_CHUNK_SIZE {
            anyhow::bail!("encrypted chunk size {chunk_len} exceeds maximum {MAX_CHUNK_SIZE}");
        }

        writer.write_all(&chunk_len.to_le_bytes()).await.context("failed to write chunk length")?;
    }

    writer.write_all(&result.data).await.context("failed to write chunk")?;

    let written = u64::try_from(result.size).context("chunk size exceeds u64")?;
    progress.add(written);

    Ok(())
}
