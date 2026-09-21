use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::config::{CHUNK_SIZE, MAX_CHUNK_SIZE};
use crate::core::{Operation, Task};

pub(super) async fn read_all<R: AsyncRead + Unpin>(operation: Operation, source: R, task_tx: Sender<Task>) -> Result<()> {
    match operation {
        Operation::Encryption => read_fixed_chunks(source, task_tx).await,
        Operation::Decryption => read_length_prefixed_chunks(source, task_tx).await,
    }
}

async fn read_fixed_chunks<R: AsyncRead + Unpin>(mut source: R, task_tx: Sender<Task>) -> Result<()> {
    let chunk_limit = u64::try_from(CHUNK_SIZE).context("invalid plain chunk size")?;

    for chunk_index in u64::MIN.. {
        let mut chunk_data = Vec::with_capacity(CHUNK_SIZE);
        let mut limited = (&mut source).take(chunk_limit);

        while chunk_data.len() < CHUNK_SIZE {
            let count = limited.read_buf(&mut chunk_data).await.context("failed to read plain chunk")?;
            if count == 0 {
                break;
            }
        }

        if chunk_data.is_empty() {
            break;
        }

        let sent = task_tx.send(Task { data: chunk_data, index: chunk_index }).await;
        if sent.is_err() {
            break;
        }
    }

    Ok(())
}

async fn read_length_prefixed_chunks<R: AsyncRead + Unpin>(source: R, task_tx: Sender<Task>) -> Result<()> {
    let mut chunk_reader = BufReader::with_capacity(CHUNK_SIZE, source);

    for chunk_index in u64::MIN.. {
        let peeked = chunk_reader.fill_buf().await.context("failed to read chunk length")?;
        if peeked.is_empty() {
            break;
        }

        let declared = chunk_reader.read_u32_le().await.context("truncated chunk length")?;
        if declared > MAX_CHUNK_SIZE {
            anyhow::bail!("encrypted chunk exceeds limit");
        }

        let chunk_len = usize::try_from(declared).context("invalid encrypted chunk size")?;
        let mut chunk_data = vec![u8::MIN; chunk_len];
        chunk_reader.read_exact(&mut chunk_data).await.context("truncated chunk data")?;

        let sent = task_tx.send(Task { data: chunk_data, index: chunk_index }).await;
        if sent.is_err() {
            break;
        }
    }

    Ok(())
}
