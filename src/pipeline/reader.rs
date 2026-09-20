use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::config::{CHUNK_SIZE, MAX_CHUNK_SIZE};
use crate::core::{Operation, Task};

pub(super) async fn read_all<R: AsyncRead + Unpin>(operation: Operation, input: R, tasks: Sender<Task>) -> Result<()> {
    match operation {
        Operation::Encryption => read_fixed_chunks(input, tasks).await,
        Operation::Decryption => read_length_prefixed_chunks(input, tasks).await,
    }
}

async fn read_fixed_chunks<R: AsyncRead + Unpin>(mut input: R, tasks: Sender<Task>) -> Result<()> {
    let limit = u64::try_from(CHUNK_SIZE).context("invalid plain chunk size")?;

    for index in 0_u64.. {
        let mut data = Vec::with_capacity(CHUNK_SIZE);
        let mut window = (&mut input).take(limit);

        while data.len() < CHUNK_SIZE {
            let read = window.read_buf(&mut data).await.context("failed to read plain chunk")?;
            if read == 0 {
                break;
            }
        }

        if data.is_empty() {
            break;
        }

        let sent = tasks.send(Task { data, index }).await;
        if sent.is_err() {
            break;
        }
    }

    Ok(())
}

async fn read_length_prefixed_chunks<R: AsyncRead + Unpin>(input: R, tasks: Sender<Task>) -> Result<()> {
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, input);

    for index in 0_u64.. {
        let buffered = reader.fill_buf().await.context("failed to read chunk length")?;
        if buffered.is_empty() {
            break;
        }

        let chunk_len = reader.read_u32_le().await.context("truncated chunk length")?;
        if chunk_len > MAX_CHUNK_SIZE {
            anyhow::bail!("encrypted chunk exceeds limit");
        }

        let chunk_len = usize::try_from(chunk_len).context("invalid encrypted chunk size")?;
        let mut data = vec![0_u8; chunk_len];
        reader.read_exact(&mut data).await.context("truncated chunk data")?;

        let sent = tasks.send(Task { data, index }).await;
        if sent.is_err() {
            break;
        }
    }

    Ok(())
}
