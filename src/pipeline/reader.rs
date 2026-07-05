use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::config::{CHUNK_SIZE, MAX_CHUNK_SIZE};

use super::processing::Processing;
use super::task::Task;

pub(super) struct Reader {
    processing: Processing,
}

impl Reader {
    pub(super) fn new(processing: Processing) -> Self {
        Self { processing }
    }

    pub(super) async fn read_all<R: AsyncRead + Unpin>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        let mut reader = BufReader::new(input);

        match self.processing {
            Processing::Encryption => Self::read_fixed_chunks(&mut reader, sender).await,
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender).await,
        }
    }

    async fn read_fixed_chunks<R: AsyncRead + Unpin>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            let mut buffer = Vec::with_capacity(CHUNK_SIZE);
            let bytes_read = reader.take(CHUNK_SIZE as u64).read_to_end(&mut buffer).await.context("failed to read chunk")?;

            if bytes_read == 0 {
                break;
            }

            sender.send(Task { data: buffer, index }).await.context("failed to send chunk")?;
            index = index.saturating_add(1);
        }

        Ok(())
    }

    async fn read_length_prefixed<R: AsyncRead + Unpin>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            match reader.read_u32_le().await {
                Ok(chunk_len) => {
                    if chunk_len > MAX_CHUNK_SIZE {
                        anyhow::bail!("chunk size {chunk_len} exceeds maximum {MAX_CHUNK_SIZE}");
                    }
                    let mut data = vec![0u8; chunk_len as usize];
                    reader.read_exact(&mut data).await.context("failed to read chunk")?;
                    sender.send(Task { data, index }).await.context("failed to send chunk")?;
                    index = index.saturating_add(1);
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).context("failed to read chunk length"),
            }
        }

        Ok(())
    }
}
