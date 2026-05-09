use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::config::CHUNK_SIZE;
use crate::types::{Processing, Task};

pub struct Reader {
    processing: Processing,
}

impl Reader {
    pub fn new(processing: Processing) -> Self {
        Self { processing }
    }

    pub async fn read_all<R: AsyncRead + Unpin>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
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

        while let Ok(chunk_len) = reader.read_u32_le().await {
            if chunk_len == 0 {
                break;
            }

            let mut data = vec![0u8; chunk_len as usize];
            reader.read_exact(&mut data).await.context("failed to read chunk")?;
            sender.send(Task { data, index }).await.context("failed to send chunk")?;
            index = index.saturating_add(1);
        }

        Ok(())
    }
}
