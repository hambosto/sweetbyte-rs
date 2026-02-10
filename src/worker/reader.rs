use anyhow::{Context, Result};
use flume::Sender;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::config::CHUNK_SIZE;
use crate::types::{Processing, Task};
pub struct Reader {
    mode: Processing,
    chunk_size: usize,
}

impl Reader {
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        if chunk_size < CHUNK_SIZE {
            anyhow::bail!("chunk size must be at least {CHUNK_SIZE} bytes, got {chunk_size}")
        }
        Ok(Self { mode, chunk_size })
    }

    pub async fn read_all<R: AsyncRead + Unpin>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        let mut reader = tokio::io::BufReader::new(input);

        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender).await,
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender).await,
        }
    }

    async fn read_fixed_chunks<R: AsyncRead + Unpin>(&self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            let mut buffer = Vec::with_capacity(self.chunk_size);
            let bytes_read = reader.take(self.chunk_size as u64).read_to_end(&mut buffer).await.context("read chunk")?;

            if bytes_read == 0 {
                break;
            }

            sender.send_async(Task { data: buffer, index }).await.context("send chunk: channel closed")?;
            index += 1;
        }

        Ok(())
    }

    async fn read_length_prefixed<R: AsyncRead + Unpin>(reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            let mut buffer_len = [0u8; 4];
            if reader.read_exact(&mut buffer_len).await.is_err() {
                break;
            }

            let chunk_len = u32::from_be_bytes(buffer_len) as usize;
            if chunk_len == 0 {
                continue;
            }

            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).await.context("read chunk data")?;
            sender.send_async(Task { data, index }).await.context("send chunk: channel closed")?;
            index += 1;
        }

        Ok(())
    }
}
