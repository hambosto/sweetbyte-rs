use anyhow::{Context, Result};
use flume::Sender;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use crate::types::{Processing, Task};

pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

pub struct Reader {
    mode: Processing,
    chunk_size: usize,
}

impl Reader {
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        if chunk_size < MIN_CHUNK_SIZE {
            anyhow::bail!("chunk size must be at least {MIN_CHUNK_SIZE} bytes, got {chunk_size}")
        }
        Ok(Self { mode, chunk_size })
    }

    pub async fn read_all<R: AsyncRead + Unpin>(&self, input: R, sender: &Sender<Task>) -> Result<()> {
        let mut reader = BufReader::new(input);

        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender).await,
            Processing::Decryption => Self::read_length_prefixed(&mut reader, sender).await,
        }
    }

    async fn read_fixed_chunks<R: AsyncRead + Unpin>(&self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut index = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer).await.context("read chunk")?;
            if bytes_read == 0 {
                break;
            }

            let data = if bytes_read == self.chunk_size { std::mem::take(&mut buffer) } else { buffer[..bytes_read].to_vec() };

            sender.send_async(Task { data, index }).await.context("send chunk: channel closed")?;

            if buffer.is_empty() {
                buffer = vec![0u8; self.chunk_size];
            }

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
