use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::config::{CHUNK_SIZE, MAX_CHUNK_SIZE};
use crate::core::{Operation, Task};

pub(super) struct Reader {
    index: u64,
    operation: Operation,
}

impl Reader {
    pub(super) fn new(operation: Operation) -> Self {
        Self { index: 0, operation }
    }

    pub(super) async fn read_all<R: AsyncRead + Unpin>(&mut self, input: R, sender: &Sender<Task>) -> Result<()> {
        self.index = 0;
        let mut reader = BufReader::new(input);

        match self.operation {
            Operation::Encryption => self.read_fixed_chunks(&mut reader, sender).await,
            Operation::Decryption => self.read_length_prefixed(&mut reader, sender).await,
        }
    }

    async fn read_fixed_chunks<R: AsyncRead + Unpin>(&mut self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        loop {
            let mut data = vec![0u8; CHUNK_SIZE];
            let bytes_read = reader.read(&mut data).await.context("failed to read chunk")?;

            if bytes_read == 0 {
                break;
            }

            data.truncate(bytes_read);
            sender.send(Task { data, index: self.index }).await.context("failed to send chunk")?;
            self.index = self.index.checked_add(1).context("chunk index overflowed u64")?;
        }

        Ok(())
    }

    async fn read_length_prefixed<R: AsyncRead + Unpin>(&mut self, reader: &mut R, sender: &Sender<Task>) -> Result<()> {
        loop {
            let chunk_len = match reader.read_u32_le().await {
                Ok(len) => len,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).context("failed to read chunk length"),
            };

            if chunk_len > MAX_CHUNK_SIZE {
                anyhow::bail!("chunk size {chunk_len} exceeds maximum {MAX_CHUNK_SIZE}");
            }

            let mut data = vec![0u8; chunk_len as usize];
            reader.read_exact(&mut data).await.context("failed to read chunk")?;

            sender.send(Task { data, index: self.index }).await.context("failed to send chunk")?;
            self.index = self.index.checked_add(1).context("chunk index overflowed u64")?;
        }

        Ok(())
    }
}
