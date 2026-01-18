use std::io::{BufReader, Read};

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::Sender;

use crate::types::{Processing, Task};

pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

pub struct Reader {
    mode: Processing,
    chunk_size: usize,
}

impl Reader {
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        if chunk_size < MIN_CHUNK_SIZE {
            bail!("chunk size must be at least {} bytes, got {}", MIN_CHUNK_SIZE, chunk_size);
        }

        Ok(Self { mode, chunk_size })
    }

    pub fn read_all<R: Read>(&self, input: R, sender: Sender<Task>) -> Result<()> {
        let mut reader = BufReader::new(input);

        match self.mode {
            Processing::Encryption => self.read_fixed_chunks(&mut reader, sender),
            Processing::Decryption => self.read_length_prefixed(&mut reader, sender),
        }
    }

    fn read_fixed_chunks<R: Read>(&self, reader: &mut R, sender: Sender<Task>) -> Result<()> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut index = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer).context("failed to read chunk")?;
            if bytes_read == 0 {
                break;
            }

            sender.send(Task { data: buffer[..bytes_read].to_vec(), index }).map_err(|_| anyhow!("channel closed"))?;

            index += 1;
        }

        Ok(())
    }

    fn read_length_prefixed<R: Read>(&self, reader: &mut R, sender: Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            let mut buffer_len = [0u8; 4];
            let read_result = reader.read_exact(&mut buffer_len);

            if read_result.is_err() {
                break;
            }

            let chunk_len = u32::from_be_bytes(buffer_len) as usize;
            if chunk_len == 0 {
                continue;
            }

            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).context("failed to read chunk data")?;

            sender.send(Task { data, index }).map_err(|_| anyhow!("channel closed"))?;

            index += 1;
        }

        Ok(())
    }
}
