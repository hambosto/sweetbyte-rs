use std::io::ErrorKind::UnexpectedEof;
use std::io::Read;

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::Sender;

use crate::config::CHUNK_SIZE;
use crate::types::{Processing, Task};

pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

pub struct ChunkReader {
    mode: Processing,
    chunk_size: usize,
}

impl ChunkReader {
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        if chunk_size < MIN_CHUNK_SIZE {
            bail!("chunk size must be at least {} bytes, got {}", MIN_CHUNK_SIZE, chunk_size);
        }

        Ok(Self { mode, chunk_size })
    }

    pub fn read_all<R: Read>(&self, input: R, sender: Sender<Task>) -> Result<()> {
        match self.mode {
            Processing::Encryption => self.read_for_encryption(input, sender),
            Processing::Decryption => self.read_for_decryption(input, sender),
        }
    }

    fn read_for_encryption<R: Read>(&self, mut reader: R, sender: Sender<Task>) -> Result<()> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut index = 0u64;

        loop {
            let n = reader.read(&mut buffer).context("failed to read chunk")?;
            if n == 0 {
                break;
            }

            let task = Task { data: buffer[..n].to_vec(), index };
            sender.send(task).map_err(|_| anyhow!("channel closed"))?;
            index += 1;
        }

        Ok(())
    }

    fn read_for_decryption<R: Read>(&self, mut reader: R, sender: Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == UnexpectedEof => break,
                Err(e) => return Err(e).context("failed to read chunk length"),
            }

            let chunk_len = u32::from_be_bytes(len_buf) as usize;

            if chunk_len == 0 {
                continue;
            }

            let mut data = vec![0u8; chunk_len];
            reader.read_exact(&mut data).context("failed to read chunk data")?;

            let task = Task { data, index };
            sender.send(task).map_err(|_| anyhow!("channel closed"))?;
            index += 1;
        }

        Ok(())
    }
}

impl Default for ChunkReader {
    fn default() -> Self {
        Self::new(Processing::Encryption, CHUNK_SIZE).expect("valid default parameters")
    }
}
