use std::io::{BufReader, ErrorKind, Read};

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
            let bytes_read = read_chunk(reader, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let task = Task { data: buffer[..bytes_read].to_vec(), index };
            sender.send(task).map_err(|_| anyhow!("channel closed"))?;

            index += 1;
        }

        Ok(())
    }

    fn read_length_prefixed<R: Read>(&self, reader: &mut R, sender: Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            let chunk_len = match read_u32(reader) {
                Ok(len) => len as usize,
                Err(e) if is_eof(&e) => break,
                Err(e) => return Err(e).context("failed to read chunk length"),
            };

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

#[inline]
fn read_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    reader.read(buffer).context("failed to read chunk")
}

#[inline]
fn read_u32<R: Read>(reader: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

#[inline]
fn is_eof(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == ErrorKind::UnexpectedEof)
}
