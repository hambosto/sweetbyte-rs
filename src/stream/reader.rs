//! Chunk reader for streaming file processing.

use std::io::Read;

use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use crossbeam_channel::Sender;

use crate::config::CHUNK_SIZE;
use crate::types::{Processing, Task};

/// Minimum chunk size (256 KB).
pub const MIN_CHUNK_SIZE: usize = 256 * 1024;

/// Reads files in chunks for encryption or decryption.
pub struct ChunkReader {
    mode: Processing,
    chunk_size: usize,
}

impl ChunkReader {
    /// Creates a new chunk reader.
    ///
    /// # Arguments
    /// * `mode` - The processing mode
    /// * `chunk_size` - The chunk size in bytes
    pub fn new(mode: Processing, chunk_size: usize) -> Result<Self> {
        if chunk_size < MIN_CHUNK_SIZE {
            bail!(
                "chunk size must be at least {} bytes, got {}",
                MIN_CHUNK_SIZE,
                chunk_size
            );
        }

        Ok(Self { mode, chunk_size })
    }

    /// Reads all chunks from the input and sends them to the channel.
    ///
    /// # Arguments
    /// * `input` - The input reader
    /// * `sender` - The channel sender for tasks
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

            let task = Task {
                data: buffer[..n].to_vec(),
                index,
            };

            sender
                .send(task)
                .map_err(|_| anyhow::anyhow!("channel closed"))?;

            index += 1;
        }

        Ok(())
    }

    fn read_for_decryption<R: Read>(&self, mut reader: R, sender: Sender<Task>) -> Result<()> {
        let mut index = 0u64;

        loop {
            // Read chunk size prefix (4 bytes)
            let chunk_len = match reader.read_u32::<BigEndian>() {
                Ok(len) => len as usize,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).context("failed to read chunk length"),
            };

            if chunk_len == 0 {
                continue;
            }

            // Read chunk data
            let mut data = vec![0u8; chunk_len];
            reader
                .read_exact(&mut data)
                .context("failed to read chunk data")?;

            let task = Task { data, index };

            sender
                .send(task)
                .map_err(|_| anyhow::anyhow!("channel closed"))?;

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
