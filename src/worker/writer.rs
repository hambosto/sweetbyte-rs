//! Asynchronous file writing and sequential reordering.
//!
//! This module handles writing processed data to the output file. Crucially, it reassembles
//! the out-of-order results from the parallel executor into a strictly sequential stream
//! to ensure file integrity.

use anyhow::{Context, Result, bail};
use flume::Receiver;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};

use crate::types::{Processing, TaskResult};
use crate::ui::progress::ProgressBar;
use crate::worker::buffer::Buffer;

/// Handles buffering and writing of processed tasks.
pub struct Writer {
    /// The processing mode (determines output format).
    mode: Processing,

    /// Reordering buffer to restore sequence.
    buffer: Buffer,
}

impl Writer {
    /// Creates a new writer.
    #[inline]
    pub fn new(mode: Processing) -> Self {
        // Start expecting chunk index 0.
        Self { mode, buffer: Buffer::new(0) }
    }

    /// Consumes results from the receiver and writes them to the output.
    pub async fn write_all<W: AsyncWrite + Unpin>(&mut self, output: W, receiver: Receiver<TaskResult>, progress: Option<&ProgressBar>) -> Result<()> {
        let mut writer = BufWriter::new(output);

        // Process results as they arrive.
        while let Ok(result) = receiver.recv_async().await {
            // Add to buffer and get back any contiguous sequence starting from next_idx.
            let ready = self.buffer.add(result);

            // Write the ready chunks.
            self.write_batch(&mut writer, &ready, progress).await?;
        }

        // Channel closed: flush any remaining items in the buffer.
        let remaining = self.buffer.flush();
        self.write_batch(&mut writer, &remaining, progress).await?;

        // Ensure all data hits the disk.
        writer.flush().await.context("failed to flush output")
    }

    /// Writes a batch of sequential task results to the stream.
    async fn write_batch<W: AsyncWrite + Unpin>(&self, writer: &mut W, results: &[TaskResult], progress: Option<&ProgressBar>) -> Result<()> {
        for r in results {
            // Check for processing errors in the task.
            if let Some(err) = &r.error {
                bail!("task {} failed: {}", r.index, err);
            }

            // If Encrypting, write the length prefix (4 bytes BE).
            // This allows the decryptor to know exactly how many bytes to read for this chunk.
            if matches!(self.mode, Processing::Encryption) {
                writer.write_all(&(r.data.len() as u32).to_be_bytes()).await.context("failed to write chunk size")?;
            }

            // Write the actual data.
            writer.write_all(&r.data).await.context("failed to write chunk data")?;

            // Update progress bar (using original input size for accurate % completion).
            if let Some(bar) = progress {
                bar.add(r.size as u64);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use flume::unbounded;

    use super::*;

    #[tokio::test]
    async fn test_write_decryption_mode() {
        let mut writer = Writer::new(Processing::Decryption);
        let mut output = Vec::new();
        let (tx, rx) = unbounded();

        // Send two valid chunks.
        tx.send(TaskResult::ok(0, b"hello".to_vec(), 5)).unwrap();
        tx.send(TaskResult::ok(1, b"world".to_vec(), 5)).unwrap();
        drop(tx);

        writer.write_all(&mut output, rx, None).await.unwrap();

        // Decryption mode writes raw bytes without length prefix.
        assert_eq!(output, b"helloworld");
    }

    #[tokio::test]
    async fn test_write_encryption_mode() {
        let mut writer = Writer::new(Processing::Encryption);
        let mut output = Vec::new();
        let (tx, rx) = unbounded();

        // Send one chunk.
        tx.send(TaskResult::ok(0, b"data".to_vec(), 4)).unwrap();
        drop(tx);

        writer.write_all(&mut output, rx, None).await.unwrap();

        // Encryption mode writes [Length: u32][Data].
        assert_eq!(output.len(), 4 + 4);
        assert_eq!(&output[0..4], &4u32.to_be_bytes());
        assert_eq!(&output[4..], b"data");
    }

    #[tokio::test]
    async fn test_write_reordering() {
        let mut writer = Writer::new(Processing::Decryption);
        let mut output = Vec::new();
        let (tx, rx) = unbounded();

        // Send out of order: #1 then #0.
        tx.send(TaskResult::ok(1, b"world".to_vec(), 5)).unwrap();
        tx.send(TaskResult::ok(0, b"hello".to_vec(), 5)).unwrap();
        drop(tx);

        writer.write_all(&mut output, rx, None).await.unwrap();

        // Output should be correct: "helloworld".
        assert_eq!(output, b"helloworld");
    }
}
