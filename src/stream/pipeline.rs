//! Processing pipeline for streaming encryption/decryption.

use std::io::{Read, Write};
use std::thread;

use anyhow::Result;
use crossbeam_channel::bounded;

use crate::config::{ARGON_KEY_LEN, CHUNK_SIZE};
use crate::stream::executor::ConcurrentExecutor;
use crate::stream::processor::DataProcessor;
use crate::stream::reader::ChunkReader;
use crate::stream::writer::ChunkWriter;
use crate::types::Processing;
use crate::ui::progress::ProgressBar;

/// Processing pipeline for file encryption/decryption.
pub struct Pipeline {
    processor: DataProcessor,
    concurrency: usize,
    mode: Processing,
}

impl Pipeline {
    /// Creates a new processing pipeline.
    ///
    /// # Arguments
    /// * `key` - The 64-byte derived key
    /// * `mode` - The processing mode
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let processor = DataProcessor::new(key, mode)?;
        let concurrency = thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);

        Ok(Self {
            processor,
            concurrency,
            mode,
        })
    }

    /// Processes the input and writes to output.
    ///
    /// # Arguments
    /// * `input` - The input reader
    /// * `output` - The output writer
    /// * `total_size` - Total input size for progress tracking
    pub fn process<R: Read + Send + 'static, W: Write + Send + 'static>(
        self,
        input: R,
        output: W,
        total_size: u64,
    ) -> Result<()> {
        let progress = ProgressBar::new(total_size, self.mode.description());

        let (task_sender, task_receiver) = bounded(self.concurrency * 2);
        let (result_sender, result_receiver) = bounded(self.concurrency * 2);

        let reader = ChunkReader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = ChunkWriter::new(self.mode);

        // Spawn reader thread
        let reader_handle = thread::spawn(move || reader.read_all(input, task_sender));

        // Spawn executor (spawns worker threads internally)
        let executor = ConcurrentExecutor::new(self.processor, self.concurrency);
        let executor_handle = thread::spawn(move || {
            executor.process(task_receiver, result_sender);
        });

        // Write results in main thread
        let write_result = writer.write_all(output, result_receiver, Some(&progress));

        // Wait for reader
        let read_result = reader_handle
            .join()
            .map_err(|_| anyhow::anyhow!("reader thread panicked"))?;

        // Wait for executor
        executor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("executor thread panicked"))?;

        progress.finish();

        // Return first error if any
        read_result?;
        write_result?;

        Ok(())
    }
}
