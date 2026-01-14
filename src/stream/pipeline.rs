use anyhow::{Result, anyhow};
use crossbeam_channel::bounded;
use std::io::{Read, Write};
use std::thread;

use crate::config::{ARGON_KEY_LEN, CHUNK_SIZE};
use crate::stream::executor::ConcurrentExecutor;
use crate::stream::processor::DataProcessor;
use crate::stream::reader::ChunkReader;
use crate::stream::writer::ChunkWriter;
use crate::types::Processing;
use crate::ui::progress::Bar;

pub struct Pipeline {
    processor: DataProcessor,
    concurrency: usize,
    mode: Processing,
}

impl Pipeline {
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

    pub fn process<R: Read + Send + 'static, W: Write + Send + 'static>(
        self,
        input: R,
        output: W,
        total_size: u64,
    ) -> Result<()> {
        let progress = Bar::new(total_size, self.mode.description());

        let (task_sender, task_receiver) = bounded(self.concurrency * 2);
        let (result_sender, result_receiver) = bounded(self.concurrency * 2);

        let reader = ChunkReader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = ChunkWriter::new(self.mode);

        let reader_handle = thread::spawn(move || reader.read_all(input, task_sender));

        let executor = ConcurrentExecutor::new(self.processor, self.concurrency);
        let executor_handle = thread::spawn(move || {
            executor.process(task_receiver, result_sender);
        });

        let write_result = writer.write_all(output, result_receiver, Some(&progress));

        let read_result = reader_handle
            .join()
            .map_err(|_| anyhow!("reader thread panicked"))?;

        executor_handle
            .join()
            .map_err(|_| anyhow!("executor thread panicked"))?;

        progress.finish();

        read_result?;
        write_result?;

        Ok(())
    }
}
