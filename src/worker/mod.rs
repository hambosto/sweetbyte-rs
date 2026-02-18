use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::CHUNK_SIZE;
use crate::secret::SecretBytes;
use crate::types::Processing;
use crate::ui::Progress;
use crate::worker::executor::Executor;
use crate::worker::pipeline::Pipeline;
use crate::worker::reader::Reader;
use crate::worker::writer::Writer;

pub mod buffer;
pub mod executor;
pub mod pipeline;
pub mod reader;
pub mod writer;

pub struct Worker {
    pipeline: Pipeline,
    mode: Processing,
}

impl Worker {
    pub fn new(key: &SecretBytes, mode: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode)?;
        Ok(Self { pipeline, mode })
    }

    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        let progress = Progress::new(total_size, self.mode.label())?;
        let channel_size = if let Ok(cores) = std::thread::available_parallelism() { cores.get() } else { 4 };

        let (task_tx, task_rx) = flume::bounded(channel_size);
        let (result_tx, result_rx) = flume::bounded(channel_size);

        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let reader_handle = tokio::spawn(async move { reader.read_all(input, &task_tx).await });

        let executor = Executor::new(Arc::new(self.pipeline));
        let executor_handle = tokio::task::spawn_blocking(move || executor.process(&task_rx, &result_tx));

        let mut writer = Writer::new(self.mode);
        let write_result = writer.write_all(output, result_rx, Some(&progress)).await.context("write failed");

        reader_handle.await.context("reader panicked")??;
        executor_handle.await.context("executor panicked")?;
        progress.finish();

        write_result?;

        Ok(())
    }
}
