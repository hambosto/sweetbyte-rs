use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::secret::SecretBytes;
use crate::types::{Processing, Task, TaskResult};
use crate::ui::Progress;
use crate::worker::executor::Executor;
use crate::worker::pipeline::Pipeline;
use crate::worker::reader::Reader;
use crate::worker::writer::Writer;

mod buffer;
mod executor;
mod pipeline;
mod reader;
mod writer;

pub struct Worker {
    processing: Processing,
    pipeline: Pipeline,
}

impl Worker {
    pub fn new(key: &SecretBytes, processing: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, processing).context("failed to initialize pipeline")?;

        Ok(Self { processing, pipeline })
    }

    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let channel_size = std::thread::available_parallelism().map(|p| p.get()).context("failed to get available parallelism")?;
        let progress_bar = Progress::new(total_size, self.processing.label());

        let (task_tx, task_rx) = tokio::sync::mpsc::channel::<Task>(channel_size);
        let (result_tx, result_rx) = tokio::sync::mpsc::channel::<TaskResult>(channel_size);

        let reader_handle = tokio::spawn(async move { Reader::new(self.processing).read_all(input, &task_tx).await });
        let writer_handle = tokio::spawn(async move { Writer::new(self.processing).write_all(output, result_rx, &progress_bar).await });
        let executor_handle = tokio::spawn(async move { Executor::new(self.pipeline, channel_size).execute(task_rx, result_tx).await });

        let (reader_result, executor_result, writer_result) = tokio::join!(reader_handle, executor_handle, writer_handle);

        let reader_inner = reader_result.context("reader panicked")?;
        reader_inner.context("failed to read")?;

        let executor_inner = executor_result.context("executor panicked")?;
        executor_inner.context("failed to execute")?;

        let writer_inner = writer_result.context("writer panicked")?;
        writer_inner.context("failed to write")?;

        Ok(())
    }
}
