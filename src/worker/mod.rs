use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::secret::SecretBytes;
use crate::types::{ProcessorMode, Task, TaskResult};
use crate::ui::progress::Progress;
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
    mode: ProcessorMode,
    pipeline: Pipeline,
}

impl Worker {
    pub fn new(key: &SecretBytes, mode: ProcessorMode) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode).context("failed to init pipeline")?;

        Ok(Self { mode, pipeline })
    }

    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let channel_size = std::thread::available_parallelism().map(|p| p.get())?;
        let progress_bar = Progress::new(total_size, self.mode.label()).context("failed to init progress")?;

        let (task_tx, task_rx) = tokio::sync::mpsc::channel::<Task>(channel_size);
        let (result_tx, result_rx) = tokio::sync::mpsc::channel::<TaskResult>(channel_size);

        let reader_handle = tokio::spawn(async move { Reader::new(self.mode).read_all(input, &task_tx).await });
        let writer_handle = tokio::spawn(async move { Writer::new(self.mode).write_all(output, result_rx, &progress_bar).await });
        let executor_handle = tokio::spawn(async move { Executor::new(self.pipeline, channel_size).execute(task_rx, result_tx).await });

        let (reader_result, executor_result, writer_result) = tokio::join!(reader_handle, executor_handle, writer_handle);

        reader_result.context("reader task panicked")?.context("failed to execute reader")?;
        executor_result.context("executor task panicked")?.context("failed to execute executor")?;
        writer_result.context("writer task panicked")?.context("failed to execute writer")?;

        Ok(())
    }
}
