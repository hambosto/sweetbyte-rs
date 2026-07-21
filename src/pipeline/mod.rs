mod executor;
mod process;
mod reader;
mod types;
mod writer;

use anyhow::{Context, Result};
use executor::Executor;
use process::Process;
use reader::Reader;
use tokio::io::{AsyncRead, AsyncWrite};
pub(crate) use types::Processing;
use types::{Task, TaskResult};
use writer::Writer;

use crate::secret::Secret;
use crate::ui::Progress;

pub(crate) struct Pipeline {
    processing: Processing,
    process: Process,
}

impl Pipeline {
    pub(crate) fn new(primary_key: &Secret, secondary_key: &Secret, processing: Processing) -> Result<Self> {
        let process = Process::new(primary_key, secondary_key, processing).context("failed to initialize process")?;

        Ok(Self { processing, process })
    }

    pub(crate) async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let channel_size = std::thread::available_parallelism().map(std::num::NonZero::get).context("failed to get available parallelism")?;
        let progress_bar = Progress::new(total_size, self.processing.label());

        let (task_tx, task_rx) = tokio::sync::mpsc::channel::<Task>(channel_size);
        let (result_tx, result_rx) = tokio::sync::mpsc::channel::<TaskResult>(channel_size);

        let reader_handle = tokio::spawn(async move { Reader::new(self.processing).read_all(input, &task_tx).await });
        let writer_handle = tokio::spawn(async move { Writer::new(self.processing).write_all(output, result_rx, &progress_bar).await });
        let executor_handle = tokio::spawn(async move { Executor::new(self.process, channel_size).execute(task_rx, result_tx).await });

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
