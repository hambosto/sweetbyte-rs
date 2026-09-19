mod executor;
mod process;
mod reader;
mod writer;

use anyhow::{Context, Result};
use executor::Executor;
use process::Process;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

use crate::core::{Operation, Secret, Task, TaskResult};
use crate::ui::Progress;

pub(crate) struct Pipeline {
    operation: Operation,
    process: Process,
}

impl Pipeline {
    pub(crate) fn new(primary_key: &Secret, secondary_key: &Secret, operation: Operation) -> Result<Self> {
        let process = Process::new(primary_key, secondary_key, operation).context("failed to initialize chunk processor")?;

        Ok(Self { operation, process })
    }

    pub(crate) async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let parallelism = std::thread::available_parallelism().context("failed to get available parallelism")?;
        let progress_bar = Progress::new(total_size, self.operation.label());

        let (task_tx, task_rx) = tokio::sync::mpsc::channel::<Task>(parallelism.get());
        let (result_tx, result_rx) = tokio::sync::mpsc::channel::<TaskResult>(parallelism.get());

        let mut stages: JoinSet<Result<()>> = JoinSet::new();
        stages.spawn(async move { reader::read_all(self.operation, input, task_tx).await.context("reader failed") });
        stages.spawn(async move { Executor::new(self.process, parallelism.get()).execute(task_rx, result_tx).await.context("executor failed") });
        stages.spawn(async move { writer::write_all(self.operation, output, result_rx, &progress_bar).await.context("writer failed") });

        while let Some(joined) = stages.join_next().await {
            let stage = joined.context("pipeline stage panicked")?;
            stage.context("pipeline stage failed")?;
        }

        Ok(())
    }
}
