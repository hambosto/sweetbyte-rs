use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::{JoinHandle, JoinSet};

use crate::secret::SecretBytes;
use crate::types::{Processing, Task, TaskResult};
use crate::ui::progress::Progress;
use crate::worker::pipeline::Pipeline;
use crate::worker::reader::Reader;
use crate::worker::writer::Writer;

pub mod buffer;
pub mod pipeline;
pub mod reader;
pub mod writer;

pub struct Worker {
    pipeline: Arc<Pipeline>,
    mode: Processing,
}

impl Worker {
    pub fn new(key: &SecretBytes, mode: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode).context("Failed to initialise pipeline")?;
        Ok(Self { pipeline: Arc::new(pipeline), mode })
    }

    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let channel_size = if let Ok(cores) = std::thread::available_parallelism() { cores.get() } else { 4 };
        let progress_bar = Progress::new(total_size, self.mode.label()).context("Failed to initialise progress")?;

        let (task_tx, task_rx) = tokio::sync::mpsc::channel::<Task>(channel_size);
        let (result_tx, result_rx) = tokio::sync::mpsc::channel::<TaskResult>(channel_size);

        let reader_handle = tokio::spawn(async move { Reader::new(self.mode).read_all(input, &task_tx).await });
        let writer_handle = tokio::spawn(async move { Writer::new(self.mode).write_all(output, result_rx, &progress_bar).await });
        let executor_handle = self.spawn_executor(task_rx, result_tx, channel_size);

        let (writer_result, reader_result, executor_result) = tokio::join!(writer_handle, reader_handle, executor_handle);

        writer_result.context("Writer panicked")?.context("Writer failed")?;
        reader_result.context("Reader panicked")?.context("Reader failed")?;
        executor_result.context("Executor panicked")?.context("Executor failed")?;

        Ok(())
    }

    fn spawn_executor(&self, mut task_rx: Receiver<Task>, result_tx: Sender<TaskResult>, concurrency: usize) -> JoinHandle<Result<()>> {
        let pipeline = Arc::clone(&self.pipeline);
        let semaphore = Arc::new(Semaphore::new(concurrency));

        tokio::spawn(async move {
            let mut handles = JoinSet::new();

            while let Some(task) = task_rx.recv().await {
                let permit = Arc::clone(&semaphore).acquire_owned().await.context("Semaphore closed unexpectedly")?;
                let pipeline = Arc::clone(&pipeline);
                let result_tx = result_tx.clone();
                handles.spawn_blocking(move || {
                    let result = pipeline.process(&task);
                    let _ = result_tx.blocking_send(result);
                    drop(permit);
                });
            }

            while let Some(handle) = handles.join_next().await {
                handle.context("Executor task panicked")?;
            }

            Ok(())
        })
    }
}
