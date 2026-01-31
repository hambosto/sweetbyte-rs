use anyhow::{Context, Result};
use flume::bounded;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{ARGON_KEY_LEN, CHUNK_SIZE};
use crate::types::Processing;
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
    pipeline: Pipeline,
    mode: Processing,
}

impl Worker {
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let pipeline = Pipeline::new(key, mode)?;
        Ok(Self { pipeline, mode })
    }

    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        let progress = Progress::new(total_size, self.mode.label())?;

        let concurrency = std::thread::available_parallelism().map(|p| p.get()).unwrap_or(4);
        let channel_size = concurrency * 2;

        let (task_sender, task_receiver) = bounded(channel_size);
        let (result_sender, result_receiver) = bounded(channel_size);

        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let mut writer = Writer::new(self.mode);

        let reader_handle = tokio::spawn(async move { reader.read_all(input, &task_sender).await });

        let executor = Executor::new(self.pipeline);
        let executor_handle = tokio::task::spawn_blocking(move || {
            executor.process(&task_receiver, &result_sender);
        });

        let write_result = writer.write_all(output, result_receiver, Some(&progress)).await;

        let read_result = reader_handle.await.context("reader task")?;
        executor_handle.await.context("executor task")?;

        progress.finish();

        read_result.context("read")?;
        write_result.context("write")?;

        Ok(())
    }
}
