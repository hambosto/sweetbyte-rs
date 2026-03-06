use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::CHUNK_SIZE;
use crate::secret::SecretBytes;
use crate::types::Processing;
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
        let pipeline = Pipeline::new(key, mode)?;
        Ok(Self { pipeline: Arc::new(pipeline), mode })
    }

    pub async fn process<R, W>(self, input: R, output: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        let progress = Progress::new(total_size, self.mode.label())?;
        let channel_size = if let Ok(cores) = std::thread::available_parallelism() { cores.get() } else { 4 };

        let (task_tx, mut task_rx) = tokio::sync::mpsc::channel(channel_size);
        let (result_tx, result_rx) = tokio::sync::mpsc::channel(channel_size);

        let reader = Reader::new(self.mode, CHUNK_SIZE)?;
        let reader_handle = tokio::spawn(async move { reader.read_all(input, &task_tx).await });

        let pipeline = self.pipeline;
        let executor_handle = tokio::spawn(async move {
            while let Some(task) = task_rx.recv().await {
                let result = pipeline.process(&task);
                if let Err(e) = result_tx.send(result).await {
                    tracing::error!("Failed to send result to writer: {}", e);
                }
            }
        });

        let mut writer = Writer::new(self.mode);
        let write_result = writer.write_all(output, result_rx, Some(&progress)).await.context("Failed to write output");

        reader_handle.await?.context("Reader thread panicked unexpectedly")?;
        executor_handle.await.context("Processing thread panicked unexpectedly")?;
        progress.finish();

        write_result?;

        Ok(())
    }
}
