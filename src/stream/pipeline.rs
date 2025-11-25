use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use super::reader::StreamReader;
use super::worker::ChunkWorker;
use super::writer::StreamWriter;
use crate::types::{Processing, Task};

use crate::stream::pool::BufferPool;
use crate::stream::reader::CHUNK_SIZE;

const BUFFER_MULTIPLIER: usize = 2;
const MIN_BUFFER_SIZE: usize = 8;
const POOL_CAPACITY_MULTIPLIER: usize = 3;

/// High-performance stream processor using concurrent pipeline architecture.
///
/// Orchestrates parallel processing through three stages:
/// - **Reader**: Reads chunks asynchronously
/// - **Worker**: Processes chunks in parallel (CPU-bound)
/// - **Writer**: Writes chunks in order
///
/// # Concurrency Model
/// Uses a semaphore to limit active chunks, preventing memory exhaustion.
/// Data flow: `Reader → [Channel] → Worker (CPU) → [Channel] → Writer`
pub struct Pipeline {
    worker: Arc<ChunkWorker>,
    mode: Processing,
    concurrency: usize,
    pool: BufferPool,
}

impl Pipeline {
    /// Creates a new pipeline with the given key and mode.
    pub fn new(key: &[u8], mode: Processing) -> Result<Self> {
        let concurrency = num_cpus::get();
        let pool_capacity = Self::calculate_pool_capacity(concurrency);
        let pool = BufferPool::new(pool_capacity, CHUNK_SIZE);

        Ok(Self {
            worker: Arc::new(ChunkWorker::new(key, mode, pool.clone())?),
            mode,
            concurrency,
            pool,
        })
    }

    /// Processes data from reader to writer with progress tracking.
    pub async fn process<R, W>(&self, mut reader: R, writer: W, total_size: u64) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let progress_bar = crate::tui::Bar::new(total_size, self.mode);
        let chunk_reader = StreamReader::new(self.mode, self.pool.clone());

        let buffer_size = (self.concurrency * BUFFER_MULTIPLIER).max(MIN_BUFFER_SIZE);
        let (result_sender, result_receiver) = mpsc::channel(buffer_size);

        let writer_handle = self.spawn_writer_task(writer, result_receiver, progress_bar.clone());

        self.process_chunks(&mut reader, chunk_reader, result_sender)
            .await?;

        writer_handle.await??;
        progress_bar.finish();

        Ok(())
    }

    fn spawn_writer_task<W>(
        &self,
        mut writer: W,
        mut result_receiver: mpsc::Receiver<crate::types::TaskResult>,
        progress_bar: crate::tui::Bar,
    ) -> tokio::task::JoinHandle<Result<()>>
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let mode = self.mode;
        let pool = self.pool.clone();

        tokio::spawn(async move {
            let mut chunk_writer = StreamWriter::new(mode, pool);

            while let Some(result) = result_receiver.recv().await {
                if let Some(err) = result.err {
                    return Err(err);
                }

                chunk_writer
                    .write_chunk(&mut writer, result.index, result.data)
                    .await?;

                progress_bar.add(result.size as u64);
            }

            chunk_writer.flush(&mut writer).await?;
            Ok(())
        })
    }

    async fn process_chunks<R>(
        &self,
        reader: &mut R,
        chunk_reader: StreamReader,
        result_sender: mpsc::Sender<crate::types::TaskResult>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
    {
        let mut join_set = JoinSet::new();
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut index = 0u64;

        loop {
            let permit = semaphore.clone().acquire_owned().await?;

            match chunk_reader.read_chunk(reader, index).await? {
                Some(data) => {
                    self.spawn_worker_task(
                        &mut join_set,
                        result_sender.clone(),
                        permit,
                        index,
                        data,
                    );
                    index += 1;
                }
                None => break,
            }
        }

        self.await_all_tasks(&mut join_set).await?;
        drop(result_sender);

        Ok(())
    }

    fn spawn_worker_task(
        &self,
        join_set: &mut JoinSet<Result<()>>,
        result_sender: mpsc::Sender<crate::types::TaskResult>,
        permit: tokio::sync::OwnedSemaphorePermit,
        index: u64,
        data: Vec<u8>,
    ) {
        let worker = Arc::clone(&self.worker);

        join_set.spawn(async move {
            let _permit = permit;

            let result =
                tokio::task::spawn_blocking(move || worker.process(Task { index, data })).await?;

            result_sender.send(result).await?;
            Ok(())
        });
    }

    async fn await_all_tasks(&self, join_set: &mut JoinSet<Result<()>>) -> Result<()> {
        while let Some(res) = join_set.join_next().await {
            res??;
        }
        Ok(())
    }

    fn calculate_pool_capacity(concurrency: usize) -> usize {
        concurrency * BUFFER_MULTIPLIER * POOL_CAPACITY_MULTIPLIER
    }
}
