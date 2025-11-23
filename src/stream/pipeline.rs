use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use super::reader::StreamReader;
use super::worker::ChunkWorker;
use super::writer::StreamWriter;
use crate::types::{Processing, Task};

use crate::stream::pool::BufferPool;
use crate::stream::reader::CHUNK_SIZE;

/// Buffer multiplier for pipeline depth
const BUFFER_MULTIPLIER: usize = 4;

/// High-performance stream processor using a concurrent pipeline architecture.
///
/// Uses Tokio for async I/O and task management.
#[derive(Clone)]
pub struct Pipeline {
    worker: Arc<ChunkWorker>,
    mode: Processing,
    concurrency: usize,
    pool: BufferPool,
}

impl Pipeline {
    /// Creates a new stream processor with the given key and processing mode.
    pub fn new(key: &[u8], mode: Processing) -> Result<Self> {
        let concurrency = num_cpus::get();
        // Pool capacity: enough for reader, writer, and in-flight chunks.
        // concurrency * BUFFER_MULTIPLIER is the channel size.
        // We probably want a bit more for the pool to avoid starvation.
        let pool_capacity = concurrency * BUFFER_MULTIPLIER * 3;
        let pool = BufferPool::new(pool_capacity, CHUNK_SIZE);

        Ok(Self {
            worker: Arc::new(ChunkWorker::new(key, mode, pool.clone())?),
            mode,
            concurrency,
            pool,
        })
    }

    /// Process data from reader to writer with optional progress callback.
    pub async fn process<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let chunk_reader = StreamReader::new(self.mode, self.pool.clone());

        // Channel for sending results to the writer
        let buffer_size = self.concurrency * BUFFER_MULTIPLIER;
        let (tx, mut rx) = mpsc::channel::<crate::types::TaskResult>(buffer_size);

        // Spawn Writer Task
        let mode = self.mode;
        let pool = self.pool.clone();
        let writer_handle = tokio::spawn(async move {
            let mut chunk_writer = StreamWriter::new(mode, pool);

            while let Some(result) = rx.recv().await {
                if let Some(err) = result.err {
                    return Err(err);
                }

                chunk_writer
                    .write_chunk(&mut writer, result.index, result.data)
                    .await?;

                if let Some(ref cb) = progress_callback {
                    cb(result.size as u64);
                }
            }

            chunk_writer.flush(&mut writer).await?;
            Ok::<_, anyhow::Error>(())
        });

        // Reader Loop & Worker Spawning
        let mut join_set = JoinSet::new();
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut index = 0u64;

        loop {
            // Acquire permit to limit concurrency
            // We use acquire_owned so we can move the permit into the task
            let permit = semaphore.clone().acquire_owned().await?;

            match chunk_reader.read_chunk(&mut reader, index).await? {
                Some(data) => {
                    let tx = tx.clone();
                    let worker = self.worker.clone();

                    join_set.spawn(async move {
                        // Permit is dropped when this task finishes
                        let _permit = permit;

                        // Run CPU-bound work in a blocking thread
                        let result = tokio::task::spawn_blocking(move || {
                            worker.process(Task { index, data })
                        })
                        .await?;

                        // Send result to writer
                        tx.send(result).await?;
                        Ok::<_, anyhow::Error>(())
                    });

                    index += 1;
                }
                _ => {
                    // EOF
                    break;
                }
            }
        }

        // Wait for all worker tasks to complete
        while let Some(res) = join_set.join_next().await {
            res??;
        }

        // Drop the original sender so the writer knows when to stop
        drop(tx);

        // Wait for writer to finish
        writer_handle.await??;

        Ok(())
    }
}
