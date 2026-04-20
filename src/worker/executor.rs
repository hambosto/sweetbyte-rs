use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

pub struct Executor {
    pipeline: Arc<Pipeline>,
    semaphore: Arc<Semaphore>,
    join_set: JoinSet<Result<()>>,
}

impl Executor {
    #[must_use]
    pub fn new(pipeline: Pipeline, concurrency: usize) -> Self {
        let pipeline = Arc::new(pipeline);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let join_set = JoinSet::new();

        Self { pipeline, semaphore, join_set }
    }

    pub async fn execute(mut self, mut task_rx: Receiver<Task>, result_tx: Sender<TaskResult>) -> Result<()> {
        while let Some(task) = task_rx.recv().await {
            let permit = self.semaphore.clone().acquire_owned().await.context("Semaphore closed unexpectedly")?;
            let pipeline = self.pipeline.clone();
            let result_tx = result_tx.clone();

            self.join_set.spawn_blocking(move || {
                let result = pipeline.process(&task);
                result_tx.blocking_send(result).context("Result channel closed before executor finished")?;

                drop(permit);

                Ok(())
            });
        }

        while let Some(join_result) = self.join_set.join_next().await {
            join_result?.context("Executor task panicked")?;
        }

        Ok(())
    }
}
