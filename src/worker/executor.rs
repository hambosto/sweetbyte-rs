use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

pub struct Executor {
    pipeline: Arc<Pipeline>,
    concurrency: usize,
}

impl Executor {
    pub fn new(pipeline: Pipeline, concurrency: usize) -> Self {
        Self { pipeline: Arc::new(pipeline), concurrency }
    }

    pub async fn execute(self, mut tasks: Receiver<Task>, results: Sender<TaskResult>) -> Result<()> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut workers: JoinSet<Result<()>> = JoinSet::new();

        while let Some(task) = tasks.recv().await {
            let permit = semaphore.clone().acquire_owned().await.context("failed to acquire limiter")?;
            let pipeline = self.pipeline.clone();
            let results = results.clone();

            workers.spawn_blocking(move || {
                let result = pipeline.process(&task)?;
                results.blocking_send(result).context("failed to send result")?;

                drop(permit);
                Ok(())
            });
        }

        while let Some(join_result) = workers.join_next().await {
            join_result?.context("executor task panicked")?;
        }

        Ok(())
    }
}
