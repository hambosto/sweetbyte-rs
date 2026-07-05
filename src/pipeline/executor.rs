use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

use super::process::Process;
use super::task::{Task, TaskResult};

pub(super) struct Executor {
    process: Arc<Process>,
    concurrency: usize,
}

impl Executor {
    pub(super) fn new(process: Process, concurrency: usize) -> Self {
        Self { process: Arc::new(process), concurrency }
    }

    pub(super) async fn execute(&self, mut tasks: Receiver<Task>, results: Sender<TaskResult>) -> Result<()> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut workers: JoinSet<Result<()>> = JoinSet::new();

        while let Some(task) = tasks.recv().await {
            let permit = Arc::clone(&semaphore).acquire_owned().await.context("failed to acquire semaphore permit")?;
            let process = Arc::clone(&self.process);
            let results = results.clone();

            workers.spawn_blocking(move || {
                let result = process.process(&task).context("failed to process task")?;
                results.blocking_send(result).context("failed to send result")?;

                drop(permit);
                Ok(())
            });
        }

        while let Some(join_result) = workers.join_next().await {
            join_result?.context("executor panicked")?;
        }

        Ok(())
    }
}
