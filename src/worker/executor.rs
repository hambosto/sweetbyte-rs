//! Parallel task execution engine.
//!
//! This module bridges the async/await world of Tokio with the CPU-bound parallel processing
//! world of Rayon. It executes the [`Pipeline`] logic for each task in a thread pool.

use std::sync::Arc;

use flume::{Receiver, Sender};
use rayon::iter::{ParallelBridge, ParallelIterator};

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

/// Coordinates the parallel execution of tasks.
pub struct Executor {
    /// The processing pipeline (shared across threads).
    pipeline: Arc<Pipeline>,
}

impl Executor {
    /// Creates a new executor.
    #[inline]
    pub fn new(pipeline: Pipeline) -> Self {
        Self { pipeline: Arc::new(pipeline) }
    }

    /// Consumes tasks from the receiver, processes them in parallel, and sends results.
    ///
    /// This method blocks the calling thread but utilizes the Rayon thread pool for
    /// the actual work. It should typically be run in `tokio::task::spawn_blocking`.
    pub fn process(&self, tasks: &Receiver<Task>, results: &Sender<TaskResult>) {
        // Use par_bridge to turn the channel receiver iterator into a parallel iterator.
        // This automatically distributes work across Rayon's work-stealing pool.
        tasks.iter().par_bridge().for_each(|task| {
            // Process the task using the pipeline.
            let result = self.pipeline.process(&task);

            // Send the result to the writer.
            // We ignore send errors because they usually mean the receiver hung up
            // (e.g., application shutting down), so we just stop processing.
            let _ = results.send(result);
        });
    }
}

#[cfg(test)]
mod tests {
    use flume::unbounded;

    use super::*;
    use crate::config::{ARGON_KEY_LEN, CHUNK_SIZE};
    use crate::types::{Processing, Task};

    #[test]
    fn test_executor_process() {
        let key = [0u8; ARGON_KEY_LEN];

        let pipeline = Pipeline::new(&key, Processing::Encryption).unwrap();
        let executor = Executor::new(pipeline);

        let (task_tx, task_rx) = unbounded();
        let (res_tx, res_rx) = unbounded();

        // Send two tasks.
        let data = vec![0u8; CHUNK_SIZE];
        task_tx.send(Task { data: data.clone(), index: 0 }).unwrap();
        task_tx.send(Task { data: data.clone(), index: 1 }).unwrap();
        drop(task_tx); // Close input

        // Run executor.
        executor.process(&task_rx, &res_tx);
        drop(res_tx); // Close output

        // Verify results.
        let mut count = 0;
        for result in res_rx {
            assert!(result.error.is_none());
            // Size here is input size for progress bar tracking
            assert_eq!(result.size, CHUNK_SIZE);
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
