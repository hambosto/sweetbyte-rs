use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

/// Parallel task executor.
///
/// Spawns multiple worker threads that process tasks from a channel
/// and send results to an output channel. Uses Arc<Pipeline> for
/// thread-safe shared access to the processing pipeline.
pub struct Executor {
    /// Thread-safe reference to the processing pipeline.
    pipeline: Arc<Pipeline>,
    /// Number of worker threads.
    concurrency: usize,
}

impl Executor {
    /// Creates a new Executor with the given pipeline and concurrency.
    ///
    /// # Arguments
    /// * `pipeline` - The processing pipeline to use.
    /// * `concurrency` - Number of worker threads to spawn.
    ///
    /// # Returns
    /// A new Executor instance.
    #[inline]
    pub fn new(pipeline: Pipeline, concurrency: usize) -> Self {
        Self { pipeline: Arc::new(pipeline), concurrency }
    }

    /// Processes tasks from the input channel using multiple threads.
    ///
    /// Each worker thread receives tasks from the shared receiver,
    /// processes them through the pipeline, and sends results to the
    /// sender. The function returns when all workers complete (which
    /// happens when the task channel is closed).
    ///
    /// # Arguments
    /// * `tasks` - Receiver for tasks to process.
    /// * `results` - Sender for sending results.
    pub fn process(&self, tasks: &Receiver<Task>, results: Sender<TaskResult>) {
        thread::scope(|scope| {
            // Spawn worker threads.
            for _ in 0..self.concurrency {
                // Clone Arc<Pipeline> for each worker.
                let pipeline = Arc::clone(&self.pipeline);
                // Clone channel handles for each worker.
                let tasks = tasks.clone();
                let results = results.clone();

                scope.spawn(move || {
                    // Process tasks until channel is closed.
                    for task in tasks {
                        let result = pipeline.process(&task);
                        // Stop if result channel is closed.
                        if results.send(result).is_err() {
                            break;
                        }
                    }
                });
            }
            // Drop sender to signal completion when all workers finish.
            drop(results);
        });
    }
}
