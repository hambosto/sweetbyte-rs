//! Concurrent executor for parallel task processing.

use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};

use crate::stream::processor::DataProcessor;
use crate::types::{Task, TaskResult};

/// Executes data processing tasks concurrently.
pub struct ConcurrentExecutor {
    processor: Arc<DataProcessor>,
    concurrency: usize,
}

impl ConcurrentExecutor {
    /// Creates a new concurrent executor.
    ///
    /// # Arguments
    /// * `processor` - The data processor
    /// * `concurrency` - Number of worker threads
    pub fn new(processor: DataProcessor, concurrency: usize) -> Self {
        Self {
            processor: Arc::new(processor),
            concurrency,
        }
    }

    /// Processes tasks from the receiver and sends results to the sender.
    ///
    /// Spawns worker threads that process tasks in parallel.
    pub fn process(&self, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        let mut handles = Vec::with_capacity(self.concurrency);

        for _ in 0..self.concurrency {
            let processor = Arc::clone(&self.processor);
            let tasks = tasks.clone();
            let results = results.clone();

            let handle = thread::spawn(move || {
                for task in tasks {
                    let result = processor.process(task);
                    if results.send(result).is_err() {
                        break;
                    }
                }
            });

            handles.push(handle);
        }

        // Drop our copy of the results sender so the receiver knows when all workers are done
        drop(results);

        // Wait for all workers to finish
        for handle in handles {
            let _ = handle.join();
        }
    }
}
