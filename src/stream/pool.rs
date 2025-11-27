use crossbeam_channel::{Receiver, Sender, bounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::types::{Task, TaskResult};

use super::worker::ChunkWorker;

/// Pool of worker threads for parallel chunk processing.
///
/// Spawns a fixed number of worker threads that process tasks concurrently.
/// Matches Go's WorkerPool architecture with goroutine-based workers.
pub struct WorkerPool {
    processor: Arc<ChunkWorker>,
    concurrency: usize,
}

impl WorkerPool {
    /// Creates a new worker pool.
    ///
    /// # Arguments
    ///
    /// * `processor` - The task processor to use for each task
    /// * `concurrency` - Number of worker threads to spawn
    pub fn new(processor: ChunkWorker, concurrency: usize) -> Self {
        Self {
            processor: Arc::new(processor),
            concurrency,
        }
    }

    /// Processes tasks from the input channel using worker threads.
    ///
    /// Spawns `concurrency` worker threads that:
    /// 1. Receive tasks from the tasks channel
    /// 2. Process each task using the ChunkWorker
    /// 3. Send results to the results channel
    /// 4. Exit when tasks channel is closed or cancellation is requested
    ///
    /// Returns a receiver for task results.
    pub fn process(&self, tasks: Receiver<Task>, cancel: Arc<AtomicBool>) -> Receiver<TaskResult> {
        let (results_tx, results_rx) = bounded(self.concurrency);

        // Spawn worker threads
        for _ in 0..self.concurrency {
            let tasks = tasks.clone();
            let results = results_tx.clone();
            let processor = Arc::clone(&self.processor);
            let cancel = Arc::clone(&cancel);

            thread::spawn(move || {
                Self::worker(processor, tasks, results, cancel);
            });
        }

        // Drop the original sender so channel closes when all workers are done
        drop(results_tx);

        results_rx
    }

    /// Worker thread function.
    ///
    /// Continuously processes tasks until the channel is closed or cancellation is requested.
    #[inline]
    fn worker(
        processor: Arc<ChunkWorker>,
        tasks: Receiver<Task>,
        results: Sender<TaskResult>,
        cancel: Arc<AtomicBool>,
    ) {
        while !cancel.load(Ordering::SeqCst) {
            // Receive next task
            let task = match tasks.recv() {
                Ok(task) => task,
                Err(_) => return, // Channel closed, exit
            };

            // Process the task
            let result = processor.process(task);

            // Send result (exit if channel closed)
            if results.send(result).is_err() {
                return;
            }
        }
    }
}
