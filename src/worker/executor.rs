//! Parallel task execution using Rayon.
//!
//! Processes tasks in parallel using Rayon's work-stealing thread pool.
//! Tasks are distributed across available CPU cores for maximum throughput.
//!
//! # Thread Safety
//!
//! The pipeline is shared via Arc to allow safe concurrent access
//! by multiple worker threads.

use std::sync::Arc;

use flume::{Receiver, Sender};
use rayon::prelude::*;

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

/// Parallel task executor using Rayon.
///
/// Receives tasks from a channel, processes them in parallel using
/// Rayon's work-stealing thread pool, and sends results to the writer.
pub struct Executor {
    /// Shared reference to the processing pipeline (Arc for thread safety).
    pipeline: Arc<Pipeline>,
}

impl Executor {
    /// Creates a new executor with the given pipeline.
    ///
    /// The pipeline is wrapped in Arc for safe sharing across threads.
    ///
    /// # Arguments
    ///
    /// * `pipeline` - The processing pipeline to use.
    #[inline]
    pub fn new(pipeline: Pipeline) -> Self {
        Self { pipeline: Arc::new(pipeline) }
    }

    /// Processes all tasks from the channel in parallel.
    ///
    /// Uses `par_bridge()` to convert the sequential channel iterator
    /// into a parallel iterator processed by Rayon's work-stealing thread pool.
    ///
    /// How par_bridge works:
    /// 1. Channel iterator produces tasks sequentially (task 0, 1, 2, ...)
    /// 2. par_bridge distributes tasks across Rayon's thread pool
    /// 3. Each task is processed in parallel by available threads
    /// 4. Results are sent back to the writer as they complete
    ///
    /// # Arguments
    ///
    /// * `tasks` - Receiver channel for incoming tasks.
    /// * `results` - Sender channel for processed results.
    pub fn process(&self, tasks: &Receiver<Task>, results: Sender<TaskResult>) {
        // Convert sequential channel iterator to parallel iterator.
        // par_bridge() automatically load-balances work across threads.
        // It handles work-stealing to keep all CPU cores busy.
        tasks.iter().par_bridge().for_each(|task| {
            // Process task through the encryption/decryption pipeline.
            // Each task is independent, enabling true parallelism.
            let result = self.pipeline.process(&task);

            // Send result to writer for output.
            // Ignore send errors - the writer may have closed the channel
            // if an earlier task failed with a fatal error.
            let _ = results.send(result);
        });
    }
}
