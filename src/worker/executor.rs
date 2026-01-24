//! Concurrent task executor with thread pool management
//!
//! This module implements the core execution engine for processing cryptographic
//! tasks in parallel. The executor bridges between task production (reader) and
//! result consumption (writer) while maximizing CPU utilization and throughput.
//!
//! ## Architecture
//!
//! The executor uses Rayon's work-stealing thread pool combined with flume
//! channels to create an efficient producer-consumer system:
///
// 1. **Channel Bridge**: Converts sequential channel iterator into parallel work
// 2. **Thread Pool**: Rayon automatically manages worker threads based on CPU cores
// 3. **Pipeline Sharing**: Arc-wrapped pipeline enables shared read-only access
//
// ## Performance Optimization
///
/// - **Work Stealing**: Rayon's scheduler balances load across threads automatically
/// - **Zero-Copy**: Tasks and results are moved without unnecessary copying
/// - **Backpressure**: Bounded channels prevent memory exhaustion
/// - **Cache Efficiency**: Shared pipeline reduces memory footprint and improves cache locality
///
/// ## Concurrency Model
///
/// The executor operates as a single consumer from the task channel but parallelizes
/// the actual processing. This design provides:
/// - Scalable parallelism across CPU cores
/// - Automatic load balancing via Rayon's scheduler
/// - Minimal thread management overhead
/// - Excellent throughput for CPU-bound cryptographic operations
use std::sync::Arc;

use flume::{Receiver, Sender};
use rayon::iter::{ParallelBridge, ParallelIterator};

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

/// Concurrent task executor with shared processing pipeline
///
/// The Executor coordinates the parallel processing of cryptographic tasks.
/// It consumes tasks from a channel and distributes them across Rayon's
/// thread pool for maximum CPU utilization.
///
/// ## Thread Safety
///
/// The executor itself runs in a single thread but manages parallel
/// processing of individual tasks. The pipeline is wrapped in Arc to
/// enable safe sharing across multiple worker threads without the overhead
/// of cloning expensive cryptographic components.
///
/// ## Performance Characteristics
///
/// - **Throughput**: Scales linearly with available CPU cores for compute-bound work
/// - **Latency**: Minimal due to direct task forwarding to worker threads
/// - **Memory**: Pipeline is shared once across all threads, reducing overhead
/// - **Scalability**: Automatic adaptation to system resources via Rayon
pub struct Executor {
    /// Shared reference to the processing pipeline
    /// Arc enables thread-safe read-only sharing across worker threads
    /// The pipeline contains cryptographic components, compression, etc.
    pipeline: Arc<Pipeline>,
}

impl Executor {
    /// Creates a new Executor with the given processing pipeline
    ///
    /// # Arguments
    ///
    /// * `pipeline` - The processing pipeline containing cryptographic components
    ///
    /// # Returns
    ///
    /// A new Executor instance ready to process tasks
    ///
    /// # Performance Notes
    ///
    /// The pipeline is wrapped in Arc immediately to enable efficient sharing
    /// across all worker threads. This avoids the overhead of cloning expensive
    /// cryptographic components for each task.
    #[inline]
    pub fn new(pipeline: Pipeline) -> Self {
        Self { pipeline: Arc::new(pipeline) }
    }

    /// Processes tasks concurrently from receiver to sender
    ///
    /// This is the main execution loop that bridges the channel-based task
    /// distribution with Rayon's parallel processing capabilities.
    ///
    /// ## Execution Model
    ///
    /// 1. Convert sequential channel iterator to parallel iterator using `par_bridge()`
    /// 2. Each task is processed by an available worker thread in Rayon's pool
    /// 3. Results are sent back through the results channel
    /// 4. Work-stealing ensures optimal load balancing across threads
    ///
    /// ## Performance Characteristics
    ///
    /// - **Parallelism**: Automatically scales to available CPU cores
    /// - **Load Balancing**: Rayon's work-stealing scheduler distributes work optimally
    /// - **Memory Efficiency**: Tasks and results are moved without copying
    /// - **Backpressure Handling**: Channel operations provide natural backpressure
    ///
    /// # Arguments
    ///
    /// * `tasks` - Receiver for incoming tasks from the reader
    /// * `results` - Sender for outgoing results to the writer
    ///
    /// # Concurrency Notes
    ///
    /// This method runs until the task receiver is closed (when reader finishes).
    /// The `par_bridge()` adapter creates a parallel iterator that automatically
    /// manages work distribution across Rayon's thread pool. Each task is processed
    /// independently, making the system highly resilient to individual task failures.
    ///
    /// ## Error Handling
    ///
    /// Results channel send failures are ignored (`let _ = results.send(result)`)
    /// because they typically indicate that the writer has shut down, which is
    /// a normal shutdown condition. Individual task errors are captured in the
    /// TaskResult structure and propagated to the writer for proper handling.
    pub fn process(&self, tasks: &Receiver<Task>, results: &Sender<TaskResult>) {
        // Convert the sequential channel iterator into a parallel iterator
        // par_bridge() efficiently distributes work across Rayon's thread pool
        // This is the key to achieving high throughput for CPU-bound work
        tasks.iter().par_bridge().for_each(|task| {
            // Process the task using the shared pipeline
            // The Arc<Pipeline> enables safe read-only access across threads
            let result = self.pipeline.process(&task);

            // Send the result to the writer thread
            // Ignore send errors as they typically indicate normal shutdown
            // Individual task errors are captured in the TaskResult itself
            let _ = results.send(result);
        });
    }
}
