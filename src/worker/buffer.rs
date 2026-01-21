//! Result buffering for in-order output.
//!
//! Maintains a buffer of results and returns them in sequential order
//! as they become available. Handles out-of-order completion from
//! parallel processing.
//!
//! # How It Works
//!
//! 1. Results arrive out of order from parallel executor
//! 2. Each result is added to the buffer by index
//! 3. The buffer returns consecutive results starting from next_idx
//! 4. At end, remaining results are sorted and returned

use hashbrown::HashMap;

use crate::types::TaskResult;

/// Reorders out-of-sequence results into sequential order.
///
/// Used by the writer to ensure output is written in the same order
/// as input, despite parallel processing.
pub struct Buffer {
    /// Buffered results indexed by task index.
    buffer: HashMap<u64, TaskResult>,

    /// The next expected index in sequence.
    next_idx: u64,
}

impl Buffer {
    /// Creates a new buffer starting at the given index.
    ///
    /// # Arguments
    ///
    /// * `start` - The initial expected index.
    #[inline]
    pub fn new(start: u64) -> Self {
        Self { buffer: HashMap::new(), next_idx: start }
    }

    /// Adds a result and returns any consecutive results ready for output.
    ///
    /// This is the core ordering logic. Parallel processing may complete
    /// chunks out of order (e.g., chunk 5 before chunk 2). This method
    /// buffers out-of-order results and returns only consecutive results.
    ///
    /// Example flow:
    /// - Add result 0 → returns \[0\] (immediate, next_idx was 0)
    /// - Add result 2 → buffers \[2\], returns \[\]
    /// - Add result 1 → buffers \[1\], then returns \[1, 2\] (consecutive)
    /// - Add result 5 → buffers \[5\], returns \[\]
    ///
    /// # Arguments
    ///
    /// * `result` - The task result to add.
    ///
    /// # Returns
    ///
    /// A vector of consecutive results ready for output, or empty if not ready.
    #[must_use]
    #[inline]
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        // Store result in buffer keyed by index for later retrieval.
        // HashMap provides O(1) lookup when checking if next_idx is available.
        self.buffer.insert(result.index, result);

        // Collect consecutive results starting from next_idx.
        // This loop runs at most once per returned result, making it efficient.
        let mut ready: Vec<TaskResult> = Vec::new();

        // Keep removing results matching next_idx until gap is found.
        // This naturally handles multiple consecutive results in one pass.
        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1; // Advance expected index
        }

        ready
    }

    /// Flushes all remaining results, sorted by index.
    ///
    /// Called when no more results will arrive (channel closed).
    /// Sorts buffered results and returns them in order.
    ///
    /// # Returns
    ///
    /// All remaining results sorted by index.
    #[must_use]
    #[inline]
    pub fn flush(&mut self) -> Vec<TaskResult> {
        // Early exit if nothing buffered - avoids unnecessary work
        if self.buffer.is_empty() {
            return Vec::new();
        }

        // Drain all buffered results into a vector of (index, result) pairs.
        // collect() is efficient for HashMap -> Vec conversion.
        let mut results: Vec<(u64, TaskResult)> = self.buffer.drain().collect();

        // Sort by index using unstable sort (faster, sufficient since indices are unique).
        results.sort_unstable_by_key(|(idx, _)| *idx);

        // Reset next_idx to 0 for potential reuse (e.g., multiple files).
        self.next_idx = 0;

        // Extract just the results, discarding the indices (they're now sorted).
        results.into_iter().map(|(_, result)| result).collect()
    }
}
