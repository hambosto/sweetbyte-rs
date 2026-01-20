use hashbrown::HashMap;

use crate::types::TaskResult;

/// In-order result buffer for parallel processing.
///
/// Holds results from parallel executors and returns them in sequential
/// order. Uses a HashMap to store out-of-order results by index, and
/// tracks the next expected index to return results in order.
pub struct Buffer {
    /// Stores results by their index for reordering.
    buffer: HashMap<u64, TaskResult>,
    /// The next index we expect to output.
    next_idx: u64,
}

impl Buffer {
    /// Creates a new Buffer starting at the given index.
    ///
    /// # Arguments
    /// * `start` - The starting index (usually 0).
    ///
    /// # Returns
    /// A new Buffer instance.
    #[inline]
    pub fn new(start: u64) -> Self {
        Self { buffer: HashMap::new(), next_idx: start }
    }

    /// Adds a result and returns any in-order results.
    ///
    /// Stores the result by index. If the result's index matches the
    /// next expected index, returns it along with any following results
    /// that are now in order.
    ///
    /// # Arguments
    /// * `result` - The result to add.
    ///
    /// # Returns
    /// A Vec of results that are now in order (can be written immediately).
    #[must_use]
    #[inline]
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        // Store the result by index.
        self.buffer.insert(result.index, result);

        // Collect results that are now in order.
        let mut ready: Vec<TaskResult> = Vec::new();
        // Keep returning results while they match the expected index.
        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1;
        }

        ready
    }

    /// Flushes all remaining buffered results.
    ///
    /// Returns all remaining results sorted by index. Used when the input
    /// channel is closed to output any straggling results.
    ///
    /// # Returns
    /// A Vec of all remaining results, sorted by index.
    #[must_use]
    #[inline]
    pub fn flush(&mut self) -> Vec<TaskResult> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        // Drain all results and sort by index.
        let mut results: Vec<(u64, TaskResult)> = self.buffer.drain().collect();
        results.sort_unstable_by_key(|(idx, _)| *idx);

        // Reset next index for potential reuse.
        self.next_idx = 0;
        // Return just the results, discarding the indices.
        results.into_iter().map(|(_, result)| result).collect()
    }
}
