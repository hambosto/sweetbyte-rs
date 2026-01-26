//! Reordering buffer for concurrent tasks.
//!
//! This module provides a `Buffer` struct that reorders out-of-sequence results
//! from the concurrent executor into a strictly sequential stream for the writer.
//!
//! # Mechanism
//!
//! Since parallel worker threads finish tasks non-deterministically, chunk #2 might
//! finish before chunk #1. The writer, however, must write to the file in order.
//! The buffer holds "future" chunks (like #2) until the "next expected" chunk (#1)
//! arrives, at which point it releases them in sequence.

use hashbrown::HashMap;

use crate::types::TaskResult;

/// A buffer that holds completed tasks and releases them in sequential order.
pub struct Buffer {
    /// Storage for out-of-order results, keyed by their chunk index.
    buffer: HashMap<u64, TaskResult>,

    /// The index of the next chunk expected to be written.
    next_idx: u64,
}

impl Buffer {
    /// Creates a new reordering buffer starting at the given index.
    #[inline]
    pub fn new(start: u64) -> Self {
        Self { buffer: HashMap::new(), next_idx: start }
    }

    /// Adds a result to the buffer and returns any contiguous sequence of available results.
    ///
    /// # Arguments
    ///
    /// * `result` - The completed task result from the executor.
    ///
    /// # Returns
    ///
    /// A vector of `TaskResult`s that are now ready to be written (in order).
    #[must_use]
    #[inline]
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        // Store the incoming result.
        self.buffer.insert(result.index, result);

        let mut ready: Vec<TaskResult> = Vec::new();

        // Check if we have the 'next' chunk(s) available.
        // We loop until we hit a gap in the sequence.
        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1;
        }

        ready
    }

    /// Flushes all remaining items in the buffer, regardless of order.
    ///
    /// This is typically called at the end of processing to ensure no data is left behind,
    /// sorting them by index to maintain best-effort ordering.
    #[must_use]
    #[inline]
    pub fn flush(&mut self) -> Vec<TaskResult> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        // Drain all items from the map.
        let mut results: Vec<(u64, TaskResult)> = self.buffer.drain().collect();

        // Sort by index to enforce order one last time.
        results.sort_unstable_by_key(|(idx, _)| *idx);

        // Reset state (though typically the buffer is dropped after flush).
        self.next_idx = 0;

        // Return the values.
        results.into_iter().map(|(_, result)| result).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_sequential() {
        let mut buffer = Buffer::new(0);

        // Add #0 -> should be returned immediately.
        let res1 = TaskResult::ok(0, vec![], 0);
        let out1 = buffer.add(res1);
        assert_eq!(out1.len(), 1);
        assert_eq!(out1[0].index, 0);

        // Add #1 -> should be returned immediately.
        let res2 = TaskResult::ok(1, vec![], 0);
        let out2 = buffer.add(res2);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].index, 1);
    }

    #[test]
    fn test_buffer_out_of_order() {
        let mut buffer = Buffer::new(0);

        // Add #2 -> must buffer (waiting for #0).
        let res2 = TaskResult::ok(2, vec![], 0);
        let out2 = buffer.add(res2);
        assert!(out2.is_empty());

        // Add #0 -> should release #0 (still waiting for #1).
        let res0 = TaskResult::ok(0, vec![], 0);
        let out0 = buffer.add(res0);
        assert_eq!(out0.len(), 1);
        assert_eq!(out0[0].index, 0);

        // Add #1 -> should release #1 and #2.
        let res1 = TaskResult::ok(1, vec![], 0);
        let out1 = buffer.add(res1);

        assert_eq!(out1.len(), 2);
        assert_eq!(out1[0].index, 1);
        assert_eq!(out1[1].index, 2);
    }

    #[test]
    fn test_buffer_flush() {
        let mut buffer = Buffer::new(0);

        // Add #2.
        let res2 = TaskResult::ok(2, vec![], 0);
        let _ = buffer.add(res2);

        // Flush -> gets #2.
        let flushed = buffer.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].index, 2);
    }
}
