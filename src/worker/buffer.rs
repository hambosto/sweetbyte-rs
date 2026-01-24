//! Thread-safe reordering buffer for concurrent task results
//!
//! This module implements a specialized buffer designed to handle out-of-order
//! task results from concurrent processing while ensuring sequential output.
//! The buffer is critical for maintaining data integrity in producer-consumer
//! systems where tasks complete in non-deterministic order.
//!
//! ## Design Rationale
//!
//! In concurrent processing, tasks may complete out of order due to varying
//! processing times, thread scheduling, or I/O characteristics. However, many
//! applications (especially file processing) require sequential output. This
//! buffer bridges that gap by:
//!
//! 1. **Buffering**: Storing out-of-order results until all predecessors arrive
//! 2. **Reordering**: Emitting results in the correct sequence
//! 3. **Efficiency**: Minimizing memory allocations and copy operations
//! 4. **Thread Safety**: Supporting concurrent access patterns
//!
//! ## Performance Characteristics
//!
//! - **Memory**: O(n) where n is the number of buffered results
//! - **Lookup**: O(1) using HashMap for result storage
//! - **Insertion**: O(1) average case with HashMap
//! - **Flush**: O(n log n) for final sorting of remaining items
//!
//! The buffer uses hashbrown::HashMap for optimal performance and memory efficiency
//! compared to the standard library HashMap.

use hashbrown::HashMap;

use crate::types::TaskResult;

/// Reordering buffer for concurrent task results
///
/// This buffer handles the critical task of reordering results from concurrent
/// processing back into sequential order. It maintains an internal HashMap of
/// pending results and tracks the next expected output index.
///
/// ## Concurrency Considerations
///
/// While the buffer itself is not thread-safe internally (it expects single-threaded
/// access), it's designed to work with results coming from multiple concurrent
/// workers through channels. The single-threaded access pattern ensures optimal
/// performance without the overhead of internal synchronization.
///
/// ## Memory Management
///
/// The buffer automatically manages memory by:
/// - Using HashMap for O(1) lookup and insertion
/// - Draining results as soon as they're ready to output
/// - Clearing all remaining data during flush operations
pub struct Buffer {
    /// Internal storage for out-of-order task results
    /// Key: Task index, Value: Completed TaskResult
    /// HashMap provides O(1) lookup for checking if specific results are ready
    buffer: HashMap<u64, TaskResult>,
    /// Next expected sequential output index
    /// This tracks which index should be output next to maintain order
    /// Incremented as results are successfully output
    next_idx: u64,
}

impl Buffer {
    /// Creates a new Buffer with the specified starting index
    ///
    /// # Arguments
    ///
    /// * `start` - The initial value for next_idx (typically 0 for new streams)
    ///
    /// # Returns
    ///
    /// A new empty Buffer ready to receive task results
    ///
    /// # Performance Notes
    ///
    /// The buffer starts with an empty HashMap to minimize initial memory allocation.
    /// HashMap will automatically resize as needed, with hashbrown's implementation
    /// providing efficient growth patterns.
    #[inline]
    pub fn new(start: u64) -> Self {
        Self { buffer: HashMap::new(), next_idx: start }
    }

    /// Adds a task result to the buffer and returns any ready sequential results
    ///
    /// This is the core method that handles reordering logic. When a new result
    /// arrives, it's stored in the buffer and the method checks if this enables
    /// the output of sequential results that were previously waiting.
    ///
    /// ## Algorithm
    ///
    /// 1. Insert the new result into the buffer using its index as key
    /// 2. Check if the result at next_idx exists in the buffer
    /// 3. If found, remove it, add to ready list, and increment next_idx
    /// 4. Repeat step 2-3 until a gap is found
    /// 5. Return the list of ready sequential results
    ///
    /// This "drain while ready" approach ensures that we output as much
    /// as possible immediately, minimizing buffer size and latency.
    ///
    /// # Arguments
    ///
    /// * `result` - The completed TaskResult to add to the buffer
    ///
    /// # Returns
    ///
    /// A vector of TaskResults that are ready for sequential output
    /// The vector maintains the original task order (ascending indices)
    ///
    /// # Performance Characteristics
    ///
    /// - **Insertion**: O(1) average case for HashMap insert
    /// - **Drain Loop**: O(k) where k is the number of consecutive ready results
    /// - **Memory**: Results are moved out of the buffer, no copying occurs
    ///
    /// # Concurrency Impact
    ///
    /// This method enables the concurrent processing pipeline to function
    /// correctly despite out-of-order task completion, which is essential
    /// for achieving high throughput in cryptographic operations with
    /// variable processing times.
    #[must_use]
    #[inline]
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        // Store the incoming result in the buffer
        // The index serves as the unique key for O(1) lookup
        self.buffer.insert(result.index, result);

        // Prepare a vector to collect ready sequential results
        // Pre-allocating with Vec::new() allows for efficient growth
        let mut ready: Vec<TaskResult> = Vec::new();

        // Drain consecutive results starting from next_idx
        // This loop continues as long as we find the expected next index
        // This is the core reordering logic that ensures sequential output
        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1; // Move to the next expected index
        }

        ready
    }

    /// Flushes all remaining results from the buffer in order
    ///
    /// This method is typically called when the processing pipeline is shutting
    /// down and no more results are expected. It drains all remaining items
    /// from the buffer, sorts them by index, and returns them in sequential order.
    ///
    /// ## Use Case
    ///
    /// This is essential for handling the final results in a producer-consumer
    /// pipeline where some tasks may still be in the buffer when the input
    /// stream ends. The flush ensures no data is lost and proper ordering is
    /// maintained for the final output.
    ///
    /// ## Algorithm
    ///
    /// 1. Early return if buffer is empty (optimization)
    /// 2. Drain all items from buffer into a vector of (index, result) pairs
    /// 3. Sort by index using unstable sort (faster than stable sort)
    /// 4. Reset next_idx for potential reuse
    /// 5. Return sorted results
    ///
    /// # Returns
    ///
    /// A vector containing all remaining TaskResults sorted by their index
    /// Empty vector if no results were pending
    ///
    /// # Performance Notes
    ///
    /// - **Empty Check**: O(1) optimization to avoid unnecessary work
    /// - **Drain**: O(n) where n is number of remaining items
    /// - **Sort**: O(n log n) using unstable sort (faster than stable)
    /// - **Memory**: All data is moved, no copying occurs
    ///
    /// The use of `sort_unstable_by_key` is intentional - it's faster than
    /// stable sort when we don't need to preserve original order for equal keys,
    /// which is guaranteed by unique indices.
    #[must_use]
    #[inline]
    pub fn flush(&mut self) -> Vec<TaskResult> {
        // Fast path: if buffer is empty, return immediately
        // This avoids the overhead of allocation and sorting
        if self.buffer.is_empty() {
            return Vec::new();
        }

        // Drain all remaining items from the buffer
        // This transfers ownership efficiently without copying
        let mut results: Vec<(u64, TaskResult)> = self.buffer.drain().collect();

        // Sort by index to restore sequential order
        // Using unstable sort is safe because indices are unique
        // This is faster than stable sort for this use case
        results.sort_unstable_by_key(|(idx, _)| *idx);

        // Reset next_idx for potential buffer reuse
        // This allows the same buffer instance to be reused
        self.next_idx = 0;

        // Extract just the TaskResults, discarding the indices
        // The order is now correct after sorting
        results.into_iter().map(|(_, result)| result).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_sequential() {
        let mut buffer = Buffer::new(0);

        let res1 = TaskResult::ok(0, vec![], 0);
        let out1 = buffer.add(res1);
        assert_eq!(out1.len(), 1);
        assert_eq!(out1[0].index, 0);

        let res2 = TaskResult::ok(1, vec![], 0);
        let out2 = buffer.add(res2);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].index, 1);
    }

    #[test]
    fn test_buffer_out_of_order() {
        let mut buffer = Buffer::new(0);

        let res2 = TaskResult::ok(2, vec![], 0);
        let out2 = buffer.add(res2);
        assert!(out2.is_empty());

        let res0 = TaskResult::ok(0, vec![], 0);
        let out0 = buffer.add(res0);
        assert_eq!(out0.len(), 1);
        assert_eq!(out0[0].index, 0);

        let res1 = TaskResult::ok(1, vec![], 0);
        let out1 = buffer.add(res1);

        assert_eq!(out1.len(), 2);
        assert_eq!(out1[0].index, 1);
        assert_eq!(out1[1].index, 2);
    }

    #[test]
    fn test_buffer_flush() {
        let mut buffer = Buffer::new(0);

        let res2 = TaskResult::ok(2, vec![], 0);
        let _ = buffer.add(res2);

        let flushed = buffer.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].index, 2);

        let res0 = TaskResult::ok(0, vec![], 0);
        let out0 = buffer.add(res0);
        assert_eq!(out0.len(), 1);
        assert_eq!(out0[0].index, 0);
    }
}
