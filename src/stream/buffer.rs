//! Sequential buffer for ordering task results.

use std::collections::HashMap;

use crate::types::TaskResult;

/// Buffer that maintains sequential ordering of task results.
///
/// Results may arrive out of order but are released in order.
pub struct SequentialBuffer {
    buffer: HashMap<u64, TaskResult>,
    next_idx: u64,
}

impl SequentialBuffer {
    /// Creates a new sequential buffer.
    ///
    /// # Arguments
    /// * `start` - The starting index
    pub fn new(start: u64) -> Self {
        Self {
            buffer: HashMap::new(),
            next_idx: start,
        }
    }

    /// Adds a result to the buffer and returns any results ready for output.
    ///
    /// Results are ready when they are the next expected index.
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        self.buffer.insert(result.index, result);

        let mut ready = Vec::new();
        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1;
        }

        ready
    }

    /// Flushes all remaining results, sorted by index.
    pub fn flush(&mut self) -> Vec<TaskResult> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut indices: Vec<u64> = self.buffer.keys().copied().collect();
        indices.sort_unstable();

        let mut results = Vec::with_capacity(indices.len());
        for idx in indices {
            if let Some(result) = self.buffer.remove(&idx) {
                results.push(result);
            }
        }

        self.next_idx = 0;
        results
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for SequentialBuffer {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(index: u64) -> TaskResult {
        TaskResult::success(index, vec![index as u8], 1)
    }

    #[test]
    fn test_in_order() {
        let mut buffer = SequentialBuffer::new(0);

        let ready = buffer.add(make_result(0));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].index, 0);

        let ready = buffer.add(make_result(1));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].index, 1);
    }

    #[test]
    fn test_out_of_order() {
        let mut buffer = SequentialBuffer::new(0);

        // Add index 1 first (out of order)
        let ready = buffer.add(make_result(1));
        assert!(ready.is_empty());

        // Add index 0, should release both
        let ready = buffer.add(make_result(0));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].index, 0);
        assert_eq!(ready[1].index, 1);
    }

    #[test]
    fn test_flush() {
        let mut buffer = SequentialBuffer::new(0);

        // Add out of order, skip 0
        buffer.add(make_result(2));
        buffer.add(make_result(1));

        let flushed = buffer.flush();
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].index, 1);
        assert_eq!(flushed[1].index, 2);

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_flush_empty() {
        let mut buffer = SequentialBuffer::new(0);
        let flushed = buffer.flush();
        assert!(flushed.is_empty());
    }
}
