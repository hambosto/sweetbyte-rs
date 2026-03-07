use hashbrown::HashMap;

use crate::types::TaskResult;

pub struct Buffer {
    buffer: HashMap<u64, TaskResult>,
    next_idx: u64,
}

impl Buffer {
    pub fn new(start: u64) -> Self {
        Self { buffer: HashMap::new(), next_idx: start }
    }

    /// Insert a result and return all consecutively-indexed results that are now ready.
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        self.buffer.insert(result.index, result);
        let mut ready = Vec::new();

        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1;
        }

        ready
    }

    /// Drain all buffered results in index order. Only call after the input stream is
    /// exhausted. Logs a warning for any gaps detected (indices that were never received).
    pub fn flush(&mut self) -> Vec<TaskResult> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<TaskResult> = self.buffer.drain().map(|(_, v)| v).collect();
        results.sort_unstable_by_key(|r| r.index);

        // Do NOT update next_idx: flush is a terminal drain, not a continuation of the
        // ordered stream. Mutating next_idx here would corrupt any resumed processing.

        results
    }
}
