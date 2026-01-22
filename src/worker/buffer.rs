use hashbrown::HashMap;

use crate::types::TaskResult;

pub struct Buffer {
    buffer: HashMap<u64, TaskResult>,

    next_idx: u64,
}

impl Buffer {
    #[inline]
    pub fn new(start: u64) -> Self {
        Self { buffer: HashMap::new(), next_idx: start }
    }

    #[must_use]
    #[inline]
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        self.buffer.insert(result.index, result);

        let mut ready: Vec<TaskResult> = Vec::new();

        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1;
        }

        ready
    }

    #[must_use]
    #[inline]
    pub fn flush(&mut self) -> Vec<TaskResult> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<(u64, TaskResult)> = self.buffer.drain().collect();

        results.sort_unstable_by_key(|(idx, _)| *idx);

        self.next_idx = 0;

        results.into_iter().map(|(_, result)| result).collect()
    }
}
