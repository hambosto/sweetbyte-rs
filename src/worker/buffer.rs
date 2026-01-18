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

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[must_use]
    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        self.buffer.insert(result.index, result);
        self.drain_consecutive()
    }

    fn drain_consecutive(&mut self) -> Vec<TaskResult> {
        let mut ready = Vec::new();

        while let Some(result) = self.buffer.remove(&self.next_idx) {
            ready.push(result);
            self.next_idx += 1;
        }

        ready
    }

    #[must_use]
    pub fn flush(&mut self) -> Vec<TaskResult> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<_> = self.buffer.drain().collect();
        results.sort_unstable_by_key(|(idx, _)| *idx);

        self.next_idx = 0;
        results.into_iter().map(|(_, result)| result).collect()
    }

    #[inline]
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.next_idx
    }
}
