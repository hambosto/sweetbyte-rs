use std::collections::BinaryHeap;

use crate::types::TaskResult;

pub struct Buffer {
    buffer: BinaryHeap<TaskResult>,
    index: u64,
}

impl Buffer {
    pub fn new(index: u64) -> Self {
        Self { buffer: BinaryHeap::new(), index }
    }

    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        self.buffer.push(result);

        let mut ready = Vec::new();
        while self.buffer.peek().is_some_and(|top| top.index == self.index) {
            if let Some(result) = self.buffer.pop() {
                ready.push(result);
            }
            self.index = self.index.saturating_add(1);
        }

        ready
    }

    pub fn flush(&mut self) -> Vec<TaskResult> {
        let mut remaining: Vec<TaskResult> = self.buffer.drain().collect();
        remaining.sort_unstable_by_key(|r| r.index);

        remaining
    }
}
