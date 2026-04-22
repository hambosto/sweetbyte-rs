use std::collections::BinaryHeap;

use crate::types::TaskResult;

pub struct Buffer {
    heap: BinaryHeap<TaskResult>,
    next: u64,
}

impl Buffer {
    pub fn new(start: u64) -> Self {
        Self { heap: BinaryHeap::new(), next: start }
    }

    pub fn add(&mut self, result: TaskResult) -> Vec<TaskResult> {
        self.heap.push(result);

        let mut ready = Vec::new();
        while self.heap.peek().is_some_and(|top| top.index == self.next) {
            if let Some(result) = self.heap.pop() {
                ready.push(result);
            }
            self.next += 1;
        }

        ready
    }

    pub fn flush(&mut self) -> Vec<TaskResult> {
        let mut remaining: Vec<TaskResult> = self.heap.drain().collect();
        remaining.sort_unstable_by_key(|r| r.index);

        remaining
    }
}
