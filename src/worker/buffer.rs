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
        self.drain_ready()
    }

    fn drain_ready(&mut self) -> Vec<TaskResult> {
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

    #[inline]
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.next_idx
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(index: u64) -> TaskResult {
        TaskResult::ok(index, vec![index as u8], 1)
    }

    #[test]
    fn test_in_order() {
        let mut buffer = Buffer::new(0);

        let ready = buffer.add(make_result(0));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].index, 0);

        let ready = buffer.add(make_result(1));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].index, 1);
    }

    #[test]
    fn test_out_of_order() {
        let mut buffer = Buffer::new(0);

        let ready = buffer.add(make_result(1));
        assert!(ready.is_empty());
        assert_eq!(buffer.len(), 1);

        let ready = buffer.add(make_result(0));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].index, 0);
        assert_eq!(ready[1].index, 1);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_flush() {
        let mut buffer = Buffer::new(0);

        let _ = buffer.add(make_result(2));
        let _ = buffer.add(make_result(1));

        let flushed = buffer.flush();
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].index, 1);
        assert_eq!(flushed[1].index, 2);

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_flush_empty() {
        let mut buffer = Buffer::new(0);
        let flushed = buffer.flush();
        assert!(flushed.is_empty());
    }

    #[test]
    fn test_next_index() {
        let mut buffer = Buffer::new(5);
        assert_eq!(buffer.next_index(), 5);

        let _ = buffer.add(make_result(5));
        assert_eq!(buffer.next_index(), 6);
    }
}
