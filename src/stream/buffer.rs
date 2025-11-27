use parking_lot::Mutex;
use std::collections::BTreeMap;

use crate::types::TaskResult;

/// Thread-safe buffer for maintaining chunk order during parallel processing.
///
/// When chunks are processed in parallel, they may complete out of order.
/// This buffer ensures chunks are delivered in the correct sequence using
/// a BTreeMap indexed by sequence number and protected by a parking_lot Mutex.
#[derive(Debug)]
pub struct OrderedBuffer {
    inner: Mutex<OrderedBufferInner>,
}

#[derive(Debug)]
struct OrderedBufferInner {
    results: BTreeMap<u64, TaskResult>,
    next_expected: u64,
}

impl OrderedBuffer {
    /// Creates a new empty buffer starting at index 0.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(OrderedBufferInner {
                results: BTreeMap::new(),
                next_expected: 0,
            }),
        }
    }

    /// Adds a result and returns all consecutive ready results.
    ///
    /// Returns consecutive results starting from `next_expected`. Out-of-order
    /// results are buffered until their predecessors arrive.
    ///
    /// This method is thread-safe and can be called from multiple threads.
    #[inline]
    pub fn add(&self, result: TaskResult) -> Vec<TaskResult> {
        let mut inner = self.inner.lock();
        inner.results.insert(result.index, result);

        let mut ready = Vec::new();
        // Use while-let for more idiomatic iteration
        let mut next = inner.next_expected;
        while let Some(result) = inner.results.remove(&next) {
            ready.push(result);
            next += 1;
        }
        inner.next_expected = next;

        ready
    }

    /// Returns all remaining results in sorted order.
    ///
    /// Used at the end of processing to flush any buffered results.
    ///
    /// This method is thread-safe and can be called from multiple threads.
    pub fn flush(&self) -> Vec<TaskResult> {
        let mut inner = self.inner.lock();
        std::mem::take(&mut inner.results).into_values().collect()
    }
}
