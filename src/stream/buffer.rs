use std::collections::BTreeMap;

/// Buffer for maintaining chunk order during parallel processing.
///
/// When chunks are processed in parallel, they may complete out of order.
/// This buffer ensures chunks are delivered in the correct sequence using
/// a BTreeMap indexed by sequence number.
pub struct ReorderBuffer {
    chunks: BTreeMap<u64, Vec<u8>>,
    next_expected: u64,
}

impl ReorderBuffer {
    /// Creates a new empty buffer starting at index 0.
    pub fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            next_expected: 0,
        }
    }

    /// Adds a chunk and returns all consecutive ready chunks.
    ///
    /// Returns consecutive chunks starting from `next_expected`. Out-of-order
    /// chunks are buffered until their predecessors arrive.
    pub fn add(&mut self, index: u64, data: Vec<u8>) -> Vec<Vec<u8>> {
        self.chunks.insert(index, data);

        let mut ready = Vec::new();
        while let Some(chunk) = self.chunks.remove(&self.next_expected) {
            ready.push(chunk);
            self.next_expected += 1;
        }

        ready
    }

    /// Returns all remaining chunks in sorted order.
    ///
    /// Used at the end of processing to flush any buffered chunks.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.chunks.is_empty() {
            return Vec::new();
        }

        std::mem::take(&mut self.chunks).into_values().collect()
    }
}

impl Default for ReorderBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_returns_chunks_in_sequence() {
        let mut buffer = ReorderBuffer::new();

        let ready = buffer.add(0, vec![1, 2, 3]);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], vec![1, 2, 3]);

        let ready = buffer.add(1, vec![4, 5, 6]);
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_add_buffers_out_of_order_chunks() {
        let mut buffer = ReorderBuffer::new();

        let ready = buffer.add(2, vec![7, 8, 9]);
        assert!(ready.is_empty());

        let ready = buffer.add(0, vec![1, 2, 3]);
        assert_eq!(ready.len(), 1);

        let ready = buffer.add(1, vec![4, 5, 6]);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_flush_returns_remaining_chunks_in_order() {
        let mut buffer = ReorderBuffer::new();

        buffer.add(2, vec![7]);
        buffer.add(0, vec![1]);
        buffer.add(4, vec![9]);

        let chunks = buffer.flush();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], vec![7]);
        assert_eq!(chunks[1], vec![9]);
    }
}
