use std::collections::BTreeMap;

/// Buffer for maintaining chunk order.
///
/// When chunks are processed in parallel, they may complete out of order.
/// This buffer ensures chunks are returned in the correct sequence.
/// Uses BTreeMap for better cache locality with sequential chunk indices.
pub struct ReorderBuffer {
    chunks: BTreeMap<u64, Vec<u8>>,
    next_expected: u64,
}

impl ReorderBuffer {
    /// Creates a new empty ordered buffer
    pub fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            next_expected: 0,
        }
    }

    /// Adds a chunk and returns all consecutive ready chunks.
    ///
    /// # Arguments
    /// * `index` - Chunk sequence number
    /// * `data` - Chunk data
    ///
    /// # Returns
    /// Vector of all consecutive chunks ready to write (may be empty)
    pub fn add(&mut self, index: u64, data: Vec<u8>) -> Vec<Vec<u8>> {
        self.chunks.insert(index, data);

        let mut ready = Vec::new();

        // Collect all consecutive chunks starting from next_expected
        loop {
            let next = self.next_expected;
            if let Some(chunk) = self.chunks.remove(&next) {
                ready.push(chunk);
                self.next_expected += 1;
            } else {
                break;
            }
        }

        ready
    }

    /// Flushes all remaining chunks in sorted order.
    ///
    /// Called at the end of processing to write any buffered chunks.
    /// This handles edge cases where chunks arrive out of order.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.chunks.is_empty() {
            return Vec::new();
        }

        // Get all indices and sort them
        let mut indices: Vec<u64> = self.chunks.keys().copied().collect();
        indices.sort_unstable();

        // Extract chunks in order
        let chunks = indices
            .into_iter()
            .filter_map(|idx| self.chunks.remove(&idx))
            .collect();

        chunks
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
    fn test_in_order() {
        let mut buffer = ReorderBuffer::new();

        let ready = buffer.add(0, vec![1, 2, 3]);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], vec![1, 2, 3]);

        let ready = buffer.add(1, vec![4, 5, 6]);
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_out_of_order() {
        let mut buffer = ReorderBuffer::new();

        // Add chunk 2 (out of order)
        let ready = buffer.add(2, vec![7, 8, 9]);
        assert!(ready.is_empty());

        // Add chunk 0
        let ready = buffer.add(0, vec![1, 2, 3]);
        assert_eq!(ready.len(), 1);

        // Add chunk 1 - should return chunk 1 and 2
        let ready = buffer.add(1, vec![4, 5, 6]);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_flush() {
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
