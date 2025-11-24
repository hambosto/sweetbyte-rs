use std::collections::BTreeMap;

/// Buffer for maintaining chunk order.
///
/// When chunks are processed in parallel, they may complete out of order.
/// This buffer ensures chunks are returned in the correct sequence.
/// It uses a `BTreeMap` to store chunks indexed by their sequence number for efficient retrieval.
///
/// The `ReorderBuffer` is designed to accept chunks that arrive in an out-of-order sequence and
/// deliver them in the correct order when requested.
pub struct ReorderBuffer {
    chunks: BTreeMap<u64, Vec<u8>>, // Stores chunks indexed by their sequence number.
    next_expected: u64,             // The index of the next expected chunk.
}

impl ReorderBuffer {
    /// Creates a new empty ordered buffer.
    ///
    /// Initializes the buffer with no chunks and sets the next expected index to 0.
    ///
    /// # Returns
    /// A new instance of `ReorderBuffer`.
    pub fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            next_expected: 0,
        }
    }

    /// Adds a chunk and returns all consecutive ready chunks.
    ///
    /// This method adds a chunk with its sequence number to the buffer. If the chunk is the next expected one
    /// or there are chunks available in sequence starting from the next expected index, they are returned.
    ///
    /// # Arguments
    ///
    /// * `index` - The sequence number of the chunk being added.
    /// * `data` - The chunk data that corresponds to the given index.
    ///
    /// # Returns
    ///
    /// A vector of consecutive chunks starting from the next expected index. If the added chunk is not the
    /// next expected one, an empty vector is returned.
    pub fn add(&mut self, index: u64, data: Vec<u8>) -> Vec<Vec<u8>> {
        // Insert the chunk data into the map using its sequence number (index)
        self.chunks.insert(index, data);

        let mut ready = Vec::new();

        // Collect all consecutive chunks starting from the next expected index
        loop {
            let next = self.next_expected;
            if let Some(chunk) = self.chunks.remove(&next) {
                ready.push(chunk);
                self.next_expected += 1; // Increment the next expected index
            } else {
                break; // Stop if no chunk is available at the next expected index
            }
        }

        ready // Return the consecutive chunks that were collected
    }

    /// Flushes all remaining chunks in sorted order.
    ///
    /// This method ensures that all chunks that were not previously returned (e.g., due to gaps in sequence)
    /// are returned in the correct order. It is a fallback method that can be used at the end of processing.
    ///
    /// # Returns
    ///
    /// A vector of all remaining chunks, sorted by their index.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.chunks.is_empty() {
            return Vec::new(); // Return an empty vector if no chunks are left
        }

        // Get all indices from the map and sort them
        let mut indices: Vec<u64> = self.chunks.keys().copied().collect();
        indices.sort_unstable();

        // Extract chunks in order of their indices
        indices
            .into_iter()
            .filter_map(|idx| self.chunks.remove(&idx)) // Remove the chunks from the map as we return them
            .collect()
    }
}

impl Default for ReorderBuffer {
    fn default() -> Self {
        Self::new() // Use the new method to create a default instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the `add` method when chunks arrive in order.
    /// It ensures that chunks are added and returned correctly when they are in sequence.
    #[test]
    fn test_in_order() {
        let mut buffer = ReorderBuffer::new();

        // Add chunk 0 and check that it is immediately returned
        let ready = buffer.add(0, vec![1, 2, 3]);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], vec![1, 2, 3]);

        // Add chunk 1 and check that it is returned next
        let ready = buffer.add(1, vec![4, 5, 6]);
        assert_eq!(ready.len(), 1);
    }

    /// Test the `add` method when chunks arrive out of order.
    /// It ensures that the buffer waits for the next expected chunk and returns them in order.
    #[test]
    fn test_out_of_order() {
        let mut buffer = ReorderBuffer::new();

        // Add chunk 2 out of order, it should not be returned yet
        let ready = buffer.add(2, vec![7, 8, 9]);
        assert!(ready.is_empty());

        // Add chunk 0, which should now be returned
        let ready = buffer.add(0, vec![1, 2, 3]);
        assert_eq!(ready.len(), 1);

        // Add chunk 1, and both chunk 1 and 2 should be returned now
        let ready = buffer.add(1, vec![4, 5, 6]);
        assert_eq!(ready.len(), 2);
    }

    /// Test the `flush` method to ensure all chunks are returned in order.
    #[test]
    fn test_flush() {
        let mut buffer = ReorderBuffer::new();

        // Add chunks out of order
        buffer.add(2, vec![7]);
        buffer.add(0, vec![1]);
        buffer.add(4, vec![9]);

        // Flush the buffer and ensure all chunks are returned in the correct order
        let chunks = buffer.flush();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], vec![7]);
        assert_eq!(chunks[1], vec![9]);
    }
}
