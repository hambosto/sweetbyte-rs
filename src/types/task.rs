/// Represents a unit of work for the processing pipeline.
///
/// A `Task` contains a chunk of data and its sequence index.
/// It is passed to workers for parallel processing.
#[derive(Debug, Clone)]
pub struct Task {
    /// The raw data chunk to be processed.
    pub data: Vec<u8>,
    /// The sequence index of this chunk (0-based).
    pub index: u64,
}

/// Represents the result of a processed task.
///
/// A `TaskResult` contains the processed data (or error) and metadata
/// needed for writing the output in the correct order.
#[derive(Debug)]
pub struct TaskResult {
    /// The sequence index of the processed chunk.
    pub index: u64,
    /// The processed data (encrypted or decrypted).
    pub data: Vec<u8>,
    /// The size of the original data represented by this chunk.
    /// Used for accurate progress reporting.
    pub size: usize,
    /// Any error that occurred during processing.
    pub err: Option<anyhow::Error>,
}

impl TaskResult {
    /// Creates a successful task result.
    ///
    /// # Arguments
    ///
    /// * `index` - Chunk sequence number.
    /// * `data` - Processed data.
    /// * `size` - Original data size (for progress reporting).
    pub fn new(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self {
            index,
            data,
            size,
            err: None,
        }
    }

    /// Creates a failed task result.
    ///
    /// # Arguments
    ///
    /// * `index` - Chunk sequence number.
    /// * `err` - The error encountered.
    pub fn with_error(index: u64, err: anyhow::Error) -> Self {
        Self {
            index,
            data: Vec::new(),
            size: 0,
            err: Some(err),
        }
    }
}
