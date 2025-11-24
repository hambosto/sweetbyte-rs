use crossbeam_channel::{Receiver, Sender};

/// A thread-safe buffer pool to reduce memory allocations.
///
/// Allocating large buffers (e.g., 256KB) frequently can be expensive and cause memory fragmentation.
/// The `BufferPool` recycles buffers to minimize the overhead of memory allocation and deallocation.
/// By reusing previously allocated memory, the pool improves performance and reduces the risk of memory fragmentation.
#[derive(Clone)]
pub struct BufferPool {
    sender: Sender<Vec<u8>>,     // Sender to push buffers back into the pool
    receiver: Receiver<Vec<u8>>, // Receiver to pull buffers from the pool
    buffer_size: usize,          // The size of each buffer in the pool
}

impl BufferPool {
    /// Creates a new buffer pool with the specified capacity and buffer size.
    ///
    /// This method initializes the buffer pool and pre-warms it with a number of buffers to eliminate
    /// allocation latency at runtime. The pool size is bounded by the specified `capacity` and the number
    /// of CPUs available.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of buffers the pool can hold at any time.
    /// * `buffer_size` - The size of each buffer in bytes.
    ///
    /// # Returns
    ///
    /// Returns a new `BufferPool` instance.
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        // Create the channel with bounded capacity
        let (sender, receiver) = crossbeam_channel::bounded(capacity);

        // Pre-warm the pool by adding buffers to eliminate allocation latency
        let prewarm_count = capacity.min(num_cpus::get() * 2); // Pre-warm with a reasonable amount of buffers
        for _ in 0..prewarm_count {
            let buffer = vec![0u8; buffer_size]; // Create an initial buffer
            let _ = sender.try_send(buffer); // Send buffer to pool
        }

        Self {
            sender,
            receiver,
            buffer_size,
        }
    }

    /// Gets a buffer from the pool, or allocates a new one if the pool is empty.
    ///
    /// If there are available buffers in the pool, it returns a reused buffer with a length of 0,
    /// ready for new data. If no buffers are available, a new one is allocated.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` buffer with a capacity of at least `buffer_size` and length 0.
    pub fn get(&self) -> Vec<u8> {
        match self.receiver.try_recv() {
            Ok(mut buffer) => {
                // Ensure the buffer is at least the requested size (typically already correct)
                if buffer.capacity() < self.buffer_size {
                    buffer.reserve(self.buffer_size - buffer.len());
                }
                // Reset the length to 0 but preserve the capacity
                buffer.clear();
                buffer
            }
            Err(_) => Vec::with_capacity(self.buffer_size), // Allocate a new buffer if the pool is empty
        }
    }

    /// Returns a buffer to the pool for reuse.
    ///
    /// The buffer is placed back in the pool for future use. If the pool is full, the buffer is dropped.
    /// The buffer is only accepted back if it meets the required size.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer to return to the pool.
    ///
    /// # Notes
    ///
    /// If the pool is at capacity, the buffer is discarded rather than being stored in the pool.
    pub fn return_buffer(&self, buffer: Vec<u8>) {
        // Only return buffers that are of the correct size or larger
        if buffer.capacity() >= self.buffer_size {
            // Skip clearing the buffer, since get() will clear it anyway
            let _ = self.sender.try_send(buffer); // Attempt to send buffer back to pool
        }
    }
}
