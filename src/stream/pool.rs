use crossbeam_channel::{Receiver, Sender};

/// A thread-safe buffer pool to reduce memory allocations.
///
/// Allocating large buffers (e.g., 256KB) frequently can be expensive and cause memory fragmentation.
/// The `BufferPool` recycles buffers to minimize the overhead of memory allocation/deallocation.
#[derive(Clone)]
pub struct BufferPool {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    buffer_size: usize,
}

impl BufferPool {
    /// Creates a new buffer pool with the specified capacity and buffer size.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of buffers to hold in the pool.
    /// * `buffer_size` - Size of each buffer in bytes.
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let (sender, receiver) = crossbeam_channel::bounded(capacity);

        // Pre-warm the pool with initial buffers to eliminate allocation latency
        // Allocate min(capacity, num_cpus * 2) buffers upfront
        let prewarm_count = capacity.min(num_cpus::get() * 2);
        for _ in 0..prewarm_count {
            let buffer = vec![0u8; buffer_size];
            let _ = sender.try_send(buffer);
        }

        Self {
            sender,
            receiver,
            buffer_size,
        }
    }

    /// Gets a buffer from the pool, or allocates a new one if the pool is empty.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` with capacity >= `buffer_size` and length 0.
    pub fn get(&self) -> Vec<u8> {
        match self.receiver.try_recv() {
            Ok(mut buffer) => {
                // Ensure buffer is at least the requested size (though we stick to fixed size usually)
                if buffer.capacity() < self.buffer_size {
                    buffer.reserve(self.buffer_size - buffer.len());
                }
                // Reset length to 0 but keep capacity
                buffer.clear();
                buffer
            }
            Err(_) => Vec::with_capacity(self.buffer_size),
        }
    }

    /// Returns a buffer to the pool for reuse.
    ///
    /// If the pool is full, the buffer is dropped (deallocated).
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer to return.
    pub fn return_buffer(&self, buffer: Vec<u8>) {
        // Only return buffers that are of the correct size (or larger)
        if buffer.capacity() >= self.buffer_size {
            // Skip clear() here - get() will clear it anyway when reused
            // This reduces CPU overhead, especially for large buffers
            let _ = self.sender.try_send(buffer);
        }
    }
}
