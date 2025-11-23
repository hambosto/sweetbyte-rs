use crossbeam_channel::{Receiver, Sender};

/// A thread-safe buffer pool to reduce memory allocations.
#[derive(Clone)]
pub struct BufferPool {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    buffer_size: usize,
}

impl BufferPool {
    /// Creates a new buffer pool with the specified capacity and buffer size.
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let (sender, receiver) = crossbeam_channel::bounded(capacity);
        Self {
            sender,
            receiver,
            buffer_size,
        }
    }

    /// Gets a buffer from the pool, or allocates a new one if the pool is empty.
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

    /// Returns a buffer to the pool.
    /// If the pool is full, the buffer is dropped.
    pub fn return_buffer(&self, mut buffer: Vec<u8>) {
        // Only return buffers that are of the correct size (or larger)
        if buffer.capacity() >= self.buffer_size {
            // We don't need to clear here necessarily, but it's good practice to not hold data.
            // However, clearing is O(1) for Vec.
            buffer.clear();
            let _ = self.sender.try_send(buffer);
        }
    }
}
