use crossbeam_channel::{Receiver, Sender};

const PREWARM_MULTIPLIER: usize = 2;

/// Thread-safe buffer pool to reduce allocation overhead.
///
/// Recycling buffers minimizes allocation costs and memory fragmentation,
/// especially for large buffers (e.g., 256KB chunks).
#[derive(Clone)]
pub struct BufferPool {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    buffer_size: usize,
}

impl BufferPool {
    /// Creates a new buffer pool with pre-warmed buffers.
    ///
    /// Pre-warming eliminates allocation latency during runtime by
    /// initializing a reasonable number of buffers upfront.
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let (sender, receiver) = crossbeam_channel::bounded(capacity);

        let prewarm_count = capacity.min(num_cpus::get() * PREWARM_MULTIPLIER);
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

    /// Gets a buffer from the pool or allocates a new one if empty.
    ///
    /// Returned buffers are cleared (length 0) but retain their capacity.
    pub fn get(&self) -> Vec<u8> {
        match self.receiver.try_recv() {
            Ok(mut buffer) => {
                buffer.clear();
                buffer
            }
            Err(_) => Vec::with_capacity(self.buffer_size),
        }
    }

    /// Returns a buffer to the pool for reuse.
    ///
    /// Buffers smaller than `buffer_size` are dropped. If the pool is full,
    /// the buffer is also dropped.
    pub fn recycle(&self, buffer: Vec<u8>) {
        if buffer.capacity() >= self.buffer_size {
            let _ = self.sender.try_send(buffer);
        }
    }
}
