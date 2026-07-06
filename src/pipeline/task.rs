pub(super) struct Task {
    pub(super) data: Vec<u8>,
    pub(super) index: u64,
}

pub(super) struct TaskResult {
    pub(super) index: u64,
    pub(super) data: Vec<u8>,
    pub(super) size: usize,
}

impl TaskResult {
    pub(super) fn new(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { index, data, size }
    }
}
