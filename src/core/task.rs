pub(crate) struct Task {
    pub(crate) data: Vec<u8>,
    pub(crate) index: u64,
}

pub(crate) struct TaskResult {
    pub(crate) index: u64,
    pub(crate) data: Vec<u8>,
    pub(crate) size: usize,
}

impl TaskResult {
    pub(crate) fn new(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self { index, data, size }
    }
}
