#[derive(Debug, Clone)]
pub struct Task {
    pub data: Vec<u8>,
    pub index: u64,
}

#[derive(Debug)]
pub struct TaskResult {
    pub index: u64,
    pub data: Vec<u8>,
    pub size: usize,
    pub err: Option<anyhow::Error>,
}

impl TaskResult {
    pub fn new(index: u64, data: Vec<u8>, size: usize) -> Self {
        Self {
            index,
            data,
            size,
            err: None,
        }
    }

    pub fn with_error(index: u64, err: anyhow::Error) -> Self {
        Self {
            index,
            data: Vec::new(),
            size: 0,
            err: Some(err),
        }
    }
}
