use std::{sync::Arc, thread};

use crossbeam_channel::{Receiver, Sender};

use crate::{
    stream::processor::DataProcessor,
    types::{Task, TaskResult},
};

pub struct ConcurrentExecutor {
    processor: Arc<DataProcessor>,
    concurrency: usize,
}

impl ConcurrentExecutor {
    pub fn new(processor: DataProcessor, concurrency: usize) -> Self {
        Self {
            processor: Arc::new(processor),
            concurrency,
        }
    }

    pub fn process(&self, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        let mut handles = Vec::with_capacity(self.concurrency);
        for _ in 0..self.concurrency {
            let processor = Arc::clone(&self.processor);
            let tasks = tasks.clone();
            let results = results.clone();
            let handle = thread::spawn(move || {
                for task in tasks {
                    let result = processor.process(task);
                    if results.send(result).is_err() {
                        break;
                    }
                }
            });

            handles.push(handle);
        }
        drop(results);
        for handle in handles {
            let _ = handle.join();
        }
    }
}
