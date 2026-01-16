use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};

use crate::stream::processor::DataProcessor;
use crate::types::{Task, TaskResult};

pub struct ConcurrentExecutor {
    processor: Arc<DataProcessor>,
    concurrency: usize,
}

impl ConcurrentExecutor {
    #[inline]
    pub fn new(processor: DataProcessor, concurrency: usize) -> Self {
        Self { processor: Arc::new(processor), concurrency }
    }

    pub fn process(&self, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        thread::scope(|scope| {
            for _ in 0..self.concurrency {
                let processor = Arc::clone(&self.processor);
                let tasks = tasks.clone();
                let results = results.clone();

                scope.spawn(move || {
                    Self::worker_loop(processor, tasks, results);
                });
            }

            drop(results);
        });
    }

    #[inline]
    fn worker_loop(processor: Arc<DataProcessor>, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        for task in tasks {
            let result = processor.process(task);
            if results.send(result).is_err() {
                break;
            }
        }
    }
}
