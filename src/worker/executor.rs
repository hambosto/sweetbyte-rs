use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

pub struct Executor {
    pipeline: Arc<Pipeline>,
    concurrency: usize,
}

impl Executor {
    #[inline]
    pub fn new(pipeline: Pipeline, concurrency: usize) -> Self {
        Self { pipeline: Arc::new(pipeline), concurrency }
    }

    pub fn process(&self, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        thread::scope(|scope| {
            for _ in 0..self.concurrency {
                let pipeline = Arc::clone(&self.pipeline);
                let tasks = tasks.clone();
                let results = results.clone();

                scope.spawn(move || {
                    Self::worker_loop(pipeline, tasks, results);
                });
            }

            drop(results);
        });
    }

    #[inline]
    fn worker_loop(pipeline: Arc<Pipeline>, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        for task in tasks {
            let result = pipeline.process(task);
            if results.send(result).is_err() {
                break;
            }
        }
    }
}
