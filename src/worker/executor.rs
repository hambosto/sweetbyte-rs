use std::sync::Arc;

use flume::{Receiver, Sender};
use rayon::iter::{ParallelBridge, ParallelIterator};

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

pub struct Executor {
    pipeline: Arc<Pipeline>,
}

impl Executor {
    pub fn new(pipeline: Pipeline) -> Self {
        Self { pipeline: Arc::new(pipeline) }
    }

    pub fn process(&self, tasks: &Receiver<Task>, results: &Sender<TaskResult>) {
        tasks.iter().par_bridge().for_each(|task| {
            let result = self.pipeline.process(&task);
            if let Err(error) = results.send(result) {
                tracing::error!("failed to send task result: {error}");
            }
        });
    }
}
