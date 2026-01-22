use std::sync::Arc;

use flume::{Receiver, Sender};
use rayon::prelude::*;

use crate::types::{Task, TaskResult};
use crate::worker::pipeline::Pipeline;

pub struct Executor {
    pipeline: Arc<Pipeline>,
}

impl Executor {
    #[inline]
    pub fn new(pipeline: Pipeline) -> Self {
        Self { pipeline: Arc::new(pipeline) }
    }

    pub fn process(&self, tasks: &Receiver<Task>, results: &Sender<TaskResult>) {
        tasks.iter().par_bridge().for_each(|task| {
            let result = self.pipeline.process(&task);

            let _ = results.send(result);
        });
    }
}
