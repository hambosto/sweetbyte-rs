use crossbeam_channel::{Receiver, Sender};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::stream::processor::DataProcessor;
use crate::types::{Task, TaskResult};

pub struct ConcurrentExecutor {
    processor: DataProcessor,
}

impl ConcurrentExecutor {
    pub fn new(processor: DataProcessor) -> Self {
        Self { processor }
    }

    pub fn process(&self, tasks: Receiver<Task>, results: Sender<TaskResult>) {
        let tasks_vec: Vec<Task> = tasks.iter().collect();

        tasks_vec.into_par_iter().for_each(|task| {
            let result = self.processor.process(task);
            let _ = results.send(result);
        });
    }
}
