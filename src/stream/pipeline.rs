use std::io::{Read, Write};

use anyhow::{Context, Result};
use byteorder::{BigEndian, WriteBytesExt};
use crossbeam_channel::bounded;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::config::{ARGON_KEY_LEN, CHUNK_SIZE};
use crate::stream::buffer::SequentialBuffer;
use crate::stream::processor::DataProcessor;
use crate::stream::reader::ChunkReader;
use crate::types::{Processing, Task, TaskResult};
use crate::ui::progress::ProgressBar;

pub struct Pipeline {
    processor: DataProcessor,
    mode: Processing,
}

impl Pipeline {
    pub fn new(key: &[u8; ARGON_KEY_LEN], mode: Processing) -> Result<Self> {
        let processor = DataProcessor::new(key, mode)?;

        Ok(Self { processor, mode })
    }

    pub fn process<R: Read + Send + 'static, W: Write + Send + 'static>(
        self,
        input: R,
        mut output: W,
        total_size: u64,
    ) -> Result<()> {
        let progress = ProgressBar::new(total_size, self.mode.description());

        let channel_size = rayon::current_num_threads() * 2;
        let (task_sender, task_receiver) = bounded::<Task>(channel_size);
        let (result_sender, result_receiver) = bounded::<TaskResult>(channel_size);

        let reader = ChunkReader::new(self.mode, CHUNK_SIZE)?;

        let mode = self.mode;
        let processor = self.processor;

        rayon::scope(|s| {
            s.spawn(|_| {
                let _ = reader.read_all(input, task_sender);
            });

            s.spawn(|_| {
                let tasks: Vec<Task> = task_receiver.iter().collect();
                tasks.into_par_iter().for_each(|task| {
                    let result = processor.process(task);
                    let _ = result_sender.send(result);
                });
                drop(result_sender);
            });

            s.spawn(|_| {
                let mut buffer = SequentialBuffer::new(0);

                for result in result_receiver.iter() {
                    if result.error.is_some() {
                        continue;
                    }

                    let ready = buffer.add(result);
                    let _ = write_ordered(&mut output, &ready, mode, Some(&progress));
                }

                let remaining = buffer.flush();
                let _ = write_ordered(&mut output, &remaining, mode, Some(&progress));
            });
        });

        progress.finish();

        Ok(())
    }
}

fn write_ordered<W: Write>(
    output: &mut W,
    results: &[TaskResult],
    mode: Processing,
    progress: Option<&ProgressBar>,
) -> Result<()> {
    match mode {
        Processing::Encryption => {
            for result in results {
                output
                    .write_u32::<BigEndian>(result.data.len() as u32)
                    .context("failed to write chunk size")?;

                output
                    .write_all(&result.data)
                    .context("failed to write chunk data")?;

                if let Some(bar) = progress {
                    bar.add(result.size as u64);
                }
            }
        }
        Processing::Decryption => {
            for result in results {
                output
                    .write_all(&result.data)
                    .context("failed to write chunk data")?;

                if let Some(bar) = progress {
                    bar.add(result.size as u64);
                }
            }
        }
    }

    Ok(())
}
