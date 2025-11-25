use crate::types::Processing;
use indicatif::{ProgressBar, ProgressStyle};

/// Progress bar wrapper for tracking operation progress.
#[derive(Clone)]
pub struct Bar {
    bar: ProgressBar,
}

impl Bar {
    /// Creates a new progress bar with the given total size and processing mode.
    pub fn new(total_size: u64, mode: Processing) -> Self {
        let bar = ProgressBar::new(total_size);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) | {bytes_per_sec} | ETA: {eta}")
                .unwrap()
                .progress_chars("━━╸")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        );
        bar.set_message(mode.to_string());
        Bar { bar }
    }

    /// Increments the progress bar by the given delta.
    pub fn add(&self, size: u64) {
        self.bar.inc(size)
    }

    /// Finishes the progress bar with a message.
    pub fn finish(&self) {
        self.bar.finish_with_message("Done");
    }
}
