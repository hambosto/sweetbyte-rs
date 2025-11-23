use indicatif::{ProgressBar, ProgressStyle};

/// Progress bar wrapper for tracking operation progress.
#[derive(Clone)]
pub struct Progress {
    pb: ProgressBar,
}

impl Progress {
    /// Creates a new progress bar with the given total size.
    pub fn new(total_size: u64) -> Self {
        let pb = ProgressBar::new(total_size);
        pb.set_style(ProgressStyle::default_bar().template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap().progress_chars("#>-"));
        Self { pb }
    }

    /// Increments the progress bar by the given delta.
    pub fn inc(&self, delta: u64) {
        self.pb.inc(delta);
    }

    /// Finishes the progress bar with a message.
    pub fn finish_with_message(&self, msg: &str) {
        self.pb.finish_with_message(msg.to_string());
    }
}
