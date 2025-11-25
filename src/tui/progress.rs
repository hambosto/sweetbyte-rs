use crate::types::Processing;
use indicatif::{ProgressBar, ProgressStyle};

const PROGRESS_TEMPLATE: &str = "{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) | {bytes_per_sec} | ETA: {eta}";
const PROGRESS_CHARS: &str = "━━╸";
const SPINNER_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";

/// Progress bar wrapper for tracking operation progress.
#[derive(Clone)]
pub struct Bar {
    bar: ProgressBar,
}

impl Bar {
    /// Creates a new progress bar with the given total size and processing mode.
    pub fn new(total_size: u64, mode: Processing) -> Self {
        let bar = ProgressBar::new(total_size);
        bar.set_style(Self::create_style());
        bar.set_message(mode.to_string());

        Self { bar }
    }

    /// Creates the progress bar style configuration.
    fn create_style() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template(PROGRESS_TEMPLATE)
            .expect("Invalid progress bar template")
            .progress_chars(PROGRESS_CHARS)
            .tick_chars(SPINNER_CHARS)
    }

    /// Increments the progress bar by the given delta.
    pub fn add(&self, size: u64) {
        self.bar.inc(size);
    }

    /// Finishes the progress bar with a completion message.
    pub fn finish(&self) {
        self.bar.finish_with_message("Done");
    }
}
