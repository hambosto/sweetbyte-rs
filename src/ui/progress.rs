//! Progress bar display.

use indicatif::{ProgressBar as IndicatifBar, ProgressStyle};

/// Progress bar wrapper.
pub struct ProgressBar {
    bar: IndicatifBar,
}

impl ProgressBar {
    /// Creates a new progress bar.
    ///
    /// # Arguments
    /// * `total` - Total size for progress tracking
    /// * `description` - Description text
    pub fn new(total: u64, description: &str) -> Self {
        let bar = IndicatifBar::new(total);

        let style = ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .expect("valid template")
            .progress_chars("●○ ");

        bar.set_style(style);
        bar.set_message(description.to_string());

        Self { bar }
    }

    /// Adds progress.
    ///
    /// # Arguments
    /// * `delta` - Amount to add
    pub fn add(&self, delta: u64) {
        self.bar.inc(delta);
    }

    /// Finishes the progress bar.
    pub fn finish(&self) {
        self.bar.finish_with_message("Done");
    }

    /// Sets the progress bar message.
    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }
}

impl Drop for ProgressBar {
    fn drop(&mut self) {
        if !self.bar.is_finished() {
            self.bar.finish();
        }
    }
}
