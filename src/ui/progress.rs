use anyhow::Result;
use indicatif::{ProgressBar as Bar, ProgressStyle as Style};

/// Terminal progress bar for displaying operation progress.
///
/// Uses indicatif for rendering a spinner, progress bar, byte count,
/// transfer rate, and estimated time remaining.
pub struct ProgressBar {
    /// The underlying indicatif progress bar.
    bar: Bar,
}

/// Format template for the progress bar display.
/// Shows: spinner | message | progress bar | bytes/total | speed | ETA
const PROGRESS_TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

impl ProgressBar {
    /// Creates a new progress bar with the given total and description.
    ///
    /// # Arguments
    /// * `total` - Total bytes to process.
    /// * `description` - Description message (e.g., "Encrypting...").
    ///
    /// # Returns
    /// A new ProgressBar instance.
    pub fn new(total: u64, description: &str) -> Result<Self> {
        let bar = Bar::new(total);
        // Configure the progress bar style with the custom template.
        bar.set_style(Style::with_template(PROGRESS_TEMPLATE)?.progress_chars("●○ "));
        // Set the description message.
        bar.set_message(description.to_owned());
        Ok(Self { bar })
    }

    /// Increments the progress by the given number of bytes.
    ///
    /// # Arguments
    /// * `delta` - Number of bytes to add to progress.
    #[inline]
    pub fn add(&self, delta: u64) {
        self.bar.inc(delta)
    }

    /// Manually finishes the progress bar.
    ///
    /// Typically called after processing is complete.
    #[inline]
    pub fn finish(&self) {
        self.bar.finish()
    }
}

impl Drop for ProgressBar {
    /// Automatically finishes the progress bar when dropped.
    ///
    /// If the bar hasn't been explicitly finished, displays "Done".
    fn drop(&mut self) {
        if self.bar.is_finished() {
            self.bar.finish_with_message("Done");
        }
    }
}
