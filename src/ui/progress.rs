//! Progress bar visualization.
//!
//! This module wraps the `indicatif` library to provide consistent progress bars
//! for long-running operations.

use anyhow::Result;
use indicatif::{ProgressBar as Bar, ProgressStyle as Style};

/// A wrapper around the `indicatif` progress bar.
pub struct ProgressBar {
    /// The inner progress bar instance.
    bar: Bar,
}

/// The template string defining the look of the progress bar.
///
/// Format: `[Spinner] [Message] [Bar] [Bytes/Total] (Speed, ETA)`
const PROGRESS_TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

impl ProgressBar {
    /// Creates and configures a new progress bar.
    ///
    /// # Arguments
    ///
    /// * `total` - The total expected bytes to process.
    /// * `description` - The label to display (e.g., "Encrypting...").
    pub fn new(total: u64, description: &str) -> Result<Self> {
        let bar = Bar::new(total);

        // Configure style and template.
        bar.set_style(
            Style::with_template(PROGRESS_TEMPLATE)?.progress_chars("●○ "), // Custom characters for the bar
        );

        bar.set_message(description.to_owned());

        Ok(Self { bar })
    }

    /// Advances the progress bar by a specific number of bytes.
    #[inline]
    pub fn add(&self, delta: u64) {
        self.bar.inc(delta)
    }

    /// Marks the progress bar as finished.
    #[inline]
    pub fn finish(&self) {
        self.bar.finish()
    }
}
