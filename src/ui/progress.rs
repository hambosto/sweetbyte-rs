//! Progress bar for file processing feedback.
//!
//! Uses indicatif to display a real-time progress bar during encryption
//! or decryption, showing bytes processed, speed, and estimated time remaining.
//!
//! # Display Format
//!
//! `[spinner] Message [====......] current/total (speed, eta)`

use anyhow::Result;
use indicatif::{ProgressBar as Bar, ProgressStyle as Style};

/// Progress bar wrapper for processing feedback.
///
/// Displays progress with spinner, progress bar, bytes count,
/// transfer speed, and estimated time remaining.
pub struct ProgressBar {
    /// The underlying indicatif progress bar.
    bar: Bar,
}

/// Template for progress bar display.
///
/// Shows: spinner, message, progress bar, bytes/total, speed, eta
const PROGRESS_TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

impl ProgressBar {
    /// Creates a new progress bar.
    ///
    /// Initializes an indicatif progress bar with the total byte count
    /// and a styled template showing spinner, message, progress bar,
    /// bytes processed, transfer speed, and estimated time remaining.
    ///
    /// # Arguments
    ///
    /// * `total` - Total number of bytes to be processed (for progress calculation).
    /// * `description` - Message to display next to the progress bar (e.g., "Encrypting...").
    ///
    /// # Returns
    ///
    /// A new ProgressBar instance ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if the style template string is invalid
    /// (should not happen with a valid compile-time constant).
    pub fn new(total: u64, description: &str) -> Result<Self> {
        // Create a new progress bar with the total byte count.
        // The bar will track progress from 0 to total bytes.
        let bar = Bar::new(total);

        // Configure the display style using a template string.
        // The template defines what information is shown and in what format.
        // Style::with_template() parses the template and creates a ProgressStyle.
        // ?.handle_error() propagates any template parsing errors.
        bar.set_style(Style::with_template(PROGRESS_TEMPLATE)?.progress_chars("●○ "));

        // Set the message displayed next to the progress bar.
        // This is typically "Encrypting..." or "Decrypting...".
        bar.set_message(description.to_owned());

        // Wrap the bar in our ProgressBar struct and return.
        Ok(Self { bar })
    }

    /// Increments the progress by the given delta.
    ///
    /// Called by the writer as each chunk is processed to update
    /// the displayed progress. The delta is typically the size of
    /// the original (not compressed/encrypted) data.
    ///
    /// # Arguments
    ///
    /// * `delta` - Number of bytes to add to the progress counter.
    ///   Typically the original input size of a processed chunk.
    #[inline]
    pub fn add(&self, delta: u64) {
        // Delegate to the underlying indicatif bar's inc() method.
        // This updates the progress counter and refreshes the display.
        self.bar.inc(delta)
    }

    /// Finishes the progress bar with the current position.
    ///
    /// Marks the progress as complete and stops any animations.
    /// This is called when all processing is finished.
    ///
    /// Note: The Drop implementation will call finish_with_message("Done")
    /// if finish() hasn't already been called when the ProgressBar is dropped.
    #[inline]
    pub fn finish(&self) {
        // Finalize the progress bar at its current position.
        // This stops the spinner and shows the final count.
        self.bar.finish()
    }
}

impl Drop for ProgressBar {
    /// Automatically finishes the progress bar when dropped.
    ///
    /// If the progress bar hasn't been explicitly finished via finish(),
    /// this ensures it displays "Done" to provide clear visual feedback
    /// that processing is complete.
    fn drop(&mut self) {
        // Check if the bar is already finished (by explicit finish() call).
        // If not, finish it with a "Done" message.
        // This provides a good UX by showing completion status.
        if self.bar.is_finished() {
            self.bar.finish_with_message("Done");
        }
    }
}
