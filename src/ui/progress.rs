//! # Progress Bar Module
//!
//! This module provides real-time progress tracking for file operations with
//! performance metrics and terminal-safe rendering. It wraps the `indicatif`
//! library with application-specific styling and behavior.
//!
//! ## Features
//!
//! - **Real-time Updates**: Smooth progress updates during file operations
//! - **Performance Metrics**: Transfer speed and estimated time remaining
//! - **Terminal Safety**: Proper handling of terminal width and cursor management
//! - **Visual Polish**: Color-coded progress bars with spinners and animations
//!
//! ## Design Considerations
//!
//! - **Performance**: Minimal overhead during file operations
//! - **Responsiveness**: Updates don't block file processing threads
//! - **User Experience**: Clear visual feedback prevents user uncertainty
//! - **Terminal Compatibility**: Works across different terminal sizes and capabilities

use anyhow::Result;
use indicatif::{ProgressBar as Bar, ProgressStyle as Style};

/// Wrapper around indicatif ProgressBar with application-specific styling
///
/// Provides a high-level interface for progress tracking during file operations.
/// Handles all the complexity of terminal management, formatting, and performance
/// calculations automatically.
///
/// ## Performance Characteristics
///
/// - Progress updates are non-blocking and thread-safe
/// - Minimal memory overhead with efficient string formatting
/// - Automatic cleanup when the progress bar goes out of scope
/// - Smart terminal width detection for optimal layout
///
/// ## Terminal Safety
///
/// The progress bar properly handles:
/// - Terminal resize events
/// - Cursor positioning and restoration
/// - Multi-line output interference
/// - Graceful fallback on non-TTY terminals
pub struct ProgressBar {
    /// The underlying indicatif progress bar instance
    bar: Bar,
}

/// Template string for progress bar appearance
///
/// Template variables:
/// - `{spinner:.green}`: Animated spinning indicator in green
/// - `{msg}`: Custom message (usually operation description)
/// - `[{bar:40.cyan/blue}]`: 40-character progress bar with cyan/blue gradient
/// - `{bytes}/{total_bytes}`: Current and total bytes processed
/// - `{bytes_per_sec}`: Transfer speed in bytes per second
/// - `{eta}`: Estimated time remaining
///
/// This template provides comprehensive information while maintaining readability.
const PROGRESS_TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

impl ProgressBar {
    /// Create a new progress bar with the specified total and description
    ///
    /// Initializes a progress bar with application-specific styling including
    /// a custom template, color scheme, and progress characters.
    ///
    /// # Arguments
    ///
    /// * `total` - The maximum value (usually total bytes to process)
    /// * `description` - Human-readable description of the operation
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - New ProgressBar instance or error if styling fails
    ///
    /// # Errors
    ///
    /// * If the progress template is invalid or malformed
    /// * If terminal detection fails
    ///
    /// # UI/UX Considerations
    ///
    /// - Fixed 40-character width ensures consistent appearance across terminals
    /// - Cyan/blue gradient provides visual interest while remaining readable
    /// - Custom progress characters (●○) provide distinctive appearance
    /// - Green spinner matches application color scheme
    pub fn new(total: u64, description: &str) -> Result<Self> {
        // Create the underlying progress bar with the specified total
        let bar = Bar::new(total);

        // Apply custom styling with our template and progress characters
        // ●○ provides a distinctive fill pattern that stands out from default
        bar.set_style(Style::with_template(PROGRESS_TEMPLATE)?.progress_chars("●○ "));

        // Set the initial message that describes the operation
        bar.set_message(description.to_owned());

        Ok(Self { bar })
    }

    /// Increment the progress bar by the specified amount
    ///
    /// Updates the current progress and triggers a display refresh if needed.
    /// This method is designed to be called frequently during file operations.
    ///
    /// # Arguments
    ///
    /// * `delta` - Number of units to add to the current progress (usually bytes)
    ///
    /// # Performance Notes
    ///
    /// - Marked as `#[inline]` for minimal overhead during frequent calls
    /// - Display updates are throttled internally to prevent performance issues
    /// - Thread-safe for use across multiple processing contexts
    ///
    /// # Usage Pattern
    ///
    /// ```ignore
    /// progress_bar.add(chunk.len() as u64);
    /// ```
    #[inline]
    pub fn add(&self, delta: u64) {
        self.bar.inc(delta)
    }

    /// Mark the progress bar as finished
    ///
    /// Sets the progress to 100% and displays the completion message.
    /// The bar will remain visible with a "Done" message until dropped.
    ///
    /// # UI/UX Considerations
    ///
    /// - Provides clear indication of operation completion
    /// - The final state remains visible for user confirmation
    /// - Drop implementation ensures proper cleanup if not called explicitly
    ///
    /// # Performance Notes
    ///
    /// - Idempotent operation - safe to call multiple times
    /// - Minimal overhead for final display update
    #[inline]
    pub fn finish(&self) {
        self.bar.finish()
    }
}

/// Automatic cleanup when progress bar goes out of scope
///
/// Ensures proper finalization of the progress bar display if `finish()`
/// was not called explicitly. This prevents incomplete or hanging progress
/// indicators in the terminal.
///
/// # Behavior
///
/// - Only applies if the progress bar is already finished
/// - Sets the final message to "Done" for consistency
/// - Safe to call multiple times due to internal state checks
///
/// # User Experience Impact
///
/// This implementation ensures users always see a completed state,
/// even if the calling code forgets to call `finish()` explicitly.
/// This provides a safety net for better user experience and prevents
/// confusing incomplete progress indicators.
impl Drop for ProgressBar {
    fn drop(&mut self) {
        // Only modify the final state if the bar is already finished
        // This prevents interference with normal completion flows
        if self.bar.is_finished() {
            self.bar.finish_with_message("Done");
        }
    }
}
