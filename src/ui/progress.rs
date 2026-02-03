use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

pub struct Progress {
    progress_bar: ProgressBar,
}

const PROGRESS_TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

impl Progress {
    pub fn new(total: u64, description: &str) -> Result<Self> {
        let progress_bar = ProgressBar::new(total);

        progress_bar.set_style(ProgressStyle::with_template(PROGRESS_TEMPLATE)?.progress_chars("●○ "));
        progress_bar.set_message(description.to_owned());

        Ok(Self { progress_bar })
    }

    pub fn add(&self, delta: u64) {
        self.progress_bar.inc(delta);
    }

    pub fn finish(&self) {
        self.progress_bar.finish();
    }
}
