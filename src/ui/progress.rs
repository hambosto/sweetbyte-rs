use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

const TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    pub fn new(total: u64, msg: impl Into<String>) -> Result<Self> {
        let bar = ProgressBar::new(total);
        bar.set_style(ProgressStyle::with_template(TEMPLATE)?.progress_chars("●○"));
        bar.set_message(msg.into());
        Ok(Self { bar })
    }

    pub fn add(&self, delta: u64) {
        self.bar.inc(delta);
    }

    pub fn finish(&self) {
        self.bar.finish();
    }
}
