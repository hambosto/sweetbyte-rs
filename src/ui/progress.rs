use anyhow::Result;
use indicatif::{ProgressBar as Bar, ProgressStyle as Style};

pub struct ProgressBar {
    bar: Bar,
}

const PROGRESS_TEMPLATE: &str = "{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

impl ProgressBar {
    pub fn new(total: u64, description: &str) -> Result<Self> {
        let bar = Bar::new(total);
        bar.set_style(Style::with_template(PROGRESS_TEMPLATE)?.progress_chars("●○ "));
        bar.set_message(description.to_string());
        Ok(Self { bar })
    }

    pub fn add(&self, delta: u64) {
        self.bar.inc(delta);
    }

    pub fn finish(&self) {
        self.bar.finish();
    }

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
