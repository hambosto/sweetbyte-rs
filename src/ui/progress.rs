use cliclack::ProgressBar;

const PROGRESS_TEMPLATE: &str = "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

pub(crate) struct Progress {
    progress_bar: Option<ProgressBar>,
}

impl Progress {
    pub(crate) fn new(total: u64, label: impl Into<String>) -> Self {
        if cfg!(test) {
            return Self { progress_bar: None };
        }

        let progress_bar = cliclack::progress_bar(total).with_template(PROGRESS_TEMPLATE);
        progress_bar.start(label.into());

        Self { progress_bar: Some(progress_bar) }
    }

    pub(crate) fn increment(&self, delta: u64) {
        if let Some(progress_bar) = &self.progress_bar {
            progress_bar.inc(delta);
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(progress_bar) = &self.progress_bar {
            progress_bar.stop("Done");
        }
    }
}
