use cliclack::ProgressBar;

const TEMPLATE: &str = "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";

pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    pub fn new(total: u64, message: impl Into<String>) -> Self {
        let bar = cliclack::progress_bar(total).with_template(TEMPLATE);
        bar.start(message.into());

        Self { bar }
    }

    pub fn add(&self, delta: u64) {
        self.bar.inc(delta);
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.bar.stop("Done");
    }
}
