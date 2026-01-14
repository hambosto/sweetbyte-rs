use indicatif::{ProgressBar, ProgressStyle};

pub struct Bar {
    bar: ProgressBar,
}

impl Bar {
    pub fn new(total: u64, description: &str) -> Self {
        let bar = ProgressBar::new(total);
        let style = ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .expect("valid template")
            .progress_chars("●○ ");

        bar.set_style(style);
        bar.set_message(description.to_string());

        Self { bar }
    }

    pub fn add(&self, delta: u64) {
        self.bar.inc(delta);
    }

    pub fn finish(&self) {
        self.bar.finish_with_message("Done");
    }

    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }
}

impl Drop for Bar {
    fn drop(&mut self) {
        if !self.bar.is_finished() {
            self.bar.finish();
        }
    }
}
