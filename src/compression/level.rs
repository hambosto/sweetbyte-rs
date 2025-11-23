#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Level {
    NoCompression,
    BestSpeed,
    DefaultCompression,
    BestCompression,
}

impl Level {
    pub fn to_flate2(&self) -> flate2::Compression {
        match self {
            Level::NoCompression => flate2::Compression::none(),
            Level::BestSpeed => flate2::Compression::fast(),
            Level::DefaultCompression => flate2::Compression::default(),
            Level::BestCompression => flate2::Compression::best(),
        }
    }
}
