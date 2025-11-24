/// Compression level for ZLIB compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// No compression (fastest, largest output)
    NoCompression,
    /// Best speed (fast compression, larger output)
    BestSpeed,
    /// Default compression (balanced speed and size)
    #[default]
    DefaultCompression,
    /// Best compression (slowest, smallest output)
    BestCompression,
}

impl From<Level> for flate2::Compression {
    fn from(level: Level) -> Self {
        match level {
            Level::NoCompression => flate2::Compression::none(),
            Level::BestSpeed => flate2::Compression::fast(),
            Level::DefaultCompression => flate2::Compression::default(),
            Level::BestCompression => flate2::Compression::best(),
        }
    }
}
