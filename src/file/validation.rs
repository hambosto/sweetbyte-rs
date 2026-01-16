use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Result, anyhow, bail};
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::config::EXCLUDED_PATTERNS;
use crate::file::operations::get_file_info;

static EXCLUSION_MATCHER: LazyLock<Gitignore> = LazyLock::new(|| {
    let mut builder = GitignoreBuilder::new("");
    for pattern in EXCLUDED_PATTERNS {
        let _ = builder.add_line(None, pattern);
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
});

#[inline]
pub fn is_excluded(path: &Path) -> bool {
    EXCLUSION_MATCHER.matched(path, false).is_ignore()
}

pub fn validate_path(path: &Path, must_exist: bool) -> Result<()> {
    let info = get_file_info(path)?;

    if must_exist {
        let info = info.ok_or_else(|| anyhow!("file not found: {}", path.display()))?;

        if path.is_dir() {
            bail!("path is directory: {}", path.display());
        }
        if info.size == 0 {
            bail!("file is empty: {}", path.display());
        }
    } else if info.is_some() {
        bail!("output exists: {}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_is_excluded() {
        assert!(is_excluded(Path::new("node_modules/package.json")));
        assert!(is_excluded(Path::new(".git/config")));
        assert!(is_excluded(Path::new("vendor/lib/file.rs")));
        assert!(is_excluded(Path::new(".config/settings.json")));
        assert!(is_excluded(Path::new(".cache/data")));
    }

    #[test]
    fn test_is_not_excluded() {
        assert!(!is_excluded(Path::new("document.txt")));
        assert!(!is_excluded(Path::new("image.png")));
        assert!(!is_excluded(Path::new("data.json")));
        assert!(!is_excluded(Path::new("photo.jpg")));
        assert!(!is_excluded(Path::new("video.mp4")));
        assert!(!is_excluded(Path::new("music.mp3")));
        assert!(!is_excluded(Path::new("spreadsheet.xlsx")));
    }

    #[test]
    fn test_validate_path_not_found() {
        let path = PathBuf::from("/nonexistent/path/file.txt");
        let result = validate_path(&path, true);
        assert!(result.is_err());
    }
}
