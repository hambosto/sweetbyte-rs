use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Result, bail};
use glob::Pattern;

use crate::config::EXCLUDED_PATTERNS;
use crate::file::operations::get_file_info;

static COMPILED_PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();

fn get_exclusion_patterns() -> &'static [Pattern] {
    COMPILED_PATTERNS.get_or_init(|| EXCLUDED_PATTERNS.iter().filter_map(|p| Pattern::new(p).ok()).collect())
}

pub fn is_excluded(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let path_str = path_str.replace('\\', "/");
    let path_str = path_str.strip_prefix("./").unwrap_or(&path_str);
    for pattern in get_exclusion_patterns() {
        if pattern.matches(path_str) {
            return true;
        }
    }

    false
}

pub fn validate_path(path: &Path, must_exist: bool) -> Result<()> {
    let info = get_file_info(path)?;
    if must_exist {
        match info {
            Some(info) if info.size == 0 => {
                bail!("file is empty: {}", path.display());
            }
            None => {
                bail!("file not found: {}", path.display());
            }
            _ => {}
        }
        if path.is_dir() {
            bail!("path is a directory: {}", path.display());
        }
    } else if info.is_some() {
        bail!("output file already exists: {}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_is_excluded_unix_paths() {
        assert!(is_excluded(Path::new("node_modules/package.json")));
        assert!(is_excluded(Path::new(".git/config")));
        assert!(is_excluded(Path::new("target/debug/binary")));
        assert!(is_excluded(Path::new("vendor/lib/file.rs")));
        assert!(is_excluded(Path::new("./.git/config")));
        assert!(is_excluded(Path::new("./node_modules/package.json")));
        assert!(is_excluded(Path::new("./target/release/app")));
    }

    #[test]
    fn test_is_excluded_windows_paths() {
        assert!(is_excluded(Path::new(r".git\config")));
        assert!(is_excluded(Path::new(r"node_modules\package.json")));
        assert!(is_excluded(Path::new(r"target\debug\binary")));
        assert!(is_excluded(Path::new(r".\.git\config")));
        assert!(is_excluded(Path::new(r".\node_modules\package.json")));
        assert!(is_excluded(Path::new(r".\target\release\app")));
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
