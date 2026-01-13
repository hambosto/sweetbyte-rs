//! File path validation.

use std::path::Path;

use anyhow::{Result, bail};
use glob::Pattern;

use crate::config::EXCLUDED_PATTERNS;
use crate::file::operations::get_file_info;

/// Cached compiled glob patterns for exclusion.
static COMPILED_PATTERNS: std::sync::OnceLock<Vec<Pattern>> = std::sync::OnceLock::new();

/// Gets compiled exclusion patterns, caching them for reuse.
fn get_exclusion_patterns() -> &'static [Pattern] {
    COMPILED_PATTERNS.get_or_init(|| {
        EXCLUDED_PATTERNS
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect()
    })
}

/// Checks if a path matches any exclusion pattern.
pub fn is_excluded(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Normalize path separators for cross-platform matching
    // Windows uses backslashes, but glob patterns use forward slashes
    let path_str = path_str.replace('\\', "/");

    // Strip leading "./" prefix if present
    let path_str = path_str.strip_prefix("./").unwrap_or(&path_str);

    for pattern in get_exclusion_patterns() {
        if pattern.matches(path_str) {
            return true;
        }
    }

    false
}

/// Validates an input file path.
///
/// # Arguments
/// * `path` - The file path
/// * `must_exist` - Whether the file must exist
pub fn validate_path(path: &Path, must_exist: bool) -> Result<()> {
    let info = get_file_info(path)?;

    if must_exist {
        match info {
            None => {
                bail!("file not found: {}", path.display());
            }
            Some(info) if info.size == 0 => {
                bail!("file is empty: {}", path.display());
            }
            _ => {}
        }

        // Check if it's a directory
        if path.is_dir() {
            bail!("path is a directory: {}", path.display());
        }
    } else {
        // For output files, check that it doesn't already exist
        if info.is_some() {
            bail!("output file already exists: {}", path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_is_excluded_unix_paths() {
        // Unix-style paths (works on all platforms)
        assert!(is_excluded(Path::new("node_modules/package.json")));
        assert!(is_excluded(Path::new(".git/config")));
        assert!(is_excluded(Path::new("target/debug/binary")));
        assert!(is_excluded(Path::new("file.exe")));
        assert!(is_excluded(Path::new(".vscode/settings.json")));
        assert!(is_excluded(Path::new("vendor/lib/file.rs")));

        // With leading ./
        assert!(is_excluded(Path::new("./.git/config")));
        assert!(is_excluded(Path::new("./node_modules/package.json")));
        assert!(is_excluded(Path::new("./target/release/app")));
    }

    #[test]
    fn test_is_excluded_windows_paths() {
        // Windows-style paths with backslashes (works on all platforms due to normalization)
        assert!(is_excluded(Path::new(r".git\config")));
        assert!(is_excluded(Path::new(r"node_modules\package.json")));
        assert!(is_excluded(Path::new(r"target\debug\binary")));
        assert!(is_excluded(Path::new(r".vscode\settings.json")));

        // With leading .\
        assert!(is_excluded(Path::new(r".\.git\config")));
        assert!(is_excluded(Path::new(r".\node_modules\package.json")));
        assert!(is_excluded(Path::new(r".\target\release\app")));
    }

    #[test]
    fn test_is_excluded_file_extensions() {
        // File extension patterns
        assert!(is_excluded(Path::new("app.exe")));
        assert!(is_excluded(Path::new("lib.dll")));
        assert!(is_excluded(Path::new("lib.so")));
        assert!(is_excluded(Path::new("archive.zip")));
        assert!(is_excluded(Path::new("data.tar.gz")));
        assert!(is_excluded(Path::new("code.rs")));
        assert!(is_excluded(Path::new("main.go")));
    }

    #[test]
    fn test_is_not_excluded() {
        // These should NOT be excluded
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
