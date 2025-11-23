pub const EXCLUDED_DIRS: &[&str] = &[
    "vendor/",
    "node_modules/",
    ".git",
    ".github",
    ".vscode/",
    "build/",
    "dist/",
    "target/",
    ".config",
    ".local",
    ".cache",
    ".ssh",
];

pub const EXCLUDED_EXTS: &[&str] = &[
    ".go",
    "go.mod",
    "go.sum",
    ".nix",
    ".gitignore",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".rs",
];
