use crate::types::ProcessorMode;
use console::style;
use figlet_rs::FIGfont;

/// Prints the application banner.
pub fn print_banner() {
    let standard_font = FIGfont::standard().unwrap();
    let figure = standard_font.convert("SweetByte").unwrap();
    println!("{}", style(figure).cyan().bold());
}

/// Prints a success message.
pub fn print_success(msg: &str) {
    println!("{} {}", style(">").green(), msg);
}

/// Prints an error message.
pub fn print_error(msg: &str) {
    eprintln!("{} Error: {}", style(">").red(), msg);
}

/// Displays information about a successful operation.
pub fn show_success_info(mode: ProcessorMode, output_path: &str) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };
    let clean_path = std::path::Path::new(output_path)
        .strip_prefix(".")
        .unwrap_or(std::path::Path::new(output_path))
        .to_string_lossy();
    println!(
        "{} File {} successfully: {}",
        style(">").green(),
        action,
        style(clean_path).blue()
    );
}

/// Displays information about a deleted source file.
pub fn show_source_deleted(path: &str) {
    let clean_path = std::path::Path::new(path)
        .strip_prefix(".")
        .unwrap_or(std::path::Path::new(path))
        .to_string_lossy();
    println!(
        "{} Source file deleted: {}",
        style(">").green(),
        style(clean_path).blue()
    );
}
