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
    println!("{} {}", style("✔").green(), msg);
}

/// Prints an error message.
pub fn print_error(msg: &str) {
    eprintln!("{} {}", style("✘").red(), msg);
}

/// Prints an informational message.
pub fn print_info(msg: &str) {
    println!("{} {}", style("ℹ").blue(), msg);
}

/// Displays information about the file being processed.
pub fn show_processing_info(mode: ProcessorMode, file: &str) {
    let mode_str = match mode {
        ProcessorMode::Encrypt => "Encrypting",
        ProcessorMode::Decrypt => "Decrypting",
    };
    println!("> {} {}...", mode_str, file);
}

/// Displays information about a successful operation.
pub fn show_success_info(mode: ProcessorMode, output_path: &str) {
    let action = match mode {
        ProcessorMode::Encrypt => "Encrypted",
        ProcessorMode::Decrypt => "Decrypted",
    };
    println!(
        "\n{} File {} successfully: {}",
        style("✔").green(),
        action,
        output_path
    );
}

/// Displays information about a deleted source file.
pub fn show_source_deleted(path: &str) {
    println!("{} Source file deleted: {}", style("✔").green(), path);
}
