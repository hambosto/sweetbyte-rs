use crate::types::ProcessorMode;
use crate::utils::format_bytes;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, modifiers, presets};
use console::style;
use figlet_rs::FIGfont;

/// Prints the application banner.
/// This function displays the "SweetByte" logo using ASCII art with a cyan, bold style.
pub fn print_banner() {
    let standard_font = FIGfont::standard().unwrap();
    let figure = standard_font.convert("SweetByte").unwrap();
    println!("{}", style(figure).cyan().bold());
}

/// Prints a success message.
/// This function prints a success message prefixed with a green ">" symbol.
///
/// # Arguments
///
/// * `msg` - The success message to display.
pub fn print_success(msg: &str) {
    println!("{} {}", style(">").green(), msg);
}

/// Prints an error message.
/// This function prints an error message prefixed with a red ">" symbol.
///
/// # Arguments
///
/// * `msg` - The error message to display.
pub fn print_error(msg: &str) {
    eprintln!("{} Error: {}", style(">").red(), msg);
}

/// Displays file information in a formatted table.
///
/// This function displays a list of files, including their sizes (in human-readable format)
/// and encryption statuses, in a table format. The table shows the following columns:
/// - No: A sequence number for each file.
/// - Name: The file name (truncated if too long).
/// - Size: The size of the file, formatted in a human-readable format.
/// - Status: Whether the file is "encrypted" or "unencrypted".
///
/// # Arguments
///
/// * `file_paths` - A vector of file paths to display.
/// * `file_sizes` - A vector of file sizes in bytes. The length of this vector must match the length of `file_paths`.
/// * `file_encrypted` - A vector of boolean flags indicating the encryption status of each file. The length of this vector must match the length of `file_paths`.
pub fn show_file_info(file_paths: &[String], file_sizes: &[u64], file_encrypted: &[bool]) {
    if file_paths.is_empty() {
        println!("No files found.");
        return;
    }

    if file_paths.len() != file_sizes.len() || file_paths.len() != file_encrypted.len() {
        println!("Error: Mismatched input arrays.");
        return;
    }

    println!();
    println!(
        "{} {} ",
        style("✓").green(),
        style(format!("Found {} file(s):", file_paths.len())).bold()
    );
    println!();

    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_FULL)
        .apply_modifier(modifiers::UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("No").add_attribute(Attribute::Bold),
            Cell::new("Name").add_attribute(Attribute::Bold),
            Cell::new("Size").add_attribute(Attribute::Bold),
            Cell::new("Status").add_attribute(Attribute::Bold),
        ]);

    for (i, path) in file_paths.iter().enumerate() {
        let file_status = if file_encrypted[i] {
            "encrypted"
        } else {
            "unencrypted"
        };

        let mut filename = path.clone();
        if filename.len() > 28 {
            filename = format!("{}...", &filename[..25]);
        }

        table.add_row(vec![
            Cell::new((i + 1).to_string()).add_attribute(Attribute::Bold),
            Cell::new(filename).fg(Color::Green),
            Cell::new(format_bytes(file_sizes[i])).add_attribute(Attribute::Bold),
            Cell::new(file_status).add_attribute(Attribute::Bold),
        ]);
    }

    println!("{table}");
    println!();
}

/// Displays success information after a successful operation.
///
/// This function prints a message indicating that a file has been successfully
/// processed (either encrypted or decrypted). The message includes the path of the
/// destination file.
///
/// # Arguments
///
/// * `mode` - The processing mode, which can be either `Encrypt` or `Decrypt`.
/// * `dest_path` - The path to the output file (should be pre-cleaned).
pub fn show_success_info(mode: ProcessorMode, dest_path: &str) {
    let action = match mode {
        ProcessorMode::Encrypt => "encrypted",
        ProcessorMode::Decrypt => "decrypted",
    };

    println!(
        "{} File {} successfully: {}",
        style(">").green(),
        action,
        style(dest_path).blue()
    );
}

/// Displays information about a deleted source file.
///
/// This function prints a message indicating that the source file has been deleted.
/// The message includes the path of the deleted file.
///
/// # Arguments
///
/// * `input_path` - The path to the deleted source file (should be pre-cleaned).
pub fn show_source_deleted(input_path: &str) {
    println!(
        "{} Source file deleted: {}",
        style(">").green(),
        style(input_path).blue()
    );
    println!();
}
