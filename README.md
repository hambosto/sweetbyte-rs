# SweetByte

A resilient, secure, and efficient file encryption tool built in Rust.

## Features

- 🔐 **Strong Encryption**: Supports both AES-256-GCM and ChaCha20-Poly1305 algorithms
- 🔑 **Secure Key Derivation**: Uses Argon2id for password-based key derivation
- 🗜️ **Compression**: Built-in compression support using DEFLATE
- 🚀 **Async I/O**: High-performance async operations powered by Tokio
- 🎯 **Interactive Mode**: User-friendly TUI for encrypting/decrypting files
- 💻 **CLI Mode**: Command-line interface for automation and scripting
- 🛡️ **Data Integrity**: HMAC-based authentication for tamper detection
- 📁 **Batch Processing**: Encrypt/decrypt entire directories
- 🔄 **Reed-Solomon Error Correction**: Optional error correction for enhanced resilience
- ⚡ **Multi-threaded**: Leverages all CPU cores for optimal performance

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo

### Build from Source

```bash
git clone https://github.com/hambosto/sweetbyte-rs.git
cd sweetbyte-rs
cargo build --release
```

The compiled binary will be available at `target/release/sweetbyte`.

### Install via Cargo

```bash
cargo install --path .
```

## Usage

### Interactive Mode

Simply run the binary without any arguments to enter interactive mode:

```bash
sweetbyte
```

The interactive mode provides a guided workflow for:
- Selecting files to encrypt/decrypt
- Choosing encryption algorithms
- Setting compression levels
- Configuring encryption options

### CLI Mode

#### Encrypt a File

```bash
sweetbyte encrypt --input /path/to/file.txt --password mypassword
```

With optional output path:

```bash
sweetbyte encrypt --input file.txt --output encrypted.bin --password mypassword
```

Delete source file after encryption:

```bash
sweetbyte encrypt --input file.txt --password mypassword --delete
```

#### Decrypt a File

```bash
sweetbyte decrypt --input encrypted.bin --password mypassword
```

With optional output path:

```bash
sweetbyte decrypt --input encrypted.bin --output decrypted.txt --password mypassword
```

Delete encrypted file after decryption:

```bash
sweetbyte decrypt --input encrypted.bin --password mypassword --delete
```

### Directory Processing

SweetByte can encrypt or decrypt entire directories:

```bash
sweetbyte encrypt --input /path/to/directory --password mypassword
sweetbyte decrypt --input /path/to/directory --password mypassword
```

## Security Features

### Encryption Algorithms

- **AES-256-GCM**: Industry-standard encryption with authenticated encryption
- **ChaCha20-Poly1305**: Modern, fast encryption algorithm

### Key Derivation

- **Argon2id**: Memory-hard password hashing algorithm
- Configurable parameters for memory cost, time cost, and parallelism
- Random salt generation for each encryption operation

### Data Integrity

- HMAC-SHA256 authentication tags
- Prevents tampering and ensures data authenticity
- Secure header structure with MAC verification

### File Format

SweetByte uses a custom file format with:
- Magic bytes for file identification
- Version information for forward compatibility
- Encrypted metadata section
- Authentication tags
- Optional error correction codes

## Performance

SweetByte is optimized for performance:

- **Async I/O**: Non-blocking file operations using Tokio
- **Worker Pool**: Configurable thread pool for parallel processing
- **Buffered Streaming**: Efficient memory usage for large files
- **Optimized Build**: Release builds use LTO and maximum optimization

## Architecture

The project is organized into several modules:

- `cli/`: Command-line interface and argument parsing
- `crypto/`: Cryptographic operations (AES, ChaCha20, key derivation)
- `compression/`: Compression and decompression logic
- `encoding/`: Reed-Solomon error correction
- `file_manager/`: File discovery and I/O operations
- `header/`: File header serialization and deserialization
- `interactive/`: Interactive TUI workflow
- `padding/`: PKCS7 padding operations
- `processor/`: High-level encryption and decryption logic
- `stream/`: Async streaming pipeline with worker pool
- `tui/`: Terminal UI components (progress bars, prompts)

## Configuration

### Excluded Files

SweetByte automatically excludes certain file types from encryption:
- Encrypted files (`.sweet` extension)
- System files
- Hidden files (configurable)

### Constants

Default encryption parameters can be found in `src/config/constants.rs`:
- Buffer sizes
- Argon2 parameters
- Compression levels
- File extensions

## Development

### Running Tests

```bash
cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy
```

### Build Profiles

Development build:
```bash
cargo build
```

Optimized release build:
```bash
cargo build --release
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security Considerations

- Always use strong, unique passwords
- Keep your passwords secure and never share them
- Backup important data before encryption
- Verify decrypted files to ensure integrity
- Be aware that forgetting your password means permanent data loss

## Acknowledgments

Built with these excellent Rust crates:
- `aes-gcm` - AES-GCM encryption
- `chacha20poly1305` - ChaCha20-Poly1305 encryption
- `argon2` - Argon2 key derivation
- `tokio` - Async runtime
- `clap` - Command-line parsing
- `inquire` - Interactive prompts
- `indicatif` - Progress bars
- And many more!

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/yourusername/sweetbyte-rs).
