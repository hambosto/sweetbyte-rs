# SweetByte

A multi-layered file encryption tool with error correction, rewritten in Rust from the [original Go implementation](https://github.com/hambosto/sweetbyte).

SweetByte chains AES-256-GCM and XChaCha20-Poly1305 encryption with Argon2id key derivation and Reed-Solomon error correction, producing files that are both secure and resilient to corruption.

## Features

- **Dual-layer encryption** - AES-256-GCM followed by XChaCha20-Poly1305 provides defense in depth
- **Strong key derivation** - Argon2id protects against brute-force attacks
- **Error correction** - Reed-Solomon encoding allows file recovery from partial corruption
- **Tamper-proof headers** - HMAC-SHA256 authentication with constant-time comparison
- **Concurrent streaming** - Chunk-based processing keeps memory usage low for large files
- **Interactive and CLI modes** - Guided wizard or scriptable command-line interface

## Installation

### From Source

Requires Rust 2024 edition or later.

```sh
git clone https://github.com/hambosto/sweetbyte-rs.git
cd sweetbyte-rs
cargo build --release
```

The binary will be at `target/release/sweetbyte-rs`.

### Cargo Install

```sh
cargo install --path .
```

## Usage

### Interactive Mode

Run without arguments to start the interactive wizard:

```sh
sweetbyte-rs
```

Or explicitly:

```sh
sweetbyte-rs interactive
```

The wizard will guide you through selecting files, entering passwords, and optionally deleting source files after processing.

### Command-Line Mode

Encrypt a file:

```sh
sweetbyte-rs encrypt -i document.txt -o document.swx
```

Decrypt a file:

```sh
sweetbyte-rs decrypt -i document.swx -o document.txt
```

If `-o` is omitted, the output path is derived automatically (adding `.swx` for encryption, removing it for decryption).

If `-p` is omitted, you will be prompted for a password:

```sh
sweetbyte-rs encrypt -i document.txt -p "your-password"
```

## How It Works

### Encryption Pipeline

Data flows through these stages:

```
Input -> Zlib Compression -> PKCS7 Padding -> AES-256-GCM -> XChaCha20-Poly1305 -> Reed-Solomon -> Output
```

1. **Compression** - Zlib reduces file size before encryption
2. **Padding** - PKCS7 pads data to a fixed block size
3. **AES-256-GCM** - First encryption layer using the industry standard
4. **XChaCha20-Poly1305** - Second encryption layer with extended nonce
5. **Reed-Solomon** - Error correction encoding for corruption resilience

Decryption reverses this pipeline exactly.

### File Format

Encrypted files use the `.swx` extension with this structure:

```
[ Header (variable) ] [ Chunk 1 ] [ Chunk 2 ] ... [ Chunk N ]
```

The header contains:

- Magic bytes (`0xCAFEBABE`)
- Salt for key derivation
- Metadata (version, flags, original size)
- HMAC-SHA256 authentication tag

Each section is individually Reed-Solomon encoded, so the header can be recovered even if partially corrupted.

Data chunks are prefixed with a 4-byte length header for streaming decryption.

### Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Argon2id time cost | 3 |
| Argon2id memory | 64 KB |
| Argon2id parallelism | 4 |
| Key length | 64 bytes (split between ciphers) |
| Salt length | 32 bytes |
| AES nonce | 12 bytes |
| XChaCha20 nonce | 24 bytes |

Reed-Solomon uses 4 data shards and 10 parity shards, providing high redundancy.

## Project Structure

```
src/
  cli.rs          - Command-line argument parsing and interactive mode
  processor.rs    - High-level encrypt/decrypt orchestration
  compression.rs  - Zlib compression/decompression
  padding.rs      - PKCS7 padding implementation
  config.rs       - Constants and parameters
  types.rs        - Shared type definitions
  crypto/
    aes.rs        - AES-256-GCM implementation
    chacha.rs     - XChaCha20-Poly1305 implementation
    cipher.rs     - Cipher abstraction layer
    derive.rs     - Argon2id key derivation
  encoding/
    reed_solomon.rs - Reed-Solomon encoding/decoding
    shards.rs     - Shard management
  header/
    mod.rs        - Header struct and serialization
    serializer.rs - Header writing
    deserializer.rs - Header reading
    mac.rs        - HMAC authentication
    section.rs    - TLV section handling
  stream/
    pipeline.rs   - Concurrent processing pipeline
    executor.rs   - Thread pool executor
    processor.rs  - Chunk transformation logic
    reader.rs     - Buffered chunk reader
    writer.rs     - Sequential chunk writer
    buffer.rs     - Ordering buffer for parallel output
  file/
    discovery.rs  - File discovery for interactive mode
    operations.rs - Path manipulation and file creation
    validation.rs - File validation utilities
  ui/
    display.rs    - Status and file info display
    progress.rs   - Progress bar handling
    prompt.rs     - User input prompts
```

## Differences from the Go Version

This Rust port maintains feature parity with the original while taking advantage of Rust's strengths:

- **Memory safety** - No garbage collector, with compile-time guarantees
- **Performance** - Concurrent chunk processing with crossbeam channels
- **Error handling** - Uses `anyhow` for ergonomic error propagation

The file format is fully compatible with the Go version.

## Security Considerations

- **Password strength matters** - Use long, unique passwords. Argon2id helps, but weak passwords are still vulnerable.
- **Secure your environment** - If your system is compromised, your password can be captured.
- **File deletion is not guaranteed** - Secure deletion depends on hardware and filesystem. SSD wear leveling and journaling filesystems may retain data.
- **Side-channel attacks** - While constant-time comparison is used for MAC verification, this tool is not hardened against all side-channel attacks.

## Running Tests

```sh
cargo test
```

The test suite includes roundtrip encryption/decryption and wrong-password rejection tests.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome. For major changes, open an issue first to discuss the approach.

Please run `cargo fmt` and `cargo clippy` before submitting.
