<div align="center">

<img src="assets/logo.png" alt="SweetByte" width="256" height="256">

**File encryption that doesn't suck.**

[![CI](https://github.com/hambosto/sweetbyte-rs/actions/workflows/check.yml/badge.svg)](https://github.com/hambosto/sweetbyte-rs/actions)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

</div>

---

SweetByte encrypts your files. It does this well.

This is a Rust rewrite of my [original Go version](https://github.com/hambosto/sweetbyte). The Go version works fine, but I wanted something with better memory safety guarantees and cleaner concurrency.

## Why this exists

Most encryption tools do one thing: encrypt. SweetByte does more:

- **Cascading encryption.** AES-256-GCM then XChaCha20-Poly1305. An attacker would need to break both ciphers, not just one.
- **Error correction.** Reed-Solomon encoding (4 data + 10 parity shards) means your encrypted file can survive some bit rot and still decrypt.
- **Proper key derivation.** Argon2id with 64MB memory cost. Brute-forcing your password won't be practical.

## Not compatible with the Go version

Files encrypted with the Go version won't work here. The file format changed. If you need to decrypt old files, use the Go version.

## Getting started

### Nix

```sh
nix run github:hambosto/sweetbyte-rs
```

### From source

```sh
git clone https://github.com/hambosto/sweetbyte-rs.git
cd sweetbyte-rs
cargo build --release
```

Binary ends up at `target/release/sweetbyte-rs`.

## Usage

### Interactive mode

Just run it:

```sh
sweetbyte-rs
```

You'll get prompts for everything. Pick encrypt or decrypt, choose a file, enter your password. Done.

## How it works

The encryption pipeline, in order:

1. **Compress** with zstd level 1
2. **Pad** with PKCS7 to 128-byte blocks
3. **Encrypt** with AES-256-GCM (12-byte random nonce)
4. **Encrypt again** with XChaCha20-Poly1305 (24-byte random nonce)
5. **Encode** with Reed-Solomon (4 data + 10 parity shards)

Decryption runs this in reverse. After decryption, the BLAKE3 hash of the output is checked against what's stored in the header.

### The header

Each encrypted file starts with a compressed and Reed-Solomon encoded header. This provides resilience against header corruption:

```
[4 bytes: compressed section length LE] [compressed + RS-encoded section data]
```

The section itself (before RS encoding) contains:

| Field      | Size     | Notes                                         |
| ---------- | -------- | --------------------------------------------- |
| Salt       | 32 bytes | Random, for Argon2id                          |
| Parameters | variable | Magic `0xDEADBEEF` + version `0x0002`         |
| Metadata   | variable | Original filename, size, BLAKE3 hash          |
| MAC        | 32 bytes | HMAC-SHA256 of (salt + parameters + metadata) |

The entire section is compressed with zstd and Reed-Solomon encoded (4+10 shards) before writing. Deserialization fails fast if magic bytes or version don't match. The HMAC uses constant-time comparison.

### Key derivation

Argon2id with these parameters:

- Memory: 64 MiB (65536 KiB)
- Time cost: 3 iterations
- Parallelism: 4 threads
- Output: 64 bytes

The 64-byte Argon2id output is fed through HKDF-SHA256 to derive three independent keys:

- **First key** (32 bytes): Used for AES-256-GCM encryption
- **Second key** (32 bytes): Used for XChaCha20-Poly1305 encryption
- **Third key** (32 bytes): Used for HMAC-SHA256 signing

### Processing pipeline

Three stages, running concurrently:

```
[Reader Task] -----> [Executor] -----> [Writer Task]
 tokio async       spawn_blocking       tokio async
```

Files get read in 256KB chunks. Channel buffer size matches CPU core count. The executor processes chunks in parallel via tokio's `spawn_blocking` with a semaphore for concurrency control. A reordering buffer ensures the writer outputs chunks in order.

### Reed-Solomon encoding

Each encoded block has this format:

```
[4 bytes: original length LE] [shard 0: 4-byte CRC32 + data] [shard 1: ...] ... [shard N: ...]
```

CRC32 validates each shard before decoding. Corrupted shards get reconstructed from parity.

## Code structure

```
src/
├── lib.rs                  # Library root, global allocator
├── main.rs                 # Entry point, interactive mode, async runtime
├── config.rs               # All constants, HKDF info strings
├── types.rs                # Processing enum, Task, TaskResult
├── secret.rs               # Wrapper types for sensitive data
├── validation.rs           # Validated newtypes (Filename, FileSize, etc.)
├── files.rs                # File discovery, BLAKE3 hashing
├── encoding.rs             # Reed-Solomon with CRC32 per-shard validation
├── compression.rs          # zstd wrapper with compression levels
├── padding.rs              # PKCS7 padding wrapper
│
├── core/
│   ├── mod.rs              # Cipher struct holding both algorithms
│   ├── aes_gcm.rs          # AES-256-GCM implementation
│   ├── chacha20poly1305.rs # XChaCha20-Poly1305 implementation
│   ├── key.rs              # Argon2id + HKDF key derivation
│   └── signer.rs           # HMAC-SHA256 with constant-time comparison
│
├── header/
│   ├── mod.rs              # Header module exports
│   ├── metadata.rs         # Metadata struct (filename, size, hash)
│   ├── parameters.rs       # Parameters struct (magic, version)
│   ├── section.rs          # SectionEncoder for RS-encoded header sections
│   ├── serializer.rs       # Header serialization
│   └── deserializer.rs     # Header deserialization
│
├── engine/
│   ├── mod.rs              # Engine, sets up the pipeline
│   ├── reader.rs           # Produces tasks from input file
│   ├── executor.rs         # Parallel task processing
│   ├── writer.rs           # Consumes results, writes output
│   ├── buffer.rs           # Reordering buffer for out-of-order results
│   └── pipeline.rs         # The actual encrypt/decrypt stages
│
└── ui/
    ├── mod.rs              # UI module exports
    ├── display.rs          # Terminal tables, banner display
    ├── input.rs            # Interactive prompts for user input
    └── progress.rs         # Progress bar display
```

## Security notes

- Your password matters. Use something strong (minimum 8 characters enforced).
- Constant-time MAC comparison prevents timing attacks.
- Keys and passwords are zeroized on drop for secure memory handling.
- "Delete source file" in interactive mode calls `remove_file`. That's it. SSDs and journaling filesystems may retain data.
- Not hardened against hardware side-channels. If that's your threat model, look elsewhere.

## Development

```sh
cargo fmt
cargo clippy  # pedantic lint level
cargo test
```

CI runs on Ubuntu via GitHub Actions.

## License

This project is licensed under the [MIT License](LICENSE).
