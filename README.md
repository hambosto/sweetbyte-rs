<div align="center">

<img src="assets/logo.png" alt="SweetByte" width="256">

**File encryption that doesn't suck.**

[![CI](https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/hambosto/sweetbyte-rs/actions)
[![Rust](https://img.shields.io/badge/Rust-nightly-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square&logo=opensourceinitiative&logoColor=white)](https://opensource.org/licenses/MIT)
[![Nix](https://img.shields.io/badge/Nix-flake-purple?style=flat-square&logo=nixos&logoColor=white)](https://nixos.org/)

---

</div>

SweetByte encrypts your files. It does this well.

This is a Rust rewrite of my [original Go version](https://github.com/hambosto/sweetbyte). The Go version works fine, but I wanted something with better memory safety guarantees and cleaner concurrency.

## Table of Contents

- [Why this exists](#why-this-exists)
- [Not compatible with the Go version](#not-compatible-with-the-go-version)
- [Getting started](#getting-started)
- [Usage](#usage)
- [How it works](#how-it-works)
  - [Encryption pipeline](#encryption-pipeline)
  - [The header](#the-header)
  - [Key derivation](#key-derivation)
  - [Processing pipeline](#processing-pipeline)
  - [Reed-Solomon encoding](#reed-solomon-encoding)
- [Security notes](#security-notes)
- [Development](#development)
- [License](#license)

## Why this exists

Most encryption tools do one thing: encrypt. SweetByte does more:

- **Cascading encryption.** AES-256-GCM then XChaCha20-Poly1305. An attacker would need to break both ciphers, not just one.
- **Error correction.** Reed-Solomon encoding (4 data + 10 parity shards) means your encrypted file can survive some bit rot and still decrypt.
- **Proper key derivation.** Argon2id with 64MB memory cost. Brute-forcing your password won't be practical.
- **Concurrent processing.** Async pipeline with parallel chunk processing for fast encryption/decryption.
- **Interactive TUI.** Clean terminal interface with progress bars and visual feedback.

## Not compatible with the Go version

Files encrypted with the Go version won't work here. The file format changed. If you need to decrypt old files, use the Go version.

## Getting started

### Nix

```sh
nix run github:hambosto/sweetbyte-rs
```

Or add as a flake input and use the overlay:

```nix
{
  inputs.sweetbyte.url = "github:hambosto/sweetbyte-rs";

  outputs = { self, nixpkgs, sweetbyte, ... }:
  {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          nixpkgs.overlays = [ sweetbyte.overlays.default ];
          environment.systemPackages = [ pkgs.sweetbyte ];
        })
      ];
    };
  };
}
```

### Download a binary

Every push to `main` that passes CI refreshes the [`tip` prerelease](https://github.com/hambosto/sweetbyte-rs/releases/tag/tip) with binaries for Linux (x86_64, aarch64), macOS (aarch64), and Windows (x86_64, aarch64), with SHA-256 checksums.

### From source

```sh
git clone https://github.com/hambosto/sweetbyte-rs.git
cd sweetbyte-rs
cargo build --release
```

Binary ends up at `target/release/sweetbyte`.

### Install to system

```sh
cargo install --path .
```

## Usage

### Interactive mode

Just run it:

```sh
sweetbyte
```

You'll get prompts for everything. Pick encrypt or decrypt, choose a file, enter your password. Done.

### What happens during encryption

1. You select a file from the current directory (only the top level is scanned; hidden files and excluded paths like `target/`, `node_modules/`, `.git/`, and source/config files such as `*.rs`, `*.go`, `*.nix`, `*.toml`, `*.lock` are filtered out)
2. You enter a password (minimum 8 characters)
3. The file is compressed, padded, double-encrypted, and error-corrected
4. The encrypted file is saved with a `.swx` extension
5. You're asked if you want to delete the original file

### What happens during decryption

1. You select a `.swx` file from the current directory
2. You enter the password used during encryption
3. The file is error-corrected, double-decrypted, unpadded, and decompressed
4. The original file is restored with its original name
5. You're asked if you want to delete the encrypted file

## How it works

### Encryption pipeline

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

The table shows the logical (pre-RS) field sizes. In reality, each field is individually Reed-Solomon encoded (4+10 shards) and hex-serialized inside the blob, then the whole blob is compressed with zstd. The final `[4 bytes: compressed length LE][compressed blob]` on disk caps the compressed section at 1 KiB. Deserialization fails fast if magic bytes or version don't match. The HMAC uses constant-time comparison.

### Key derivation

Argon2id with these parameters:

- Memory: 64 MiB (65536 KiB)
- Time cost: 3 iterations
- Parallelism: 4 threads
- Output: 64 bytes

The password you type is SHA-256-hashed first, and that digest (not the raw password) is what goes into Argon2id.

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

Files get read in 256KB chunks. Channel buffer size matches CPU core count. The executor processes chunks in parallel via tokio's `spawn_blocking` with a semaphore for concurrency control. A reordering buffer ensures the writer outputs chunks in order. Each resulting chunk is written to the `.swx` body as `[4 bytes: length LE][data]`; the decryptor reads the same length-prefixed stream (chunks capped at 1 MiB).

### Reed-Solomon encoding

Each encoded block has this format:

```
[4 bytes: original length LE] [shard 0: 4-byte CRC32 + data] [shard 1: ...] ... [shard N: ...]
```

CRC32 validates each shard before decoding. Corrupted shards get reconstructed from parity.

## Security notes

- Your password matters. Use something strong (minimum 8 characters enforced).
- Constant-time MAC comparison prevents timing attacks.
- Keys and passwords are zeroized on drop for secure memory handling.
- "Delete source file" in interactive mode calls `remove_file`. That's it. SSDs and journaling filesystems may retain data.
- Not hardened against hardware side-channels. If that's your threat model, look elsewhere.

## Development

### Prerequisites

- Rust 1.85+ toolchain (nightly rustfmt required for `cargo fmt`; CI runs on nightly)
- Nix (optional, for reproducible builds)

### Commands

```sh
cargo fmt              # Format code
cargo clippy           # Run clippy (51 individually-configured lints)
cargo test             # Run tests
cargo build --release  # Build optimized binary
```

The project enforces strict code quality via 51 clippy lints, including warnings for: indexing/slicing, unwrap/expect usage, panics, unsafe blocks, arithmetic side effects, async anti-patterns, float comparisons, and cast issues. These are relaxed in test code via `clippy.toml`.

Release builds use maximum optimizations: `codegen-units = 1`, `lto = "fat"`, `opt-level = 3`, `panic = "abort"`, and debug symbol stripping.

Code formatting uses `rustfmt` with merged imports, grouped by std/external/local, and a 200-character max line width.

### CI/CD

GitHub Actions workflows:

- **CI** (`check.yml`): Runs on push/PR to `main`. Verifies formatting, runs clippy, executes tests. A second job (push only) builds the Nix package and pushes it to the Cachix binary cache.
- **Prerelease** (`prerelease.yml`): After CI passes on `main`, rotates the `tip` prerelease with binaries for Linux (x86_64, aarch64), macOS (aarch64), and Windows (x86_64, aarch64), plus SHA-256 checksums.
- **Flake Updates** (`update.yml`): Hourly dependency updates via `DeterminateSystems/update-flake-lock`.

Dependabot is configured for daily Cargo and GitHub Actions updates.

## License

This project is licensed under the [MIT License](LICENSE).
