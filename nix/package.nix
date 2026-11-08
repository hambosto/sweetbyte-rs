{
  date ? "19700101",
  lib,
  pkg-config,
  rev ? "unknown",
  rustPlatform,
  version ? "git",
  zstd,
}:
rustPlatform.buildRustPackage {
  pname = "sweetbyte";
  inherit version;

  src = ../.;

  cargoLock.lockFile = ../Cargo.lock;
  doCheck = false;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ zstd ];

  SWEETBYTE_BUILD_VERSION = "unstable ${date} (commit ${rev})";

  meta = {
    description = "A very small, very simple, yet very secure encryption tool written in rust.";
    homepage = "https://github.com/hambosto/sweetbyte-rs";
    license = lib.licenses.mit;
    mainProgram = "sweetbyte";
    platforms = lib.platforms.unix;
  };
}