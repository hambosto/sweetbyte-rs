{
  date ? "19700101",
  lib,
  rev ? "unknown",
  rustPlatform,
  version ? "git",
}:
rustPlatform.buildRustPackage {
  pname = "sweetbyte";
  inherit version;

  src = ../.;

  cargoLock.lockFile = ../Cargo.lock;
  doCheck = false;

  SWEETBYTE_BUILD_VERSION = "unstable ${date} (commit ${rev})";

  meta = {
    description = "A very small, very simple, yet very secure encryption tool written in rust.";
    homepage = "https://github.com/hambosto/sweetbyte-rs";
    license = lib.licenses.mit;
    mainProgram = "sweetbyte";
    platforms = lib.platforms.unix;
  };
}
