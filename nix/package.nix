{
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage (final: {
  pname = "sweetbyte-rs";
  version = "v26.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../assets
      ../src
      ../Cargo.lock
      ../Cargo.toml
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  meta = {
    description = "A very small, very simple, yet very secure encryption tool written in rust.";
    homepage = "https://github.com/hambosto/sweetbyte-rs";
    license = lib.licenses.mit;
    mainProgram = "sweetbyte-rs";
    platforms = lib.platforms.unix;
  };
})
