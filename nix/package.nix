{
  self,
  lib,
  rustPlatform,
}:
let
  fmtDate =
    raw:
    let
      year = builtins.substring 0 4 raw;
      month = builtins.substring 4 2 raw;
      day = builtins.substring 6 2 raw;
    in
    "${year}-${month}-${day}";
in
rustPlatform.buildRustPackage {
  pname = "sweetbyte-rs";
  version = "unstable-${fmtDate self.lastModifiedDate}-${self.shortRev or "dirty"}";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src
      ../Cargo.lock
      ../Cargo.toml
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  doCheck = false;

  SWEETBYTE_BUILD_VERSION = "unstable ${fmtDate self.lastModifiedDate} (commit ${self.rev or "dirty"})";

  meta = {
    description = "A very small, very simple, yet very secure encryption tool written in rust.";
    homepage = "https://github.com/hambosto/sweetbyte-rs";
    license = lib.licenses.mit;
    mainProgram = "sweetbyte-rs";
    platforms = lib.platforms.unix;
  };
}
