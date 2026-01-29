{
  lib,
  cmake,
  rustPlatform,
}:
rustPlatform.buildRustPackage (
  final:
  let
    inherit (lib.fileset) toSource unions;
    inherit (lib) licenses platforms;
  in
  {
    pname = "sweetbyte-rs";
    version = "26.1.0";

    src = toSource {
      root = ../.;
      fileset = unions [
        ../assets
        ../src
        ../Cargo.lock
        ../Cargo.toml
      ];
    };

    nativeBuildInputs = [
      cmake
    ];

    cargoLock.lockFile = ../Cargo.lock;

    meta = {
      description = "A very small, very simple, yet very secure encryption tool written in rust.";
      homepage = "https://github.com/hambosto/sweetbyte-rs";
      license = licenses.mit;
      mainProgram = "sweetbyte-rs";
      platforms = platforms.unix;
    };
  }
)
