{
  lib,
  rustPlatform,
  stdenvAdapters,
  clangStdenv,
}:
(rustPlatform.buildRustPackage.override {
  stdenv = stdenvAdapters.useMoldLinker clangStdenv;
})
  (
    final:
    let
      inherit (lib.fileset) toSource unions;
      inherit (lib) licenses platforms;
    in
    {
      pname = "sweetbyte-rs";
      version = "v26.1.0";

      src = toSource {
        root = ../.;
        fileset = unions [
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
        license = licenses.mit;
        mainProgram = "sweetbyte-rs";
        platforms = platforms.unix;
      };
    }
  )
