{

  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      fenix,
      flake-utils,
      nixpkgs,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages.default =
        let
          toolchain = fenix.packages.${system}.minimal.toolchain;
          pkgs = nixpkgs.legacyPackages.${system};
        in
        (pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        }).buildRustPackage
          {
            pname = "sweetbyte-rs";
            version = self.shortRev or self.dirtyShortRev or "unknown";

            src = ./.;

            cargoLock.lockFile = ./Cargo.lock;

            doCheck = false;
            CARGO_BUILD_INCREMENTAL = "false";
            RUST_BACKTRACE = "full";

            meta = {
              description = "A very small, very simple, yet very secure encryption tool written in rust.";
              homepage = "https://github.com/hambosto/sweetbyte-rs";
              license = pkgs.lib.licenses.gpl3Plus;
              mainProgram = "sweetbyte-rs";
            };
          };
    });
}
