{

  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    fenix.url = "github:nix-community/fenix";
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
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        toolchain = fenix.packages.${system}.minimal.toolchain;
        devToolchain = fenix.packages.${system}.complete.toolchain;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          pname = "sweetbyte-rs";
          version = self.shortRev or self.dirtyShortRev or "unknown";

          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          doCheck = true;

          meta = {
            description = "A very small, very simple, yet very secure encryption tool written in rust.";
            homepage = "https://github.com/hambosto/sweetbyte-rs";
            license = pkgs.lib.licenses.gpl3Plus;
            mainProgram = "sweetbyte-rs";
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [ devToolchain ];

          shellHook = ''
            echo "🦀 Rust development environment for sweetbyte-rs"
            echo "Available tools: cargo, rust-analyzer, clippy, rustfmt, cargo-watch, cargo-edit"
          '';
        };
      }
    );
}
