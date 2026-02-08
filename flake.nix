{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      nixpkgs,
      systems,
      rust-overlay,
      self,
      ...
    }:
    let
      withOverlay = pkgs: pkgs.extend (import rust-overlay);
      eachSystem =
        fn:
        nixpkgs.lib.genAttrs (import systems) (system: fn (withOverlay nixpkgs.legacyPackages.${system}));
    in
    {
      overlays.default = final: prev: {
        sweetbyte-rs = final.callPackage ./nix/package.nix {
          rustPlatform = final.makeRustPlatform {
            cargo = final.rust-bin.stable.latest.default;
            rustc = final.rust-bin.stable.latest.default;
          };
        };
      };

      packages = eachSystem (
        pkgs:
        let
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };
        in
        {
          default = pkgs.callPackage ./nix/package.nix {
            rustPlatform = pkgs.makeRustPlatform {
              cargo = rustToolchain;
              rustc = rustToolchain;
            };
          };
        }
      );

      devShells = eachSystem (pkgs: {
        default = pkgs.callPackage ./nix/shell.nix {
          sweetbyte-rs = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      });
    };
}
