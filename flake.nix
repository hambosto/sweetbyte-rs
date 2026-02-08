{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
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
      applyOverlays = pkgs: pkgs.extend rust-overlay.overlays.default;
      forAllSystems = nixpkgs.lib.genAttrs (import systems);
      pkgsFor = system: applyOverlays nixpkgs.legacyPackages.${system};
      mkRustToolchain =
        pkgs:
        pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
            "rustfmt"
          ];
        };

      mkRustPlatform =
        pkgs: toolchain:
        pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };
    in
    {
      overlays.default = final: prev: {
        sweetbyte-rs = final.callPackage ./nix/package.nix {
          rustPlatform = mkRustPlatform final final.rust-bin.stable.latest.default;
        };
      };

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          toolchain = mkRustToolchain pkgs;
        in
        {
          default = pkgs.callPackage ./nix/package.nix {
            rustPlatform = mkRustPlatform pkgs toolchain;
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.callPackage ./nix/shell.nix {
            sweetbyte-rs = self.packages.${system}.default;
          };
        }
      );
    };
}
