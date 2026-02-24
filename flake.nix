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
      forAllSystems = f: nixpkgs.lib.genAttrs (import systems) f;

      pkgsFor = system: nixpkgs.legacyPackages.${system}.extend rust-overlay.overlays.default;

      mkRustPlatform =
        pkgs:
        let
          toolchain = pkgs.rust-bin.nightly.latest.default;
        in
        pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };

    in
    {
      overlays.default = final: prev: {
        sweetbyte-rs = final.callPackage ./nix/package.nix {
          rustPlatform = mkRustPlatform final;
        };
      };

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.callPackage ./nix/package.nix {
            rustPlatform = mkRustPlatform pkgs;
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
