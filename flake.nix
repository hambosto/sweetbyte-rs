{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
    garnix-lib.url = "github:garnix-io/garnix-lib";
  };

  nixConfig = {
    extra-substituters = [ "https://cache.garnix.io" ];
    extra-trusted-public-keys = [ "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g=" ];
  };

  outputs =
    {
      nixpkgs,
      systems,
      rust-overlay,
      garnix-lib,
      self,
      ...
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs (import systems);

      pkgsFor = system: nixpkgs.legacyPackages.${system}.extend rust-overlay.overlays.default;

      mkPackage =
        pkgs: rustChannel:
        pkgs.callPackage ./nix/package.nix {
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustChannel;
            rustc = rustChannel;
          };
        };

      flakeOutputs = {
        overlays.default = final: _: {
          sweetbyte-rs = mkPackage final final.rust-bin.stable.latest.default;
        };

        packages = forAllSystems (
          system:
          let
            pkgs = pkgsFor system;
          in
          {
            default = mkPackage pkgs pkgs.rust-bin.nightly.latest.default;
          }
        );

        devShells = forAllSystems (system: {
          default = (pkgsFor system).callPackage ./nix/shell.nix {
            sweetbyte-rs = self.packages.${system}.default;
          };
        });
      };

      garnixOutputs = garnix-lib.lib.mkModules {
        modules = [ ];
        config =
          { ... }:
          {
            garnix.deployBranch = "main";
          };
      };
    in
    flakeOutputs // garnixOutputs;
}
