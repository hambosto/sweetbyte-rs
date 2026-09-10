{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay/stable";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        toolchain = pkgs.rust-bin.stable.latest.default;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };
        fmtDate =
          raw:
          let
            year = builtins.substring 0 4 raw;
            month = builtins.substring 4 2 raw;
            day = builtins.substring 6 2 raw;
          in
          "${year}-${month}-${day}";
        rev = self.rev or "dirty";
        date = "${fmtDate self.lastModifiedDate}";
        version = "unstable-${fmtDate self.lastModifiedDate}-${self.shortRev or "dirty"}";
      in
      {
        packages = {
          sweetbyte = pkgs.callPackage ./nix/package.nix {
            inherit
              date
              rev
              rustPlatform
              version
              ;
          };
          default = self.packages.${system}.sweetbyte;
        };

        devShells = {
          default = pkgs.callPackage ./nix/shell.nix {
            inherit (self.packages.${system}) sweetbyte;
          };
        };

        formatter = pkgs.nixfmt-tree;
      }
    )
    // {
      overlays.default = _: prev: {
        inherit (self.packages.${prev.stdenv.system}) sweetbyte;
      };
    };
}
