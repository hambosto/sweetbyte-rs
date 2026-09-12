{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      flake-utils,
      nixpkgs,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
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
      }
    )
    // {
      overlays.default = final: prev: {
        inherit (self.packages.${prev.stdenv.system}) sweetbyte;
      };
    };
}
