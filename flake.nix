{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      inherit (nixpkgs.lib) genAttrs;
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forEachSystem =
        perSystem:
        genAttrs systems (
          system:
          let
            pkgs = nixpkgs.legacyPackages.${system};
          in
          perSystem { inherit pkgs system; }
        );
    in
    {
      overlays.default = final: prev: {
        sweetbyte-rs = final.callPackage ./nix/package.nix { inherit self; };
      };

      packages = forEachSystem (
        { pkgs, ... }: {
          default = pkgs.callPackage ./nix/package.nix { inherit self; };
        }
      );

      devShells = forEachSystem (
        { pkgs, system }: {
          default = pkgs.callPackage ./nix/shell.nix {
            sweetbyte-rs = self.packages.${system}.default;
          };
        }
      );
    };
}
