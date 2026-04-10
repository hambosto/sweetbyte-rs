{
  description = "A very small, very simple, yet very secure encryption tool written in rust.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs =
    {
      nixpkgs,
      systems,
      self,
      ...
    }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs (import systems) f;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      overlays.default = final: _prev: {
        sweetbyte-rs = final.callPackage ./nix/package.nix { };
      };

      packages = forAllSystems (system: {
        default = (pkgsFor system).callPackage ./nix/package.nix { };
      });

      devShells = forAllSystems (system: {
        default = (pkgsFor system).callPackage ./nix/shell.nix {
          sweetbyte-rs = self.packages.${system}.default;
        };
      });
    };
}
