{
  description = "A Zip file checker, now in Zig";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

    flake-utils.url = "github:numtide/flake-utils";

    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs = {
      nixpkgs.follows = "nixpkgs";
      flake-utils.follows = "flake-utils";
    };

    # Using this fork until https://github.com/nix-community/zon2nix/pull/8 is merged.
    zon2nix.url = "github:acristoffers/zon2nix";
    zon2nix.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    zig-overlay,
    zon2nix,
    gitignore,
    ...
  }: let
    # Our supported systems are the same supported systems as the Zig binaries
    systems = builtins.attrNames zig-overlay.packages;
  in
    flake-utils.lib.eachSystem systems (
      system: let
        pkgs = import nixpkgs {inherit system;};
        zig = zig-overlay.packages.${system}.master;
        zon2nixbin = zon2nix.packages.${system}.default;
        inherit (gitignore.lib) gitignoreSource;

        pure = pkgs.stdenvNoCC.mkDerivation {
          name = "pure";
          version = "master";
          src = gitignoreSource ./.;
          nativeBuildInputs = [zig];
          dontConfigure = true;
          dontInstall = true;
          doCheck = true;
          buildPhase = ''
            mkdir -p .cache
            ln -s ${pkgs.callPackage ./deps.nix {}} .cache/p
            zig build install \
              --cache-dir $(pwd)/zig-cache \
              --global-cache-dir $(pwd)/.cache \
              -Dcpu=baseline \
              -Doptimize=ReleaseSafe \
              --prefix $out
          '';
          checkPhase = ''
            zig build test \
              --cache-dir $(pwd)/zig-cache \
              --global-cache-dir $(pwd)/.cache \
              -Dcpu=baseline \
              --summary all
          '';
        };
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            zig
            zon2nixbin
          ];
        };
        formatter = pkgs.alejandra;
        packages.default = pure;
        checks = {inherit pure;};
      }
    );
}
