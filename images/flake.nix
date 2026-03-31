{
  description = "DevOps Defender — confidential VM image builder";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      in {
        devShells.default = pkgs.mkShell {
          name = "dd-image-builder";
          buildInputs = [
            pkgs.mkosi-full
            pkgs.qemu
            pkgs.qemu-utils
            pkgs.dosfstools
            pkgs.e2fsprogs
            pkgs.cryptsetup
            pkgs.squashfsTools
            pkgs.mtools
            pkgs.apt
            pkgs.dpkg
            pkgs.debootstrap
          ];
        };
      }
    );
}
