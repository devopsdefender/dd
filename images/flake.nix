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
            pkgs.qemu
            pkgs.qemu-utils
            pkgs.dosfstools
            pkgs.e2fsprogs
            pkgs.cryptsetup
            pkgs.util-linux
            pkgs.zstd
            pkgs.busybox
            pkgs.cpio
            pkgs.kmod
          ];
        };
      }
    );
}
