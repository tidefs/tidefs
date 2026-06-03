# TideFS K7-VAL: Nix build environment for kmod-posix-vfs compile validation.
#
# Provides a Nix derivation that enters a Linux 7.0 kernel build
# environment with Rust-for-Linux toolchain support, suitable for
# running `scripts/compile-kmod-posix-vfs.sh`.
#
# This is the repeatable build environment for kmod compile validation.
# It extends the existing
# nix/packages/linux-7.0-kernel.nix package with the kernel dev output
# needed for out-of-tree module compilation.
#
# Usage:
#   nix build .#kmodPosixVfsBuildEnv
#   nix develop .#kmodPosixVfsBuildEnv
#
# Or directly:
#   nix-shell nix/kmod-posix-vfs-build.nix --run \
#     'bash scripts/compile-kmod-posix-vfs.sh'

{
  pkgs ? import <nixpkgs> { },
  lib ? pkgs.lib,
  rustPlatform ? pkgs.makeRustPlatform {
    cargo = pkgs.rust-bin.stable.latest.default;
    rustc = pkgs.rust-bin.stable.latest.default;
  },
  linuxKernel_7_0 ? null,
}:

let
  # Try to build the kernel package if not provided
  kernel = if linuxKernel_7_0 != null
    then linuxKernel_7_0
    else pkgs.callPackage ./packages/linux-7.0-kernel.nix { };

  # Build environment with kernel dev output
  buildEnv = pkgs.buildEnv {
    name = "tidefs-kmod-posix-vfs-build-env";
    paths = [
      kernel.dev
      kernel
      pkgs.busybox
      pkgs.cpio
      pkgs.qemu
    ];
  };

  # Build script wrapper that sets up the environment
  compileScript = pkgs.writeShellScriptBin "compile-kmod-posix-vfs" ''
    set -euo pipefail

    REPO_ROOT="''${TIDEFS_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

    # Use the Nix-built kernel tree for the build
    export KERNEL_TREE="''${KERNEL_TREE:-${kernel.dev}}"

    # Set Rust toolchain paths from the Nix environment
    export RUSTC="${rustPlatform.rust.cargo}/bin/rustc"
    export CARGO="${rustPlatform.rust.cargo}/bin/cargo"

    echo "=== TideFS K7-VAL: Nix-based kmod-posix-vfs compile environment ==="
    echo "  Kernel dev tree: $KERNEL_TREE"
    echo "  Repo root:       $REPO_ROOT"

    if [ -f "$REPO_ROOT/scripts/compile-kmod-posix-vfs.sh" ]; then
      exec bash "$REPO_ROOT/scripts/compile-kmod-posix-vfs.sh" \
        --kernel-tree "$KERNEL_TREE" \
        "''${@}"
    else
      echo "ERROR: compile script not found at $REPO_ROOT/scripts/compile-kmod-posix-vfs.sh" >&2
      exit 1
    fi
  '';

in
pkgs.mkShell {
  name = "tidefs-kmod-posix-vfs-build-shell";
  buildInputs = [
    compileScript
    pkgs.bash
    pkgs.coreutils
    pkgs.gnutar
    pkgs.gzip
    pkgs.curl
    pkgs.gcc
    pkgs.gnumake
    pkgs.busybox
  ];

  shellHook = ''
    echo "TideFS K7-VAL: kmod-posix-vfs build environment"
    echo "  Kernel dev: ${kernel.dev}"
    echo "  Rust toolchain: $(rustc --version)"
    echo ""
    echo "Run: compile-kmod-posix-vfs [--output LOGFILE]"
  '';

  # Environment variables for the kernel build
  KERNELRELEASE = "${kernel.version}";
  KERNEL_TREE = "${kernel.dev}";
}
