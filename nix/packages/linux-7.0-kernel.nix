# TideFS K7-02: Linux 7.0 kernel build for QEMU validation.
#
# Uses nixpkgs buildLinux infrastructure to produce a kernel derivation
# compatible with linuxPackagesFor and NixOS boot.kernelPackages.
{
  lib,
  buildLinux,
  fetchurl,
  llvmPackages,
  rustc,
  bindgen,
  ...
}:

let
  version = "7.0";
  configFile = ./../vm/kernel-7.0-config;
  rustLibSrc = "${rustc}/lib/rustlib/src/rust/library";
in
(buildLinux {
  inherit version;
  defconfig = "tinyconfig";
  stdenv = llvmPackages.stdenv;

  src = fetchurl {
    url = "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${version}.tar.xz";
    hash = "sha256-u39tgLOHx1e30Uu5MCj8uQ95PFwNNnc27oFaEAs4kfA=";
  };

  modDirVersion = "7.0.0";

  # Merge our QEMU config fragment via extraConfig string
  extraConfig = builtins.readFile configFile;
  structuredExtraConfig = with lib.kernel; {
    RUST = yes;
    MODULE_UNLOAD = yes;
    MODULE_FORCE_UNLOAD = yes;
  };

  # Start from tinyconfig plus the TideFS fragment rather than x86_64
  # defconfig or the broad nixpkgs common config. The common config selects
  # large families of unrelated modules (DRM/media/wireless/NFS/f2fs) that do
  # not participate in FUSE, ublk, RDMA, or Rust-for-Linux validation.
  enableCommonConfig = false;
  # Keep the validation kernel tied to the explicit QEMU/Rust/FUSE/ublk/RDMA
  # fragment above.  Nixpkgs' autoModules mode answers nearly every optional
  # tristate Kconfig prompt with "m", which turns each cold smoke run into a
  # broad driver/module build instead of a release-validation kernel build.
  autoModules = false;
  # Optional symbols in the fragment use `?`; unexpected missing or renamed
  # required options should fail the derivation so QEMU validation keeps proving
  # the intended kernel surface.
  ignoreConfigErrors = false;

  # buildLinux enables parallel building; workers must invoke full kernel
  # acceptance with `nix build --max-jobs 1 --cores 8 ...` or higher so
  # NIX_BUILD_CORES gives Kbuild real parallelism without overlapping kernels.
  extraMakeFlags = [
    "LLVM=1"
    "RUSTC=${rustc}/bin/rustc"
    "BINDGEN=${bindgen}/bin/bindgen"
    "RUST_LIB_SRC=${rustLibSrc}"
    "RUSTC_BOOTSTRAP=1"
  ];

  # Rust tooling for CONFIG_RUST=y kernel module build support.
  # The kernel build system calls rustc and bindgen directly; both must
  # be in PATH during the build. These come from callPackage via pkgs.
  nativeBuildInputs = [
    rustc
    bindgen
  ];

  # Explicitly set RUSTC and BINDGEN as environment variables so the kernel's
  # rust_is_available.sh can find them during make olddefconfig. The kernel
  # Makefile defaults RUSTC=rustc/BINDGEN=bindgen and exports them, but the
  # nix build environment may not have them in PATH during the config phase.
  RUSTC = "${rustc}/bin/rustc";
  BINDGEN = "${bindgen}/bin/bindgen";
  RUST_LIB_SRC = rustLibSrc;

  meta = {
    description = "Linux 7.0 kernel for TideFS QEMU validation";
    homepage = "https://www.kernel.org";
    license = lib.licenses.gpl2;
    platforms = [ "x86_64-linux" ];
  };
}).overrideAttrs (previousAttrs: {
  env = (previousAttrs.env or { }) // {
    RUST_LIB_SRC = rustLibSrc;
    KRUSTFLAGS = "--remap-path-prefix ${rustLibSrc}=/";
  };
})
