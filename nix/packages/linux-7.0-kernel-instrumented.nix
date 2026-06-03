# TideFS K7-INSTRUMENTED: Linux 7.0 kernel built with lockdep, KCSAN, KASAN,
# and KFENCE instrumentation for kernel safety smoke campaigns.
#
# Uses nixpkgs buildLinux infrastructure to produce a kernel derivation
# compatible with linuxPackagesFor and NixOS boot.kernelPackages.
#
# This kernel is intended for QEMU validation only. It carries substantial
# runtime overhead from the sanitizers and must not be used as a production
# kernel.
{
  lib,
  buildLinux,
  fetchurl,
  rustc,
  bindgen,
  ...
}:

let
  version = "7.0";
  configFile = ./../vm/kernel-7.0-config-instrumented;
in
buildLinux {
  inherit version;
  defconfig = "tinyconfig";

  src = fetchurl {
    url = "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${version}.tar.xz";
    hash = "sha256-u39tgLOHx1e30Uu5MCj8uQ95PFwNNnc27oFaEAs4kfA=";
  };

  modDirVersion = "7.0.0";

  extraConfig = builtins.readFile configFile;

  # Start from tinyconfig plus the focused instrumented TideFS fragment;
  # nixpkgs common config pulls in broad unrelated driver families.
  enableCommonConfig = false;
  # The instrumented kernel should pay sanitizer overhead, not the cost of
  # building every optional driver as a module.
  autoModules = false;
  # Optional symbols in the fragment use `?`; unexpected missing or renamed
  # required options should fail the derivation so instrumented validation keeps
  # proving the intended kernel surface.
  ignoreConfigErrors = false;

  nativeBuildInputs = [
    rustc
    bindgen
  ];

  meta = {
    description = "Linux 7.0 kernel instrumented with lockdep, KCSAN, KASAN, and KFENCE for TideFS kernel safety validation";
    homepage = "https://www.kernel.org";
    license = lib.licenses.gpl2;
    platforms = [ "x86_64-linux" ];
  };
}
