{
  pkgs,
  lib,
  linuxKernel_7_0,
  rustToolchain,
  bindgen,
}:

let
  kernel = linuxKernel_7_0;
  kernelSource = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/source";
  kernelBuild = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";
in
kernel.stdenv.mkDerivation {
  pname = "tidefs-block-kmod";
  version = "0.1.0-${kernel.modDirVersion}";

  src = lib.cleanSourceWith {
    src = ../..;
    filter = path: type:
      let
        root = toString ../..;
        rel = lib.removePrefix (root + "/") (toString path);
      in
      rel == ""
      || rel == "kmod"
      || lib.hasPrefix "kmod/" rel
      || rel == "crates"
      || rel == "crates/tidefs-block-kmod"
      || lib.hasPrefix "crates/tidefs-block-kmod/" rel;
  };

  nativeBuildInputs = kernel.moduleBuildDependencies ++ [
    bindgen
    pkgs.kmod
    pkgs.llvmPackages_19.lld
    pkgs.llvmPackages_19.llvm
    rustToolchain
  ];

  dontConfigure = true;
  dontPatchELF = true;
  dontStrip = true;

  buildPhase = ''
    runHook preBuild

    module_out="$TMPDIR/module-out/block-kmod"
    mkdir -p "$module_out"

    make -j"''${NIX_BUILD_CORES:-8}" \
      -C "$src/crates/tidefs-block-kmod" \
      KDIR="${kernelSource}" \
      O="${kernelBuild}" \
      MO="$module_out" \
      LLVM=1 \
      KBUILD_CC="${kernel.stdenv.cc.cc}/bin/clang" \
      KBUILD_RUSTC="${rustToolchain}/bin/rustc" \
      KBUILD_BINDGEN="${bindgen}/bin/bindgen" \
      KBUILD_RUST_LIB_SRC="${rustToolchain}/lib/rustlib/src/rust/library" \
      KBUILD_RUSTC_BOOTSTRAP=1

    test -f "$module_out/tidefs_block_kmod.ko"

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    install -Dm444 "$TMPDIR/module-out/block-kmod/tidefs_block_kmod.ko" \
      "$out/lib/modules/${kernel.modDirVersion}/extra/tidefs_block_kmod.ko"
    install -Dm444 "$TMPDIR/module-out/block-kmod/tidefs_block_kmod.ko" \
      "$out/tidefs_block_kmod.ko"
    ${pkgs.kmod}/bin/modinfo "$out/tidefs_block_kmod.ko" > "$out/tidefs_block_kmod.modinfo"

    runHook postInstall
  '';

  meta = {
    description = "TideFS block-volume kernel module built against the Nix Linux 7.0 guest kernel";
    license = lib.licenses.gpl2Only;
    platforms = [ "x86_64-linux" ];
  };
}
