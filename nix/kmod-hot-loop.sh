#!/usr/bin/env bash
# TideFS K7-04B: Linux 7.0 out-of-tree Rust-for-Linux kmod hot loop.
#
# This is the per-edit development loop for external Rust-for-Linux kernel
# modules. It complements, not replaces, the full Nix/QEMU acceptance gate
# (`nix run .#"kernel-7.0-validation"`).
#
# Workflow:
#   1) Prepare a Linux 7.0 build tree for out-of-tree module builds.
#   2) Edit kmod/smoke_module/rust_tidefs_smoke.rs (or your own module).
#   3) Build with the hot loop: nix/kmod-hot-loop.sh build
#   4) Smoke-test in disposable QEMU: nix/kmod-hot-loop.sh smoke
#   5) Iterate.
#
# All mutable build products (.ko, kernel build artifacts, QEMU images)
# live under TIDEFS_KMOD_TMPDIR (default
# /root/ai/state/tidefs/kernel-dev/hot-loop). Nothing is placed inside the
# repo or worktree.
#
# Experimental modules load ONLY inside disposable QEMU guests, never on
# the host. The --smoke step creates and destroys the guest automatically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- defaults -----------------------------------------------------------

TIDEFS_KMOD_TMPDIR="${TIDEFS_KMOD_TMPDIR:-/root/ai/state/tidefs/kernel-dev/hot-loop}"
KERNEL_TREE="${KERNEL_TREE:-${LINUX_SRC:-${TIDEFS_KMOD_TMPDIR}/linux-7.0/source}}"
KERNEL_BUILD="${KERNEL_BUILD:-${LINUX_BUILD:-}}"
QEMU_KERNEL="${QEMU_KERNEL:-}"
QEMU_INITRD="${QEMU_INITRD:-}"
SMOKE_MODULE_DIR="${REPO_ROOT}/kmod/smoke_module"
MODULE_OUT="${MODULE_OUT:-${TIDEFS_KMOD_TMPDIR}/module-out/smoke}"
KO_PATH="${KO_PATH:-${MODULE_OUT}/rust_tidefs_smoke.ko}"
MODULE_NAME="${MODULE_NAME:-}"
EXPECT_FS_OPTIONS="${EXPECT_FS_OPTIONS:-}"
ACCEPT_MODULE_PATH="${ACCEPT_MODULE_PATH:-}"
QEMU_BIN="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
TIMEOUT_SEC="${TIDEFS_KMOD_TIMEOUT:-60}"
MIN_KERNEL_JOBS=8

resolve_kbuild_rustc() {
  if [ -n "${KBUILD_RUSTC:-}" ]; then
    printf '%s\n' "$KBUILD_RUSTC"
    return
  fi
  local sysroot=""
  sysroot="$(cd "$REPO_ROOT" && rustc --print sysroot 2>/dev/null || true)"
  if [ -n "$sysroot" ] && [ -x "$sysroot/bin/rustc" ]; then
    printf '%s\n' "$sysroot/bin/rustc"
  elif command -v rustc >/dev/null 2>&1; then
    command -v rustc
  else
    printf '%s\n' "rustc"
  fi
}

resolve_kernel_jobs() {
  local jobs="${TIDEFS_KERNEL_JOBS:-}"
  if [ -z "$jobs" ]; then
    if command -v nproc >/dev/null 2>&1; then
      jobs="$(nproc)"
    else
      jobs="$MIN_KERNEL_JOBS"
    fi
  fi
  case "$jobs" in
    ''|*[!0-9]*) jobs="$MIN_KERNEL_JOBS" ;;
  esac
  if [ "$jobs" -lt "$MIN_KERNEL_JOBS" ]; then
    jobs="$MIN_KERNEL_JOBS"
  fi
  printf '%s\n' "$jobs"
}

KERNEL_JOBS="$(resolve_kernel_jobs)"
KBUILD_RUSTC="$(resolve_kbuild_rustc)"
KBUILD_RUSTC_BOOTSTRAP="${KBUILD_RUSTC_BOOTSTRAP:-1}"

kernel_build_dir() {
  if [ -n "$KERNEL_BUILD" ]; then
    printf '%s\n' "$KERNEL_BUILD"
  else
    printf '%s\n' "$KERNEL_TREE"
  fi
}

kbuild_make() {
  if [ -n "$KERNEL_BUILD" ]; then
    make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" O="$KERNEL_BUILD" "$@"
  else
    make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" "$@"
  fi
}

resolve_module_name() {
  if [ -n "$MODULE_NAME" ]; then
    printf '%s\n' "$MODULE_NAME"
    return
  fi
  if command -v modinfo >/dev/null 2>&1 && [ -f "$KO_PATH" ]; then
    local name
    name="$(modinfo -F name "$KO_PATH" 2>/dev/null || true)"
    if [ -n "$name" ]; then
      printf '%s\n' "$name"
      return
    fi
  fi
  basename "$KO_PATH" .ko
}

shared_kernel_build() {
  case "$(kernel_build_dir)" in
    /root/ai/state/tidefs/kernel-dev/shared/*) return 0 ;;
    *) return 1 ;;
  esac
}

kernel_ready() {
  local build_dir
  build_dir="$(kernel_build_dir)"
  [ -f "$KERNEL_TREE/Makefile" ] && [ -f "$build_dir/include/config/auto.conf" ]
}

require_kernel_feature() {
  local feature="$1"
  local build_dir
  build_dir="$(kernel_build_dir)"
  if ! grep -q "^${feature}=y" "$build_dir/include/config/auto.conf" 2>/dev/null; then
    echo "ERROR: ${feature}=y is not present in $build_dir/include/config/auto.conf" >&2
    if grep -q "^${feature}=y" "$build_dir/.config" 2>/dev/null; then
      echo "  ${feature}=y exists in .config but not auto.conf; the prepared Kbuild metadata is stale or unavailable." >&2
    fi
    echo "  Do not patch the shared kernel config from a module build." >&2
    echo "  Re-bootstrap the Linux 7.0 shared baseline/toolchain, then rerun 'nix/kmod-hot-loop.sh prepare' or pass fresh KERNEL_TREE/KERNEL_BUILD paths." >&2
    exit 1
  fi
}

# ---- usage --------------------------------------------------------------

usage() {
  cat <<EOF
Usage: kmod-hot-loop.sh <command> [options]

Commands:
  prepare    Prepare a Linux 7.0 kernel build tree for out-of-tree module
             builds. Downloads/extracts if needed, runs modules_prepare.
  build      Build the smoke module (or set SMOKE_MODULE_DIR) against the
             prepared kernel tree with O= and MO= when provided.
  smoke      Boot the smoke module in a disposable QEMU guest, load it,
             record kernel version + dmesg, and destroy the guest.
  clean      Remove .ko, .o, and intermediate build artifacts from the
             smoke module directory.
  accept     Hand off a built .ko module to the Nix/QEMU acceptance gate
             for reproducible validation. Requires Nix with flake support.
             Usage: kmod-hot-loop.sh accept [--module /path/to/module.ko]
  check-kmod Run cargo check on the POSIX and block kernel-module crates
             (tidefs-kmod-posix-vfs, tidefs-block-kmod).
             This validates kmod crate code compiles against its trait
             contracts without requiring a kernel build tree.
  build-all  Build smoke module .ko + run cargo check on kmod crates.


Options:
  --kernel-tree DIR    Path to prepared Linux 7.0 build tree
                       (default: $KERNEL_TREE)
  --kernel-build DIR   Optional out-of-tree Linux build dir used with O=DIR
                       (default: ${KERNEL_BUILD:-<unset>})
  --module-out DIR     External module output dir used with MO=DIR
                       (default: $MODULE_OUT)
  --qemu-kernel PATH   Kernel image for QEMU smoke boot
  --qemu-initrd PATH   Initrd image for QEMU smoke boot
  --timeout SECONDS    QEMU smoke timeout (default: $TIMEOUT_SEC)
  --help, -h           Show this message

Environment:
  TIDEFS_KMOD_TMPDIR   Root for kernel tree and build artifacts
                       (default: /root/ai/state/tidefs/kernel-dev/hot-loop)
  KERNEL_TREE          Linux source tree, or prepared build tree when
                       KERNEL_BUILD is unset
  KERNEL_BUILD         Optional out-of-tree Linux build dir
  MODULE_OUT           Kbuild MO= directory for module products
  KBUILD_RUSTC         Rust compiler passed to Kbuild. Defaults to the
                       repo-pinned rustc sysroot binary, not the rustup shim,
                       because MO= builds run outside the repo tree.
  KBUILD_RUSTC_BOOTSTRAP
                       RUSTC_BOOTSTRAP value passed to Kbuild (default: 1)
  TIDEFS_KERNEL_JOBS   Kbuild/Nix kernel build jobs; values below 8 are
                       raised to 8 (default: nproc, minimum: 8)
  KO_PATH              Module artifact to load during smoke
                       (default: \$MODULE_OUT/rust_tidefs_smoke.ko)
  MODULE_NAME          Loaded module name. Defaults to 'modinfo -F name
                       \$KO_PATH', then KO basename if modinfo is unavailable.
  EXPECT_FS_TYPE       Optional filesystem type expected in /proc/filesystems.
                       When set, smoke also attempts mount -t \$EXPECT_FS_TYPE
                       and records the mount result.
  EXPECT_FS_OPTIONS    Optional comma-separated mount options passed to the
                       EXPECT_FS_TYPE smoke mount.
  QEMU_KERNEL          Kernel image for QEMU smoke boot
  QEMU_INITRD          Initrd image for QEMU smoke boot
  QEMU_SYSTEM_X86_64   QEMU binary (default: qemu-system-x86_64)
  TIDEFS_KMOD_TIMEOUT  QEMU smoke timeout in seconds (default: 60)

Examples:
  # First-time setup (download kernel, prepare build tree):
  kmod-hot-loop.sh prepare

  # Build the smoke module after editing:
  kmod-hot-loop.sh build

  # Smoke-test in disposable QEMU:
  kmod-hot-loop.sh smoke --qemu-kernel /path/to/bzImage

  # Combine: build + smoke (if kernel available):
  kmod-hot-loop.sh build && kmod-hot-loop.sh smoke --qemu-kernel /path/to/bzImage
EOF
}

# ---- argument parsing ---------------------------------------------------

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --kernel-tree)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --kernel-tree requires a path" >&2; exit 2; }
        KERNEL_TREE="$2"; shift 2 ;;
      --kernel-build)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --kernel-build requires a path" >&2; exit 2; }
        KERNEL_BUILD="$2"; shift 2 ;;
      --module-out)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --module-out requires a path" >&2; exit 2; }
        MODULE_OUT="$2"; KO_PATH="$MODULE_OUT/rust_tidefs_smoke.ko"; shift 2 ;;
      --qemu-kernel)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --qemu-kernel requires a path" >&2; exit 2; }
        QEMU_KERNEL="$2"; shift 2 ;;
      --qemu-initrd)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --qemu-initrd requires a path" >&2; exit 2; }
        QEMU_INITRD="$2"; shift 2 ;;
      --timeout)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --timeout requires seconds" >&2; exit 2; }
        TIMEOUT_SEC="$2"; shift 2 ;;
      --module)
        [[ "$#" -lt 2 ]] && { echo "ERROR: --module requires a path" >&2; exit 2; }
        ACCEPT_MODULE_PATH="$2"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
  done
}

# ---- prepare ------------------------------------------------------------

cmd_prepare() {
  echo "=== TideFS K7-04B: Preparing kernel build tree ==="
  local build_dir
  build_dir="$(kernel_build_dir)"
  echo "  Kernel source/tree: $KERNEL_TREE"
  echo "  Kernel build dir:   $build_dir"
  echo "  Kernel jobs: $KERNEL_JOBS"

  if kernel_ready; then
    echo "  Kernel tree already appears prepared at $build_dir"
    echo "  Run 'nix/kmod-hot-loop.sh clean' and remove the tree to force re-prepare."
    return 0
  fi

  if [ -n "$KERNEL_BUILD" ]; then
    if [ ! -f "$KERNEL_TREE/Makefile" ]; then
      echo "ERROR: KERNEL_TREE=$KERNEL_TREE is not a Linux source tree." >&2
      echo "Pass KERNEL_TREE=<linux-src> and KERNEL_BUILD=<linux-build>, then rerun 'nix/kmod-hot-loop.sh prepare'." >&2
      exit 1
    fi
    if shared_kernel_build && [ "${TIDEFS_KMOD_MUTATE_SHARED_BASELINE:-0}" != "1" ]; then
      echo "ERROR: refusing to mutate shared kernel build metadata in $KERNEL_BUILD" >&2
      echo "The shared baseline is operator-owned. Use explicit KERNEL_TREE/KERNEL_BUILD/MODULE_OUT paths, or set" >&2
      echo "TIDEFS_KMOD_MUTATE_SHARED_BASELINE=1 only during an explicit baseline bootstrap." >&2
      exit 1
    fi
    mkdir -p "$KERNEL_BUILD"
    if [ ! -f "$KERNEL_BUILD/.config" ]; then
      if [ -f "$REPO_ROOT/nix/vm/kernel-7.0-config" ]; then
        cp "$REPO_ROOT/nix/vm/kernel-7.0-config" "$KERNEL_BUILD/.config"
      fi
    fi
    if [ ! -f "$KERNEL_BUILD/.config" ]; then
      kbuild_make defconfig 2>&1 | tail -5
    else
      kbuild_make olddefconfig 2>&1 | tail -5
    fi
    echo "  Running modules_prepare..."
    kbuild_make modules_prepare 2>&1 | tail -10
    echo "  Kernel tree prepared at $KERNEL_BUILD"
    return 0
  fi

  # Try Nix-based preparation first: extract kernel dev output.
  local nix_kernel_dev=""
  if command -v nix &>/dev/null; then
    if [ "${TIDEFS_KMOD_ALLOW_NIX_KERNEL_BOOTSTRAP:-0}" = "1" ]; then
      echo "  Nix bootstrap explicitly allowed; attempting to extract kernel dev tree from package..."
    else
      echo "  Nix bootstrap disabled for the per-edit loop."
      echo "  Set TIDEFS_KMOD_ALLOW_NIX_KERNEL_BOOTSTRAP=1 only for one-time baseline bootstrap."
      nix_kernel_dev="skip"
    fi
    # Try building the kernel package and extracting its dev output
    # which includes the prepared build tree for external modules.
    if [ "$nix_kernel_dev" != "skip" ] && nix build "$REPO_ROOT#packages.x86_64-linux.kernel7Validation" --no-link --max-jobs 1 --cores "$KERNEL_JOBS" 2>/dev/null; then
      echo "  Kernel 7.0 validation package built; extracting dev output..."
      local nix_store_kernel
      nix_store_kernel=$(nix eval --raw "$REPO_ROOT#packages.x86_64-linux.linuxKernel_7_0.dev" 2>/dev/null || true)
      if [ -n "$nix_store_kernel" ] && [ -d "$nix_store_kernel" ]; then
        echo "  Linking kernel dev tree from Nix store: $nix_store_kernel"
        mkdir -p "$(dirname "$KERNEL_TREE")"
        # Copy, not symlink, so we can mutate (modules_prepare needs write access)
        echo "  Copying kernel dev tree (this may take a moment)..."
        cp -r "$nix_store_kernel" "$KERNEL_TREE"
        # Nix kernel dev output should already be prepared; verify.
        if [ -f "$KERNEL_TREE/Makefile" ]; then
          echo "  Kernel dev tree ready at $KERNEL_TREE"
          # Ensure modules_prepare has been run
          if [ ! -f "$KERNEL_TREE/Module.symvers" ]; then
            echo "  Running modules_prepare..."
            make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" modules_prepare 2>&1 | tail -5
          fi
          return 0
        fi
      fi
    fi
    echo "  Nix kernel dev extraction not available; falling back to regular source tree."
  fi

  # Manual preparation: look for or download Linux 7.0 source.
  local kver="7.0"
  local ksrc="$TIDEFS_KMOD_TMPDIR/linux-${kver}.tar.xz"

  # If kernel tree dir exists with Kconfig but not fully prepared, run modules_prepare
  if [ -f "$KERNEL_TREE/Kconfig" ]; then
    echo "  Kernel source found; configuring and preparing..."
    if [ ! -f "$KERNEL_TREE/.config" ]; then
      if [ -f "$REPO_ROOT/nix/vm/kernel-7.0-config" ]; then
        echo "  Using TideFS kernel config fragment..."
        cp "$REPO_ROOT/nix/vm/kernel-7.0-config" "$KERNEL_TREE/.config"
        make -C "$KERNEL_TREE" olddefconfig 2>&1 | tail -5
      else
        make -C "$KERNEL_TREE" defconfig 2>&1 | tail -5
      fi
    fi
    echo "  Running modules_prepare..."
    make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" modules_prepare 2>&1 | tail -10
    echo "  Kernel tree prepared at $KERNEL_TREE"
    return 0
  fi

  # Try to find an existing Linux 7.0 source tree
  local candidate_dirs=(
    /usr/src/linux-7.0
    /usr/src/linux
    "$TIDEFS_KMOD_TMPDIR/linux-source-7.0"
  )
  for d in "${candidate_dirs[@]}"; do
    if [ -f "$d/Kconfig" ]; then
      echo "  Found kernel source at $d"
      echo "  Linking to $KERNEL_TREE..."
      mkdir -p "$(dirname "$KERNEL_TREE")"
      ln -sf "$d" "$KERNEL_TREE"
      cmd_prepare  # recurse to configure
      return $?
    fi
  done

  # Download and extract Linux 7.0
  echo "  Downloading Linux ${kver} source..."
  mkdir -p "$TIDEFS_KMOD_TMPDIR"
  local url="https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${kver}.tar.xz"
  if ! curl -fL --connect-timeout 30 "$url" -o "$ksrc" 2>/dev/null; then
    echo ""
    echo "  ERROR: Cannot download Linux ${kver} from kernel.org."
    echo ""
    echo "  Linux 7.0 may not yet be released. The kmod hot loop requires a"
    echo "  prepared Linux 7.0 kernel build tree at: $KERNEL_TREE"
    echo ""
    echo "  Options:"
    echo "    1) Point at an existing tree:"
    echo "       kmod-hot-loop.sh prepare --kernel-tree /path/to/linux-7.0"
    echo "    2) Build via Nix and extract:"
    echo "       nix build --max-jobs 1 --cores $KERNEL_JOBS .#packages.x86_64-linux.linuxKernel_7_0"
    echo "    3) Wait for the Linux 7.0 release and re-run prepare."
    echo ""
    echo "  The full Nix/QEMU gate ('nix run .#\"kernel-7.0-validation\"')"
    echo "  remains the publication/admission acceptance target."
    exit 1
  fi

  echo "  Extracting..."
  tar -xf "$ksrc" -C "$TIDEFS_KMOD_TMPDIR"
  # Find the extracted directory
  local extracted
  extracted=$(ls -d "$TIDEFS_KMOD_TMPDIR/linux-${kver}"*/ 2>/dev/null | head -1 || true)
  if [ -z "$extracted" ]; then
    extracted=$(ls -d "$TIDEFS_KMOD_TMPDIR/linux-${kver}" 2>/dev/null | head -1 || true)
  fi
  if [ -n "$extracted" ] && [ "$extracted" != "$KERNEL_TREE" ]; then
    mv "$extracted" "$KERNEL_TREE" 2>/dev/null || ln -sf "$extracted" "$KERNEL_TREE"
  fi

  # Configure and prepare
  if [ -f "$REPO_ROOT/nix/vm/kernel-7.0-config" ]; then
    cp "$REPO_ROOT/nix/vm/kernel-7.0-config" "$KERNEL_TREE/.config"
    make -C "$KERNEL_TREE" olddefconfig 2>&1 | tail -5
  else
    make -C "$KERNEL_TREE" defconfig 2>&1 | tail -5
  fi
  echo "  Running modules_prepare..."
  make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" modules_prepare 2>&1 | tail -10
  echo "  Kernel tree prepared at $KERNEL_TREE"
}

# ---- build --------------------------------------------------------------

cmd_build() {
  echo "=== TideFS K7-04B: Building smoke module ==="
  local build_dir
  build_dir="$(kernel_build_dir)"
  echo "  Kernel source/tree: $KERNEL_TREE"
  echo "  Kernel build dir:   $build_dir"
  echo "  Module dir:  $SMOKE_MODULE_DIR"
  echo "  Module out:  $MODULE_OUT"
  echo "  Kernel jobs: $KERNEL_JOBS"
  echo "  Kbuild rustc: $KBUILD_RUSTC"

  if [ ! -f "$KERNEL_TREE/Makefile" ]; then
    echo "ERROR: Kernel source/build tree not found at $KERNEL_TREE" >&2
    echo "Run 'nix/kmod-hot-loop.sh prepare' first." >&2
    exit 1
  fi

  if [ ! -f "$SMOKE_MODULE_DIR/Makefile" ]; then
    echo "ERROR: Smoke module not found at $SMOKE_MODULE_DIR" >&2
    exit 1
  fi

  if [ ! -f "$build_dir/include/config/auto.conf" ]; then
    echo "ERROR: prepared kernel metadata missing at $build_dir/include/config/auto.conf" >&2
    echo "Run 'nix/kmod-hot-loop.sh prepare' or pass explicit KERNEL_TREE/KERNEL_BUILD paths; do not run a hidden full kernel prepare from the module loop." >&2
    exit 1
  fi
  require_kernel_feature CONFIG_MODULES
  require_kernel_feature CONFIG_RUST

  # Set KDIR to our kernel tree and build
  mkdir -p "$MODULE_OUT"
  if [ -n "$KERNEL_BUILD" ]; then
    echo "  Building with make -j$KERNEL_JOBS -C $KERNEL_TREE LLVM=1 O=$KERNEL_BUILD M=$SMOKE_MODULE_DIR MO=$MODULE_OUT modules"
  else
    echo "  Building with make -j$KERNEL_JOBS -C $KERNEL_TREE LLVM=1 M=$SMOKE_MODULE_DIR MO=$MODULE_OUT modules"
  fi
  KDIR="$KERNEL_TREE" LLVM=1 O="$KERNEL_BUILD" MO="$MODULE_OUT" \
    KBUILD_JOBS="$KERNEL_JOBS" KBUILD_RUSTC="$KBUILD_RUSTC" \
    KBUILD_RUSTC_BOOTSTRAP="$KBUILD_RUSTC_BOOTSTRAP" \
    make -j"$KERNEL_JOBS" -C "$SMOKE_MODULE_DIR" 2>&1

  if [ -f "$KO_PATH" ]; then
    echo "  Smoke module built: $KO_PATH"
    echo "  Module info:"
    if command -v modinfo &>/dev/null; then
      modinfo "$KO_PATH" 2>&1 | sed 's/^/    /' || true
    else
      echo "    (modinfo not available on host)"
    fi
  else
    echo "ERROR: Build did not produce $KO_PATH" >&2
    exit 1
  fi
}

# ---- smoke --------------------------------------------------------------

cmd_smoke() {
  echo "=== TideFS K7-04B: Smoketesting module in disposable QEMU ==="

  if [ ! -f "$KO_PATH" ]; then
    echo "ERROR: Smoke module .ko not found at $KO_PATH" >&2
    echo "Run 'nix/kmod-hot-loop.sh build' first." >&2
    exit 1
  fi

  # Resolve QEMU kernel image
  local kernel_img="${QEMU_KERNEL}"
  if [ -z "$kernel_img" ]; then
    if [ -n "$KERNEL_BUILD" ] && [ -f "$KERNEL_BUILD/arch/x86/boot/bzImage" ]; then
      kernel_img="$KERNEL_BUILD/arch/x86/boot/bzImage"
    elif [ -f "$KERNEL_TREE/arch/x86/boot/bzImage" ]; then
      kernel_img="$KERNEL_TREE/arch/x86/boot/bzImage"
    elif command -v nix &>/dev/null && [ "${TIDEFS_KMOD_ALLOW_NIX_KERNEL_BOOTSTRAP:-0}" = "1" ]; then
      kernel_img=$(nix build "$REPO_ROOT#packages.x86_64-linux.linuxKernel_7_0" --no-link --print-out-paths --max-jobs 1 --cores "$KERNEL_JOBS" 2>/dev/null || true)
      if [ -n "$kernel_img" ]; then
        kernel_img="${kernel_img}/bzImage"
      fi
    fi
  fi

  if [ -z "$kernel_img" ] || [ ! -f "$kernel_img" ]; then
    echo ""
    echo "  ERROR: No QEMU kernel image available."
    echo ""
    echo "  The smoke step requires a Linux 7.0 kernel image (bzImage) to boot"
    echo "  in QEMU. Provide one via:"
    echo ""
    echo "    --qemu-kernel /path/to/bzImage"
    echo "    QEMU_KERNEL=/path/to/bzImage"
    echo ""
    echo "  If this is a one-time baseline bootstrap, build or hydrate the shared"
    echo "  kernel image first. Hidden Nix kernel builds are disabled in smoke by"
    echo "  default; set TIDEFS_KMOD_ALLOW_NIX_KERNEL_BOOTSTRAP=1 only for bootstrap:"
    echo "    TIDEFS_KMOD_ALLOW_NIX_KERNEL_BOOTSTRAP=1 nix build --max-jobs 1 --cores $KERNEL_JOBS .#packages.x86_64-linux.linuxKernel_7_0"
    echo ""
    echo "  No host module loading is performed."
    exit 1
  fi

  echo "  Kernel image: $kernel_img"

  # Check QEMU binary
  if ! command -v "$QEMU_BIN" &>/dev/null; then
    echo "ERROR: QEMU binary not found: $QEMU_BIN" >&2
    echo "Install qemu or set QEMU_SYSTEM_X86_64." >&2
    exit 1
  fi
  echo "  QEMU binary:  $QEMU_BIN"

  # Create a minimal initrd with busybox + our .ko + a test script
  local initrd_dir="$TIDEFS_KMOD_TMPDIR/initrd-smoke"
  local initrd_img="$TIDEFS_KMOD_TMPDIR/initrd-smoke.img"
  local expect_fs_type="${EXPECT_FS_TYPE:-}"
  local expect_fs_options="${EXPECT_FS_OPTIONS:-}"
  rm -rf "$initrd_dir"
  mkdir -p "$initrd_dir"/{bin,dev,proc,sys,lib/modules,tmp}

  # Copy the .ko into the initrd
  local module_file
  local module_name
  module_file="$(basename "$KO_PATH")"
  module_name="$(resolve_module_name)"
  cp "$KO_PATH" "$initrd_dir/lib/modules/$module_file"

  # Find busybox
  local busybox
  busybox=$(command -v busybox 2>/dev/null || true)
  if [ -z "$busybox" ]; then
    # Try nix shell
    busybox=$(nix shell nixpkgs#busybox -c which busybox 2>/dev/null || true)
  fi
  if [ -z "$busybox" ]; then
    echo "ERROR: busybox not found; required for minimal initrd." >&2
    exit 1
  fi
  cp "$busybox" "$initrd_dir/bin/busybox"
  chmod +x "$initrd_dir/bin/busybox"

  copy_elf_dep() {
    local dep="$1"
    [ -n "$dep" ] || return 0
    [ -e "$dep" ] || return 0
    mkdir -p "$initrd_dir$(dirname "$dep")"
    cp -L "$dep" "$initrd_dir$dep"
  }

  if command -v ldd >/dev/null 2>&1; then
    while IFS= read -r dep; do
      copy_elf_dep "$dep"
    done < <(ldd "$busybox" 2>/dev/null | awk '
      /^[[:space:]]*\// { print $1 }
      /=>[[:space:]]*\// { print $3 }
    ')
  fi

  # Create symlinks for essential busybox applets
  for applet in sh ls cat echo mount umount grep insmod rmmod dmesg sleep poweroff reboot uname tail lsmod mkdir df stat; do
    ln -sf busybox "$initrd_dir/bin/$applet"
  done

  # Create /init script
  cat > "$initrd_dir/init" << INITSCRIPT
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS K7-04B QEMU smoke guest ==="
echo "Kernel: \$(uname -r)"
echo ""

echo "--- Loading ${module_name} module ---"
insmod /lib/modules/${module_file} 2>&1 || echo "INSMOD_FAILED"
echo ""

echo "--- dmesg (last 30 lines) ---"
dmesg | tail -30
echo ""

echo "--- Checking module ---"
if lsmod | grep -q "${module_name}"; then
    echo "MODULE_LOADED: ${module_name}"
    if [ -n "${expect_fs_type}" ]; then
        echo ""
        echo "--- Checking filesystem type ${expect_fs_type} ---"
        if grep -w "${expect_fs_type}" /proc/filesystems; then
            echo "FS_REGISTERED: ${expect_fs_type}"
        else
            echo "FS_NOT_REGISTERED: ${expect_fs_type}"
        fi

        mkdir -p /tmp/tidefs-mnt
        if [ -n "${expect_fs_options}" ]; then
            echo "FS_MOUNT_OPTIONS: ${expect_fs_options}"
            mount -o "${expect_fs_options}" -t "${expect_fs_type}" none /tmp/tidefs-mnt 2>/tmp/tidefs-mount.err
        else
            mount -t "${expect_fs_type}" none /tmp/tidefs-mnt 2>/tmp/tidefs-mount.err
        fi
        if [ \$? -eq 0 ]; then
            echo "FS_MOUNTED: ${expect_fs_type}"
            if df -P /tmp/tidefs-mnt 2>/tmp/tidefs-df.err; then
                echo "FS_STATFS_OK: ${expect_fs_type}"
            else
                echo "FS_STATFS_FAILED: ${expect_fs_type}"
                cat /tmp/tidefs-df.err
            fi
            if umount /tmp/tidefs-mnt 2>/tmp/tidefs-umount.err; then
                echo "FS_UNMOUNTED: ${expect_fs_type}"
            else
                echo "FS_UNMOUNT_FAILED: ${expect_fs_type}"
                cat /tmp/tidefs-umount.err
            fi
        else
            rc=\$?
            echo "FS_MOUNT_FAILED: ${expect_fs_type}: rc=\${rc}"
            cat /tmp/tidefs-mount.err
        fi
    fi
    if rmmod "${module_name}" 2>&1; then
        echo "MODULE_UNLOADED: ${module_name}"
    else
        echo "RMMOD_FAILED: ${module_name}"
    fi
else
    echo "MODULE_NOT_FOUND_IN_LSMOD"
fi
echo ""

echo "--- dmesg after unload (last 5 lines) ---"
dmesg | tail -5
echo ""

echo "=== Smoke complete; powering off ==="
poweroff -f
INITSCRIPT
  chmod +x "$initrd_dir/init"

  # Build cpio initrd
  (cd "$initrd_dir" && find . | cpio -o -H newc 2>/dev/null) > "$initrd_img"

  echo "  Initrd built:  $initrd_img"
  echo "  Starting QEMU (timeout: ${TIMEOUT_SEC}s)..."

  # Boot QEMU with console output captured
  local smoke_log="$TIDEFS_KMOD_TMPDIR/smoke-$(date +%Y%m%d-%H%M%S).log"
  timeout "${TIMEOUT_SEC}" "$QEMU_BIN" \
    -kernel "$kernel_img" \
    -initrd "$initrd_img" \
    -append "console=ttyS0 quiet panic=10" \
    -m 512M \
    -smp 1 \
    -nographic \
    -no-reboot \
    > "$smoke_log" 2>&1 || true

  echo ""
  echo "  Smoke log: $smoke_log"

  # Parse and display results
  echo ""
  echo "=== Smoke Results ==="
  if grep -q "MODULE_LOADED: ${module_name}" "$smoke_log" 2>/dev/null; then
    echo "  PASS: ${module_name} module loaded successfully"
  else
    echo "  FAIL: ${module_name} module did not load (check $smoke_log)"
  fi

  if grep -q "MODULE_UNLOADED: ${module_name}" "$smoke_log" 2>/dev/null; then
    echo "  PASS: ${module_name} module unloaded cleanly"
  fi

  if [ -n "$expect_fs_type" ]; then
    if grep -q "FS_REGISTERED: ${expect_fs_type}" "$smoke_log" 2>/dev/null; then
      echo "  PASS: filesystem type ${expect_fs_type} was registered"
    else
      echo "  FAIL: filesystem type ${expect_fs_type} was not registered"
    fi

    if grep -q "FS_MOUNTED: ${expect_fs_type}" "$smoke_log" 2>/dev/null; then
      echo "  PASS: filesystem type ${expect_fs_type} mounted"
      if grep -q "FS_STATFS_OK: ${expect_fs_type}" "$smoke_log" 2>/dev/null; then
        echo "  PASS: filesystem type ${expect_fs_type} answered statfs"
      else
        echo "  FAIL: filesystem type ${expect_fs_type} did not answer statfs"
      fi
    elif grep -q "FS_MOUNT_FAILED: ${expect_fs_type}" "$smoke_log" 2>/dev/null; then
      echo "  BLOCKED: mount reached VFS but failed; inspect blocker in $smoke_log"
    fi
  fi

  # Extract kernel version
  local kver
  kver=$(grep "^Kernel:" "$smoke_log" 2>/dev/null | head -1 || echo "unknown")
  echo "  $kver"

  # Extract relevant dmesg lines
  echo ""
  echo "  Module dmesg:"
  grep -i "${module_name}\\|Rust" "$smoke_log" 2>/dev/null | head -10 | sed 's/^/    /' || echo "    (none)"

  # Cleanup initrd
  rm -rf "$initrd_dir" "$initrd_img"

  echo ""
  echo "  Guest destroyed. Full log: $smoke_log"
}

# ---- accept -------------------------------------------------------------

cmd_accept() {
  echo "=== TideFS K7-VAL: Hot-loop to Nix acceptance handoff ==="

  local ko="${ACCEPT_MODULE_PATH:-$KO_PATH}"
  if [ -z "$ko" ] || [ ! -f "$ko" ]; then
    echo "ERROR: No .ko module found" >&2
    echo "  Specify with --module /path/to/module.ko or build first." >&2
    exit 1
  fi

  echo "  Module: $ko"

  if ! command -v nix &>/dev/null; then
    echo "ERROR: Nix is required for the acceptance gate." >&2
    echo "  Install Nix: https://nixos.org/download" >&2
    exit 1
  fi

  # Build the kmod acceptance package if needed
  echo "  Building Nix acceptance package..."
  local accept_bin
  accept_bin=$(nix build "$REPO_ROOT#kmodAcceptance" --no-link --print-out-paths 2>&1) || {
    echo "ERROR: Failed to build kmodAcceptance Nix package." >&2
    echo "$accept_bin" >&2
    exit 1
  }

  echo "  Acceptance runner: $accept_bin/bin/tidefs-kmod-accept"
  echo ""

  # Run acceptance
  exec "$accept_bin/bin/tidefs-kmod-accept" "$ko"
}

# ---- check-kmod ---------------------------------------------------------

cmd_check_kmod() {
  echo "=== TideFS K7-VAL: Checking kernel-module crates ==="
  if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="$TIDEFS_KMOD_TMPDIR/cargo-target/kmod-hot-loop"
  fi
  echo "  CARGO_TARGET_DIR: $CARGO_TARGET_DIR"
  echo ""

  local crates=(
    "tidefs-kmod-posix-vfs"
    "tidefs-block-kmod"
    "tidefs-kmod-bridge"
    "tidefs-kmod-policy-authority"
  )

  local failed=0
  for crate in "${crates[@]}"; do
    echo "  cargo check -p $crate..."
    if cargo check -p "$crate" 2>&1; then
      echo "    PASS: $crate compiles"
    else
      echo "    FAIL: $crate has errors"
      failed=1
    fi
  done

  echo ""
  if [ "$failed" -eq 0 ]; then
    echo "  All kmod crates compile clean."
    echo ""
    echo "  NOTE: These crates are no_std library crates that compile via cargo."
    echo "  They are not yet built as .ko kernel modules because they need:"
    echo "    1. Concrete Linux kernel type implementations of the kmod-bridge traits"
    echo "    2. A kernel-module wrapper using kernel::prelude and module!() macro"
    echo "    3. Kbuild infrastructure linking against the kernel's Rust support"
    echo "  The smoke module (kmod/smoke_module/) demonstrates the full .ko pipeline."
  else
    echo "  Some kmod crates failed. Fix errors before proceeding."
    exit 1
  fi
}

# ---- build-all -----------------------------------------------------------

cmd_build_all() {
  echo "=== TideFS K7-VAL: Building all kmod artifacts ==="
  echo ""

  # Build smoke module .ko
  if [ -f "$KERNEL_TREE/Makefile" ]; then
    echo "--- Building smoke module .ko ---"
    cmd_build
    echo ""
  else
    echo "  SKIP: Kernel tree not prepared; run 'kmod-hot-loop.sh prepare' first."
    echo "  Smoke module .ko requires a prepared Linux 7.0 kernel build tree."
    echo ""
  fi

  # Check kmod crates
  echo "--- Checking kmod crates ---"
  cmd_check_kmod
}

# ---- clean --------------------------------------------------------------

cmd_clean() {
  echo "=== TideFS K7-04B: Cleaning smoke module build artifacts ==="
  if [ -f "$SMOKE_MODULE_DIR/Makefile" ]; then
    if [ -f "$KERNEL_TREE/Makefile" ]; then
      KDIR="$KERNEL_TREE" LLVM=1 O="$KERNEL_BUILD" MO="$MODULE_OUT" make -C "$SMOKE_MODULE_DIR" clean 2>&1 || true
    else
      # Manual cleanup if kernel tree not available
      rm -f "$SMOKE_MODULE_DIR"/*.o "$SMOKE_MODULE_DIR"/*.ko "$SMOKE_MODULE_DIR"/*.mod.c
      rm -f "$SMOKE_MODULE_DIR"/.rust_tidefs_smoke.* "$SMOKE_MODULE_DIR"/modules.order
      rm -f "$SMOKE_MODULE_DIR"/Module.symvers
    fi
  fi
  rm -f "$KO_PATH"
  rm -rf "$MODULE_OUT"
  echo "  Smoke module build artifacts cleaned."
}

# ---- main ---------------------------------------------------------------

main() {
  if [ "$#" -lt 1 ]; then
    usage >&2
    exit 2
  fi

  local cmd="$1"
  shift

  case "$cmd" in
    prepare)   parse_args "$@"; cmd_prepare ;;
    build)     parse_args "$@"; cmd_build ;;
    smoke)     parse_args "$@"; cmd_smoke ;;
    accept)    parse_args "$@"; cmd_accept ;;
    check-kmod) parse_args "$@"; cmd_check_kmod ;;
    build-all)  parse_args "$@"; cmd_build_all ;;
    clean)     parse_args "$@"; cmd_clean ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "ERROR: unknown command: $cmd" >&2
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
