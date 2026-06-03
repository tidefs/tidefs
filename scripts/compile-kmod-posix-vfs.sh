#!/usr/bin/env bash
# TideFS K7-VAL: Compile validation script for kmod-posix-vfs.
#
# Attempts to build the kmod-posix-vfs crate as a Linux 7.0 kernel module
# and records the raw build output, exit code, and environment fingerprint.
# This validation run discovers the real gap between current code and a
# successful kernel build for the May 25 kernel delivery gate.
#
# Usage:
#   bash scripts/compile-kmod-posix-vfs.sh [--output LOGFILE]
#
# Output:
#   A timestamped log file containing:
#   - Environment fingerprint (Nix hash, kernel version, rustc version)
#   - Cargo check result
#   - Kernel module build attempt (Kbuild) result
#   - Blocker summary extracted from error output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIDEFS_KMOD_TMPDIR="${TIDEFS_KMOD_TMPDIR:-/root/ai/state/tidefs/kernel-dev/hot-loop}"
KERNEL_TREE="${KERNEL_TREE:-${LINUX_SRC:-${TIDEFS_KMOD_TMPDIR}/linux-7.0/source}}"
KERNEL_BUILD="${KERNEL_BUILD:-}"
MODULE_OUT="${MODULE_OUT:-${TIDEFS_KMOD_TMPDIR}/module-out/posix-vfs}"
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
  export CARGO_TARGET_DIR="${TIDEFS_KMOD_TMPDIR}/cargo-target/compile-kmod-posix-vfs"
fi
OUTPUT_LOG=""
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
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

# ---- usage -----------------------------------------------------------

usage() {
  cat <<EOF
Usage: compile-kmod-posix-vfs.sh [options]

Options:
  --kernel-tree DIR    Path to Linux 7.0 source or prepared build tree
                       (default: $KERNEL_TREE)
  --kernel-build DIR   Optional out-of-tree Linux build dir used with O=DIR
  --module-out DIR     External module output dir used with MO=DIR
                       (default: $MODULE_OUT)
  --output LOGFILE     Output log file path
                       (default: $TIDEFS_KMOD_TMPDIR/compile-validation-$TIMESTAMP.log)
  --skip-prepare       Skip kernel tree preparation step
  --help, -h           Show this message

Environment:
  TIDEFS_KERNEL_JOBS   Kbuild jobs; values below 8 are raised to 8
                       (default: nproc, minimum: 8)
  KERNEL_TREE          Linux source tree, or prepared build tree when
                       KERNEL_BUILD is unset
  KERNEL_BUILD         Optional out-of-tree Linux build dir
  MODULE_OUT           Kbuild MO= directory for module products
  KBUILD_RUSTC         Rust compiler passed to Kbuild. Defaults to the
                       repo-pinned rustc sysroot binary, not the rustup shim,
                       because MO= builds run outside the repo tree.
  KBUILD_RUSTC_BOOTSTRAP
                       RUSTC_BOOTSTRAP value passed to Kbuild (default: 1)
EOF
}

# ---- argument parsing ------------------------------------------------

SKIP_PREPARE=0

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
      MODULE_OUT="$2"; shift 2 ;;
    --output)
      [[ "$#" -lt 2 ]] && { echo "ERROR: --output requires a path" >&2; exit 2; }
      OUTPUT_LOG="$2"; shift 2 ;;
    --skip-prepare) SKIP_PREPARE=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$OUTPUT_LOG" ]; then
  OUTPUT_LOG="${TIDEFS_KMOD_TMPDIR}/compile-validation-${TIMESTAMP}.log"
fi
mkdir -p "$(dirname "$OUTPUT_LOG")"
BUILD_DIR="$KERNEL_TREE"
if [ -n "$KERNEL_BUILD" ]; then
  BUILD_DIR="$KERNEL_BUILD"
fi

make_kernel() {
  if [ -n "$KERNEL_BUILD" ]; then
    make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" O="$KERNEL_BUILD" "$@"
  else
    make -j"$KERNEL_JOBS" -C "$KERNEL_TREE" "$@"
  fi
}

kernel_auto_conf_ready() {
  [ -f "$KERNEL_TREE/Makefile" ] && [ -f "$BUILD_DIR/include/config/auto.conf" ]
}

# ---- run all phases ------------------------------------------------

run_validation() {
  # environment fingerprint
  echo "=== TideFS K7-VAL: kmod-posix-vfs Compile Validation ==="
  echo "  Timestamp:  $TIMESTAMP"
  echo "  Hostname:   $(hostname 2>/dev/null || echo unknown)"
  echo "  Uname:      $(uname -a)"
  echo "  Output log: $OUTPUT_LOG"
  echo ""

  echo "=== Environment Fingerprint ==="
  echo ""

  if command -v rustc &>/dev/null; then
    echo "rustc version: $(rustc --version)"
    echo "rustc host:    $(rustc -vV 2>/dev/null | grep host | cut -d' ' -f2)"
  else
    echo "rustc: NOT FOUND"
  fi
  echo ""

  if command -v cargo &>/dev/null; then
    echo "cargo version: $(cargo --version)"
  else
    echo "cargo: NOT FOUND"
  fi
  echo ""

  echo "CARGO_TARGET_DIR: ${CARGO_TARGET_DIR:-<unset>}"
  echo "RUSTFLAGS:        ${RUSTFLAGS:-<unset>}"
  echo "RUST_TEST_THREADS: ${RUST_TEST_THREADS:-<unset>}"
  echo "CARGO_BUILD_JOBS:  ${CARGO_BUILD_JOBS:-<unset>}"
  echo "KBUILD_JOBS:       $KERNEL_JOBS"
  echo "KERNEL_TREE:       $KERNEL_TREE"
  echo "KERNEL_BUILD:      ${KERNEL_BUILD:-<unset>}"
  echo "MODULE_OUT:        $MODULE_OUT"
  echo "KBUILD_RUSTC:      $KBUILD_RUSTC"
  echo "KBUILD_RUSTC_BOOTSTRAP: $KBUILD_RUSTC_BOOTSTRAP"
  echo ""

  echo "Git revision: $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "Git branch:   $(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo ""

  if command -v nix &>/dev/null; then
    echo "nix version: $(nix --version 2>/dev/null || echo unknown)"
    local nkern_hash
    nkern_hash=$(nix eval --raw "$REPO_ROOT#packages.x86_64-linux.linuxKernel_7_0.drvPath" 2>/dev/null || echo "unavailable")
    echo "linuxKernel_7_0 drv: $nkern_hash"
  else
    echo "nix: NOT FOUND"
  fi
  echo ""

  # Phase 1: cargo check baseline
  echo "=== Phase 1: Cargo Check Baseline ==="
  echo ""

  cd "$REPO_ROOT"
  echo "Running: cargo check -p tidefs-kmod-posix-vfs 2>&1"
  CARGO_CHECK_RC=0
  cargo check -p tidefs-kmod-posix-vfs 2>&1 || CARGO_CHECK_RC=$?
  echo ""
  echo "CARGO_CHECK_EXIT_CODE: $CARGO_CHECK_RC"
  echo ""

  # Phase 1b: cargo build
  echo "=== Phase 1b: Cargo Build ==="
  echo ""
  echo "Running: cargo build -p tidefs-kmod-posix-vfs 2>&1"
  CARGO_BUILD_RC=0
  cargo build -p tidefs-kmod-posix-vfs 2>&1 || CARGO_BUILD_RC=$?
  echo ""
  echo "CARGO_BUILD_EXIT_CODE: $CARGO_BUILD_RC"
  echo ""

  # Phase 2: kernel tree preparation
  echo "=== Phase 2: Kernel Tree Preparation ==="
  echo ""

  KERNEL_READY=0
  if [ "$SKIP_PREPARE" -eq 0 ]; then
    echo "Preparing Linux 7.0 kernel build tree at $BUILD_DIR..."
    if [ -n "$KERNEL_BUILD" ] && [ -f "$KERNEL_TREE/Makefile" ]; then
      if kernel_auto_conf_ready; then
        echo "  External kernel build metadata already present; not running olddefconfig/syncconfig/modules_prepare."
      else
        echo "KERNEL_PREPARE: SKIPPED"
        echo "  KERNEL_BUILD was supplied, but prepared metadata is missing at:"
        echo "  $BUILD_DIR/include/config/auto.conf"
        echo "  This script will not mutate an external/shared kernel build. Bootstrap the"
        echo "  shared Linux 7.0 baseline first, then rerun with linux-prepare paths."
      fi
    elif [ -f "$REPO_ROOT/nix/kmod-hot-loop.sh" ]; then
      bash "$REPO_ROOT/nix/kmod-hot-loop.sh" prepare --kernel-tree "$KERNEL_TREE" 2>&1 || {
        echo ""
        echo "KERNEL_PREPARE: FAILED"
        echo "  The kernel tree could not be prepared. Kbuild validation cannot be produced."
      }
    else
      echo "  kmod-hot-loop.sh not found; skipping kernel tree preparation."
    fi
  else
    echo "  Skipping kernel tree preparation (--skip-prepare)."
  fi
  echo ""

  # Check if kernel tree is ready
  if kernel_auto_conf_ready; then
    KERNEL_READY=1
    echo "Kernel source/build ready at: $KERNEL_TREE / $BUILD_DIR"
    local kver_line

    kver_line=$(head -10 "$KERNEL_TREE/Makefile" | grep -E '^VERSION|^PATCHLEVEL|^SUBLEVEL' | tr '\n' ' ' || echo "")

    echo "Kernel version lines: $kver_line"

    if grep -q 'CONFIG_MODULES=y' "$BUILD_DIR/.config" 2>/dev/null; then
      echo "CONFIG_MODULES (.config): y"
    else
      echo "CONFIG_MODULES (.config): NOT SET"
    fi

    if grep -q 'CONFIG_RUST=y' "$BUILD_DIR/.config" 2>/dev/null; then
      echo "CONFIG_RUST (.config): y"
    else
      echo "CONFIG_RUST (.config): NOT SET"
    fi

    echo "  Not regenerating kernel config from this validation script."

    # Check CONFIG_RUST in auto.conf and bindgen availability
    if grep -q 'CONFIG_RUST=y' "$BUILD_DIR/include/config/auto.conf" 2>/dev/null; then
      echo "CONFIG_RUST (auto.conf): y"
    else
      echo "CONFIG_RUST (auto.conf): NOT SET"
      if grep -q 'CONFIG_RUST=y' "$BUILD_DIR/.config" 2>/dev/null; then
        echo "  CONFIG_RUST is in .config but not auto.conf (likely missing bindgen)"
      fi
      if command -v bindgen &>/dev/null; then
        echo "  bindgen: available at $(which bindgen)"
      else
        echo "  bindgen: NOT FOUND — required for CONFIG_RUST"
      fi
      KERNEL_READY=0
    fi

    # Verify CONFIG_MODULES is in auto.conf (not just .config)
    if grep -q 'CONFIG_MODULES=y' "$BUILD_DIR/include/config/auto.conf" 2>/dev/null; then
      echo "CONFIG_MODULES (auto.conf): y"
    else
      echo "CONFIG_MODULES (auto.conf): NOT SET — kbuild will fail"
      KERNEL_READY=0
    fi

  else
    echo "Kernel tree NOT ready at: $KERNEL_TREE"
  fi
  echo ""

  # Phase 3: kernel module build attempt
  echo "=== Phase 3: Kernel Module Build Attempt ==="
  echo ""

  KMOD_DIR="$REPO_ROOT/crates/tidefs-kmod-posix-vfs"
  KBUILD_RC=-1

  if [ "$KERNEL_READY" -eq 1 ]; then
    echo "Attempting kernel module build..."
    if [ -n "$KERNEL_BUILD" ]; then
      echo "Command: make -j$KERNEL_JOBS -C $KERNEL_TREE LLVM=1 O=$KERNEL_BUILD M=$KMOD_DIR MO=$MODULE_OUT modules"
    else
      echo "Command: make -j$KERNEL_JOBS -C $KERNEL_TREE LLVM=1 M=$KMOD_DIR MO=$MODULE_OUT modules"
    fi
    echo ""

    KBUILD_RC=0
    mkdir -p "$MODULE_OUT"
    KDIR="$KERNEL_TREE" LLVM=1 O="$KERNEL_BUILD" MO="$MODULE_OUT" \
      KBUILD_JOBS="$KERNEL_JOBS" KBUILD_RUSTC="$KBUILD_RUSTC" \
      KBUILD_RUSTC_BOOTSTRAP="$KBUILD_RUSTC_BOOTSTRAP" \
      make -j"$KERNEL_JOBS" -C "$KMOD_DIR" 2>&1 || KBUILD_RC=$?
    echo ""
    echo "KBUILD_EXIT_CODE: $KBUILD_RC"
    echo ""

    local produced_ko=""
    for candidate in \
      "$MODULE_OUT/tidefs_posix_vfs.ko" \
      "$KMOD_DIR/tidefs_posix_vfs.ko"; do
      if [ -f "$candidate" ]; then
        produced_ko="$candidate"
        break
      fi
    done

    if [ -n "$produced_ko" ]; then
      echo "KBUILD_RESULT: .ko PRODUCED"
      echo "Module path: $produced_ko"
      if command -v modinfo &>/dev/null; then
        echo "Module info:"
        modinfo "$produced_ko" 2>&1 || true
      fi
    else
      echo "KBUILD_RESULT: NO .ko produced"
    fi
  else
    echo "Skipping kernel module build: kernel tree not ready."
    echo "KBUILD_EXIT_CODE: N/A (no kernel tree)"
  fi
  echo ""

  # Phase 4: RUSTFLAGS cargo build
  echo "=== Phase 4: Cargo Build with Kernel-like RUSTFLAGS ==="
  echo ""
  echo "Running cargo build with no_std compatible flags..."
  RUSTFLAGS_KERNEL_RC=0
  RUSTFLAGS="--cfg kernel --cfg kmod_build" cargo build -p tidefs-kmod-posix-vfs 2>&1 || RUSTFLAGS_KERNEL_RC=$?
  echo ""
  echo "CARGO_BUILD_KERNEL_FLAGS_EXIT_CODE: $RUSTFLAGS_KERNEL_RC"
  echo ""

  # Phase 5: blocker summary
  echo "=== Phase 5: Blocker Summary ==="
  echo ""

  local ck_status="PASS"
  local cb_status="PASS"
  [ "$CARGO_CHECK_RC" -ne 0 ] && ck_status="FAIL"
  [ "$CARGO_BUILD_RC" -ne 0 ] && cb_status="FAIL"
  echo "Cargo check result:  $ck_status (exit $CARGO_CHECK_RC)"
  echo "Cargo build result:  $cb_status (exit $CARGO_BUILD_RC)"
  if [ "$KERNEL_READY" -eq 1 ]; then
    local kb_status="PASS"
    [ "$KBUILD_RC" -ne 0 ] && kb_status="FAIL"
    echo "Kbuild result:       $kb_status (exit $KBUILD_RC)"
  else
    echo "Kbuild result:       SKIPPED (no kernel tree)"
  fi
  echo "RUSTFLAGS build:     $([ "$RUSTFLAGS_KERNEL_RC" -eq 0 ] && echo PASS || echo "FAIL (exit $RUSTFLAGS_KERNEL_RC)")"

  echo ""
  echo "=== COMPILE VALIDATION COMPLETE ==="
  echo "  Log file: $OUTPUT_LOG"

  if [ "$CARGO_CHECK_RC" -ne 0 ] || [ "$CARGO_BUILD_RC" -ne 0 ] || [ "$RUSTFLAGS_KERNEL_RC" -ne 0 ]; then
    return 1
  fi
  if [ "$KERNEL_READY" -ne 1 ]; then
    return 2
  fi
  return "$KBUILD_RC"
}

RUN_RC=0
run_validation > "$OUTPUT_LOG" 2>&1 || RUN_RC=$?
echo ""
echo "Compile validation log written to: $OUTPUT_LOG"
echo "Lines: $(wc -l < "$OUTPUT_LOG")"
exit "$RUN_RC"
