# TideFS K7-VAL: Hot-loop to Nix acceptance handoff gate.
#
# This Nix derivation produces a script that accepts a compiled kernel
# module (.ko file) produced by the hot loop (`nix run .#kmod-hot-loop --
# build`) and validates it in a reproducible Nix/QEMU environment using
# the same Linux 7.0 kernel as the full acceptance gate.
#
# The handoff path is:
#   1. Developer edits module source
#   2. Hot loop builds .ko: nix/kmod-hot-loop.sh build
#   3. Nix acceptance validates .ko: nix/kmod-hot-loop.sh accept
#   4. Full gate: nix build .#kernel7Validation
#
# Usage:
#   nix build .#kmodAcceptance
#   ./result/bin/tidefs-kmod-accept /path/to/module.ko
#
# Or via hot loop:
#   nix run .#kmod-hot-loop -- accept --module /path/to/module.ko
{
  pkgs,
  linuxKernel_7_0,
}:

let
  acceptScript = pkgs.writeShellScriptBin "tidefs-kmod-accept" ''
    set -euo pipefail

    # ── Resolve fixed Nix store paths ──────────────────────────────────
    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"

    # Runtime paths
    ACCEPT_TMPDIR="''${TIDEFS_KMOD_ACCEPT_TMPDIR:-/tmp/tidefs-kmod-accept}"
    KO_PATH=""
    MODULE_NAME=""
    TIMEOUT_SEC="''${TIDEFS_KMOD_ACCEPT_TIMEOUT:-120}"

    # ── Usage ──────────────────────────────────────────────────────────
    usage() {
      cat <<EOF
    Usage: tidefs-kmod-accept <module.ko> [options]

    Validate a hot-loop-produced kernel module (.ko) in a reproducible
    Nix/QEMU Linux 7.0 environment. This is the acceptance handoff gate
    between the per-edit hot loop and the full Nix release validation.

    Options:
      --name MODULE_NAME   Module name for insmod (default: derived from .ko)
      --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
      --keep-tmp           Do not remove temp directory on exit
      --help, -h           Show this message

    Environment:
      TIDEFS_KMOD_ACCEPT_TMPDIR   Temp directory (default: /tmp/tidefs-kmod-accept)
      TIDEFS_KMOD_ACCEPT_TIMEOUT  QEMU timeout in seconds (default: 120)

    Exit codes:
      0  Module loaded and unloaded successfully
      1  Module failed to load or smoke test failed
      2  Usage or argument error
    EOF
    }

    # ── Argument parsing ───────────────────────────────────────────────
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --name)
          MODULE_NAME="$2"; shift 2 ;;
        --timeout)
          TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp)
          KEEP_TMP=1; shift ;;
        --help|-h)
          usage; exit 0 ;;
        -*)
          echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)
          if [ -z "$KO_PATH" ]; then
            KO_PATH="$1"
          else
            echo "ERROR: unexpected argument: $1" >&2; usage >&2; exit 2
          fi
          shift ;;
      esac
    done

    if [ -z "$KO_PATH" ]; then
      echo "ERROR: no module .ko file specified" >&2
      usage >&2
      exit 2
    fi

    if [ ! -f "$KO_PATH" ]; then
      echo "ERROR: module .ko not found: $KO_PATH" >&2
      exit 2
    fi

    # Auto-detect module name from basename without .ko
    if [ -z "$MODULE_NAME" ]; then
      MODULE_NAME=''${KO_PATH##*/}   # strip path
      MODULE_NAME=''${MODULE_NAME%.ko}  # strip .ko
      MODULE_NAME=''${MODULE_NAME//-/_}  # dashes -> underscores (kernel convention)
    fi

    # ── Pre-flight checks ──────────────────────────────────────────────
    echo "=== TideFS K7 Hot-Loop → Nix Acceptance Handoff ==="
    echo "  Module:       $KO_PATH"
    echo "  Module name:  $MODULE_NAME"
    echo "  Kernel:       $KERNEL_IMG"
    echo "  QEMU:         $QEMU_BIN"
    echo "  Timeout:      ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    # ── Set up temp directory ──────────────────────────────────────────
    RUN_DIR="$ACCEPT_TMPDIR/accept-''$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,lib/modules,tmp}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi; rm -f "$RUN_DIR"/initrd.img' EXIT

    # Copy .ko and busybox into initrd
    cp "$KO_PATH" "$RUN_DIR/lib/modules/"
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"

    # Busybox applets
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot mknod; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # ── Init script ────────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
    #!/bin/sh
    export PATH=/bin

    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev

    echo "=== TideFS Nix Acceptance: kernel module validation ==="
    echo "kernel_version=''$(uname -r)"
    echo "module=MODNAME_PLACEHOLDER"
    echo ""

    echo "--- Loading module ---"
    if insmod /lib/modules/MODNAME_PLACEHOLDER.ko 2>&1; then
        echo "ACCEPT_LOAD: OK"
    else
        echo "ACCEPT_LOAD: FAIL (insmod returned error)"
    fi

    echo ""
    echo "--- dmesg (last 30 lines) ---"
    dmesg | tail -30

    echo ""
    echo "--- Verifying in lsmod ---"
    if lsmod | grep -q MODNAME_PLACEHOLDER; then
        echo "ACCEPT_LSMOD: OK"
        rmmod MODNAME_PLACEHOLDER 2>&1 && echo "ACCEPT_UNLOAD: OK" || echo "ACCEPT_UNLOAD: FAIL (rmmod returned error)"
    else
        echo "ACCEPT_LSMOD: FAIL (module not found in lsmod)"
        echo "ACCEPT_UNLOAD: SKIPPED"
    fi

    echo ""
    echo "--- dmesg after unload ---"
    dmesg | tail -5

    echo ""
    echo "ACCEPT_COMPLETE: 1"
    poweroff -f
    INITSCRIPT

    # Substitute module name
    sed -i "s/MODNAME_PLACEHOLDER/$MODULE_NAME/g" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    # ── Build initrd ───────────────────────────────────────────────────
    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

    # ── Boot QEMU ──────────────────────────────────────────────────────
    ACCEPT_LOG="$RUN_DIR/accept.log"
    echo "  Booting acceptance QEMU..."

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      > "$ACCEPT_LOG" 2>&1 || true

    echo ""
    echo "=== Acceptance Results ==="

    # Parse results
    FAILED=0

    KVER=$(grep "^kernel_version=" "$ACCEPT_LOG" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" || echo "unknown")
    echo "  Kernel: $KVER"

    if grep -q "ACCEPT_LOAD: OK" "$ACCEPT_LOG" 2>/dev/null; then
      echo "  PASS: module loaded"
    else
      echo "  FAIL: module did not load"
      FAILED=1
    fi

    if grep -q "ACCEPT_LSMOD: OK" "$ACCEPT_LOG" 2>/dev/null; then
      echo "  PASS: module found in lsmod"
    else
      echo "  FAIL: module not in lsmod"
      FAILED=1
    fi

    if grep -q "ACCEPT_UNLOAD: OK" "$ACCEPT_LOG" 2>/dev/null; then
      echo "  PASS: module unloaded"
    elif grep -q "ACCEPT_UNLOAD: SKIPPED" "$ACCEPT_LOG" 2>/dev/null; then
      echo "  SKIP: unload skipped (load failed)"
    else
      echo "  FAIL: module did not unload cleanly"
      FAILED=1
    fi

    # Extract dmesg module lines
    echo ""
    echo "  Module dmesg:"
    grep -i "$MODULE_NAME" "$ACCEPT_LOG" 2>/dev/null | head -10 | sed 's/^/    /' || echo "    (none)"

    echo ""
    if [ "$FAILED" -eq 0 ]; then
      echo "ACCEPTANCE: PASS — module validated in Nix/QEMU Linux 7.0"
      echo "  Validation log: $ACCEPT_LOG"
      exit 0
    else
      echo "ACCEPTANCE: FAIL — module validation failed"
      echo "  Validation log: $ACCEPT_LOG"
      exit 1
    fi
  '';
in
acceptScript
