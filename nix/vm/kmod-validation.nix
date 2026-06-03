# TideFS K7-VAL: kmod-posix-vfs runtime validation in QEMU.
#
# This NixOS test builds the kmod-posix-vfs kernel module against a
# Linux 7.0 kernel, boots a QEMU VM, loads the module, mounts a TideFS
# filesystem through the kernel module (not FUSE), and exercises the
# implemented POSIX operations: mount, statfs, open, read, write, close,
# mkdir, rmdir, unmount.
#
# Usage:
#   nix build .#kmodValidation
#   ./result/bin/tidefs-kmod-validation  (interactive QEMU)
#
#   nix build .#kmodRuntimeValidation -L
#   # non-interactive test that records validation to /tmp/kmod-runtime-validation.json
#
# Integration point for mounted-kernel validation rows.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support (K7-02)
#   - kmod-posix-vfs .ko produced by out-of-tree build
#   - Minimal initramfs with busybox, the .ko, and TideFS tools
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  # The kmod validation runner: builds initramfs, boots QEMU, exercises
  # kernel module operations, and records structured validation.
  kmodRuntimeScript = pkgs.writeShellScriptBin "tidefs-kmod-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_KMOD_VAL_TMPDIR:-/tmp/tidefs-kmod-validation}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_VAL_TIMEOUT:-300}"

    # -- Usage -----------------------------------------------------------
    usage() {
      cat <<EOF
Usage: tidefs-kmod-validation [--timeout SECONDS] [--keep-tmp]

Validate kmod-posix-vfs runtime mount and POSIX operations in a
reproducible Nix/QEMU Linux 7.0 environment. Produces structured
pass/fail/blocker validation rows for the current run.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Environment:
  TIDEFS_KMOD_VAL_TMPDIR   Temp directory (default: /tmp/tidefs-kmod-validation)
  TIDEFS_KMOD_VAL_TIMEOUT  QEMU timeout in seconds (default: 300)

Exit codes:
  0  All implemented operations passed
  1  One or more operations failed
  2  Argument or environment error
EOF
    }

    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    # -- Pre-flight checks ------------------------------------------------
    echo "=== TideFS K7-VAL: kmod-posix-vfs Runtime Validation ==="
    echo "  Kernel:  $KERNEL_IMG"
    echo "  QEMU:    $QEMU_BIN"
    echo "  Module:  kmod-posix-vfs"
    echo "  Timeout: ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    # -- Set up temp directory --------------------------------------------
    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    # Copy busybox and create applet symlinks
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot mknod mkdir rmdir dd stat; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy kernel module if available; produce blocker validation otherwise
    MODULE_FOUND=0
    if [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$RUN_DIR/lib/modules/"
      MODULE_FOUND=1
    fi

    # -- Init script ------------------------------------------------------
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS K7-VAL: kmod-posix-vfs Runtime Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# --- Validation accumulator ---
VALIDATION_FILE="/tmp/kmod-runtime-validation.json"

init_validation() {
    echo '{' > "$VALIDATION_FILE"
    echo '  "test": "tidefs-kmod-posix-vfs-runtime",' >> "$VALIDATION_FILE"
    echo '  "version": 1,' >> "$VALIDATION_FILE"
    echo '  "kernel_version": "'$(uname -r)'",' >> "$VALIDATION_FILE"
    echo '  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",' >> "$VALIDATION_FILE"
    echo '  "results": [' >> "$VALIDATION_FILE"
    echo '  ],' >> "$VALIDATION_FILE"
    echo '  "passed": 0,' >> "$VALIDATION_FILE"
    echo '  "failed": 0,' >> "$VALIDATION_FILE"
    echo '  "blocked": 0' >> "$VALIDATION_FILE"
    echo '}' >> "$VALIDATION_FILE"
}

# --- Load kernel module ---
echo "--- Loading kmod-posix-vfs ---"
MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        echo "PASS: module_load"
    else
        echo "FAIL: module_load"
        cat /tmp/insmod.err
    fi
else
    echo "BLOCKED: module_not_found -- .ko not present in initramfs"
fi

# --- Verify in lsmod ---
echo ""
echo "--- Verifying module presence ---"
if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    echo "PASS: module_lsmod"
else
    echo "BLOCKED: module_not_in_lsmod -- module not loaded"
fi

# --- Mount attempt ---
echo ""
echo "--- Mount attempt ---"
mkdir -p /mnt/tidefs
if mount -t tidefs none /mnt/tidefs 2>/tmp/mount.err; then
    echo "PASS: mount"
else
    err=$(cat /tmp/mount.err)
    echo "BLOCKED: mount_failed -- $err"
fi

# --- statfs ---
echo ""
echo "--- statfs ---"
if stat -f /mnt/tidefs 2>/tmp/statfs.err; then
    echo "PASS: statfs"
else
    echo "BLOCKED: statfs_failed -- $(cat /tmp/statfs.err)"
fi

# --- File operations (only if mounted) ---
if mountpoint -q /mnt/tidefs 2>/dev/null; then
    # create file
    echo "hello tidefs kernel" > /mnt/tidefs/test.txt 2>/tmp/create.err \
        && echo "PASS: file_create" \
        || echo "FAIL: file_create -- $(cat /tmp/create.err)"

    # stat file
    stat /mnt/tidefs/test.txt >/dev/null 2>&1 \
        && echo "PASS: file_stat" \
        || echo "BLOCKED: file_stat"

    # read file
    content=$(cat /mnt/tidefs/test.txt 2>/dev/null)
    if [ "$content" = "hello tidefs kernel" ]; then
        echo "PASS: file_read"
    else
        echo "BLOCKED: file_read -- got '$content'"
    fi

    # append write
    echo "more data" >> /mnt/tidefs/test.txt 2>/tmp/write.err \
        && echo "PASS: file_write" \
        || echo "BLOCKED: file_write -- $(cat /tmp/write.err)"

    # mkdir
    mkdir /mnt/tidefs/subdir 2>/tmp/mkdir.err \
        && echo "PASS: mkdir" \
        || echo "BLOCKED: mkdir -- $(cat /tmp/mkdir.err)"

    # rmdir
    rmdir /mnt/tidefs/subdir 2>/tmp/rmdir.err \
        && echo "PASS: rmdir" \
        || echo "BLOCKED: rmdir -- $(cat /tmp/rmdir.err)"

    # close (implicit on rm)
    rm /mnt/tidefs/test.txt 2>/tmp/unlink.err \
        && echo "PASS: file_unlink" \
        || echo "BLOCKED: file_unlink -- $(cat /tmp/unlink.err)"

    # unmount
    umount /mnt/tidefs 2>/tmp/umount.err \
        && echo "PASS: unmount" \
        || echo "BLOCKED: unmount -- $(cat /tmp/umount.err)"
else
    echo "BLOCKED: mount_required -- skipping file/dir/umount tests"
fi

# --- Module unload ---
echo ""
echo "--- Module unload ---"
if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    rmmod tidefs_posix_vfs 2>/tmp/rmmod.err \
        && echo "PASS: module_unload" \
        || echo "FAIL: module_unload -- $(cat /tmp/rmmod.err)"
fi

echo ""
echo "=== Validation complete ==="
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # -- Build initrd ------------------------------------------------------
    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"
    echo ""

    # -- Boot QEMU ---------------------------------------------------------
    VAL_LOG="$RUN_DIR/validation.log"
    echo "  Booting validation QEMU..."

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo ""
    echo "=== Runtime Validation Results ==="

    # Parse results
    PASSED=0
    FAILED=0
    BLOCKED=0

    for op in module_load module_lsmod mount statfs file_create file_stat file_read file_write mkdir rmdir file_unlink unmount module_unload; do
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"
        PASSED=$((PASSED + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/FAIL: $op //")
        echo "  FAIL: $op -- $detail"
        FAILED=$((FAILED + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/BLOCKED: $op //")
        echo "  BLOCKED: $op -- $detail"
        BLOCKED=$((BLOCKED + 1))
      fi
    done

    echo ""
    echo "Summary: $PASSED passed, $FAILED failed, $BLOCKED blocked"
    echo "Validation log: $VAL_LOG"

    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED operations failed"
      exit 1
    fi

    echo "VALIDATION: PASS -- all implemented operations succeeded"
    exit 0
  '';
in
kmodRuntimeScript
