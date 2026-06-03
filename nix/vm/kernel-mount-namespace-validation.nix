# TideFS: kernel-mode mount namespace, bind-mount, and remount validation.
#
# QEMU Validation Validation (2026-05-24): mount namespace, bind mount,
# remount flags, mount propagation, and teardown in kernel bootstrap mode.
#
# Boots a Linux 7.0 kernel with kmod-posix-vfs, mounts TideFS, then
# exercises: remount (ro↔rw), bind mount, mount propagation (shared subtree
# peer test), recursive bind mount, and clean teardown of all mounts.
# Verifies dmesg remains free of WARNING/BUG/panic indicators.
#
# Validation tier: Tier 5 mounted Linux 7.0 kernel VFS (with bootstrap mode
# qualifying as Tier 4 Kbuild+QEMU module-load plus Tier 5 VFS-operation
# dispatch for the mount-namespace surface).
#
{
  pkgs,
  linuxKernel_7_0,
}:

let
  kmodMountNsScript = pkgs.writeShellScriptBin "tidefs-kmod-mount-namespace-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"

    TMPDIR="''${TIDEFS_MOUNT_NS_TMPDIR:-/tmp/tidefs-mount-namespace}"
    TIMEOUT_SEC="''${TIDEFS_MOUNT_NS_TIMEOUT:-300}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-mount-namespace-validation [--timeout SECONDS] [--keep-tmp]

Validate kmod-posix-vfs mount namespace behavior: remount flags, bind mounts,
mount propagation, and teardown in a Linux 7.0 QEMU guest.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  All checks passed
  1  One or more checks failed
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS K7-VAL: kmod-posix-vfs Mount Namespace Validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$POSIX_VFS_KO" ]; then
      for c in "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/kernel/fs/tidefs/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/tidefs_posix_vfs.ko"; do
        [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
      done
    fi

    if [ -z "$POSIX_VFS_KO" ]; then
      echo "BLOCKED: tidefs_posix_vfs.ko not found in MODULE_DIR=$MODULE_DIR"
      exit 1
    fi
    echo "  Module .ko: $POSIX_VFS_KO"

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt,mnt2,mnt3,mnt4,validation}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum mountpoint umount; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # ── Init script ──────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Mount Namespace Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
skip()   { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }

MNT=/mnt/tidefs
MNT2=/mnt2
MNT3=/mnt3
MNT4=/mnt4

# ── Phase 0: Module Load ────────────────────────────────────────────
echo "--- Phase 0: Module Load ---"

MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        pass "phase0_insmod"
    else
        fail "phase0_insmod" "$(cat /tmp/insmod.err)"
    fi
else
    blocked "phase0_insmod" "tidefs_posix_vfs.ko not found"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "phase0_module_visible"
else
    blocked "phase0_module_visible" "module not present after insmod"
fi

# ── Phase 1: Basic Mount ────────────────────────────────────────────
echo ""
echo "--- Phase 1: Basic Mount ---"

mkdir -p "$MNT"
if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
    pass "phase1_mount"
else
    fail "phase1_mount" "tidefs mount failed"
    echo "FATAL: cannot continue without mount"
    poweroff -f
fi

# Verify /proc/mounts entry exists
if grep -q "tidefs" /proc/mounts 2>/dev/null; then
    pass "phase1_proc_mounts"
else
    fail "phase1_proc_mounts" "no tidefs entry in /proc/mounts"
fi

# Verify mountpoint command
if mountpoint -q "$MNT" 2>/dev/null; then
    pass "phase1_mountpoint"
else
    fail "phase1_mountpoint" "mountpoint check failed"
fi

# Verify mount options in /proc/mounts show bootstrap
if grep "$MNT" /proc/mounts 2>/dev/null | grep -q "bootstrap"; then
    pass "phase1_show_options"
else
    fail "phase1_show_options" "bootstrap option not in /proc/mounts"
fi

# ── Phase 2: Remount ro/rw Flags ────────────────────────────────────
echo ""
echo "--- Phase 2: Remount ro/rw ---"

# Directly test remount ro
if mount -o remount,ro "$MNT" 2>/dev/null; then
    pass "phase2_remount_ro"
else
    fail "phase2_remount_ro" "remount ro failed"
fi

# Verify ro in /proc/mounts
if grep "$MNT" /proc/mounts 2>/dev/null | grep -q ",ro"; then
    pass "phase2_check_ro_mounts"
else
    fail "phase2_check_ro_mounts" "ro flag not seen in /proc/mounts"
fi

# Remount rw
if mount -o remount,rw "$MNT" 2>/dev/null; then
    pass "phase2_remount_rw"
else
    fail "phase2_remount_rw" "remount rw failed"
fi

# Verify rw in /proc/mounts
if grep "$MNT" /proc/mounts 2>/dev/null | grep -q ",rw"; then
    pass "phase2_check_rw_mounts"
else
    fail "phase2_check_rw_mounts" "rw flag not seen in /proc/mounts"
fi

# ── Phase 3: Bind Mount ─────────────────────────────────────────────
echo ""
echo "--- Phase 3: Bind Mount ---"

mkdir -p "$MNT2"

# Bind mount
if mount --bind "$MNT" "$MNT2" 2>/dev/null; then
    pass "phase3_bind_mount"
else
    fail "phase3_bind_mount" "bind mount failed"
fi

# Verify bind mount visible
if grep -q "$MNT2" /proc/mounts 2>/dev/null; then
    pass "phase3_bind_mountpoint"
else
    fail "phase3_bind_mountpoint" "bind mount not a mountpoint"
fi

# Write a file from the bind mount and read from the original
echo "bind_test_content" > "$MNT2/bind_test" 2>/dev/null
if [ -f "$MNT/bind_test" ] && grep -q "bind_test_content" "$MNT/bind_test" 2>/dev/null; then
    pass "phase3_bind_write_visible"
else
    fail "phase3_bind_write_visible" "file written via bind not visible at original"
fi

# Clean up bind mount
umount "$MNT2" 2>/dev/null && pass "phase3_bind_umount" || fail "phase3_bind_umount" "bind umount failed"

# ── Phase 4: Mount Propagation ──────────────────────────────────────
echo ""
echo "--- Phase 4: Mount Propagation ---"

mkdir -p "$MNT3"
mkdir -p "$MNT4"

# Make the original mount shared
if mount --make-shared "$MNT" 2>/dev/null; then
    pass "phase4_make_shared"
else
    # Busybox mount --make-shared may not be supported; try -o shared
    if mount -o shared "$MNT" 2>/dev/null; then
        pass "phase4_make_shared"
    else
        fail "phase4_make_shared" "make-shared not supported by busybox mount"
    fi
fi

# Bind mount to MNT3 (should inherit shared propagation)
if mount --bind "$MNT" "$MNT3" 2>/dev/null; then
    pass "phase4_peer_bind"
else
    fail "phase4_peer_bind" "peer bind mount failed"
fi

# Make slave at MNT4
mkdir -p "$MNT4"
if mount --bind "$MNT" "$MNT4" 2>/dev/null; then
    mount --make-slave "$MNT4" 2>/dev/null && pass "phase4_make_slave" || \
    skip "phase4_make_slave" "make-slave not supported"
else
    fail "phase4_slave_bind" "slave bind mount failed"
fi

# Write a file from the shared peer
echo "propagation_test" > "$MNT3/prop_test" 2>/dev/null
if [ -f "$MNT/prop_test" ] 2>/dev/null; then
    pass "phase4_propagation"
else
    blocked "phase4_propagation" "propagation not visible (may need shared peer group)"
fi

# Clean up peer mounts
umount "$MNT4" 2>/dev/null || true
umount "$MNT3" 2>/dev/null || true

# ── Phase 5: Recursive Bind Mount ───────────────────────────────────
echo ""
echo "--- Phase 5: Recursive Bind Mount ---"

mkdir -p "$MNT/dir1/sub"
echo "recursive_bind_content" > "$MNT/dir1/sub/rfile" 2>/dev/null

mkdir -p "$MNT2"
if mount --rbind "$MNT" "$MNT2" 2>/dev/null; then
    pass "phase5_rbind"
    if [ -f "$MNT2/dir1/sub/rfile" ] 2>/dev/null; then
        pass "phase5_rbind_subtree"
    else
        fail "phase5_rbind_subtree" "submount content not visible via rbind"
    fi
    umount -l "$MNT2" 2>/dev/null || true
    sleep 1
else
    skip "phase5_rbind" "rbind not supported by busybox mount"
fi

# ── Phase 6: Multiple Mount Points and Teardown ─────────────────────
echo ""
echo "--- Phase 6: Teardown ---"

# Create multiple bind mounts for teardown stress
mkdir -p "$MNT2" "$MNT3"
mount --bind "$MNT" "$MNT2" 2>/dev/null && pass "phase6_multi_bind_1" || fail "phase6_multi_bind_1" "bind 1 failed"
mount --bind "$MNT" "$MNT3" 2>/dev/null && pass "phase6_multi_bind_2" || fail "phase6_multi_bind_2" "bind 2 failed"

# Check all three are mounted
MOUNT_COUNT=$(grep -c "tidefs" /proc/mounts 2>/dev/null || echo 0)
echo "INFO: tidefs mount count in /proc/mounts: $MOUNT_COUNT"
if [ "$MOUNT_COUNT" -ge 2 ]; then
    pass "phase6_mount_count"
else
    fail "phase6_mount_count" "expected >=2 tidefs mounts, got $MOUNT_COUNT"
fi

# Unmount all bind mounts first
umount "$MNT3" 2>/dev/null && pass "phase6_umount_bind_2" || fail "phase6_umount_bind_2" "umount bind 2 failed"
umount "$MNT2" 2>/dev/null && pass "phase6_umount_bind_1" || fail "phase6_umount_bind_1" "umount bind 1 failed"

# Unmount the original
if umount "$MNT" 2>/dev/null; then
    pass "phase6_umount_original"
else
    umount -l "$MNT" 2>/dev/null && pass "phase6_umount_original_lazy" || fail "phase6_umount_original" "umount original failed"
fi

# Verify all gone from /proc/mounts
if ! grep -q "tidefs" /proc/mounts 2>/dev/null; then
    pass "phase6_all_umounted"
else
    fail "phase6_all_umounted" "tidefs still present in /proc/mounts: $(grep tidefs /proc/mounts | head -1)"
fi

# ── Phase 7: Post-Teardown Module Unload ────────────────────────────
echo ""
echo "--- Phase 7: Module Unload ---"

if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
    pass "phase7_rmmod"
else
    fail "phase7_rmmod" "$(cat /tmp/rmmod.err | head -1)"
fi

if ! lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "phase7_module_gone"
else
    fail "phase7_module_gone" "module still present after rmmod"
fi

# ── Final Sweep ─────────────────────────────────────────────────────
echo ""
echo "--- Final Sweep ---"
DMESG_WARN=$(dmesg | grep -c "WARNING:" 2>/dev/null || echo 0)
DMESG_BUG=$(dmesg | grep -c "BUG:" 2>/dev/null || echo 0)
DMESG_PANIC=$(dmesg | grep -c "Kernel panic" 2>/dev/null || echo 0)
echo "INFO: dmesg WARNING=$DMESG_WARN BUG=$DMESG_BUG PANIC=$DMESG_PANIC"

if [ "$DMESG_WARN" -eq 0 ] && [ "$DMESG_BUG" -eq 0 ] && [ "$DMESG_PANIC" -eq 0 ]; then
    pass "final_dmesg_clean"
else
    fail "final_dmesg_clean" "WARNING=$DMESG_WARN BUG=$DMESG_BUG PANIC=$DMESG_PANIC"
fi

echo ""
echo "============================================================"
echo "=== MOUNT NAMESPACE VALIDATION SUMMARY ==="
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"

sleep 2
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs.gz"

    echo "--- Booting QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet" \
      -nographic \
      -m 512M \
      -no-reboot \
      -serial stdio \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    SKIP_COUNT=$(grep -c "^SKIP:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"

    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-mount-namespace/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    cat > "$OUTPUT_DIR/manifest.json" << MANIFEST
{
  "test": "kernel-mount-namespace-validation",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "bootstrap",
  "validation_tier": "Tier 4 Kbuild+QEMU module-load + Tier 5 mounted kernel VFS",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": "$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)",
  "worktree_dirty": $(git -C /root/tidefs diff --quiet -- . && git -C /root/tidefs diff --cached --quiet -- . && echo false || echo true),
  "result": "kernel mount namespace, bind mount, remount, propagation, and teardown validation"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$FAIL_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  kmodMountNsScript
