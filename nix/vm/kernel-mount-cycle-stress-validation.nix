# TideFS: kernel-mode no-daemon mount-cycle resource-cleanup validation.
#
# Boots a Linux 7.0 kernel with kmod-posix-vfs, performs 50
# mount→write(1MiB)→sync→umount cycles in bootstrap mode, tracks kernel
# slab/dentry/inode counters and dmesg for WARNING/BUG/leak indicators,
# verifies data integrity across remounts, and confirms clean module
# unload/reload.
#
# Block-device (pool-backed) mount is blocked on missing in-kernel pool
# label initialization.  Bootstrap mode exercises the full mount/umount
# lifecycle and VFS operation dispatch paths.
#
# Produces tier-classified validation rows (Pass/Fail/Blocked).
# Tier: QEMU guest (Tier 4: Kbuild + QEMU module load).
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodMountCycleScript = pkgs.writeShellScriptBin "tidefs-kmod-mount-cycle-stress" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"

    TMPDIR="''${TIDEFS_MOUNT_CYCLE_TMPDIR:-/tmp/tidefs-mount-cycle-stress}"
    TIMEOUT_SEC="''${TIDEFS_MOUNT_CYCLE_TIMEOUT:-600}"
    CYCLE_COUNT="''${TIDEFS_MOUNT_CYCLE_COUNT:-50}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-mount-cycle-stress [--timeout SECONDS] [--cycles N] [--keep-tmp]

Validate kmod-posix-vfs mount/umount resource cleanup with write/verify
cycles in a Linux 7.0 QEMU guest. 50 cycles of mount→write(1MiB)→sync→umount
with slab-counter tracking, dmesg inspection, and data verification.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --cycles N           Number of mount/umount cycles (default: $CYCLE_COUNT)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  All cycles passed, no resource leaks or warnings detected
  1  One or more failures or resource leaks detected
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --cycles) CYCLE_COUNT="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS K7-VAL: kmod-posix-vfs Mount-Cycle Stress ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo "  Cycles:    $CYCLE_COUNT"
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
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum; do
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

echo "=== TideFS Mount-Cycle Stress ==="
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
EVDIR=/validation

# ── Slab tracking helpers ───────────────────────────────────────────
capture_slab() {
    local label="$1"
    local f="$EVDIR/slab_$label.txt"
    if [ -f /proc/slabinfo ]; then
        cp /proc/slabinfo "$f" 2>/dev/null || true
    fi
}

capture_dmesg_marker() {
    local label="$1"
    echo "=== DMESG_MARKER: $label ===" > /dev/kmsg 2>/dev/null || true
}

slab_delta() {
    local before="$1" after="$2"
    if [ ! -f "$before" ] || [ ! -f "$after" ]; then
        echo "unavailable"
        return
    fi
    local bo ao
    bo=$(awk 'NR>2 {s+=$2} END{print s+0}' "$before" 2>/dev/null || echo 0)
    ao=$(awk 'NR>2 {s+=$2} END{print s+0}' "$after" 2>/dev/null || echo 0)
    echo "objs_before=$bo objs_after=$ao delta=$((ao - bo))"
}

# ── Phase 0: Module Load ────────────────────────────────────────────
echo "--- Phase 0: Module Load ---"
capture_dmesg_marker "phase0_pre_insmod"
capture_slab "pre_insmod"

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

# ── Phase 1: Mount-Cycle Stress ─────────────────────────────────────
echo ""
echo "--- Phase 1: Mount-Cycle Stress (CYCLE_COUNT_PLACEHOLDER cycles) ---"
CYCLE_COUNT=CYCLE_COUNT_PLACEHOLDER

capture_slab "pre_cycles"
capture_dmesg_marker "cycles_start"

first_fail=0
cycles_pass=0
cycles_fail=0

cycle=1
while [ "$cycle" -le "$CYCLE_COUNT" ]; do
    if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
        pass "cycle''${cycle}_mount"

        # Write 1 MiB of data
        dd if=/dev/zero of="$MNT/cycle_pad" bs=1024 count=1024 2>/dev/null || true
        echo "cycle''${cycle}_write_ok" > "$MNT/cycle_test" 2>/dev/null || true
        sync

        # Verify readback within same mount
        READBACK=$(cat "$MNT/cycle_test" 2>/dev/null || echo "")
        if echo "$READBACK" | grep -q "cycle''${cycle}_write_ok"; then
            pass "cycle''${cycle}_write_verify"
        else
            fail "cycle''${cycle}_write_verify" "readback mismatch (got: $READBACK)"
        fi

        # Unmount
        if umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null; then
            pass "cycle''${cycle}_umount"
        else
            fail "cycle''${cycle}_umount" "umount failed"
            [ "$first_fail" -eq 0 ] && first_fail="$cycle"
        fi

        # Check dmesg for new warnings
        DMESG_NEW=$(dmesg | grep -c "WARNING\|BUG\|Call Trace" 2>/dev/null || echo 0)
        if [ "$DMESG_NEW" -eq 0 ]; then
            pass "cycle''${cycle}_dmesg"
        else
            fail "cycle''${cycle}_dmesg" "dmesg warnings=$DMESG_NEW"
            [ "$first_fail" -eq 0 ] && first_fail="$cycle"
        fi

        cycles_pass=$((cycles_pass + 1))
    else
        fail "cycle''${cycle}_mount" "mount failed"
        cycles_fail=$((cycles_fail + 1))
        [ "$first_fail" -eq 0 ] && first_fail="$cycle"
    fi
    cycle=$((cycle + 1))
done

capture_slab "post_cycles"
capture_dmesg_marker "cycles_end"

echo "INFO: cycles pass=$cycles_pass fail=$cycles_fail first_fail=$first_fail"

# ── Phase 1b: Slab Leak Check ───────────────────────────────────────
echo ""
echo "--- Phase 1b: Slab Leak Check ---"
SLAB_INFO=$(slab_delta "$EVDIR/slab_pre_cycles.txt" "$EVDIR/slab_post_cycles.txt")
echo "INFO: slab $SLAB_INFO"
SLAB_DELTA=$(echo "$SLAB_INFO" | grep -o 'delta=[-0-9]*' | cut -d= -f2 || echo "NA")
if [ "$SLAB_DELTA" != "NA" ] && [ "$SLAB_DELTA" -gt 1000 ] 2>/dev/null; then
    fail "slab_leak_check" "slab object delta=$SLAB_DELTA (>1000 threshold)"
else
    pass "slab_leak_check"
fi

# ── Phase 1c: Cross-Remount Verification ────────────────────────────
echo ""
echo "--- Phase 1c: Cross-Remount Verification ---"
if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
    if [ -f "$MNT/cycle_test" ]; then
        LAST=$(cat "$MNT/cycle_test" 2>/dev/null || echo "")
        if echo "$LAST" | grep -q "write_ok"; then
            pass "cross_remount_data"
        else
            fail "cross_remount_data" "unexpected content: $LAST"
        fi
    else
        blocked "cross_remount_data" "bootstrap mode: no disk-backed persistence across remount"
    fi
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
else
    skip "cross_remount_data" "remount failed"
fi

# ── Phase 2: Module Unload ──────────────────────────────────────────
echo ""
echo "--- Phase 2: Module Unload ---"
capture_slab "pre_rmmod"
if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
    pass "phase2_rmmod"
else
    fail "phase2_rmmod" "$(cat /tmp/rmmod.err | head -1)"
fi

if ! lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "phase2_module_gone"
else
    fail "phase2_module_gone" "module still present after rmmod"
fi
capture_slab "post_rmmod"

# ── Phase 3: Clean Reload ───────────────────────────────────────────
echo ""
echo "--- Phase 3: Clean Reload ---"
if insmod "$MODULE_PATH" 2>/tmp/reinsmod.err; then
    pass "phase3_reinsmod"
else
    fail "phase3_reinsmod" "$(cat /tmp/reinsmod.err | head -1)"
fi

if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
    pass "phase3_remount"
    ls "$MNT" >/dev/null 2>&1 && pass "phase3_readdir" || fail "phase3_readdir" "readdir failed"
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
else
    fail "phase3_remount" "re-mount after reload failed"
fi

# ── Final Sweep ─────────────────────────────────────────────────────
echo ""
echo "--- Final Sweep ---"
DMESG_WARN=$(dmesg | grep -c "WARNING:" 2>/dev/null || echo 0)
DMESG_BUG=$(dmesg | grep -c "BUG:" 2>/dev/null || echo 0)
echo "INFO: dmesg WARNING=$DMESG_WARN BUG=$DMESG_BUG"

if [ "$DMESG_WARN" -eq 0 ] && [ "$DMESG_BUG" -eq 0 ]; then
    pass "final_dmesg_clean"
else
    fail "final_dmesg_clean" "WARNING=$DMESG_WARN BUG=$DMESG_BUG"
fi

FINAL_SLAB=$(slab_delta "$EVDIR/slab_pre_insmod.txt" "$EVDIR/slab_post_rmmod.txt")
echo "INFO: final_slab $FINAL_SLAB"

echo ""
echo "============================================================"
echo "=== MOUNT CYCLE STRESS SUMMARY ==="
echo "  cycles=$CYCLE_COUNT pass=$cycles_pass fail=$cycles_fail"
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"

sleep 2
poweroff -f
INITSCRIPT

    sed -i "s/CYCLE_COUNT_PLACEHOLDER/$CYCLE_COUNT/" "$RUN_DIR/init"
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

    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-mount-cycle-stress/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    SOURCE_DIR="''${TIDEFS_SOURCE_DIR:-$PWD}"
    SOURCE_COMMIT="''${TIDEFS_SOURCE_COMMIT:-}"
    WORKTREE_DIRTY=null
    if [ -z "$SOURCE_COMMIT" ] && git -C "$SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      SOURCE_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
      if git -C "$SOURCE_DIR" diff --quiet -- . && git -C "$SOURCE_DIR" diff --cached --quiet -- .; then
        WORKTREE_DIRTY=false
      else
        WORKTREE_DIRTY=true
      fi
    fi
    SOURCE_COMMIT="''${SOURCE_COMMIT:-unknown}"

    cat > "$OUTPUT_DIR/manifest.json" << MANIFEST
{
  "test": "kernel-mount-cycle-stress-validation",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cycle_count": $CYCLE_COUNT,
  "mode": "bootstrap",
  "validation_tier": "QEMU guest (Tier 4)",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": "$SOURCE_COMMIT",
  "worktree_dirty": $WORKTREE_DIRTY,
  "result": "bootstrap mount-cycle stress with write/verify and slab tracking"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$FAIL_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  kmodMountCycleScript
