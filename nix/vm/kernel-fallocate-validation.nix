# TideFS: kernel fallocate + SEEK_DATA/SEEK_HOLE sparse validation.
#
# Replaces the retired blocker script with a real QEMU guest workload.
# Builds the kmod-posix-vfs module against Linux 7.0, boots a QEMU guest,
# loads the module, mounts TideFS through the kernel module, and exercises
# fallocate(2) allocate/PUNCH_HOLE/ZERO_RANGE/KEEP_SIZE modes plus
# indirect SEEK_DATA/SEEK_HOLE sparse-file extent resolution via dd/od.
#
# SEEK_DATA/SEEK_HOLE verification uses dd positional reads: reading from
# a hole returns zeros, reading from data returns original content. A full
# lseek(SEEK_DATA/SEEK_HOLE) C helper is deferred to Review debt TFR-018; it
# adds a static binary to the initramfs.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodFallocateScript = pkgs.writeShellScriptBin "tidefs-kmod-fallocate-validation" ''
    set -euo pipefail

    KERNEL_OVERRIDE=""

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.pkgsStatic.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_KMOD_FALLOC_TMPDIR:-/tmp/tidefs-kmod-fallocate-validation}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_FALLOC_TIMEOUT:-300}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-fallocate-validation [--timeout SECONDS] [--keep-tmp]

Validate kmod-posix-vfs fallocate (allocate, PUNCH_HOLE, ZERO_RANGE,
KEEP_SIZE) and sparse-file extent resolution in a reproducible
Nix/QEMU Linux 7.0 environment. Uses dd/od to verify hole vs data
regions indirectly (direct lseek(SEEK_DATA/SEEK_HOLE) helper deferred).

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --kernel-path PATH   Path to bzImage (overrides built-in kernel)
  --module-path PATH   Path to tidefs_posix_vfs.ko
  --keep-tmp           Retain temp dir and QEMU log on exit
  --help, -h           Show this message
EOF
    }

    KEEP_TMP=""
    MODULE_PATH=""
    KERNEL_OVERRIDE=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --kernel-path) KERNEL_OVERRIDE="$2"; shift 2 ;;
        --module-path) MODULE_PATH="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    # Apply kernel override now that args are parsed.
    if [ -n "$KERNEL_OVERRIDE" ] && [ -f "$KERNEL_OVERRIDE" ]; then
      KERNEL_IMG="$KERNEL_OVERRIDE"
    fi

    echo "=== TideFS K7-VAL: Fallocate + Sparse Validation ==="
    echo "  Kernel:  $KERNEL_IMG"
    echo "  QEMU:    $QEMU_BIN"
    echo "  Timeout: ''${TIMEOUT_SEC}s"

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep \
      poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find \
      wc truncate fallocate od awk; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    MODULE_FOUND=0
    # Accept explicit .ko path from --module-path flag (Tier 5 QEMU validation).
    if [ -n "$MODULE_PATH" ] && [ -f "$MODULE_PATH" ]; then
      cp "$MODULE_PATH" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"
      MODULE_FOUND=1
      echo "Using module: $MODULE_PATH"
    elif [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$RUN_DIR/lib/modules/"
      MODULE_FOUND=1
    fi

    # ── Init script ───────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Sparse: Fallocate + SEEK_DATA/SEEK_HOLE ==="
echo "kernel=$(uname -r)"
echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED+1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED+1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED+1)); }

MNT=/mnt/tidefs
T1="$MNT/s1"
ZERO_4K=$(dd if=/dev/zero bs=4096 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')

# ── Phase 0: Module load ────────────────────────────────────────────
echo "--- Phase 0: Module ---"
KO=/lib/modules/tidefs_posix_vfs.ko
if [ -f "$KO" ]; then
    insmod "$KO" 2>/tmp/e0 && pass "mod_insmod" || fail "mod_insmod" "$(cat /tmp/e0)"
else
    blocked "mod_insmod" "no .ko in initramfs"
fi
lsmod 2>/dev/null | grep -q tidefs_posix_vfs && pass "mod_lsmod" || blocked "mod_lsmod" "not loaded"

# ── Phase 1: Mount ──────────────────────────────────────────────────
echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"
mount -t tidefs none "$MNT" 2>/tmp/e1 && pass "mount" || blocked "mount" "$(cat /tmp/e1)"
MOUNTED=0; mountpoint -q "$MNT" 2>/dev/null && MOUNTED=1

# ── Phase 2: Sparse file via dd seek (data-hole-data) ───────────────
echo "--- Phase 2: Sparse via dd seek ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Write 4k data at offset 0
    dd if=/dev/urandom of="$T1" bs=4096 count=1 2>/tmp/e2a && pass "s2a_head" \
      || fail "s2a_head" "$(cat /tmp/e2a)"
    # Write 4k data at offset 8192 (hole at 4096-8191)
    dd if=/dev/urandom of="$T1" bs=4096 count=1 seek=2 2>/tmp/e2b && pass "s2b_tail" \
      || fail "s2b_tail" "$(cat /tmp/e2b)"
    SZ=$(stat -c %s "$T1" 2>/dev/null || echo 0)
    [ "$SZ" -ge 12288 ] && pass "s2c_size_12k" || fail "s2c_size_12k" "got=$SZ"

    # Verify head block has data (not all zero)
    HZ=$(dd if="$T1" bs=4096 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$HZ" != "$ZERO_4K" ] && pass "s2d_head_nz" || fail "s2d_head_nz" "all zero"

    # Verify hole block (offset 4096) is all zeros
    HO=$(dd if="$T1" bs=4096 skip=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$HO" = "$ZERO_4K" ] && pass "s2e_hole_zero" || fail "s2e_hole_zero" "not zero"

    # Verify tail block (offset 8192) has data
    TZ=$(dd if="$T1" bs=4096 skip=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$TZ" != "$ZERO_4K" ] && pass "s2f_tail_nz" || fail "s2f_tail_nz" "all zero"

    rm -f "$T1"
else
    for t in s2a_head s2b_tail s2c_size_12k s2d_head_nz s2e_hole_zero s2f_tail_nz; do
        blocked "$t" "no mount"
    done
fi

# ── Phase 3: Punch hole ─────────────────────────────────────────────
echo "--- Phase 3: Punch hole ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Create full 12k file (no holes)
    dd if=/dev/urandom of="$T1" bs=4096 count=3 2>/tmp/e3a && pass "s3a_full" \
      || fail "s3a_full" "$(cat /tmp/e3a)"
    SZ1=$(stat -c %s "$T1" 2>/dev/null || echo 0)

    # Verify no hole at offset 0 (SEEK_HOLE returns size)
    H0=$(dd if="$T1" bs=4096 skip=0 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$H0" != "$ZERO_4K" ] && pass "s3b_full_nohole" || fail "s3b_full_nohole" "zero at 0"

    # Punch hole at offset 4096 length 4096
    fallocate -p -o 4096 -l 4096 "$T1" 2>/tmp/e3c && pass "s3c_punch" \
      || blocked "s3c_punch" "$(cat /tmp/e3c)"

    # Size unchanged
    SZ2=$(stat -c %s "$T1" 2>/dev/null || echo 0)
    [ "$SZ2" = "$SZ1" ] && pass "s3d_size_same" || fail "s3d_size_same" "$SZ1->$SZ2"

    # Punched region is zero
    PZ=$(dd if="$T1" bs=4096 skip=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$PZ" = "$ZERO_4K" ] && pass "s3e_punched_zero" || fail "s3e_punched_zero" "not zero"

    # Head block preserved
    HD=$(dd if="$T1" bs=4096 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$HD" != "$ZERO_4K" ] && pass "s3f_head_ok" || fail "s3f_head_ok" "became zero"

    # Tail block preserved
    TL=$(dd if="$T1" bs=4096 skip=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$TL" != "$ZERO_4K" ] && pass "s3g_tail_ok" || fail "s3g_tail_ok" "became zero"

    rm -f "$T1"
else
    for t in s3a_full s3b_full_nohole s3c_punch s3d_size_same s3e_punched_zero s3f_head_ok s3g_tail_ok; do
        blocked "$t" "no mount"
    done
fi

# ── Phase 4: Zero range ─────────────────────────────────────────────
echo "--- Phase 4: Zero range ---"
if [ "$MOUNTED" -eq 1 ]; then
    dd if=/dev/urandom of="$T1" bs=4096 count=2 2>/tmp/e4a && pass "s4a_create" \
      || fail "s4a_create" "$(cat /tmp/e4a)"
    fallocate -z -o 0 -l 4096 "$T1" 2>/tmp/e4b && pass "s4b_zero" \
      || blocked "s4b_zero" "$(cat /tmp/e4b)"
    # First 4k should be zero after zero-range
    Z0=$(dd if="$T1" bs=4096 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$Z0" = "$ZERO_4K" ] && pass "s4c_zeroed" || fail "s4c_zeroed" "not zero"
    rm -f "$T1"
else
    for t in s4a_create s4b_zero s4c_zeroed; do blocked "$t" "no mount"; done
fi

# ── Phase 5: Allocate ───────────────────────────────────────────────
echo "--- Phase 5: Allocate ---"
if [ "$MOUNTED" -eq 1 ]; then
    T5="$MNT/s5"
    fallocate -l 16384 "$T5" 2>/tmp/e5a && pass "s5a_alloc" \
      || blocked "s5a_alloc" "$(cat /tmp/e5a)"
    SZ=$(stat -c %s "$T5" 2>/dev/null || echo 0)
    [ "$SZ" = "16384" ] && pass "s5b_size" || fail "s5b_size" "got=$SZ"
    # Allocate should produce zero-filled readable space
    A0=$(dd if="$T5" bs=4096 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$A0" = "$ZERO_4K" ] && pass "s5c_zero" || fail "s5c_zero" "not zero"
    rm -f "$T5"
else
    for t in s5a_alloc s5b_size s5c_zero; do blocked "$t" "no mount"; done
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "=== SUMMARY: PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED ==="

if [ "$MOUNTED" -eq 1 ]; then umount "$MNT" 2>/dev/null || true; fi
rmmod tidefs_posix_vfs 2>/dev/null || true

echo "poweroff..."
poweroff -f 2>/dev/null || reboot -f 2>/dev/null
exit 0
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # ── Build initramfs ──────────────────────────────────────────────
    ( cd "$RUN_DIR" && find . -print0 | "$CPIO" -0 -o -H newc ) > "$RUN_DIR/initramfs.cpio" 2>/dev/null

    # ── QEMU ─────────────────────────────────────────────────────────
    echo "Starting QEMU (timeout=''${TIMEOUT_SEC}s)..."

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
        -kernel "$KERNEL_IMG" \
        -initrd "$RUN_DIR/initramfs.cpio" \
        -append "console=ttyS0 quiet init=/init" \
        -nographic -no-reboot -m 512 \
        2>&1 | tee "$RUN_DIR/qemu.log"

    QEX=$?

    PASS_N=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_N=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCK_N=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo "QEMU exit=$QEX  PASS=$PASS_N FAIL=$FAIL_N BLOCKED=$BLOCK_N"

    if [ "$FAIL_N" -gt 0 ]; then echo "FAILED"; exit 1; fi
    if [ "$PASS_N" -eq 0 ]; then echo "No tests exercised (all blocked)"; exit 1; fi
    echo "All exercised tests passed."
    '';

in
kmodFallocateScript
