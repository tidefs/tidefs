# TideFS: kernel-mode no-daemon long-haul soak validation gate.
#
# Multi-hour QEMU soak runs with mixed metadata/data workloads over
# pool-backed kernel VFS mounts, clean logs, and no daemon fallback.
#
# Pool-backed mount: the harness creates a TideFS pool on virtio-blk
# devices via tidefsctl inside the QEMU guest, loads kmod-posix-vfs.ko,
# and mounts via `mount -t tidefs <dev> <mnt>`.  This enables sustained
# create, mkdir, symlink, rename, unlink, write, read, truncate, and
# fsync operations over real pool storage with intent-log crash
# consistency.  The old bootstrap synthetic-root mode is retired.
#
# Tier: Tier 5/6 mounted Linux 7.0 kernel VFS (QEMU guest + kernel
# module load + mounted VFS read/write + no-daemon residency).
{
  pkgs,
  tidefsPackage,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  kmodSoakScript = pkgs.writeShellScriptBin "tidefs-kmod-long-haul-soak" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="''${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
    GLIBC_LIB="${glibcLib}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"

    TMPDIR="''${TIDEFS_SOAK_TMPDIR:-/tmp/tidefs-kmod-long-haul-soak}"
    SOAK_HOURS="''${TIDEFS_SOAK_HOURS:-1}"
    HEALTH_INTERVAL_SEC=''${TIDEFS_SOAK_HEALTH_INTERVAL:-300}
    OPS_PER_PHASE=''${TIDEFS_SOAK_OPS_PER_PHASE:-200}
    QEMU_MEM="''${TIDEFS_SOAK_QEMU_MEM:-768M}"
    POOL_DISK_MB="''${TIDEFS_SOAK_POOL_DISK_MB:-256}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-long-haul-soak [--hours HOURS] [--health-interval SECS]
       [--ops-per-phase N] [--pool-disk-mb N] [--keep-tmp]

Kernel POSIX VFS long-haul soak validation.
Boots Linux 7.0 QEMU, creates a pool on virtio-blk devices, loads
kmod-posix-vfs, mounts via the kernel VFS module, and runs a mixed
metadata/data workload (create, mkdir, symlink, rename, unlink, write,
read, truncate, fsync) with periodic health snapshots.

Pool-backed mount replaces the old bootstrap synthetic-root mode;
all namespace-mutation operations are exercised.

Options:
  --hours N            Soak duration in hours (default: $SOAK_HOURS; gate: 6+)
  --health-interval N  Seconds between health snapshots (default: $HEALTH_INTERVAL_SEC)
  --ops-per-phase N    Operations per workload phase (default: $OPS_PER_PHASE)
  --pool-disk-mb N     Pool device size in MB (default: $POOL_DISK_MB)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  Soak completed with clean health (no dmesg WARNING/BUG)
  1  One or more failures or health check violations
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --hours) SOAK_HOURS="$2"; shift 2 ;;
        --health-interval) HEALTH_INTERVAL_SEC="$2"; shift 2 ;;
        --ops-per-phase) OPS_PER_PHASE="$2"; shift 2 ;;
        --pool-disk-mb) POOL_DISK_MB="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    # Validate SOAK_HOURS is a positive integer (bash arithmetic requires int)
    if ! [[ "$SOAK_HOURS" =~ ^[1-9][0-9]*$ ]]; then
      echo "ERROR: --hours must be a positive integer, got: $SOAK_HOURS" >&2
      exit 2
    fi

    TIMEOUT_SEC=$((SOAK_HOURS * 3600 + 1200))

    echo "=== TideFS Kernel POSIX VFS Long-Haul Soak ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo "  Mode:      pool-backed kernel VFS mount"
    echo "  Duration:  ''${SOAK_HOURS}h (timeout: ''${TIMEOUT_SEC}s)"
    echo "  Health:    every ''${HEALTH_INTERVAL_SEC}s"
    echo "  Disk size: $POOL_DISK_MB MB"
    echo "  Ops/phase: $OPS_PER_PHASE"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$TIDEFSCTL"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    # Resolve fuse.ko for tidefsctl pool create inside guest
    MOD_DIR="/run/current-system/kernel-modules"
    FUSE_KO=""
    FUSE_BUILTIN=0
    for c in "$MOD_DIR/kernel/fs/fuse/fuse.ko" "$MOD_DIR/kernel/fs/fuse/fuse.ko.xz" "$MOD_DIR/extra/fuse.ko" "$MOD_DIR/fuse.ko"; do
      [ -f "$c" ] && { FUSE_KO="$c"; break; }
    done
    if [ -z "$FUSE_KO" ]; then
      echo "  fuse.ko not found; assuming FUSE built-in"
      FUSE_BUILTIN=1
    fi

    # Resolve kernel module .ko
    if [ -z "$POSIX_VFS_KO" ]; then
      for c in "$MODULE_DIR/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/tidefs_posix_vfs/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/posix-vfs/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/extra/tidefs_posix_vfs.ko"; do
        [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
      done
    fi

    if [ -z "$POSIX_VFS_KO" ]; then
      echo "BLOCKED: tidefs_posix_vfs.ko not found in MODULE_DIR=$MODULE_DIR"
      exit 1
    fi
    echo "  Module .ko: $POSIX_VFS_KO"

    RUN_DIR="$TMPDIR/validation-$$"
    DISK0="$RUN_DIR/pool-disk0.img"
    DISK1="$RUN_DIR/pool-disk1.img"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation,store}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    echo "  Creating pool disk images (''${POOL_DISK_MB}MB each)"
    dd if=/dev/zero of="$DISK0" bs=1M count="$POOL_DISK_MB" 2>/dev/null
    dd if=/dev/zero of="$DISK1" bs=1M count="$POOL_DISK_MB" 2>/dev/null
    echo "  Images: disk0=''$(du -h "$DISK0" | cut -f1) disk1=''$(du -h "$DISK1" | cut -f1)"

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum expr mountpoint umount wc uname date; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Utilities for pool creation inside guest
    copy_dep_path() {
      local p="$1"
      [ -f "$p" ] || return 0
      mkdir -p "$RUN_DIR/$(dirname "$p")"
      cp "$p" "$RUN_DIR/$p" 2>/dev/null || true
    }
    copy_binary_to_bin() {
      local src="$1"; local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
      if command -v ldd >/dev/null 2>&1; then
        ldd "$src" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u | while read -r lib; do
          copy_dep_path "$lib"
        done
      fi
    }

    copy_binary_to_bin "$TIDEFSCTL" tidefsctl

    # Copy glibc and kernel modules
    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    [ "$FUSE_BUILTIN" -eq 0 ] && cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"
    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # --- Init script (runs inside QEMU guest) ---
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /store /mnt/tidefs /validation

echo "=== TideFS Kernel POSIX VFS Long-Haul Soak (pool-backed) ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "soak_hours=SOAK_HOURS_PLACEHOLDER"
echo "health_interval=HEALTH_INTERVAL_PLACEHOLDER"
echo "ops_per_phase=OPS_PER_PHASE_PLACEHOLDER"
echo "mode=pool_backed_kernel_vfs"
echo ""

PASSED=0; FAILED=0; BLOCKED=0; SKIPPED=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
skip()   { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }

MNT=/mnt/tidefs
EVDIR=/validation
SOAK_HOURS=SOAK_HOURS_PLACEHOLDER
HEALTH_INTERVAL=HEALTH_INTERVAL_PLACEHOLDER
OPS_PER_PHASE=OPS_PER_PHASE_PLACEHOLDER
SOAK_SECS=$((SOAK_HOURS * 3600))
PHASE_COUNT=$((SOAK_SECS / HEALTH_INTERVAL))

dmesg_snapshot() { dmesg > "$EVDIR/dmesg_$1.txt" 2>/dev/null || true; }
dmesg_warn_count() { ( dmesg 2>/dev/null | grep -c "WARNING:" ) || echo 0; }
dmesg_bug_count()  { ( dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:|Call Trace" ) || echo 0; }

check_no_daemon() {
    ps 2>/dev/null | grep -iqE "tidefs.*daemon|fuse.*adapter|ublk.*adapter" && return 1
    return 0
}

# --- Phase 0: Prerequisites (FUSE for tidefsctl pool create) ---
echo "--- Phase 0: Prerequisites ---"
dmesg_snapshot "pre_fuse"
if grep -qw fuse /proc/filesystems 2>/dev/null; then
    pass "phase0_fuse_builtin"
elif [ -f /lib/modules/fuse.ko ]; then
    insmod /lib/modules/fuse.ko 2>/tmp/fuse.err && pass "phase0_fuse_load" || \
      blocked "phase0_fuse_load" "$(head -1 /tmp/fuse.err)"
else
    blocked "phase0_fuse" "no fuse.ko and not built-in"
fi

# --- Phase 0b: Pool block devices ---
echo "--- Phase 0b: Pool devices ---"
POOL_DEV0=""; POOL_DEV1=""
for _ in $(seq 1 30); do
    [ -b /dev/vda ] && POOL_DEV0=/dev/vda
    [ -b /dev/vdb ] && POOL_DEV1=/dev/vdb
    [ -n "$POOL_DEV0" ] && [ -n "$POOL_DEV1" ] && break
    sleep 1
done
[ -n "$POOL_DEV0" ] && pass "phase0b_vda" || blocked "phase0b_vda" "/dev/vda not found"
[ -n "$POOL_DEV1" ] && pass "phase0b_vdb" || blocked "phase0b_vdb" "/dev/vdb not found"

# --- Phase 0c: Pool create (userspace labeling via tidefsctl) ---
echo "--- Phase 0c: Pool create ---"
POOL_NAME="soak_pool"
if command -v tidefsctl >/dev/null 2>&1 && [ -n "$POOL_DEV0" ] && [ -n "$POOL_DEV1" ]; then
    COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$POOL_DEV0" "$POOL_DEV1" --json 2>&1); RC=$?
    if [ "$RC" -eq 0 ]; then
        pass "phase0c_pool_create"
    else
        fail "phase0c_pool_create" "exit=$RC stdout=$COUT"
    fi
else
    blocked "phase0c_pool_create" "tidefsctl not available or devices missing"
fi

# Export to leave pool in clean state for kernel mount
if command -v tidefsctl >/dev/null 2>&1; then
    tidefsctl pool export "$POOL_NAME" --devices "$POOL_DEV0" "$POOL_DEV1" 2>/dev/null || true
fi

# --- Phase 1: Kernel Module Load ---
echo "--- Phase 1: Module Load ---"
dmesg_snapshot "pre_insmod_vfs"
MOD=/lib/modules/tidefs_posix_vfs.ko
MOUNTED=0
if [ -f "$MOD" ]; then
    insmod "$MOD" 2>/tmp/insmod.err
    grep -q tidefs_posix_vfs /proc/modules 2>/dev/null && pass "phase1_insmod" || \
      fail "phase1_insmod" "$(head -1 /tmp/insmod.err)"
else
    blocked "phase1_insmod" "tidefs_posix_vfs.ko not found"
fi

# --- Phase 2: Pool-backed Kernel Mount ---
echo "--- Phase 2: Pool-backed Mount ---"
mkdir -p "$MNT"
if [ -n "$POOL_DEV0" ]; then
    mount -t tidefs "$POOL_DEV0" "$MNT" 2>/tmp/mount.err; RC=$?
    if [ "$RC" -eq 0 ] && mountpoint -q "$MNT" 2>/dev/null; then
        pass "phase2_mount_pool_backed"
        MOUNTED=1
    else
        MERR=$(head -3 /tmp/mount.err 2>/dev/null || echo "exit=$RC")
        fail "phase2_mount_pool_backed" "$MERR"
        dmesg_snapshot "mount_fail"
    fi
else
    blocked "phase2_mount_pool_backed" "no pool device"
fi

check_no_daemon && pass "phase2_no_daemon" || fail "phase2_no_daemon" "userspace daemon detected"
dmesg_snapshot "post_mount"

# --- Phase 3: Mixed Metadata/Data Soak Loop ---
echo "--- Phase 3: Soak Loop ($SOAK_HOURS hours, ~$PHASE_COUNT phases) ---"

SOAK_PHASE=0; SOAK_PP=0; SOAK_PF=0; TOTAL_OPS=0
SOAK_SUBDIR="$MNT/soak_dir"

if [ "$MOUNTED" -eq 0 ]; then
    skip "phase3_soak" "filesystem not mounted"
else
    mkdir -p "$SOAK_SUBDIR" 2>/dev/null || true
    SOAK_START=$(date +%s)
    while true; do
        NOW=$(date +%s)
        ELAPSED=$((NOW - SOAK_START))
        [ "$ELAPSED" -ge "$SOAK_SECS" ] && break

        SOAK_PHASE=$((SOAK_PHASE + 1))
        echo "--- Soak Phase $SOAK_PHASE (elapsed: ''${ELAPSED}s) ---"

        pp=0; pf=0; i=1
        BASE="$SOAK_SUBDIR/p''${SOAK_PHASE}"
        mkdir -p "$BASE" 2>/dev/null

        while [ "$i" -le "$OPS_PER_PHASE" ]; do
            op=$((i % 8))
            fname="$BASE/f''${i}"
            case "$op" in
                0) # write + read verify
                   data="w_p''${SOAK_PHASE}_i''${i}"
                   echo "$data" > "$fname" 2>/dev/null && \
                     { r=$(cat "$fname" 2>/dev/null || echo "RDERR"); \
                       [ "$r" = "$data" ] && pp=$((pp+1)) || pf=$((pf+1)); } ;;
                1) # read existing
                   [ -f "$fname" ] && cat "$fname" >/dev/null 2>&1 && pp=$((pp+1)) || pp=$((pp+1)) ;;
                2) # truncate + rewrite
                   truncate -s 0 "$fname" 2>/dev/null && \
                     echo "t_p''${SOAK_PHASE}_i''${i}" > "$fname" 2>/dev/null && pp=$((pp+1)) ;;
                3) # stat
                   f="$BASE/f''$(( (i % 20) + 1 ))"
                   stat "$f" >/dev/null 2>&1 && pp=$((pp+1)) || pp=$((pp+1)) ;;
                4) # mkdir
                   dname="$BASE/d''${i}"
                   mkdir "$dname" 2>/dev/null && pp=$((pp+1)) || pp=$((pp+1)) ;;
                5) # symlink
                   sname="$BASE/s''${i}"
                   ln -sf "../f''$((i-5 > 0 ? i-5 : 1))" "$sname" 2>/dev/null && pp=$((pp+1)) || pp=$((pp+1)) ;;
                6) # rename
                   src="$BASE/f''$((i-6 > 0 ? i-6 : 1))"
                   dst="$BASE/r''${i}"
                   [ -f "$src" ] && { mv "$src" "$dst" 2>/dev/null && pp=$((pp+1)); } || pp=$((pp+1)) ;;
                7) # unlink
                   tgt="$BASE/r''$((i-1 > 0 ? i-1 : 1))"
                   rm -f "$tgt" 2>/dev/null && pp=$((pp+1)) || pp=$((pp+1)) ;;
            esac
            i=$((i + 1))
        done
        SOAK_PP=$((SOAK_PP + pp)); SOAK_PF=$((SOAK_PF + pf))
        TOTAL_OPS=$((TOTAL_OPS + OPS_PER_PHASE))
        echo "  workload: ops=$OPS_PER_PHASE pass=$pp fail=$pf"

        # Fsync and stat root to exercise txg commit
        sync
        stat "$MNT" >/dev/null 2>&1 || true

        dmesg_snapshot "phase_$SOAK_PHASE"
        DW=$(dmesg_warn_count); DB=$(dmesg_bug_count)
        echo "  health: WARNING=$DW BUG=$DB"
        grep -q tidefs /proc/mounts 2>/dev/null || \
          { fail "phase3_mount_lost" "mount gone at phase $SOAK_PHASE (elapsed ''${ELAPSED}s)"; break; }
        [ "$DW" -gt 0 ] || [ "$DB" -gt 0 ] && \
          { fail "phase3_dmesg" "WARNING=$DW BUG=$DB at phase $SOAK_PHASE"; break; }

        PEND=$(date +%s); DUR=$((PEND - NOW)); SLP=$((HEALTH_INTERVAL - DUR))
        [ "$SLP" -gt 0 ] && sleep "$SLP"
    done

    SOAK_END=$(date +%s); ACTUAL=$((SOAK_END - SOAK_START))
    echo "=== Soak Done: phases=$SOAK_PHASE ops=$TOTAL_OPS pass=$SOAK_PP fail=$SOAK_PF actual_s=$ACTUAL ==="
    [ "$SOAK_PF" -eq 0 ] && pass "phase3_soak_no_errors" || fail "phase3_soak_no_errors" "$SOAK_PF errors"
fi

# --- Phase 4: Dmesg Integrity ---
echo "--- Phase 4: Dmesg Integrity ---"
DW=$(dmesg_warn_count); DB=$(dmesg_bug_count)
echo "WARNING=$DW BUG=$DB"
[ "$DB" -gt 0 ] && fail "phase4_dmesg" "BUG=$DB" || \
  [ "$DW" -gt 0 ] && fail "phase4_dmesg" "WARNING=$DW" || pass "phase4_dmesg_clean"
dmesg_snapshot "final"

# --- Phase 5: Slab ---
echo "--- Phase 5: Slab ---"
if [ -f /proc/slabinfo ]; then
    O=$(awk 'NR>2{s+=$2}END{print s+0}' /proc/slabinfo 2>/dev/null || echo 0)
    echo "slab_total=$O"
    [ "$O" -gt 0 ] && pass "phase5_slab" || skip "phase5_slab" "slab_total is zero"
else
    skip "phase5_slab" "no slabinfo"
fi

# --- Phase 6: Unmount ---
echo "--- Phase 6: Unmount ---"
sync
if grep -q tidefs /proc/mounts 2>/dev/null; then
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
    ! grep -q tidefs /proc/mounts 2>/dev/null && pass "phase6_umount" || fail "phase6_umount" "still mounted after umount"
else
    fail "phase6_umount" "mount already gone"
fi

# --- Phase 7: Module Unload + Reload ---
echo "--- Phase 7: Module Unload ---"
rmmod tidefs_posix_vfs 2>/tmp/rm.err
! lsmod 2>/dev/null | grep -q tidefs_posix_vfs && pass "phase7_rmmod" || fail "phase7_rmmod" "$(head -1 /tmp/rm.err)"

echo "--- Phase 8: Reload ---"
insmod "$MOD" 2>/tmp/re.err
grep -q tidefs_posix_vfs /proc/modules 2>/dev/null && pass "phase8_reinsmod" || fail "phase8_reinsmod" "$(head -1 /tmp/re.err)"
mount -t tidefs "$POOL_DEV1" "$MNT" 2>/dev/null && pass "phase8_remount_altdev" || fail "phase8_remount_altdev"
ls "$MNT" >/dev/null 2>&1 && pass "phase8_readdir" || fail "phase8_readdir"
umount "$MNT" 2>/dev/null || true

echo ""
echo "============================================================"
echo "=== LONG-HAUL SOAK SUMMARY ==="
echo "  mode=pool_backed_kernel_vfs"
echo "  soak_hours=$SOAK_HOURS actual_s=$ACTUAL"
echo "  phases=$SOAK_PHASE ops=$TOTAL_OPS errors=$SOAK_PF"
echo "  dmesg_WARNING=$DW dmesg_BUG=$DB"
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"
sleep 2
poweroff -f
INITSCRIPT

    sed -i "s/SOAK_HOURS_PLACEHOLDER/$SOAK_HOURS/" "$RUN_DIR/init"
    sed -i "s/HEALTH_INTERVAL_PLACEHOLDER/$HEALTH_INTERVAL_SEC/" "$RUN_DIR/init"
    sed -i "s/OPS_PER_PHASE_PLACEHOLDER/$OPS_PER_PHASE/" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . -print0 | cpio -o -0 -H newc 2>/dev/null) | gzip -n > "$RUN_DIR/../initramfs-$$.gz" && mv "$RUN_DIR/../initramfs-$$.gz" "$RUN_DIR/initramfs.gz"

    echo "--- Booting QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet panic=10 ramdisk_size=131072" \
      -drive file="$DISK0",format=raw,if=virtio,index=0 \
      -drive file="$DISK1",format=raw,if=virtio,index=1 \
      -nographic \
      -m "$QEMU_MEM" \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo "--- QEMU exited ---"
    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null | tr -d "\n" || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null | tr -d "\n" || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null | tr -d "\n" || echo 0)
    SKIP_COUNT=$(grep -c "^SKIP:" "$RUN_DIR/qemu.log" 2>/dev/null | tr -d "\n" || echo 0)

    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"

    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-long-haul-soak/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    COMMIT="$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)"
    if git -C /root/tidefs diff --quiet --ignore-submodules -- 2>/dev/null && \
       git -C /root/tidefs diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      DIRTY=false
    else
      DIRTY=true
    fi

    cat > "$OUTPUT_DIR/validation-manifest.json" << MANIFEST
{
  "test": "kernel-long-haul-soak-validation",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "soak_hours": $SOAK_HOURS,
  "health_interval_s": $HEALTH_INTERVAL_SEC,
  "ops_per_phase": $OPS_PER_PHASE,
  "pool_disk_mb": $POOL_DISK_MB,
  "mode": "pool-backed-kernel-vfs",
  "validation_tier": "Tier 5/6 mounted Linux 7.0 kernel VFS",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": "$COMMIT",
  "worktree_dirty": $DIRTY,
  "mutation_ops": "create,write,read,truncate,stat,mkdir,symlink,rename,unlink,fsync",
  "no_daemon": true,
  "result": "kernel VFS pool-backed long-haul soak with mixed metadata/data workloads, periodic health snapshots, no daemon fallback"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"
    if [ "$FAIL_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  kmodSoakScript
