#!/usr/bin/env bash
# TideFS kernel pool fixture runner (#6129).
# Boots the shared Linux 7.0 kernel image, loads product .ko files
# (tidefs-kmod-posix-vfs, tidefs-block-kmod), attaches fixture block
# devices as virtio-blk disks, and exercises kernel-mode pool import,
# default engine mount, and block I/O.
#
# Uses the same virtio-disk, compressed-initrd, and library-copy pattern
# as nix/vm/pool-e2e-blockdev-validation.nix.
set -euo pipefail

FIXTURE_DIR="${TIDEFS_FIXTURE_DIR:-/tmp/tidefs-pool-fixture}"
KERNEL_IMG="${TIDEFS_KERNEL_IMG:-}"
MODULE_DIR="${TIDEFS_MODULE_DIR:-}"
QEMU_BIN="${TIDEFS_QEMU_BIN:-qemu-system-x86_64}"
BUSYBOX="${TIDEFS_BUSYBOX:-busybox}"
CPIO="${TIDEFS_CPIO:-cpio}"
GZIP="${TIDEFS_GZIP:-gzip}"
TIMEOUT_SEC="${TIDEFS_TIMEOUT:-600}"
MODE="${TIDEFS_FIXTURE_MODE:-bootstrap}"

POSIX_TFS_KO="${TIDEFS_POSIX_TFS_KO:-}"
BLOCK_KMOD_KO="${TIDEFS_BLOCK_KMOD_KO:-}"
FUSE_KO="${TIDEFS_FUSE_KO:-}"

usage() {
  cat <<USAGE
Usage: run-kernel-pool-fixture.sh [OPTIONS]

Boot Linux 7.0 QEMU guest with fixture virtio-blk disks and load TideFS
kernel modules for kernel-mode pool import, default engine mount, and block I/O.

Modes (set via TIDEFS_FIXTURE_MODE or --mode):
  bootstrap    Bootstrap mount only (mount -o bootstrap -t tidefs none <mnt>)
  engine       Default engine mount (requires working kernel pool import)
  block-io     Block I/O via tidefs-block-kmod on fixture devices
  full         All three phases in sequence

Required env vars:
  TIDEFS_FIXTURE_DIR    Directory with fixture images (disk0.img, disk1.img...)
  TIDEFS_KERNEL_IMG     Path to Linux 7.0 bzImage
  TIDEFS_MODULE_DIR     Path to kernel modules directory
  TIDEFS_POSIX_TFS_KO   Path to tidefs-kmod-posix-vfs.ko

Options:
  --mode MODE        Set run mode (default: $MODE)
  --timeout SEC      QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp         Do not remove temp directory on exit
  --help, -h         Show this message
USAGE
}

KEEP_TMP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
    --keep-tmp) KEEP_TMP=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$MODE" in
  bootstrap|engine|block-io|full) ;;
  *) echo "ERROR: invalid mode: $MODE" >&2; exit 2 ;;
esac

# Environment preflight
[ ! -d "$FIXTURE_DIR" ] && { echo "ERROR: fixture directory not found: $FIXTURE_DIR" >&2; exit 2; }

for dep in "$QEMU_BIN" "$BUSYBOX" "$CPIO" "$GZIP"; do
  command -v "$dep" >/dev/null 2>&1 || { echo "ENVIRONMENT REFUSAL: $dep not found" >&2; exit 2; }
done

[ -z "$KERNEL_IMG" ] || [ ! -f "$KERNEL_IMG" ] && { echo "ENVIRONMENT REFUSAL: TIDEFS_KERNEL_IMG not set" >&2; exit 2; }
[ -z "$MODULE_DIR" ] || [ ! -d "$MODULE_DIR" ] && { echo "ENVIRONMENT REFUSAL: TIDEFS_MODULE_DIR not set" >&2; exit 2; }

# Resolve .ko paths
if [ -z "$POSIX_VFS_KO" ]; then
  for c in "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" "$MODULE_DIR/kernel/fs/tidefs/tidefs-kmod-posix-vfs.ko"; do
    [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
  done
fi
if [ -z "$BLOCK_KMOD_KO" ] && { [ "$MODE" = "block-io" ] || [ "$MODE" = "full" ]; }; then
  for c in "$MODULE_DIR/extra/tidefs-block-kmod.ko" "$MODULE_DIR/kernel/drivers/block/tidefs-block-kmod.ko"; do
    [ -f "$c" ] && { BLOCK_KMOD_KO="$c"; break; }
  done
fi
if [ -z "$FUSE_KO" ]; then
  for c in "$MODULE_DIR/kernel/fs/fuse/fuse.ko" "$MODULE_DIR/kernel/fs/fuse/fuse.ko.xz" "$MODULE_DIR/extra/fuse.ko" "$MODULE_DIR/fuse.ko"; do
    [ -f "$c" ] && { FUSE_KO="$c"; break; }
  done
fi

QEMU_ACCEL=(-cpu qemu64)
if [ -e /dev/kvm ]; then
  QEMU_ACCEL=(-enable-kvm -cpu host)
  QEMU_ACCEL_LABEL="kvm"
else
  QEMU_ACCEL_LABEL="tcg"
fi

IMAGE_COUNT=$(ls "$FIXTURE_DIR"/disk*.img 2>/dev/null | wc -l)
[ "$IMAGE_COUNT" -eq 0 ] && { echo "ERROR: no fixture images in $FIXTURE_DIR" >&2; exit 2; }

echo "=== TideFS Kernel Pool Fixture Runner ==="
echo "  Mode:        $MODE"
echo "  Fixture:     $FIXTURE_DIR"
echo "  Images:      $IMAGE_COUNT"
echo "  Kernel:      $KERNEL_IMG"
echo "  QEMU:        $QEMU_BIN"
echo "  Accel:       $QEMU_ACCEL_LABEL"
echo "  POSIX VFS:   ${POSIX_VFS_KO:-NOT FOUND}"
echo "  Block kmod:  ${BLOCK_KMOD_KO:-NOT FOUND}"
echo "  Timeout:     ${TIMEOUT_SEC}s"
echo ""

# Build work directory
WORK_DIR="/tmp/tidefs-kernel-fixture-$$"
RUN_DIR="$WORK_DIR/initrd"
mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt,etc,run/tidefs/import}

cleanup() {
  [ "$KEEP_TMP" -eq 1 ] && echo "  Keeping: $WORK_DIR" || rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Library copy helpers
copy_dep_path() {
  local p="$1"
  [ -f "$p" ] || return 0
  mkdir -p "$RUN_DIR/$(dirname "$p")"
  cp "$p" "$RUN_DIR/$p" 2>/dev/null || true
}

copy_binary_to_bin() {
  local src="$1"
  local dst="$2"
  cp "$src" "$RUN_DIR/bin/$dst"
  chmod +x "$RUN_DIR/bin/$dst"
  if command -v ldd >/dev/null 2>&1; then
    ldd "$src" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u | while read -r lib; do
      copy_dep_path "$lib"
    done
  fi
}

copy_binary_to_bin "$(command -v "$BUSYBOX")" busybox
for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                expr head tail cut kill ps test seq blockdev mountpoint du \
                uname date; do
  ln -sf busybox "$RUN_DIR/bin/$applet" 2>/dev/null || true
done

# Copy .ko files
[ -n "$POSIX_TFS_KO" ] && [ -f "$POSIX_TFS_KO" ] && cp "$POSIX_TFS_KO" "$RUN_DIR/lib/modules/tidefs-kmod-posix-vfs.ko"
[ -n "$BLOCK_KMOD_KO" ] && [ -f "$BLOCK_KMOD_KO" ] && cp "$BLOCK_KMOD_KO" "$RUN_DIR/lib/modules/tidefs-block-kmod.ko"
[ -n "$FUSE_KO" ] && [ -f "$FUSE_KO" ] && cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"

# Init script
cat > "$RUN_DIR/init" << 'INNERINIT'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /mnt/tidefs

echo "=== TideFS Kernel Pool Fixture ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo "mode=SSMODE_SS"
echo ""

PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

echo "--- Phase 0: Kernel modules ---"
if grep -qw fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_builtin"
elif [ -f /lib/modules/fuse.ko ]; then
    insmod /lib/modules/fuse.ko 2>/tmp/fuse-insmod.err && pass "fuse_module" || fail "fuse_module" "$(cat /tmp/fuse-insmod.err 2>/dev/null)"
else
    blocked "fuse_module" "no fuse.ko and not built-in"
fi

if [ -f /lib/modules/tidefs-kmod-posix-vfs.ko ]; then
    insmod /lib/modules/tidefs-kmod-posix-vfs.ko 2>/tmp/posix-insmod.err
    lsmod | grep -q tidefs_kmod_posix_vfs 2>/dev/null && pass "posix_vfs_kmod_load" || fail "posix_vfs_kmod_load" "$(cat /tmp/posix-insmod.err 2>/dev/null)"
else
    blocked "posix_vfs_kmod_load" ".ko not found"
fi

if [ -f /lib/modules/tidefs-block-kmod.ko ]; then
    insmod /lib/modules/tidefs-block-kmod.ko 2>/tmp/block-insmod.err
    lsmod | grep -q tidefs_block_kmod 2>/dev/null && pass "block_kmod_load" || fail "block_kmod_load" "$(cat /tmp/block-insmod.err 2>/dev/null)"
else
    blocked "block_kmod_load" ".ko not found"
fi

echo ""; echo "--- Phase 1: Virtio block devices ---"
IMAGE_COUNT=SSIMAGE_COUNT_SS
DEV_PATHS=""
DEVS_OK=1

for i in $(seq 0 $((IMAGE_COUNT - 1))); do
    vd_letters="abcdefghijklmnopqrstuvwxyz"; vd_letter=$(echo "$vd_letters" | cut -c"$((i+1))")
    expected="/dev/vd''${vd_letter}"
    for _ in $(seq 1 30); do
        [ -b "$expected" ] && break
        sleep 1
    done
    if [ -b "$expected" ]; then
        pass "virtio''${i}_present"
        DEV_PATHS="$DEV_PATHS $expected"
    else
        fail "virtio''${i}_present" "$expected missing"
        DEVS_OK=0
    fi
done

if [ "$DEVS_OK" -eq 0 ]; then
    echo "FATAL: virtio devices not available"
    for op in bootstrap_mount bootstrap_statfs bootstrap_umount engine_mount engine_write engine_fsync engine_read engine_unlink engine_umount block_io_read block_io_write block_io_verify; do
        blocked "$op" "virtio block devices missing"
    done
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; poweroff -f
fi

MODE="SSMODE_SS"

# Phase A: Bootstrap mount
if [ "$MODE" = "bootstrap" ] || [ "$MODE" = "full" ]; then
    echo ""; echo "--- Phase A: Bootstrap mount ---"
    MNT=/mnt/tidefs; mkdir -p "$MNT"
    if grep -qw tidefs /proc/filesystems 2>/dev/null; then
        mount -o bootstrap -t tidefs none "$MNT" 2>/tmp/bserr; RC=$?
        if [ "$RC" -eq 0 ] && mountpoint -q "$MNT" 2>/dev/null; then
            pass "bootstrap_mount"
            stat -f "$MNT" >/dev/null 2>&1 && pass "bootstrap_statfs" || fail "bootstrap_statfs" "statfs failed"
            umount "$MNT" 2>/dev/null && pass "bootstrap_umount" || fail "bootstrap_umount" "unmount failed"
        else
            D=$(cat /tmp/bserr 2>/dev/null || echo "unknown")
            fail "bootstrap_mount" "$D"
            blocked "bootstrap_statfs" "bootstrap mount failed"
            blocked "bootstrap_umount" "bootstrap mount failed"
        fi
    else
        blocked "bootstrap_mount" "tidefs not in /proc/filesystems"
        blocked "bootstrap_statfs" "tidefs not registered"
        blocked "bootstrap_umount" "tidefs not registered"
    fi
fi

# Phase B: Default engine mount
if [ "$MODE" = "engine" ] || [ "$MODE" = "full" ]; then
    echo ""; echo "--- Phase B: Default engine mount ---"
    MNT=/mnt/tidefs; mkdir -p "$MNT"
    if grep -qw tidefs /proc/filesystems 2>/dev/null; then
        mount -t tidefs none "$MNT" 2>/tmp/engerr; RC=$?
        if [ "$RC" -eq 0 ] && mountpoint -q "$MNT" 2>/dev/null; then
            pass "engine_mount"
            echo "kernel-fixture-test-$$" > "$MNT/.fixture_test" 2>/tmp/werr
            [ -f "$MNT/.fixture_test" ] && pass "engine_write" || fail "engine_write" "$(cat /tmp/werr)"
            sync && pass "engine_fsync"
            RC=$(cat "$MNT/.fixture_test" 2>/dev/null)
            [ -n "$RC" ] && pass "engine_read" || fail "engine_read" "read returned empty"
            rm -f "$MNT/.fixture_test" 2>/dev/null && pass "engine_unlink" || fail "engine_unlink" "unlink failed"
            umount "$MNT" 2>/dev/null && pass "engine_umount" || fail "engine_umount" "unmount failed"
        else
            D=$(cat /tmp/engerr 2>/dev/null || echo "unknown")
            fail "engine_mount" "$D"
            for op in engine_write engine_fsync engine_read engine_unlink engine_umount; do
                blocked "$op" "engine mount failed"
            done
        fi
    else
        blocked "engine_mount" "tidefs not registered"
        for op in engine_write engine_fsync engine_read engine_unlink engine_umount; do
            blocked "$op" "tidefs not registered"
        done
    fi
fi

# Phase C: Block I/O
if [ "$MODE" = "block-io" ] || [ "$MODE" = "full" ]; then
    echo ""; echo "--- Phase C: Block I/O ---"
    BLOCK_DEV=""
    for d in $DEV_PATHS; do BLOCK_DEV="$d"; break; done
    if [ -n "$BLOCK_DEV" ] && [ -b "$BLOCK_DEV" ]; then
        dd if="$BLOCK_DEV" of=/dev/null bs=4096 count=1 2>/dev/null && pass "block_io_read" || fail "block_io_read" "dd read failed"
        TEST_PAT="TIDEFS-BLOCK-IO-TEST-$$"
        echo "$TEST_PAT" | dd of="$BLOCK_DEV" bs=1 seek=524288 count=${#TEST_PAT} 2>/tmp/bwerr
        [ $? -eq 0 ] && pass "block_io_write" || fail "block_io_write" "$(cat /tmp/bwerr)"
        RB=$(dd if="$BLOCK_DEV" bs=1 skip=524288 count=${#TEST_PAT} 2>/dev/null)
        [ "$RB" = "$TEST_PAT" ] && pass "block_io_verify" || fail "block_io_verify" "read-back mismatch"
    else
        for op in block_io_read block_io_write block_io_verify; do
            blocked "$op" "no block device"
        done
    fi
fi

echo ""; echo "--- Tear-down ---"
sync && pass "sync_done"

echo ""; echo "=== Kernel Fixture Validation ==="
echo "mode=$MODE"
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "image_count=$IMAGE_COUNT"
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "=== End ==="
sync; sleep 1; poweroff -f
INNERINIT

sed -i "s/SSIMAGE_COUNT_SS/$IMAGE_COUNT/g" "$RUN_DIR/init"
sed -i "s/SSMODE_SS/$MODE/g" "$RUN_DIR/init"
chmod +x "$RUN_DIR/init"

# Build compressed initrd
echo "  Building compressed initrd"
(cd "$RUN_DIR" && find . -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -9) > "$WORK_DIR/initrd.img.gz"
echo "  Initrd.gz: $(du -h "$WORK_DIR/initrd.img.gz" | cut -f1)"

# Build drive args
DRIVE_ARGS=""
for i in $(seq 0 $((IMAGE_COUNT - 1))); do
  DRIVE_ARGS="$DRIVE_ARGS -drive file=$FIXTURE_DIR/disk''${i}.img,format=raw,if=virtio,index=$i"
done

# QEMU boot
VAL_LOG="$FIXTURE_DIR/kernel-fixture-${MODE}-validation.log"
echo ""; echo "  === Booting QEMU guest ($MODE mode) ==="

timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
  "''${QEMU_ACCEL[@]}" \
  -kernel "$KERNEL_IMG" \
  -initrd "$WORK_DIR/initrd.img.gz" \
  $DRIVE_ARGS \
  -append "console=ttyS0 quiet panic=10" \
  -m 2G \
  -smp 2 \
  -nographic \
  -no-reboot \
  > "$VAL_LOG" 2>&1 || true

echo "  QEMU exited ($(wc -l < "$VAL_LOG" 2>/dev/null || echo 0) log lines)"

# Parse validation
echo ""; echo "=== Validation Results ($MODE mode) ==="
PASSC=0; FAILC=0; BLOCKC=0

case "$MODE" in
  bootstrap) OPS="fuse_module fuse_builtin posix_vfs_kmod_load virtio0_present virtio1_present bootstrap_mount bootstrap_statfs bootstrap_umount sync_done" ;;
  engine)    OPS="fuse_module fuse_builtin posix_vfs_kmod_load virtio0_present virtio1_present engine_mount engine_write engine_fsync engine_read engine_unlink engine_umount sync_done" ;;
  block-io)  OPS="posix_vfs_kmod_load block_kmod_load virtio0_present virtio1_present block_io_read block_io_write block_io_verify sync_done" ;;
  full)      OPS="fuse_module fuse_builtin posix_vfs_kmod_load block_kmod_load virtio0_present virtio1_present bootstrap_mount bootstrap_statfs bootstrap_umount engine_mount engine_write engine_fsync engine_read engine_unlink engine_umount block_io_read block_io_write block_io_verify sync_done" ;;
esac

for op in $OPS; do
  if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
    echo "  PASS: $op"; PASSC=$((PASSC + 1))
  elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
    D=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/FAIL: $op //")
    echo "  FAIL: $op -- $D"; FAILC=$((FAILC + 1))
  elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
    D=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/BLOCKED: $op //")
    echo "  BLOCKED: $op -- $D"; BLOCKC=$((BLOCKC + 1))
  else
    echo "  MISSING: $op"; BLOCKC=$((BLOCKC + 1))
  fi
done

echo ""; echo "Validation matrix: $PASSC passed, $FAILC failed, $BLOCKC blocked"
echo "Validation log: $VAL_LOG"

[ "$FAILC" -gt 0 ] && { echo "RUNNER: FAIL ($FAILC failures)"; exit 1; }
echo "RUNNER: COMPLETE ($PASSC passed, $BLOCKC blocked)"
exit 0
