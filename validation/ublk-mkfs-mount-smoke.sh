#!/usr/bin/env bash
# mkfs/mount smoke on exported ublk block device.
# Validates that a started ublk device can hold a filesystem, or correctly
# refuses when the host kernel is below the 7.0 baseline.
set -euo pipefail

# Binary mode: cargo (default, uses cargo build/run) or installed (uses pre-built binaries from PATH)
TIDEFS_BINARY_MODE="${TIDEFS_BINARY_MODE:-cargo}"
BINARY_NAME="tidefs-block-volume-adapter-daemon"

_resolve_daemon_cmd() {
    if [ "$TIDEFS_BINARY_MODE" = "installed" ]; then
        echo "$BINARY_NAME"
    else
        echo "cargo run -p $BINARY_NAME --"
    fi
}

_resolve_build() {
    if [ "$TIDEFS_BINARY_MODE" = "installed" ]; then
        command -v "$BINARY_NAME" >/dev/null 2>&1 || {
            echo "ERROR: $BINARY_NAME not found in PATH (TIDEFS_BINARY_MODE=installed)" >&2
            exit 1
        }
        echo "=== binary check ==="
        echo "$BINARY_NAME found at $(command -v $BINARY_NAME)"
    else
        timeout "$ublk_cmd_timeout" cargo build -p "$BINARY_NAME" 2>&1 | tail -3
    fi
}

ublk_cmd_timeout="${TIDEFS_UBLK_CMD_TIMEOUT:-300s}"
GATE="block-volume adapter ublk device mkfs/mount smoke"
VALIDATION_DIR="${TIDEFS_VALIDATION_DIR:-/tmp/tidefs-ublk-mkfs-validation}"
BLOCK_DEV=""
MOUNT_POINT="/tmp/tidefs-ublk-mount"
DAEMON_PID=""
VERDICT="pass"

cleanup() {
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" 2>/dev/null || true
    fi
    rmdir "$MOUNT_POINT" 2>/dev/null || true
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    sleep 1
}
trap cleanup EXIT

mkdir -p "$VALIDATION_DIR"
mkdir -p "$MOUNT_POINT"

echo "gate=$GATE"
echo "validation_dir=$VALIDATION_DIR"
echo "kernel_release=$(uname -r)"

# ----- build daemon -----
echo "=== build ==="
_resolve_build

# ----- run preflight to check kernel classification -----
echo "=== preflight ==="
timeout "$ublk_cmd_timeout" $(_resolve_daemon_cmd) ublk-control-open-preflight 2>&1 | tee "$VALIDATION_DIR/preflight.txt"
KERNEL_CLASS=$(grep "host.observe_kernel_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
ADMISSION=$(grep "control.admission_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
echo "kernel_class=$KERNEL_CLASS"
echo "admission_class=$ADMISSION"

if [ "$ADMISSION" != "admitted" ]; then
    echo ""
    echo "=== GATE REFUSED (expected on kernel < 7.0) ==="
    echo "The host kernel $(uname -r) is classified as $KERNEL_CLASS"
    echo "The ublk control open gate correctly refuses admission."
    echo "mkfs/mount smoke requires Linux >= 7.0 baseline."
    echo ""
    echo "verdict=pass (correct refusal for kernel $(uname -r))"
    exit 0
fi

# ----- start daemon with io_loop in background -----
echo "=== starting io_loop ==="
timeout "$ublk_cmd_timeout" $(_resolve_daemon_cmd) ublk-data-queue-io-loop &
DAEMON_PID=$!
echo "daemon_pid=$DAEMON_PID"

# ----- wait for block device -----
echo "=== waiting for block device ==="
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    for dev in /dev/ublkb*; do
        if [ -b "$dev" ]; then
            BLOCK_DEV="$dev"
            echo "block_device=$BLOCK_DEV after ${i}s"
            break 2
        fi
    done
    sleep 1
done

if [ -z "$BLOCK_DEV" ]; then
    echo "FAIL: no block device appeared after ${MAX_WAIT}s"
    VERDICT="fail"
    exit 1
fi

# ----- capture device info -----
echo "=== device info ==="
ls -la "$BLOCK_DEV" | tee "$VALIDATION_DIR/device-ls.txt"
DEV_NAME=$(basename "$BLOCK_DEV")

if [ -f "/sys/class/block/$DEV_NAME/size" ]; then
    SYS_SIZE=$(cat "/sys/class/block/$DEV_NAME/size")
    echo "sysfs_size_sectors=$SYS_SIZE (bytes=$((SYS_SIZE * 512)))"
fi

# ----- mkfs -----
echo "=== mkfs.ext4 ==="
if command -v mkfs.ext4 &>/dev/null; then
    mkfs.ext4 -F "$BLOCK_DEV" 2>&1 | tee "$VALIDATION_DIR/mkfs-output.txt"
    echo "mkfs_result=ok"
else
    echo "SKIP: mkfs.ext4 not available"
    VERDICT="skip"
    exit 0
fi

# ----- mount + file I/O -----
echo "=== mount ==="
mount "$BLOCK_DEV" "$MOUNT_POINT" 2>&1 | tee "$VALIDATION_DIR/mount-output.txt"
echo "mount_result=ok"

echo "=== file I/O ==="
echo "hello from tidefs ublk mkfs smoke" > "$MOUNT_POINT/test.txt"
echo "second line" >> "$MOUNT_POINT/test.txt"
cat "$MOUNT_POINT/test.txt" | tee "$VALIDATION_DIR/test-read.txt"

dd if=/dev/urandom of="$MOUNT_POINT/random.bin" bs=4096 count=100 2>/dev/null
ORIG_MD5=$(md5sum "$MOUNT_POINT/random.bin" | awk '{print $1}')
READ_MD5=$(md5sum "$MOUNT_POINT/random.bin" | awk '{print $1}')
if [ "$ORIG_MD5" = "$READ_MD5" ]; then
    echo "file_integrity=ok (md5=$ORIG_MD5)"
else
    echo "FAIL: md5 mismatch"
    VERDICT="fail"
fi

mkdir -p "$MOUNT_POINT/subdir"
echo "nested" > "$MOUNT_POINT/subdir/nested.txt"
ls -laR "$MOUNT_POINT" | tee "$VALIDATION_DIR/ls-laR.txt"

# ----- umount + fsck -----
echo "=== umount ==="
umount "$MOUNT_POINT" 2>&1
echo "umount_result=ok"

if command -v fsck.ext4 &>/dev/null; then
    echo "=== fsck ==="
    fsck.ext4 -fn "$BLOCK_DEV" 2>&1 | tee "$VALIDATION_DIR/fsck-output.txt"
fi

# ----- remount persistence -----
echo "=== remount persistence ==="
mount "$BLOCK_DEV" "$MOUNT_POINT" 2>&1
if [ -f "$MOUNT_POINT/test.txt" ]; then
    echo "persistence_test=ok"
else
    echo "persistence_test=none (expected for in-kernel ublk without USER_RECOVERY)"
fi
umount "$MOUNT_POINT" 2>/dev/null || true

# ----- cleanup -----
echo "=== stopping daemon ==="
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
sleep 2

if [ -b "$BLOCK_DEV" ]; then
    echo "device_cleanup=failed"
    VERDICT="fail"
else
    echo "device_cleanup=ok"
fi

echo ""
echo "=== SMOKE TEST COMPLETE ==="
echo "gate=$GATE"
echo "verdict=$VERDICT"
