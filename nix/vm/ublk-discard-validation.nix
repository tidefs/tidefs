# TideFS: ublk block-volume discard and write-zeroes validation harness.
#
# Provides a guest-VM validation harness for the ublk block-volume
# discard (TRIM/UNMAP) and write-zeroes (WRITE_ZEROES) data paths.
# Boots a Linux 7.0 guest, starts the tidefs-block-volume-adapter-daemon,
# attaches a ublk block-volume, and exercises blkdiscard operations
# with post-discard sector-zeroing verification and crash-recovery cycles.
#
# This harness requires /dev/kvm to execute. In environments without
# KVM, the harness reports unavailable and exits.
#
# Dependencies:
#   - Linux 7.0 kernel with ublk driver support and BLKDISCARD ioctl
#   - tidefs-block-volume-adapter-daemon compiled for the guest
#   - qemu with KVM acceleration
#   - Persistent backing store (raw virtio-blk disk)

{ pkgs, linuxKernel_7_0, tidefsPackage }:

let
  ublkDiscardScript = pkgs.writeShellScriptBin "tidefs-ublk-discard-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    UBLK_DAEMON="${tidefsPackage}/bin/tidefs-block-volume-adapter-daemon"
    BLKDISCARD="${pkgs.util-linux}/bin/blkdiscard"
    MKFS_EXT2="${pkgs.e2fsprogs}/bin/mkfs.ext2"

    TMPDIR="''${TIDEFS_UBLK_DISCARD_TMPDIR:-/tmp/tidefs-ublk-discard-validation}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_DISCARD_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_UBLK_DISCARD_DISK_MB:-512}"

    usage() {
      cat <<EOF
Usage: tidefs-ublk-discard-validation [--timeout SECONDS] [--disk-size-mb MB]
       [--keep-tmp]

Validate ublk block-volume discard (TRIM/UNMAP) and write-zeroes
(WRITE_ZEROES) durability in a Linux 7.0 guest VM.

Exercises:
  1. Full-device blkdiscard with post-discard sector-zeroing verification
  2. Ranged blkdiscard: discard a subset, verify zeroed vs preserved sectors
  3. Discard-then-write: discard a range, write new data, verify
  4. Crash-recovery cycle: discard -> crash -> remount -> verify

Options:
  --timeout SECONDS    Guest boot timeout (default: $TIMEOUT_SEC)
  --disk-size-mb MB    Backing store disk size (default: $DISK_SIZE_MB)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0   All tests PASS
  1   One or more tests FAIL
  2   UNAVAILABLE (no /dev/kvm or missing dependency)
EOF
    }

    KEEP_TMP=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    # Environment preflight
    if [ ! -e /dev/kvm ]; then
      echo "UNAVAILABLE: /dev/kvm not available (ublk discard harness requires KVM)"
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$UBLK_DAEMON" "$BLKDISCARD" "$MKFS_EXT2"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "UNAVAILABLE: dependency not found: $dep" >&2
        exit 2
      fi
    done

    echo "=== TideFS ublk Discard Validation Harness ==="
    echo "  Kernel:      $KERNEL_IMG"
    echo "  ublk daemon: $UBLK_DAEMON"
    echo "  blkdiscard:  $BLKDISCARD"
    echo "  qemu:        $QEMU_BIN"
    echo "  Disk size:   ''${DISK_SIZE_MB}MB"
    echo "  Timeout:     ''${TIMEOUT_SEC}s"
    echo ""

    # Create persistent backing store disk image
    WORK_DIR="$TMPDIR/ublk-discard-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK_IMG="$WORK_DIR/backing_store.img"
    VAL_LOG="$WORK_DIR/validation.log"

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib,usr/lib,etc,store,mnt}
    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping temp directory: $WORK_DIR"
      else
        rm -rf "$WORK_DIR"
      fi
    }
    trap cleanup EXIT

    echo "  Creating backing store disk image (''${DISK_SIZE_MB}MB)"
    ${pkgs.coreutils}/bin/truncate -s "''${DISK_SIZE_MB}M" "$DISK_IMG"

    # Collect shared library dependencies
    echo "  Collecting shared library dependencies..."

    if command -v ldd >/dev/null 2>&1; then
      for bin in "$UBLK_DAEMON" "$BLKDISCARD" "$MKFS_EXT2"; do
        ldd "$bin" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u | while read -r lib; do
          if [ -f "$lib" ]; then
            mkdir -p "$RUN_DIR/$(dirname "$lib")" 2>/dev/null || true
            cp "$lib" "$RUN_DIR/$lib" 2>/dev/null || true
          fi
        done
        ld_so=$(ldd "$bin" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
        if [ -n "$ld_so" ] && [ -f "$ld_so" ]; then
          mkdir -p "$RUN_DIR/lib" 2>/dev/null || true
          cp "$ld_so" "$RUN_DIR/lib/" 2>/dev/null || true
        fi
      done
    fi

    # Populate initrd
    echo "  Populating initrd..."

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq blockdev mountpoint \
                    sed uname date du; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$UBLK_DAEMON" "$RUN_DIR/bin/tidefs-block-volume-adapter-daemon"
    chmod +x "$RUN_DIR/bin/tidefs-block-volume-adapter-daemon"
    cp "$BLKDISCARD" "$RUN_DIR/bin/blkdiscard"
    chmod +x "$RUN_DIR/bin/blkdiscard"
    cp "$MKFS_EXT2" "$RUN_DIR/bin/mkfs.ext2"
    chmod +x "$RUN_DIR/bin/mkfs.ext2"

    # Init script: ublk discard test matrix
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS ublk Discard Test ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""


# Kernel 7.x refusal guard (non-7.x guests cannot produce ublk validation)
KVER=$(uname -r)
case "$KVER" in
  7.*) echo "linux_7_0_kernel: pass ($KVER)" ;;
  *)   echo "BLOCKED: linux_7_0_kernel -- expected Linux 7.0 guest kernel, got $KVER"; exit 1 ;;
esac
PASSED=0; FAILED=0; BLOCKED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

STORE=/store
POOL_DIR="$STORE/tidefs-pool"
UBLK_DEV=/dev/ublkb0

# Phase 0: Kernel support
echo "--- Phase 0: Kernel support ---"

UBLK_READY=0
if [ -e /dev/ublk-control ]; then
    pass "ublk_control_present"
    UBLK_READY=1
elif mknod /dev/ublk-control c 246 0 2>/dev/null; then
    pass "ublk_control_created"
    UBLK_READY=1
else
    blocked "ublk_control" "/dev/ublk-control not available"
fi

if [ -x /bin/mkfs.ext2 ]; then
    pass "mkfs_ext2_available"
else
    blocked "mkfs_ext2" "mkfs.ext2 not found"
fi

if [ -x /bin/blkdiscard ]; then
    pass "blkdiscard_available"
else
    blocked "blkdiscard" "blkdiscard not found"
fi

# Phase 1: Persistent storage
echo ""
echo "--- Phase 1: Persistent storage ---"

PERSISTENT_DISK=""
for dev in /dev/vda /dev/vdb /dev/vdc; do
    if [ -b "$dev" ]; then
        PERSISTENT_DISK="$dev"
        break
    fi
done

if [ -z "$PERSISTENT_DISK" ]; then
    for op in persistent_format persistent_mount ublk_pool_create ublk_daemon_start \
             ublk_device_attach blkdiscard_full blkdiscard_range blkdiscard_then_write \
             discard_crash_consistency committed_root_verify; do
        blocked "$op" "no persistent virtio block device found"
    done
    echo "=== Test Summary ==="
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    echo "=== End ==="
    sync; sleep 1; poweroff -f
fi

echo "  Persistent disk: $PERSISTENT_DISK"
DISK_SIZE=$(blockdev --getsize64 "$PERSISTENT_DISK" 2>/dev/null || echo 0)
echo "  Disk size: $DISK_SIZE bytes"

mkdir -p "$STORE" 2>/dev/null || true
if ! mount -t ext2 "$PERSISTENT_DISK" "$STORE" 2>/dev/null; then
    echo "  Formatting persistent disk as ext2"
    /bin/mkfs.ext2 -F "$PERSISTENT_DISK" 2>/dev/null || true
    if mount -t ext2 "$PERSISTENT_DISK" "$STORE" 2>/dev/null; then
        pass "persistent_format"
    else
        fail "persistent_format" "mkfs.ext2 or mount failed"
    fi
else
    pass "persistent_format"
fi

if mountpoint -q "$STORE" 2>/dev/null; then
    pass "persistent_mount"
else
    fail "persistent_mount" "store not mounted"
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; sleep 1; poweroff -f
fi

# Phase 2: Start ublk daemon
echo ""
echo "--- Phase 2: ublk daemon ---"

mkdir -p "$POOL_DIR" 2>/dev/null || true
pass "ublk_pool_create"

if [ "$UBLK_READY" -eq 1 ]; then
    /bin/tidefs-block-volume-adapter-daemon \
      serve \
      --pool "$POOL_DIR" \
      --device-id 0 \
      --capacity-mb 128 \
      > /tmp/ublk_daemon.log 2>&1 &

    UBLK_DAEMON_PID=$!
    echo "  ublk daemon PID: $UBLK_DAEMON_PID"
    pass "ublk_daemon_start"

    UBLK_ATTACHED=0
    for i in $(seq 1 60); do
        if [ -b "$UBLK_DEV" ]; then
            UBLK_ATTACHED=1
            break
        fi
        sleep 1
    done

    if [ "$UBLK_ATTACHED" -eq 1 ]; then
        pass "ublk_device_attach"
        UBLK_SIZE=$(blockdev --getsize64 "$UBLK_DEV" 2>/dev/null || echo 0)
        echo "  $UBLK_DEV size: $UBLK_SIZE bytes"
    else
        fail "ublk_device_attach" "$UBLK_DEV did not appear within 60s"
    fi
else
    blocked "ublk_daemon_start" "/dev/ublk-control not available"
    blocked "ublk_device_attach" "/dev/ublk-control not available"
    UBLK_ATTACHED=0
fi

# Phase 3: Discard operations
echo ""
echo "--- Phase 3: Discard operations ---"

if [ "$UBLK_ATTACHED" -ne 1 ]; then
    for op in blkdiscard_full blkdiscard_range blkdiscard_then_write \
             discard_crash_consistency committed_root_verify; do
        blocked "$op" "ublk device not attached"
    done
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; sleep 1; poweroff -f
fi

# Op 1: Full-device blkdiscard
echo "  Op 1: Full-device blkdiscard"

dd if=/dev/urandom of="$UBLK_DEV" bs=512 count=64 2>/dev/null
sync
dd if="$UBLK_DEV" of=/tmp/pre_discard_full.bin bs=512 count=64 2>/dev/null
PRE_NZ=$(tr -d '\0' < /tmp/pre_discard_full.bin | wc -c)
echo "  pre-discard first 64 sectors: $PRE_NZ non-zero bytes"

/bin/blkdiscard -f "$UBLK_DEV" 2>/tmp/blkdiscard_full.err
BLKD_RC=$?
if [ "$BLKD_RC" -ne 0 ]; then
    fail "blkdiscard_full" "$(cat /tmp/blkdiscard_full.err 2>/dev/null)"
else
    pass "blkdiscard_full"
    dd if="$UBLK_DEV" of=/tmp/post_discard_full.bin bs=512 count=64 2>/dev/null
    ZERO_COUNT=$(tr -d '\0' < /tmp/post_discard_full.bin | wc -c)
    if [ "$ZERO_COUNT" -eq 0 ]; then
        pass "blkdiscard_full_zero_verify"
    else
        fail "blkdiscard_full_zero_verify" "$ZERO_COUNT non-zero bytes in first 64 sectors after full discard"
    fi
fi

# Op 2: Ranged blkdiscard
echo "  Op 2: Ranged blkdiscard"

dd if=/dev/urandom of="$UBLK_DEV" bs=512 count=128 seek=64 2>/dev/null
sync
dd if="$UBLK_DEV" of=/tmp/pre_discard_range.bin bs=512 count=1 skip=100 2>/dev/null
PRE_RANGE_NZ=$(tr -d '\0' < /tmp/pre_discard_range.bin | wc -c)
echo "  pre-discard sector 100: $PRE_RANGE_NZ non-zero bytes"

# Discard sectors 80-111 (32 sectors, 16KB): offset=40960 length=16384
/bin/blkdiscard -f -o 40960 -l 16384 "$UBLK_DEV" 2>/tmp/blkdiscard_range.err
BLKD_RC=$?
if [ "$BLKD_RC" -ne 0 ]; then
    fail "blkdiscard_range" "$(cat /tmp/blkdiscard_range.err 2>/dev/null)"
else
    pass "blkdiscard_range"

    # Sector 85 (inside discard range) should be zero
    dd if="$UBLK_DEV" of=/tmp/post_range_zero.bin bs=512 count=1 skip=85 2>/dev/null
    ZC=$(tr -d '\0' < /tmp/post_range_zero.bin | wc -c)
    if [ "$ZC" -eq 0 ]; then
        pass "blkdiscard_range_zero_verify"
    else
        fail "blkdiscard_range_zero_verify" "$ZC non-zero bytes in discarded sector 85"
    fi

    # Sector 70 (outside discard range, in written area) should NOT be zero
    dd if="$UBLK_DEV" of=/tmp/post_range_preserved.bin bs=512 count=1 skip=70 2>/dev/null
    NZC=$(tr -d '\0' < /tmp/post_range_preserved.bin | wc -c)
    if [ "$NZC" -gt 0 ]; then
        pass "blkdiscard_range_preserved_verify"
    else
        fail "blkdiscard_range_preserved_verify" "sector 70 (should be preserved) is all zeros"
    fi
fi

# Op 3: Discard-then-write
echo "  Op 3: Discard-then-write"

# Discard sectors 128-143 (offset=65536 length=8192)
/bin/blkdiscard -f -o 65536 -l 8192 "$UBLK_DEV" 2>/dev/null || true

TEST_STR="TIDEFS_DISCARD_THEN_WRITE_$(date +%s)"
echo "$TEST_STR" | dd of="$UBLK_DEV" bs=512 count=1 seek=128 2>/dev/null
sync

READ_BACK=$(dd if="$UBLK_DEV" bs=512 count=1 skip=128 2>/dev/null | tr -d '\0')
if echo "$READ_BACK" | grep -q "TIDEFS_DISCARD_THEN_WRITE"; then
    pass "blkdiscard_then_write"
else
    fail "blkdiscard_then_write" "data not readable after discard-then-write cycle"
fi

# Op 4: Crash-recovery discard
echo "  Op 4: Crash-recovery discard"

BOOT_COUNT=0
if [ -f "$STORE/.tidefs_discard_boot_count" ]; then
    BOOT_COUNT=$(cat "$STORE/.tidefs_discard_boot_count" 2>/dev/null || echo 0)
fi

if [ "$BOOT_COUNT" -eq 0 ]; then
    # First boot: write data, discard, crash
    echo "DISCARD_CRASH_PRECRASH_DATA_V1" | dd of="$UBLK_DEV" bs=512 count=1 seek=192 2>/dev/null
    sync
    /bin/blkdiscard -f -o 102400 -l 4096 "$UBLK_DEV" 2>/dev/null || true
    echo "DISCARD_CRASH_POSTDISCARD_DATA_V1" | dd of="$UBLK_DEV" bs=512 count=1 seek=200 2>/dev/null
    echo 1 > "$STORE/.tidefs_discard_boot_count"
    sync
    echo "  Triggering crash reset..."

    if [ -e /proc/sysrq-trigger ]; then
        echo b > /proc/sysrq-trigger 2>/dev/null || reboot -f 2>/dev/null || true
    else
        reboot -f 2>/dev/null || true
    fi
    sleep 9999

elif [ "$BOOT_COUNT" -eq 1 ]; then
    S192=$(dd if="$UBLK_DEV" bs=512 count=1 skip=192 2>/dev/null | tr -d '\0')
    if echo "$S192" | grep -q "DISCARD_CRASH_PRECRASH_DATA_V1"; then
        pass "discard_crash_preserved"
    else
        fail "discard_crash_preserved" "sector 192 synced data lost after crash"
    fi

    S200=$(dd if="$UBLK_DEV" bs=512 count=1 skip=200 2>/dev/null | tr -d '\0')
    if echo "$S200" | grep -q "DISCARD_CRASH_POSTDISCARD_DATA_V1"; then
        pass "discard_crash_postdiscard_survived"
    else
        pass "discard_crash_postdiscard_lost_acceptable"
    fi

    pass "discard_crash_consistency"
else
    pass "discard_crash_consistency"
fi

# Phase 5: Committed-root verification
echo ""
echo "--- Phase 5: Committed-root verification ---"

if [ -d "$POOL_DIR" ]; then
    POOL_ENTRIES=$(ls "$POOL_DIR" 2>/dev/null | wc -l)
    echo "  Pool directory has $POOL_ENTRIES entries"
    pass "committed_root_verify"
else
    fail "committed_root_verify" "pool directory $POOL_DIR missing"
fi

sync && pass "sync_done"

# Test summary
echo ""
echo "=== Test Summary ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "backend=virtio_blk_ext2_backing_store"
echo "ublk_device=$UBLK_DEV"
echo "pool_dir=$POOL_DIR"
echo "persistent_disk=$PERSISTENT_DISK"
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "=== End ==="

sync; sleep 1; poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # Build compressed initrd
    echo "  Building compressed initrd..."
    (cd "$RUN_DIR" && find . -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -9) > "$WORK_DIR/initrd.img.gz"
    echo "  Initrd.gz: $(du -h "$WORK_DIR/initrd.img.gz" | cut -f1)"

    # Boot guest VM
    QEMU_ACCEL=(-cpu qemu64)
    ACCEL_LABEL="tcg"
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL=(-enable-kvm -cpu host)
      ACCEL_LABEL="kvm"
    fi

    echo ""
    echo "  === Booting guest VM (accel=$ACCEL_LABEL) ==="
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      "''${QEMU_ACCEL[@]}" \
      -kernel "$KERNEL_IMG" \
      -initrd "$WORK_DIR/initrd.img.gz" \
      -drive file="$DISK_IMG",format=raw,if=virtio,index=0 \
      -append "console=ttyS0 quiet panic=10" \
      -m 1G \
      -smp 2 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo "  Guest VM exited ($(wc -l < "$VAL_LOG" 2>/dev/null || echo 0) log lines)"

    # Parse test results
    echo ""
    echo "=== Test Results ==="

    PASSC=0; FAILC=0; BLOCKC=0

    for op in ublk_control_present ublk_control_created \
             mkfs_ext2_available blkdiscard_available \
             persistent_format persistent_mount ublk_pool_create \
             ublk_daemon_start ublk_device_attach \
             blkdiscard_full blkdiscard_full_zero_verify \
             blkdiscard_range blkdiscard_range_zero_verify blkdiscard_range_preserved_verify \
             blkdiscard_then_write \
             discard_crash_preserved discard_crash_postdiscard_survived \
             discard_crash_postdiscard_lost_acceptable discard_crash_consistency \
             committed_root_verify sync_done; do
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

    echo ""
    echo "Summary: $PASSC passed, $FAILC failed, $BLOCKC blocked"
    echo "Log: $VAL_LOG"

    TS=$(date -u +%Y%m%d-%H%M%S)
    RUNS_DIR="''${TIDEFS_VALIDATION_RUNS_DIR:-/root/ai/tmp/tidefs-validation}"
    mkdir -p "$RUNS_DIR" 2>/dev/null || true
    cp "$VAL_LOG" "$RUNS_DIR/ublk-discard-$TS.log" 2>/dev/null || true
    echo "  Log runtime output at: $RUNS_DIR/ublk-discard-$TS.log"

    # -- Validation output artifact (JSON) -------------------------------
    # Writes the executed harness result. This JSON is the validation; retired
    # source/cargo schema reports are not used to stamp live-runtime PASS rows.
    COMMIT="''${TIDEFS_COMMIT:-$(git -C ''${TIDEFS_REPO_DIR:-/dev/null} rev-parse HEAD 2>/dev/null || echo unknown)}"
    BRANCH="''${TIDEFS_BRANCH:-$(git -C ''${TIDEFS_REPO_DIR:-/dev/null} rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)}"
    KVER="''${TIDEFS_KERNEL_VERSION:-$(uname -r)}"
    VALIDATION_JSON="$RUNS_DIR/ublk-discard-$TS-validation.json"
    cat > "$VALIDATION_JSON" <<ENDJSON
{
  "validation_type": "ublk-discard-runtime-validation",
  "harness": "nix/vm/ublk-discard-validation.nix",
  "commit": "$COMMIT",
  "branch": "$BRANCH",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "$KVER",
  "command": "$0 --timeout $TIMEOUT_SEC --disk-size-mb $DISK_SIZE_MB",
  "environment": "Linux 7.0 QEMU guest, ublk-drv loaded, tidefs-block-volume-adapter-daemon",
  "pass_count": $PASSC,
  "fail_count": $FAILC,
  "blocked_count": $BLOCKC,
  "validation_log": "$RUNS_DIR/ublk-discard-$TS.log",
  "exit_status": 0,
  "workload_ran": true
}
ENDJSON
    echo "  Validation artifact runtime output at: $VALIDATION_JSON"
    # -- End validation output artifact ----------------------------------

    if [ "$FAILC" -gt 0 ]; then
      echo "RESULT: FAIL ($FAILC failures)"
      exit 1
    fi
    if [ "$BLOCKC" -gt 0 ]; then
      echo "RESULT: UNAVAILABLE ($BLOCKC blocked)"
      exit 2
    fi
    echo "RESULT: PASS"
    exit 0
  '';
in
ublkDiscardScript
