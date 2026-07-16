# TideFS: pool remount-lifecycle validation (#6136).
#
# Boots a Linux 7.0 qemu guest with two raw virtio-blk disks and exercises
# the pool remount lifecycle with owner-authority, mounted I/O, and crash
# recovery observations:
#   pool create -> ownerless import refusal -> owner-mediated FUSE mount ->
#   write/fsync/read -> unmount -> pool export -> ownerless reimport refusal ->
#   owner-mediated remount -> persist verify -> live/ownerless status checks ->
#   crash recovery.
#
# Validation tier: qemu guest.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  poolRemountLifecycleScript = pkgs.writeShellScriptBin "tidefs-pool-remount-lifecycle-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"

    TMPDIR="''${TIDEFS_POOL_REMOUNT_TMPDIR:-/tmp/tidefs-pool-remount-lifecycle-validation}"
    TIMEOUT_SEC="''${TIDEFS_POOL_REMOUNT_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_POOL_REMOUNT_DISK_MB:-128}"
    VALIDATION_TIER="qemu guest"

    usage() {
      cat <<USAGE
Usage: tidefs-pool-remount-lifecycle-validation [--timeout SECONDS] [--disk-size-mb MB] [--keep-tmp]

Full remount lifecycle on two virtio-blk disks in a Linux 7.0 qemu guest:
  pool create -> ownerless import refusal -> owner-mediated FUSE mount ->
  write/fsync/read -> unmount -> pool export -> ownerless reimport refusal ->
  owner-mediated remount -> persist verify -> live/ownerless status checks ->
  crash recovery.

Options:
  --timeout SECONDS  QEMU boot timeout (default: $TIMEOUT_SEC)
  --disk-size-mb MB  Size of each raw block device image (default: $DISK_SIZE_MB)
  --keep-tmp         Do not remove temp directory on exit
  --help, -h         Show this message
USAGE
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

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$TIDEFSCTL" "$FUSE_DAEMON"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ENVIRONMENT REFUSAL: dependency not found: $dep" >&2
        exit 2
      fi
    done

    QEMU_ACCEL=(-cpu qemu64)
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL=(-enable-kvm -cpu host)
      QEMU_ACCEL_LABEL="kvm"
    else
      QEMU_ACCEL_LABEL="tcg"
    fi

    echo "=== TideFS VAL: pool-remount-lifecycle QEMU ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  tidefsctl: $TIDEFSCTL"
    echo "  Daemon:    $FUSE_DAEMON"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Accel:     $QEMU_ACCEL_LABEL"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Disk size: ''${DISK_SIZE_MB}MB each"
    echo ""

    FUSE_KO=""
    for c in \
      "$MODULE_DIR/kernel/fs/fuse/fuse.ko" \
      "$MODULE_DIR/kernel/fs/fuse/fuse.ko.xz" \
      "$MODULE_DIR/extra/fuse.ko" \
      "$MODULE_DIR/fuse.ko"; do
      [ -f "$c" ] && { FUSE_KO="$c"; break; }
    done
    FUSE_BUILTIN=0
    [ -z "$FUSE_KO" ] && { echo "  fuse.ko not found; assuming built-in"; FUSE_BUILTIN=1; }

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK1_IMG="$WORK_DIR/disk1.img"
    DISK2_IMG="$WORK_DIR/disk2.img"
    VAL_LOG="$WORK_DIR/validation.log"

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,etc,run/tidefs/import}
    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping: $WORK_DIR"
      else
        rm -rf "$WORK_DIR"
      fi
    }
    trap cleanup EXIT

    echo "  Creating raw virtio disk images"
    dd if=/dev/zero of="$DISK1_IMG" bs=1M count="$DISK_SIZE_MB" 2>/dev/null
    dd if=/dev/zero of="$DISK2_IMG" bs=1M count="$DISK_SIZE_MB" 2>/dev/null

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

    copy_binary_to_bin "$BUSYBOX" busybox
    for applet in sh ls cat echo mount umount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq blockdev mountpoint du \
                    uname date hexdump sed timeout; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    copy_binary_to_bin "$TIDEFSCTL" tidefsctl
    copy_binary_to_bin "$FUSE_DAEMON" tidefs-posix-filesystem-adapter-daemon

    [ "$FUSE_BUILTIN" -eq 0 ] && cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000001

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /mnt/tidefs

echo "=== TideFS Pool Remount Lifecycle Validation ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo ""

PASSED=0; FAILED=0; BLOCKED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

echo "--- Phase 0: Kernel support ---"

if grep -qw fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_builtin"
    pass "fuse_support"
elif [ -f /lib/modules/fuse.ko ]; then
    if insmod /lib/modules/fuse.ko 2>/tmp/fuse-insmod.err; then
        pass "fuse_module"
        pass "fuse_support"
    else
        fail "fuse_support" "$(cat /tmp/fuse-insmod.err 2>/dev/null)"
    fi
else
    blocked "fuse_support" "no fuse.ko and not built-in"
fi

[ ! -e /dev/fuse ] && mknod /dev/fuse c 10 229 2>/dev/null || true
[ -e /dev/fuse ] && pass "fuse_device" || blocked "fuse_device" "cannot create /dev/fuse"
FUSE_OK=0; [ -e /dev/fuse ] && FUSE_OK=1

echo ""
echo "--- Phase 1: Virtio block devices ---"

DEV0="/dev/vda"
DEV1="/dev/vdb"
for _ in $(seq 1 30); do
    [ -b "$DEV0" ] && [ -b "$DEV1" ] && break
    sleep 1
done

[ -b "$DEV0" ] && pass "virtio0_present" || fail "virtio0_present" "$DEV0 missing"
[ -b "$DEV1" ] && pass "virtio1_present" || fail "virtio1_present" "$DEV1 missing"

if [ ! -b "$DEV0" ] || [ ! -b "$DEV1" ]; then
    for op in virtio0_size virtio1_size pool_create ownerless_import_refused \
             owner_mediated_import mount write_data fsync_data read_verify \
             unmount pool_export ownerless_reimport_refused \
             owner_mediated_reimport remount \
             persist_verify live_owner_status_visible post_remount_write_read \
             ownerless_active_status_refused \
             crash_cycle_export_prep crash_cycle_ownerless_preimport_refused \
             crash_cycle_owner_mediated_preimport crash_cycle_premount \
             crash_cycle_write_committed crash_cycle_write_uncommitted \
             crash_cycle_committed_pre_crash_read crash_cycle_sigkill \
             crash_cycle_stale_mount_detached \
             crash_cycle_ownerless_reimport_refused \
             crash_cycle_owner_mediated_reimport \
             crash_cycle_recovery_remount crash_cycle_committed_survived \
             crash_cycle_unfsynced_bounded; do
        blocked "$op" "virtio block devices missing"
    done
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; poweroff -f
fi

echo ""
echo "--- Phase 2: Device sizes ---"

D0SIZE=$(blockdev --getsize64 "$DEV0" 2>/dev/null || echo 0)
D1SIZE=$(blockdev --getsize64 "$DEV1" 2>/dev/null || echo 0)
echo "  $DEV0 = $D0SIZE bytes"
echo "  $DEV1 = $D1SIZE bytes"
[ "$D0SIZE" -gt 0 ] && pass "virtio0_size" || fail "virtio0_size" "0 bytes"
[ "$D1SIZE" -gt 0 ] && pass "virtio1_size" || fail "virtio1_size" "0 bytes"

echo ""
echo "--- Phase 3: Pool create ---"

POOL_NAME="remount_lifecycle_pool"
POOL_UUID=""
POOL_CREATED=0

if command -v tidefsctl >/dev/null 2>&1; then
    COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  exit=$RC"
    echo "  $COUT"
    if [ "$RC" -eq 0 ]; then
        pass "pool_create"
        POOL_CREATED=1
        POOL_UUID=$(echo "$COUT" | grep -o '"pool_guid"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
    else
        fail "pool_create" "$COUT"
    fi
else
    blocked "pool_create" "tidefsctl not found"
fi

echo ""
echo "--- Phase 4: Ownerless pool import refusal ---"

IMPORT_READY=0
if [ "$POOL_CREATED" -eq 1 ]; then
    IOUT=$(tidefsctl pool import "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  ownerless import exit=$RC"
    echo "  $IOUT"
    if [ "$RC" -ne 0 ] && printf '%s\n' "$IOUT" | grep -q '"owner_required"[[:space:]]*:[[:space:]]*true'; then
        pass "ownerless_import_refused"
        IMPORT_READY=1
    else
        fail "ownerless_import_refused" "expected owner_required refusal, exit=$RC output=$IOUT"
    fi
else
    blocked "ownerless_import_refused" "pool not created"
fi

echo ""
echo "--- Phase 5: FUSE mount ---"

MNT=/mnt/tidefs
MOUNTED=0
DAEMON_PID=""

if [ "$FUSE_OK" -eq 1 ] && [ "$IMPORT_READY" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/mount.log 2>&1 &
    DAEMON_PID=$!
    echo "  daemon PID=$DAEMON_PID"

    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { MOUNTED=1; break; }
        sleep 1
    done

    if [ "$MOUNTED" -eq 1 ]; then
        pass "owner_mediated_import"
        pass "mount"
    else
        fail "owner_mediated_import" "$(tail -20 /tmp/mount.log 2>/dev/null)"
        fail "mount" "$(tail -20 /tmp/mount.log 2>/dev/null)"
    fi
else
    blocked "owner_mediated_import" "FUSE not ready or ownerless refusal missing"
    blocked "mount" "FUSE not ready or ownerless refusal missing"
fi

echo ""
echo "--- Phase 6: Write/fsync/read data ---"

TF="$MNT/remount_lifecycle_test.txt"
TC="TideFS-Remount-Lifecycle-Validation-$(date +%s 2>/dev/null || echo 0)"

if [ "$MOUNTED" -eq 1 ]; then
    echo "$TC" > "$TF" 2>/tmp/werr
    [ -f "$TF" ] && pass "write_data" || fail "write_data" "$(cat /tmp/werr 2>/dev/null)"

    if sync -f "$TF" 2>/tmp/fsync.err; then
        pass "fsync_data"
    else
        fail "fsync_data" "sync -f failed: $(cat /tmp/fsync.err 2>/dev/null)"
    fi

    RC=$(cat "$TF" 2>/dev/null || true)
    [ "$RC" = "$TC" ] && pass "read_verify" || fail "read_verify" "expected '$TC' got '$RC'"
else
    for op in write_data fsync_data read_verify; do
        blocked "$op" "not mounted"
    done
fi

echo ""
echo "--- Phase 7: Unmount ---"

if [ "$MOUNTED" -eq 1 ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    DAEMON_EXITED=0
    for _ in $(seq 1 10); do
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            DAEMON_EXITED=1
            break
        fi
        sleep 1
    done
    if [ "$DAEMON_EXITED" -eq 0 ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "  daemon still running after SIGTERM; sending SIGKILL"
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    else
        echo "  daemon exited after SIGTERM"
    fi
    wait "$DAEMON_PID" 2>/dev/null || true
    echo "  initial mount daemon log:"
    tail -80 /tmp/mount.log 2>/dev/null || true
    umount "$MNT" 2>/dev/null || true
    mountpoint -q "$MNT" 2>/dev/null && fail "unmount" "still mounted" || pass "unmount"
else
    blocked "unmount" "not mounted"
fi

echo ""
echo "--- Phase 8: Pool export ---"

EXPORT_OK=0
if [ "$MOUNTED" -eq 1 ]; then
    EOUT=$(tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" --force 2>&1); RC=$?
    echo "  export exit=$RC"
    echo "  $EOUT"
    if [ "$RC" -eq 0 ]; then
        pass "pool_export"
        EXPORT_OK=1
    else
        fail "pool_export" "$EOUT"
    fi
else
    blocked "pool_export" "not mounted"
fi

echo ""
echo "--- Phase 9: Ownerless reimport refusal ---"

REIMPORT_READY=0
if [ "$EXPORT_OK" -ne 1 ]; then
    blocked "ownerless_reimport_refused" "pool export failed"
elif command -v tidefsctl >/dev/null 2>&1; then
    RIOUT=$(tidefsctl pool import "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  ownerless reimport exit=$RC"
    echo "  $RIOUT"
    if [ "$RC" -ne 0 ] && printf '%s\n' "$RIOUT" | grep -q '"owner_required"[[:space:]]*:[[:space:]]*true'; then
        pass "ownerless_reimport_refused"
        REIMPORT_READY=1
    else
        fail "ownerless_reimport_refused" "expected owner_required refusal, exit=$RC output=$RIOUT"
    fi
else
    blocked "ownerless_reimport_refused" "tidefsctl missing"
fi

echo ""
echo "--- Phase 10: Remount ---"

REMOUNTED=0
RPID=""
if [ "$REIMPORT_READY" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/remount.log 2>&1 &
    RPID=$!
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { REMOUNTED=1; break; }
        sleep 1
    done

    if [ "$REMOUNTED" -eq 1 ]; then
        pass "owner_mediated_reimport"
        pass "remount"
    else
        fail "owner_mediated_reimport" "$(tail -20 /tmp/remount.log 2>/dev/null)"
        fail "remount" "$(tail -20 /tmp/remount.log 2>/dev/null)"
    fi
else
    blocked "owner_mediated_reimport" "ownerless refusal/FUSE not ready"
    blocked "remount" "ownerless refusal/FUSE not ready"
fi

echo ""
echo "--- Phase 11: Persist verify ---"

if [ "$REMOUNTED" -eq 1 ]; then
    echo "  remount directory listing before read:"
    ls -la "$MNT" 2>/dev/null || true
    echo "  remount target stat before read:"
    stat "$TF" 2>/dev/null || true
    if timeout -k 2 15 cat "$TF" > /tmp/persist-read.out 2>/tmp/persist-read.err; then
        PB=$(cat /tmp/persist-read.out 2>/dev/null || true)
    else
        PB=""
        echo "  persist read timed out or failed"
        echo "  persist read stderr:"
        cat /tmp/persist-read.err 2>/dev/null || true
        echo "  persist read bytes before timeout:"
        wc -c /tmp/persist-read.out 2>/dev/null || true
    fi
    if [ "$PB" = "$TC" ]; then
        pass "persist_verify"
    else
        echo "  remount directory listing:"
        ls -la "$MNT" 2>/dev/null || true
        echo "  remount target stat:"
        stat "$TF" 2>/dev/null || true
        echo "  remount daemon log:"
        tail -80 /tmp/remount.log 2>/dev/null || true
        fail "persist_verify" "expected '$TC' got '$PB'"
    fi
else
    blocked "persist_verify" "remount failed"
fi

echo ""
echo "--- Phase 12: Live-owner status visibility ---"

if [ "$REMOUNTED" -eq 1 ]; then
    # Write and fsync new data before querying the live owner.
    TC2="TideFS-Live-Owner-Status-$(date +%s 2>/dev/null || echo 0)"
    TF2="$MNT/live_owner_status_test.txt"
    echo "$TC2" > "$TF2" 2>/dev/null
    sync -f "$TF2" 2>/dev/null || sync

    POST_STATUS="/tmp/post_remount_status.json"
    if tidefsctl pool status "$POOL_NAME" --devices "$DEV0" "$DEV1" --json > "$POST_STATUS" 2>/tmp/post_remount_status.err \
       && grep -q '"state"[[:space:]]*:[[:space:]]*"[^"]*"' "$POST_STATUS" 2>/dev/null; then
        pass "live_owner_status_visible"
    else
        fail "live_owner_status_visible" "$(cat /tmp/post_remount_status.err 2>/dev/null)"
    fi
else
    blocked "live_owner_status_visible" "remount failed"
fi

echo ""
echo "--- Phase 13: Post-remount write/read ---"

if [ "$REMOUNTED" -eq 1 ]; then
    TF3="$MNT/post_remount_write_read_test.txt"
    TC3="TideFS-Post-Remount-Write-Read-$(date +%s 2>/dev/null || echo 0)"
    echo "$TC3" > "$TF3" 2>/dev/null
    sync -f "$TF3" 2>/dev/null || sync
    RC3=$(cat "$TF3" 2>/dev/null || true)
    if [ "$RC3" = "$TC3" ]; then
        pass "post_remount_write_read"
    else
        fail "post_remount_write_read" "expected '$TC3' got '$RC3'"
    fi
else
    blocked "post_remount_write_read" "remount failed"
fi

# Cleanup remount daemon
if [ -n "$RPID" ]; then
    kill "$RPID" 2>/dev/null || true
    sleep 1
    umount "$MNT" 2>/dev/null || true
fi


echo ""
echo "--- Phase 14: Ownerless active-status refusal ---"

if [ "$REMOUNTED" -eq 1 ]; then
    SOUT=$(tidefsctl pool status "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
    if [ "$RC" -ne 0 ] && printf '%s\n' "$SOUT" | grep -q '"owner_required"[[:space:]]*:[[:space:]]*true'; then
        pass "ownerless_active_status_refused"
    else
        fail "ownerless_active_status_refused" "expected owner_required refusal, exit=$RC output=$SOUT"
    fi
else
    blocked "ownerless_active_status_refused" "remount failed"
fi

echo ""
echo "--- Phase 15: Crash-cycle (SIGKILL without export) ---"

# This phase exercises the storage durability/recovery spine:
# - Write fsynced data (committed through txg commit boundary)
# - Write non-fsynced data while keeping the writer fd open, so FUSE_FLUSH
#   cannot turn the row into a close-path durability commit. This row is
#   bounded old-or-new: absent is valid, exact intent-log replay is valid,
#   corrupted or partial content is not.
# - SIGKILL the daemon (simulating crash/power-loss, no clean export)
# - Detach the dead FUSE mount before starting the recovery mount
# - Refuse ownerless import, then import through the new FUSE owner
# - Remount and verify: committed data survives, unfsynced data is bounded

CRASH_CYCLE_EXPORT_OK=0
if tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" --force > /tmp/crash_export.log 2>&1; then
    CRASH_CYCLE_EXPORT_OK=1
    pass "crash_cycle_export_prep"
else
    fail "crash_cycle_export_prep" "$(cat /tmp/crash_export.log 2>/dev/null)"
fi

CRASH_CYCLE_IMPORT_OK=0
if [ "$CRASH_CYCLE_EXPORT_OK" -eq 1 ]; then
    CIOUT=$(tidefsctl pool import "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
    if [ "$RC" -ne 0 ] && printf '%s\n' "$CIOUT" | grep -q '"owner_required"[[:space:]]*:[[:space:]]*true'; then
        pass "crash_cycle_ownerless_preimport_refused"
        CRASH_CYCLE_IMPORT_OK=1
    else
        fail "crash_cycle_ownerless_preimport_refused" "expected owner_required refusal, exit=$RC output=$CIOUT"
    fi
else
    blocked "crash_cycle_ownerless_preimport_refused" "export preparation failed"
fi

CRASH_CYCLE_MOUNTED=0
CRASH_PID=""
if [ "$CRASH_CYCLE_IMPORT_OK" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/crash_mount.log 2>&1 &
    CRASH_PID=$!
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { CRASH_CYCLE_MOUNTED=1; break; }
        sleep 1
    done
    if [ "$CRASH_CYCLE_MOUNTED" -eq 1 ]; then
        pass "crash_cycle_owner_mediated_preimport"
        pass "crash_cycle_premount"
    else
        fail "crash_cycle_owner_mediated_preimport" "$(tail -20 /tmp/crash_mount.log 2>/dev/null)"
        fail "crash_cycle_premount" "$(tail -20 /tmp/crash_mount.log 2>/dev/null)"
    fi
else
    blocked "crash_cycle_owner_mediated_preimport" "ownerless refusal/FUSE not ready"
    blocked "crash_cycle_premount" "ownerless refusal/FUSE not ready"
fi

# Write committed (fsynced) and uncommitted (not fsynced) data
CRASH_COMMITTED_CONTENT="TideFS-CrashCycle-Committed-$(date +%s 2>/dev/null || echo 0)"
CRASH_UNCOMMITTED_CONTENT="TideFS-CrashCycle-Uncommitted-$(date +%s 2>/dev/null || echo 0)"
CRASH_COMMITTED_FILE="$MNT/crash_committed.txt"
CRASH_UNCOMMITTED_FILE="$MNT/crash_uncommitted.txt"
CRASH_UNCOMMITTED_READY="/tmp/crash_uncommitted_ready"
CRASH_UNCOMMITTED_HOLDER=""

if [ "$CRASH_CYCLE_MOUNTED" -eq 1 ]; then
    echo "$CRASH_COMMITTED_CONTENT" > "$CRASH_COMMITTED_FILE" 2>/dev/null
    sync -f "$CRASH_COMMITTED_FILE" 2>/dev/null || sync
    [ -f "$CRASH_COMMITTED_FILE" ] && pass "crash_cycle_write_committed" || fail "crash_cycle_write_committed" "write failed"
    echo "  committed file stat before crash:"
    stat "$CRASH_COMMITTED_FILE" 2>/dev/null || true
    CRASH_PRE_COMMITTED=$(cat "$CRASH_COMMITTED_FILE" 2>/dev/null || true)
    if [ "$CRASH_PRE_COMMITTED" = "$CRASH_COMMITTED_CONTENT" ]; then
        pass "crash_cycle_committed_pre_crash_read"
    else
        fail "crash_cycle_committed_pre_crash_read" "expected '$CRASH_COMMITTED_CONTENT' got '$CRASH_PRE_COMMITTED'"
    fi

    rm -f "$CRASH_UNCOMMITTED_READY" 2>/dev/null || true
    (
        exec 9>"$CRASH_UNCOMMITTED_FILE"
        printf "%s\n" "$CRASH_UNCOMMITTED_CONTENT" >&9
        echo ready > "$CRASH_UNCOMMITTED_READY"
        sleep 300
    ) &
    CRASH_UNCOMMITTED_HOLDER=$!
    for _ in $(seq 1 30); do
        [ -s "$CRASH_UNCOMMITTED_READY" ] && break
        sleep 1
    done
    # Deliberately do NOT fsync or close this file before the daemon crash.
    if [ -s "$CRASH_UNCOMMITTED_READY" ] && [ -f "$CRASH_UNCOMMITTED_FILE" ]; then
        pass "crash_cycle_write_uncommitted"
    else
        fail "crash_cycle_write_uncommitted" "open writer did not stage the uncommitted file"
    fi
else
    blocked "crash_cycle_write_committed" "crash-cycle mount failed"
    blocked "crash_cycle_committed_pre_crash_read" "crash-cycle mount failed"
    blocked "crash_cycle_write_uncommitted" "crash-cycle mount failed"
fi

# CRASH: SIGKILL daemon without clean export
echo "  Triggering crash (SIGKILL without export)..."
if [ -n "$CRASH_PID" ] && kill -0 "$CRASH_PID" 2>/dev/null; then
    kill -KILL "$CRASH_PID" 2>/dev/null || true
    wait "$CRASH_PID" 2>/dev/null || true
    pass "crash_cycle_sigkill"
else
    blocked "crash_cycle_sigkill" "crash-cycle daemon not running"
fi
if [ -n "$CRASH_UNCOMMITTED_HOLDER" ] && kill -0 "$CRASH_UNCOMMITTED_HOLDER" 2>/dev/null; then
    kill -KILL "$CRASH_UNCOMMITTED_HOLDER" 2>/dev/null || true
    wait "$CRASH_UNCOMMITTED_HOLDER" 2>/dev/null || true
fi
echo "  crash mount daemon log:"
tail -120 /tmp/crash_mount.log 2>/dev/null || true

if [ "$CRASH_CYCLE_MOUNTED" -eq 1 ]; then
    if mountpoint -q "$MNT" 2>/dev/null; then
        if umount -l "$MNT" 2>/tmp/crash_umount.err; then
            pass "crash_cycle_stale_mount_detached"
        else
            fail "crash_cycle_stale_mount_detached" "$(cat /tmp/crash_umount.err 2>/dev/null)"
        fi
    else
        pass "crash_cycle_stale_mount_detached"
    fi
else
    blocked "crash_cycle_stale_mount_detached" "crash-cycle mount never became active"
fi

# REFUSE OWNERLESS IMPORT WITHOUT EXPORT: recovery mount owns import/replay.
CRASH_RECOVERY_IMPORT_OK=0
CROUT=$(tidefsctl pool import "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
echo "  crash-recovery ownerless import exit=$RC"
if [ "$RC" -ne 0 ] && printf '%s\n' "$CROUT" | grep -q '"owner_required"[[:space:]]*:[[:space:]]*true'; then
    pass "crash_cycle_ownerless_reimport_refused"
    CRASH_RECOVERY_IMPORT_OK=1
else
    fail "crash_cycle_ownerless_reimport_refused" "expected owner_required refusal, exit=$RC output=$CROUT"
fi

# Remount after crash recovery
CRASH_RECOVERY_MOUNTED=0
CRP=""
if [ "$CRASH_RECOVERY_IMPORT_OK" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/crash_recovery_mount.log 2>&1 &
    CRP=$!
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { CRASH_RECOVERY_MOUNTED=1; break; }
        sleep 1
    done
    if [ "$CRASH_RECOVERY_MOUNTED" -eq 1 ]; then
        pass "crash_cycle_owner_mediated_reimport"
        pass "crash_cycle_recovery_remount"
    else
        fail "crash_cycle_owner_mediated_reimport" "$(tail -20 /tmp/crash_recovery_mount.log 2>/dev/null)"
        fail "crash_cycle_recovery_remount" "$(tail -20 /tmp/crash_recovery_mount.log 2>/dev/null)"
    fi
else
    blocked "crash_cycle_owner_mediated_reimport" "ownerless refusal/FUSE not ready"
    blocked "crash_cycle_recovery_remount" "ownerless refusal/FUSE not ready"
fi

# Verify: committed data survived; unfsynced data is absent or exact.
POST_CRASH_COMMITTED=""
POST_CRASH_UNCOMMITTED=""
if [ "$CRASH_RECOVERY_MOUNTED" -eq 1 ]; then
    echo "  crash recovery mount daemon log:"
    tail -120 /tmp/crash_recovery_mount.log 2>/dev/null || true
    echo "  crash recovery directory listing before read:"
    ls -la "$MNT" 2>/dev/null || true
    echo "  crash recovery committed file stat before read:"
    stat "$CRASH_COMMITTED_FILE" 2>/dev/null || true
    if timeout -k 2 15 cat "$CRASH_COMMITTED_FILE" > /tmp/crash_committed_read.out 2>/dev/null; then
        POST_CRASH_COMMITTED=$(cat /tmp/crash_committed_read.out 2>/dev/null || true)
    else
        POST_CRASH_COMMITTED=""
    fi
    if [ "$POST_CRASH_COMMITTED" = "$CRASH_COMMITTED_CONTENT" ]; then
        pass "crash_cycle_committed_survived"
    else
        echo "  crash recovery committed read bytes:"
        wc -c /tmp/crash_committed_read.out 2>/dev/null || true
        fail "crash_cycle_committed_survived" "expected '$CRASH_COMMITTED_CONTENT' got '$POST_CRASH_COMMITTED'"
    fi

    if [ -f "$CRASH_UNCOMMITTED_FILE" ]; then
        POST_CRASH_UNCOMMITTED=$(cat "$CRASH_UNCOMMITTED_FILE" 2>/dev/null || true)
        if [ "$POST_CRASH_UNCOMMITTED" = "$CRASH_UNCOMMITTED_CONTENT" ]; then
            pass "crash_cycle_unfsynced_bounded"
        else
            fail "crash_cycle_unfsynced_bounded" "expected absent or exact replay, got '$POST_CRASH_UNCOMMITTED'"
        fi
    else
        pass "crash_cycle_unfsynced_bounded"
    fi
else
    blocked "crash_cycle_committed_survived" "crash-recovery remount failed"
    blocked "crash_cycle_unfsynced_bounded" "crash-recovery remount failed"
fi

# Cleanup crash recovery daemon
if [ -n "$CRP" ]; then
    kill "$CRP" 2>/dev/null || true
    sleep 1
    umount "$MNT" 2>/dev/null || true
fi

sync && pass "sync_done"

echo ""
echo "=== Validation Summary ==="
echo "validation_tier=qemu guest"
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "backend=virtio_blk_raw_disks"
echo "mode=pool_remount_lifecycle_userspace_fuse_with_crash_cycle"
echo "pool_name=$POOL_NAME"
echo "pool_uuid=$POOL_UUID"
echo "dev0=$DEV0 dev0_size=$D0SIZE"
echo "dev1=$DEV1 dev1_size=$D1SIZE"
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "test_content_pre_unmount=$TC"
echo "test_content_post_remount=$PB"
echo "crash_committed_content=$CRASH_COMMITTED_CONTENT"
echo "crash_uncommitted_content=$CRASH_UNCOMMITTED_CONTENT"
echo "post_crash_committed=$POST_CRASH_COMMITTED"
echo "post_crash_uncommitted=$POST_CRASH_UNCOMMITTED"
echo "=== End ==="

sync; sleep 1; poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "  Building compressed initrd"
    (cd "$RUN_DIR" && find . -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -9) > "$WORK_DIR/initrd.img.gz"
    echo "  Initrd.gz: $(du -h "$WORK_DIR/initrd.img.gz" | cut -f1)"

    echo ""
    echo "  === Booting qemu guest ==="
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      "''${QEMU_ACCEL[@]}" \
      -kernel "$KERNEL_IMG" \
      -initrd "$WORK_DIR/initrd.img.gz" \
      -drive file="$DISK1_IMG",format=raw,if=virtio,index=0 \
      -drive file="$DISK2_IMG",format=raw,if=virtio,index=1 \
      -append "console=ttyS0 quiet panic=10" \
      -m 2G \
      -smp 2 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo "  QEMU exited ($(wc -l < "$VAL_LOG" 2>/dev/null || echo 0) log lines)"

    echo ""
    echo "=== Validation Results ==="
    PASSC=0; FAILC=0; BLOCKC=0

    for op in \
      fuse_support fuse_device \
      virtio0_present virtio1_present virtio0_size virtio1_size \
      pool_create ownerless_import_refused owner_mediated_import mount \
      write_data fsync_data read_verify unmount pool_export \
      ownerless_reimport_refused owner_mediated_reimport remount persist_verify \
      live_owner_status_visible post_remount_write_read \
      ownerless_active_status_refused \
      crash_cycle_export_prep crash_cycle_ownerless_preimport_refused \
      crash_cycle_owner_mediated_preimport crash_cycle_premount \
      crash_cycle_write_committed crash_cycle_write_uncommitted \
      crash_cycle_committed_pre_crash_read crash_cycle_sigkill \
      crash_cycle_stale_mount_detached crash_cycle_ownerless_reimport_refused \
      crash_cycle_owner_mediated_reimport \
      crash_cycle_recovery_remount crash_cycle_committed_survived \
      crash_cycle_unfsynced_bounded \
      sync_done; do
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
    echo "Matrix: $PASSC passed, $FAILC failed, $BLOCKC blocked"
    echo "Validation log: $VAL_LOG"

    TS=$(date -u +%Y%m%d-%H%M%S)
    RUNS_DIR="''${TIDEFS_VALIDATION_RUNS_DIR:-/root/ai/tmp/tidefs-validation}"
    mkdir -p "$RUNS_DIR" 2>/dev/null || true
    cp "$VAL_LOG" "$RUNS_DIR/pool-remount-lifecycle-$TS.log" 2>/dev/null || true
    echo "  Validation output: $RUNS_DIR/pool-remount-lifecycle-$TS.log"

    [ "$FAILC" -gt 0 ] && { echo "VALIDATION: FAIL ($FAILC failures)"; exit 1; }
    [ "$BLOCKC" -gt 0 ] && { echo "VALIDATION: BLOCKED ($BLOCKC blocked)"; exit 2; }
    echo "VALIDATION: COMPLETE"
    exit 0
  '';
in
poolRemountLifecycleScript
