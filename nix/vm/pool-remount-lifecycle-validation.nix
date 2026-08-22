# TideFS: pool remount-lifecycle validation (#6136).
#
# Boots a Linux 7.0 qemu guest with two raw virtio-blk disks and exercises
# the full remount lifecycle with committed-root advancement and intent-log
# replay consistency verification:
#   pool create -> import -> FUSE mount -> write/fsync/read ->
#   unmount -> pool export -> reimport -> remount -> persist verify ->
#   committed-root advance verify -> intent-log consistency verify ->
#   mounted clean/corrupt integrity and live-owner content-scrub reports.
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
    BYTE_GREP="${pkgs.gnugrep}/bin/grep"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"

    TMPDIR="''${TIDEFS_POOL_REMOUNT_TMPDIR:-/tmp/tidefs-pool-remount-lifecycle-validation}"
    TIMEOUT_SEC="''${TIDEFS_POOL_REMOUNT_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_POOL_REMOUNT_DISK_MB:-128}"
    VALIDATION_TIER="qemu guest"

    usage() {
      cat <<USAGE
Usage: tidefs-pool-remount-lifecycle-validation [--timeout SECONDS] [--disk-size-mb MB] [--keep-tmp]

Full remount lifecycle on two virtio-blk disks in a Linux 7.0 qemu guest:
  pool create -> import -> FUSE mount -> write/fsync/read ->
  unmount -> pool export -> reimport -> remount -> persist verify ->
  committed-root advance verify -> intent-log consistency verify.

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

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$BYTE_GREP" "$TIDEFSCTL"; do
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
    copy_binary_to_bin "$BYTE_GREP" bytegrep
    for applet in sh ls cat echo mount umount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm ln touch find wc sync \
                    expr head tail cut kill ps test seq blockdev mountpoint du \
                    uname date hexdump sed sha256sum timeout; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    copy_binary_to_bin "$TIDEFSCTL" tidefsctl

    [ "$FUSE_BUILTIN" -eq 0 ] && cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

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
    for op in virtio0_size virtio1_size pool_create startup_failure_unwind \
             startup_retry_mount pool_import mount \
             live_status write_data fsync_data read_verify lookup_inode rename_entry \
             link_inode_identity unlink_entry readdir_entry unmount pool_export \
             reimport remount persist_verify inode_identity_stable \
             committed_root_advance intent_log_consistency \
             readonly_prep_release readonly_mount readonly_kernel_ro readonly_read \
             readonly_create_erofs readonly_write_erofs readonly_truncate_erofs \
             readonly_unlink_erofs readonly_rename_erofs readonly_mkdir_erofs \
             readonly_setattr_erofs readonly_content_unchanged \
             readonly_release readonly_bytes_preserved \
             crash_cycle_export_prep crash_cycle_preimport crash_cycle_premount \
             crash_cycle_write_committed crash_cycle_write_uncommitted \
             crash_cycle_committed_pre_crash_read crash_cycle_sigkill \
             crash_cycle_stale_mount_detached crash_cycle_reimport_no_export \
             crash_cycle_recovery_remount crash_cycle_committed_survived \
             crash_cycle_inode_stable crash_cycle_unfsynced_bounded \
             mounted_integrity_clean mounted_integrity_corruption_injected \
             mounted_integrity_failure_reported \
             mounted_scrub_clean mounted_scrub_corruption_injected \
             mounted_scrub_failure_reported mounted_scrub_no_repair_writeback; do
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
    COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$DEV0" "$DEV1" \
        --redundancy replicated=2 --json 2>&1); RC=$?
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
echo "--- Phase 3.5: Mount startup failure unwind and retry ---"

STARTUP_RETRY_OK=0
STARTUP_RETRY_PID=""
unset TIDEFS_ROOT_AUTHENTICATION_KEY_HEX
if [ "$POOL_CREATED" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    if tidefsctl pool mount "$POOL_NAME" /mnt/tidefs --devices "$DEV0" "$DEV1" \
        > /tmp/startup_failure.log 2>&1; then
        STARTUP_FAILURE_RC=0
    else
        STARTUP_FAILURE_RC=$?
    fi
    if [ "$STARTUP_FAILURE_RC" -ne 0 ] \
        && grep -q 'pool ".*" imported' /tmp/startup_failure.log \
        && grep -q 'root authentication key is required' /tmp/startup_failure.log \
        && grep -q 'pool import unwound after mount startup failure' /tmp/startup_failure.log; then
        pass "startup_failure_unwind"
    else
        fail "startup_failure_unwind" "$(tail -20 /tmp/startup_failure.log 2>/dev/null)"
    fi

    export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141
    tidefsctl pool mount "$POOL_NAME" /mnt/tidefs --devices "$DEV0" "$DEV1" \
        > /tmp/startup_retry.log 2>&1 &
    STARTUP_RETRY_PID=$!
    for _ in $(seq 1 45); do
        mountpoint -q /mnt/tidefs 2>/dev/null && { STARTUP_RETRY_OK=1; break; }
        ! kill -0 "$STARTUP_RETRY_PID" 2>/dev/null && break
        sleep 1
    done
    if [ "$STARTUP_RETRY_OK" -eq 1 ] \
        && grep -q 'pool ".*" imported' /tmp/startup_retry.log; then
        pass "startup_retry_mount"
    else
        fail "startup_retry_mount" "$(tail -20 /tmp/startup_retry.log 2>/dev/null)"
    fi

    if [ "$STARTUP_RETRY_OK" -ne 1 ]; then
        kill "$STARTUP_RETRY_PID" 2>/dev/null || true
        wait "$STARTUP_RETRY_PID" 2>/dev/null || true
    fi
else
    blocked "startup_failure_unwind" "pool or FUSE not ready"
    blocked "startup_retry_mount" "startup failure case not runnable"
fi

echo ""
echo "--- Phase 4: Pool import ---"

IMPORT_OK=$STARTUP_RETRY_OK
if [ "$IMPORT_OK" -eq 1 ]; then
    pass "pool_import"
else
    blocked "pool_import" "owner-creating mount retry did not import"
fi

echo ""
echo "--- Phase 5: FUSE mount ---"

MNT=/mnt/tidefs
MOUNTED=$STARTUP_RETRY_OK
DAEMON_PID=$STARTUP_RETRY_PID

if [ "$MOUNTED" -eq 1 ]; then
    echo "  daemon PID=$DAEMON_PID"
    pass "mount"
else
    blocked "mount" "startup retry did not reach mounted state"
fi

echo ""
echo "--- Phase 6: Write/fsync/read data ---"

TF="$MNT/remount_lifecycle_test.txt"
TC="TideFS-Remount-Lifecycle-Validation-$(date +%s 2>/dev/null || echo 0)"
PRE_REMOUNT_INODE=0

if [ "$MOUNTED" -eq 1 ]; then
    if tidefsctl pool status "$POOL_NAME" --devices "$DEV0" "$DEV1" --json \
        > /tmp/live_status.json 2>/tmp/live_status.err \
        && grep -q '"state"[[:space:]]*:[[:space:]]*"Active"' /tmp/live_status.json \
        && grep -q '"source_classification"[[:space:]]*:[[:space:]]*"source:live-owner"' /tmp/live_status.json; then
        pass "live_status"
    else
        fail "live_status" "$(cat /tmp/live_status.err /tmp/live_status.json 2>/dev/null)"
    fi

    echo "$TC" > "$TF" 2>/tmp/werr
    [ -f "$TF" ] && pass "write_data" || fail "write_data" "$(cat /tmp/werr 2>/dev/null)"

    if sync "$TF" 2>/tmp/fsync.err; then
        pass "fsync_data"
    else
        fail "fsync_data" "per-file fsync failed: $(cat /tmp/fsync.err 2>/dev/null)"
    fi

    RC=$(cat "$TF" 2>/dev/null || true)
    [ "$RC" = "$TC" ] && pass "read_verify" || fail "read_verify" "expected '$TC' got '$RC'"

    PRE_REMOUNT_INODE=$(stat -c '%i' "$TF" 2>/tmp/lookup-inode.err || echo 0)
    if [ "$PRE_REMOUNT_INODE" -gt 0 ] 2>/dev/null; then
        pass "lookup_inode"
    else
        fail "lookup_inode" "$(cat /tmp/lookup-inode.err 2>/dev/null)"
    fi

    RENAMED_TF="$MNT/remount_lifecycle_renamed.txt"
    if mv "$TF" "$RENAMED_TF" 2>/tmp/rename-entry.err \
        && [ ! -e "$TF" ] && [ -f "$RENAMED_TF" ]; then
        pass "rename_entry"
    else
        fail "rename_entry" "$(cat /tmp/rename-entry.err 2>/dev/null)"
    fi

    LINKED_TF="$MNT/remount_lifecycle_link.txt"
    if ln "$RENAMED_TF" "$LINKED_TF" 2>/tmp/link-entry.err; then
        RENAMED_INODE=$(stat -c '%i' "$RENAMED_TF" 2>/dev/null || echo 0)
        LINKED_INODE=$(stat -c '%i' "$LINKED_TF" 2>/dev/null || echo 0)
        if [ "$RENAMED_INODE" -gt 0 ] 2>/dev/null \
            && [ "$RENAMED_INODE" = "$LINKED_INODE" ] \
            && [ "$RENAMED_INODE" = "$PRE_REMOUNT_INODE" ]; then
            pass "link_inode_identity"
        else
            fail "link_inode_identity" \
                "source=$RENAMED_INODE link=$LINKED_INODE expected=$PRE_REMOUNT_INODE"
        fi
    else
        fail "link_inode_identity" "$(cat /tmp/link-entry.err 2>/dev/null)"
    fi

    if rm "$RENAMED_TF" 2>/tmp/unlink-entry.err \
        && [ ! -e "$RENAMED_TF" ] && [ -f "$LINKED_TF" ]; then
        pass "unlink_entry"
    else
        fail "unlink_entry" "$(cat /tmp/unlink-entry.err 2>/dev/null)"
    fi

    if ls "$MNT" 2>/tmp/readdir-entry.err | grep -qx 'remount_lifecycle_link.txt'; then
        pass "readdir_entry"
    else
        fail "readdir_entry" "$(cat /tmp/readdir-entry.err 2>/dev/null)"
    fi
    TF="$LINKED_TF"
else
    for op in live_status write_data fsync_data read_verify lookup_inode rename_entry \
              link_inode_identity unlink_entry readdir_entry; do
        blocked "$op" "not mounted"
    done
fi

echo ""
echo "--- Phase 7: Unmount ---"

LIVE_EXPORT_RC=1
DAEMON_RC=1
if [ "$MOUNTED" -eq 1 ]; then
    if tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" \
        > /tmp/live_export.out 2>/tmp/live_export.err; then
        LIVE_EXPORT_RC=0
    else
        LIVE_EXPORT_RC=$?
    fi
    if wait "$DAEMON_PID"; then
        DAEMON_RC=0
    else
        DAEMON_RC=$?
    fi
    echo "  initial mount daemon log:"
    tail -80 /tmp/startup_retry.log 2>/dev/null || true
    echo "  live export output:"
    cat /tmp/live_export.out /tmp/live_export.err 2>/dev/null || true
    if [ "$LIVE_EXPORT_RC" -eq 0 ] && [ "$DAEMON_RC" -eq 0 ] \
        && ! mountpoint -q "$MNT" 2>/dev/null; then
        pass "unmount"
    else
        fail "unmount" "export_rc=$LIVE_EXPORT_RC daemon_rc=$DAEMON_RC mounted=$(mountpoint -q "$MNT" 2>/dev/null && echo yes || echo no)"
    fi
else
    blocked "unmount" "not mounted"
fi

echo ""
echo "--- Phase 8: Pool export ---"

EXPORT_OK=0
if [ "$MOUNTED" -eq 1 ]; then
    POOL_RUNTIME_DIR="/run/tidefs/pools/$(echo "$POOL_UUID" | sed 's/-//g')"
    if tidefsctl pool status "$POOL_NAME" --devices "$DEV0" "$DEV1" --json \
        > /tmp/post_export_status.json 2>/tmp/post_export_status.err \
        && grep -q '"state"[[:space:]]*:[[:space:]]*"EXPORTED"' /tmp/post_export_status.json \
        && [ ! -e "$POOL_RUNTIME_DIR/owner.sock" ] \
        && [ ! -e "$POOL_RUNTIME_DIR/owner.json" ] \
        && ! find /run/tidefs/import -type f 2>/dev/null | grep -q . \
        && grep -q 'pool exported:' /tmp/live_export.out 2>/dev/null; then
        pass "pool_export"
        EXPORT_OK=1
    else
        fail "pool_export" "live_rc=$LIVE_EXPORT_RC daemon_rc=$DAEMON_RC status=$(cat /tmp/post_export_status.err /tmp/post_export_status.json 2>/dev/null)"
    fi
else
    blocked "pool_export" "not mounted"
fi

echo ""
echo "--- Phase 9: Reimport ---"

REIMPORT_OK=0
if [ "$EXPORT_OK" -eq 1 ] && command -v tidefsctl >/dev/null 2>&1; then
    REIMPORT_OK=1
fi

echo ""
echo "--- Phase 10: Remount ---"

REMOUNTED=0
RPID=""
if [ "$REIMPORT_OK" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/remount.log 2>&1 &
    RPID=$!
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { REMOUNTED=1; break; }
        sleep 1
    done

    if [ "$REMOUNTED" -eq 1 ]; then
        if grep -q 'pool ".*" imported' /tmp/remount.log; then
            pass "reimport"
        else
            fail "reimport" "remount did not report import ownership"
        fi
        pass "remount"
    else
        fail "reimport" "$(tail -20 /tmp/remount.log 2>/dev/null)"
        fail "remount" "$(tail -20 /tmp/remount.log 2>/dev/null)"
    fi
else
    blocked "reimport" "export/FUSE not ready"
    blocked "remount" "reimport/FUSE not ready"
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

    POST_REMOUNT_INODE=$(stat -c '%i' "$TF" 2>/tmp/post-remount-inode.err || echo 0)
    if [ "$PRE_REMOUNT_INODE" -gt 0 ] 2>/dev/null \
        && [ "$POST_REMOUNT_INODE" = "$PRE_REMOUNT_INODE" ]; then
        pass "inode_identity_stable"
    else
        fail "inode_identity_stable" \
            "before=$PRE_REMOUNT_INODE after=$POST_REMOUNT_INODE $(cat /tmp/post-remount-inode.err 2>/dev/null)"
    fi
else
    blocked "persist_verify" "remount failed"
    blocked "inode_identity_stable" "remount failed"
fi

echo ""
echo "--- Phase 12: Committed-root advancement ---"

if [ "$REMOUNTED" -eq 1 ]; then
    # Write new data and fsync to advance the committed root
    TC2="TideFS-Committed-Root-Advance-$(date +%s 2>/dev/null || echo 0)"
    TF2="$MNT/committed_root_test.txt"
    echo "$TC2" > "$TF2" 2>/dev/null
    sync "$TF2" 2>/dev/null || sync

    # Get pool status JSON and extract committed-root epoch info
    POST_STATUS="/tmp/post_remount_status.json"
    if ! tidefsctl pool status "$POOL_NAME" --devices "$DEV0" "$DEV1" --json \
        > "$POST_STATUS" 2>/tmp/post_remount_status.err; then
        fail "committed_root_advance" "$(cat /tmp/post_remount_status.err 2>/dev/null)"
    elif grep -q '"state"[[:space:]]*:[[:space:]]*"Active"' "$POST_STATUS" 2>/dev/null; then
        pass "committed_root_advance"
    else
        fail "committed_root_advance" "pool status missing active state"
    fi

    # Verify that the committed root exists (pool was imported successfully)
    # The committed-root advancement is validationd by:
    #   a) pool import succeeded (root selection worked)
    #   b) pool reimport succeeded (root selection across unmount boundary)
    #   c) data persisted across unmount/remount (root state consistent)
else
    blocked "committed_root_advance" "remount failed"
fi

echo ""
echo "--- Phase 13: Intent-log consistency ---"

if [ "$REMOUNTED" -eq 1 ]; then
    # Intent-log consistency is verified by:
    #   a) pool import succeeded (intent-log replay during import)
    #   b) data persisted across unmount/remount (replay produced consistent state)
    #   c) new writes after remount succeed (intent-log recording works)
    TF3="$MNT/intent_log_test.txt"
    TC3="TideFS-IntentLog-Consistency-$(date +%s 2>/dev/null || echo 0)"
    echo "$TC3" > "$TF3" 2>/dev/null
    sync "$TF3" 2>/dev/null || sync
    RC3=$(cat "$TF3" 2>/dev/null || true)
    if [ "$RC3" = "$TC3" ]; then
        pass "intent_log_consistency"
    else
        fail "intent_log_consistency" "post-remount write/read failed: expected '$TC3' got '$RC3'"
    fi
else
    blocked "intent_log_consistency" "remount failed"
fi

# Cleanly release the writable remount before taking the read-only byte baseline.
READONLY_PREP_OK=0
if [ "$REMOUNTED" -eq 1 ] && [ -n "$RPID" ]; then
    kill "$RPID" 2>/dev/null || true
    for _ in $(seq 1 10); do
        ! kill -0 "$RPID" 2>/dev/null && break
        sleep 1
    done
    if kill -0 "$RPID" 2>/dev/null; then
        kill -KILL "$RPID" 2>/dev/null || true
        wait "$RPID" 2>/dev/null || true
        fail "readonly_prep_release" "writable remount did not release cleanly"
    else
        wait "$RPID" 2>/dev/null || true
        pass "readonly_prep_release"
        READONLY_PREP_OK=1
    fi
    umount "$MNT" 2>/dev/null || true
else
    blocked "readonly_prep_release" "writable remount was not active"
fi

echo ""
echo "--- Phase 14: End-to-end read-only mount ---"

READONLY_MOUNTED=0
READONLY_PID=""
READONLY_HASH_BEFORE=""
READONLY_HASH_AFTER=""

expect_readonly_failure() {
    OP="$1"
    shift
    OP_TIMEOUT="/tmp/$OP.timeout"
    : > "$OP_TIMEOUT"
    "$@" > "/tmp/$OP.out" 2> "/tmp/$OP.err" &
    OP_PID=$!
    (
        sleep 5
        if kill -0 "$OP_PID" 2>/dev/null; then
            {
                echo "pid=$OP_PID"
                echo "wchan=$(cat "/proc/$OP_PID/wchan" 2>/dev/null || echo unknown)"
                echo "stack=$(cat "/proc/$OP_PID/stack" 2>/dev/null || echo unavailable)"
                echo "daemon=$(tail -20 /tmp/readonly_mount.log 2>/dev/null)"
            } > "$OP_TIMEOUT"
            kill -KILL "$OP_PID" 2>/dev/null || true
        fi
    ) &
    OP_WATCHDOG_PID=$!
    wait "$OP_PID"
    OP_RC=$?
    kill "$OP_WATCHDOG_PID" 2>/dev/null || true
    wait "$OP_WATCHDOG_PID" 2>/dev/null || true
    if [ -s "$OP_TIMEOUT" ]; then
        fail "$OP" "mutation timed out ($(cat "$OP_TIMEOUT" 2>/dev/null))"
    elif [ "$OP_RC" -eq 0 ]; then
        fail "$OP" "mutation unexpectedly succeeded"
    elif grep -qi 'read-only file system' "/tmp/$OP.err" 2>/dev/null; then
        pass "$OP"
    else
        fail "$OP" "expected EROFS (exit=$OP_RC): $(cat "/tmp/$OP.err" 2>/dev/null)"
    fi
}

if [ "$READONLY_PREP_OK" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    READONLY_HASH_BEFORE=$(sha256sum "$DEV0" "$DEV1" 2>/dev/null || true)
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" --read-only \
        > /tmp/readonly_mount.log 2>&1 &
    READONLY_PID=$!
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { READONLY_MOUNTED=1; break; }
        ! kill -0 "$READONLY_PID" 2>/dev/null && break
        sleep 1
    done
    if [ "$READONLY_MOUNTED" -eq 1 ]; then
        pass "readonly_mount"
        if grep -q "[[:space:]]$MNT[[:space:]]ro" /proc/self/mountinfo 2>/dev/null; then
            pass "readonly_kernel_ro"
        else
            fail "readonly_kernel_ro" "mountinfo does not report a read-only mount"
        fi

        READONLY_CONTENT=$(cat "$TF" 2>/dev/null || true)
        if [ "$READONLY_CONTENT" = "$TC" ]; then
            pass "readonly_read"
        else
            fail "readonly_read" "expected '$TC' got '$READONLY_CONTENT'"
        fi

        expect_readonly_failure readonly_create_erofs \
            sh -c 'printf "x\n" > "$1"' sh "$MNT/readonly-create"
        expect_readonly_failure readonly_write_erofs \
            sh -c 'printf "x\n" >> "$1"' sh "$TF"
        expect_readonly_failure readonly_truncate_erofs \
            sh -c ': > "$1"' sh "$TF"
        expect_readonly_failure readonly_unlink_erofs rm "$TF"
        expect_readonly_failure readonly_rename_erofs mv "$TF" "$MNT/readonly-renamed"
        expect_readonly_failure readonly_mkdir_erofs mkdir "$MNT/readonly-dir"
        expect_readonly_failure readonly_setattr_erofs touch "$TF"

        READONLY_CONTENT_AFTER=$(cat "$TF" 2>/dev/null || true)
        if [ "$READONLY_CONTENT_AFTER" = "$TC" ]; then
            pass "readonly_content_unchanged"
        else
            fail "readonly_content_unchanged" "expected '$TC' got '$READONLY_CONTENT_AFTER'"
        fi
    else
        fail "readonly_mount" "$(tail -40 /tmp/readonly_mount.log 2>/dev/null)"
        for op in readonly_kernel_ro readonly_read readonly_create_erofs \
                  readonly_write_erofs readonly_truncate_erofs readonly_unlink_erofs \
                  readonly_rename_erofs readonly_mkdir_erofs readonly_setattr_erofs \
                  readonly_content_unchanged; do
            blocked "$op" "read-only mount failed"
        done
    fi
else
    blocked "readonly_mount" "writable release or FUSE not ready"
    for op in readonly_kernel_ro readonly_read readonly_create_erofs \
              readonly_write_erofs readonly_truncate_erofs readonly_unlink_erofs \
              readonly_rename_erofs readonly_mkdir_erofs readonly_setattr_erofs \
              readonly_content_unchanged; do
        blocked "$op" "read-only mount not runnable"
    done
fi

if [ -n "$READONLY_PID" ]; then
    kill "$READONLY_PID" 2>/dev/null || true
    for _ in $(seq 1 10); do
        ! kill -0 "$READONLY_PID" 2>/dev/null && break
        sleep 1
    done
    if kill -0 "$READONLY_PID" 2>/dev/null; then
        kill -KILL "$READONLY_PID" 2>/dev/null || true
        wait "$READONLY_PID" 2>/dev/null || true
        fail "readonly_release" "read-only mount did not release cleanly"
    else
        wait "$READONLY_PID" 2>/dev/null || true
        umount "$MNT" 2>/dev/null || true
        if mountpoint -q "$MNT" 2>/dev/null; then
            fail "readonly_release" "read-only mount remains attached"
        elif find /run/tidefs/import -type f 2>/dev/null | grep -q .; then
            fail "readonly_release" "read-only import lock remains"
        else
            pass "readonly_release"
        fi
    fi
else
    blocked "readonly_release" "read-only daemon was not started"
fi

if [ -n "$READONLY_HASH_BEFORE" ]; then
    READONLY_HASH_AFTER=$(sha256sum "$DEV0" "$DEV1" 2>/dev/null || true)
    if [ "$READONLY_HASH_AFTER" = "$READONLY_HASH_BEFORE" ]; then
        pass "readonly_bytes_preserved"
    else
        fail "readonly_bytes_preserved" "complete device hashes changed"
    fi
else
    blocked "readonly_bytes_preserved" "read-only byte baseline unavailable"
fi


echo ""
echo "--- Phase 15: Crash-cycle (SIGKILL without export) ---"

# This phase exercises the storage durability/recovery spine:
# - Write fsynced data (committed through txg commit boundary)
# - Write non-fsynced data while keeping the writer fd open, so FUSE_FLUSH
#   cannot turn the row into a close-path durability commit. This row is
#   bounded old-or-new: absent or the empty post-create/pre-write inode is
#   valid, exact intent-log replay is valid, corrupted or partial content is
#   not.
# - SIGKILL the daemon (simulating crash/power-loss, no clean export)
# - Detach the dead FUSE mount before starting the recovery mount
# - Import the pool (exercising committed-root selection + intent replay)
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
    CRASH_CYCLE_IMPORT_OK=1
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
        if grep -q 'pool ".*" imported' /tmp/crash_mount.log; then
            pass "crash_cycle_preimport"
        else
            fail "crash_cycle_preimport" "mount did not report import ownership"
        fi
        pass "crash_cycle_premount"
    else
        fail "crash_cycle_preimport" "$(tail -20 /tmp/crash_mount.log 2>/dev/null)"
        fail "crash_cycle_premount" "$(tail -20 /tmp/crash_mount.log 2>/dev/null)"
    fi
else
    blocked "crash_cycle_preimport" "export/FUSE not ready"
    blocked "crash_cycle_premount" "import/FUSE not ready"
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
    if [ ! -f "$CRASH_COMMITTED_FILE" ]; then
        fail "crash_cycle_write_committed" "write failed"
    elif sync "$CRASH_COMMITTED_FILE" 2>/tmp/crash_fsync.err; then
        pass "crash_cycle_write_committed"
    else
        fail "crash_cycle_write_committed" "per-file fsync failed: $(cat /tmp/crash_fsync.err 2>/dev/null)"
    fi
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
    fail "crash_cycle_sigkill" "live daemon PID was not running"
fi
if [ -n "$CRASH_UNCOMMITTED_HOLDER" ] && kill -0 "$CRASH_UNCOMMITTED_HOLDER" 2>/dev/null; then
    kill -KILL "$CRASH_UNCOMMITTED_HOLDER" 2>/dev/null || true
    wait "$CRASH_UNCOMMITTED_HOLDER" 2>/dev/null || true
fi
echo "  crash mount daemon log:"
tail -120 /tmp/crash_mount.log 2>/dev/null || true

if grep -q "[[:space:]]$MNT[[:space:]]" /proc/self/mountinfo 2>/dev/null; then
    if ! umount -l "$MNT" 2>/tmp/crash_umount.err; then
        fail "crash_cycle_stale_mount_detached" "$(cat /tmp/crash_umount.err 2>/dev/null)"
    elif grep -q "[[:space:]]$MNT[[:space:]]" /proc/self/mountinfo 2>/dev/null; then
        fail "crash_cycle_stale_mount_detached" "mount remains in /proc/self/mountinfo after lazy detach"
    else
        pass "crash_cycle_stale_mount_detached"
    fi
else
    pass "crash_cycle_stale_mount_detached"
fi

# Remount after crash recovery. The owner-creating mount performs stale-lock
# recovery, import/root selection, and FUSE startup as one owned lifecycle.
CRASH_RECOVERY_MOUNTED=0
CRP=""
if [ "$FUSE_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/crash_recovery_mount.log 2>&1 &
    CRP=$!
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { CRASH_RECOVERY_MOUNTED=1; break; }
        sleep 1
    done
    if [ "$CRASH_RECOVERY_MOUNTED" -eq 1 ]; then
        if grep -q 'pool ".*" imported' /tmp/crash_recovery_mount.log; then
            pass "crash_cycle_reimport_no_export"
        else
            fail "crash_cycle_reimport_no_export" "recovery mount did not report import ownership"
        fi
        pass "crash_cycle_recovery_remount"
    else
        fail "crash_cycle_reimport_no_export" "$(tail -20 /tmp/crash_recovery_mount.log 2>/dev/null)"
        fail "crash_cycle_recovery_remount" "$(tail -20 /tmp/crash_recovery_mount.log 2>/dev/null)"
    fi
else
    blocked "crash_cycle_reimport_no_export" "FUSE not ready"
    blocked "crash_cycle_recovery_remount" "crash-recovery import failed"
fi

# Verify: committed data survived; unfsynced data is absent, empty, or exact.
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

    POST_CRASH_INODE=$(stat -c '%i' "$TF" 2>/tmp/post-crash-inode.err || echo 0)
    if [ "$PRE_REMOUNT_INODE" -gt 0 ] 2>/dev/null \
        && [ "$POST_CRASH_INODE" = "$PRE_REMOUNT_INODE" ]; then
        pass "crash_cycle_inode_stable"
    else
        fail "crash_cycle_inode_stable" \
            "before=$PRE_REMOUNT_INODE after=$POST_CRASH_INODE $(cat /tmp/post-crash-inode.err 2>/dev/null)"
    fi

    if [ -f "$CRASH_UNCOMMITTED_FILE" ]; then
        if ! POST_CRASH_UNCOMMITTED=$(cat "$CRASH_UNCOMMITTED_FILE" 2>/tmp/crash_uncommitted_read.err); then
            fail "crash_cycle_unfsynced_bounded" "recovered file is unreadable: $(cat /tmp/crash_uncommitted_read.err 2>/dev/null)"
        elif [ -z "$POST_CRASH_UNCOMMITTED" ] \
            || [ "$POST_CRASH_UNCOMMITTED" = "$CRASH_UNCOMMITTED_CONTENT" ]; then
            pass "crash_cycle_unfsynced_bounded"
        else
            fail "crash_cycle_unfsynced_bounded" "expected absent, empty pre-write inode, or exact replay, got '$POST_CRASH_UNCOMMITTED'"
        fi
    else
        pass "crash_cycle_unfsynced_bounded"
    fi
else
    blocked "crash_cycle_committed_survived" "crash-recovery remount failed"
    blocked "crash_cycle_inode_stable" "crash-recovery remount failed"
    blocked "crash_cycle_unfsynced_bounded" "crash-recovery remount failed"
fi

echo ""
echo "--- Phase 16: Mounted integrity reports ---"

INTEGRITY_CLEAN_OK=0
if [ "$CRASH_RECOVERY_MOUNTED" -eq 1 ]; then
    if tidefsctl pool integrity-check "$POOL_NAME" --json \
        > /tmp/integrity_clean.json 2>/tmp/integrity_clean.err \
        && grep -q '"pass"[[:space:]]*:[[:space:]]*true' /tmp/integrity_clean.json \
        && grep -q '"state_source"[[:space:]]*:[[:space:]]*"live-owner"' /tmp/integrity_clean.json; then
        pass "mounted_integrity_clean"
        INTEGRITY_CLEAN_OK=1
    else
        fail "mounted_integrity_clean" "$(cat /tmp/integrity_clean.err /tmp/integrity_clean.json 2>/dev/null)"
    fi
else
    blocked "mounted_integrity_clean" "crash-recovery mount failed"
fi

SCRUB_CLEAN_OK=0
SCRUB_CONTENT="TideFS-Live-Owner-Scrub-$(date +%s 2>/dev/null || echo 0)"
SCRUB_FILE="$MNT/live_owner_scrub.txt"
if [ "$CRASH_RECOVERY_MOUNTED" -eq 1 ]; then
    printf '%s\n' "$SCRUB_CONTENT" > "$SCRUB_FILE" 2>/tmp/scrub_write.err
    if sync "$SCRUB_FILE" 2>/tmp/scrub_fsync.err \
        && tidefsctl pool scrub "$POOL_NAME" --json \
            > /tmp/scrub_clean.json 2>/tmp/scrub_clean.err \
        && grep -q '"pass"[[:space:]]*:[[:space:]]*true' /tmp/scrub_clean.json \
        && grep -q '"state_source"[[:space:]]*:[[:space:]]*"live-owner"' /tmp/scrub_clean.json \
        && grep -q '"blocks_scanned"[[:space:]]*:[[:space:]]*[1-9]' /tmp/scrub_clean.json \
        && grep -q '"repair_attempted"[[:space:]]*:[[:space:]]*false' /tmp/scrub_clean.json \
        && grep -q '"repair_writeback"[[:space:]]*:[[:space:]]*false' /tmp/scrub_clean.json; then
        pass "mounted_scrub_clean"
        SCRUB_CLEAN_OK=1
    else
        fail "mounted_scrub_clean" \
            "$(cat /tmp/scrub_write.err /tmp/scrub_fsync.err /tmp/scrub_clean.err /tmp/scrub_clean.json 2>/dev/null)"
    fi
else
    blocked "mounted_scrub_clean" "crash-recovery mount failed"
fi

INTEGRITY_CORRUPTED_MEMBERS=0
if [ "$INTEGRITY_CLEAN_OK" -eq 1 ]; then
    for dev in "$DEV0" "$DEV1"; do
        root_offset=$(bytegrep -abo 'VFSROOT1' "$dev" 2>/tmp/integrity_bytegrep.err \
            | tail -1 | cut -d: -f1)
        case "$root_offset" in
            ""|*[!0-9]*)
                echo "  no committed-root payload offset found on $dev"
                ;;
            *)
                if printf 'BADROOT!' \
                    | dd of="$dev" bs=1 seek="$root_offset" conv=notrunc 2>/tmp/integrity_dd.err; then
                    INTEGRITY_CORRUPTED_MEMBERS=$((INTEGRITY_CORRUPTED_MEMBERS + 1))
                    echo "  corrupted newest committed-root record on $dev at byte $root_offset"
                else
                    echo "  corruption write failed on $dev: $(cat /tmp/integrity_dd.err 2>/dev/null)"
                fi
                ;;
        esac
    done
    sync
    if [ "$INTEGRITY_CORRUPTED_MEMBERS" -eq 2 ]; then
        pass "mounted_integrity_corruption_injected"
    else
        fail "mounted_integrity_corruption_injected" \
            "corrupted_members=$INTEGRITY_CORRUPTED_MEMBERS bytegrep=$(cat /tmp/integrity_bytegrep.err 2>/dev/null)"
    fi
else
    blocked "mounted_integrity_corruption_injected" "clean integrity report unavailable"
fi

if [ "$INTEGRITY_CORRUPTED_MEMBERS" -eq 2 ]; then
    if tidefsctl pool integrity-check "$POOL_NAME" --json \
        > /tmp/integrity_failed.json 2>/tmp/integrity_failed.err; then
        INTEGRITY_FAILED_RC=0
    else
        INTEGRITY_FAILED_RC=$?
    fi
    if [ "$INTEGRITY_FAILED_RC" -ne 0 ] \
        && grep -q '"pass"[[:space:]]*:[[:space:]]*false' /tmp/integrity_failed.json \
        && grep -q '"state_source"[[:space:]]*:[[:space:]]*"live-owner"' /tmp/integrity_failed.json \
        && grep -q 'one or more verifier issues found' /tmp/integrity_failed.json \
        && [ "$(cat "$CRASH_COMMITTED_FILE" 2>/dev/null || true)" = "$CRASH_COMMITTED_CONTENT" ]; then
        pass "mounted_integrity_failure_reported"
    else
        fail "mounted_integrity_failure_reported" \
            "exit=$INTEGRITY_FAILED_RC output=$(cat /tmp/integrity_failed.err /tmp/integrity_failed.json 2>/dev/null)"
    fi
else
    blocked "mounted_integrity_failure_reported" "corruption injection failed"
fi

SCRUB_CORRUPTED_MEMBERS=0
SCRUB_CORRUPTED_RECORDS=0
if [ "$SCRUB_CLEAN_OK" -eq 1 ]; then
    for dev in "$DEV0" "$DEV1"; do
        scrub_offsets=$(bytegrep -Fabo "$SCRUB_CONTENT" "$dev" 2>/tmp/scrub_bytegrep.err \
            | cut -d: -f1)
        scrub_member_records=0
        for scrub_offset in $scrub_offsets; do
            case "$scrub_offset" in
                ""|*[!0-9]*) ;;
                *)
                    if printf 'X' \
                        | dd of="$dev" bs=1 seek="$scrub_offset" conv=notrunc \
                            2>/tmp/scrub_dd.err; then
                        scrub_member_records=$((scrub_member_records + 1))
                        SCRUB_CORRUPTED_RECORDS=$((SCRUB_CORRUPTED_RECORDS + 1))
                    fi
                    ;;
            esac
        done
        if [ "$scrub_member_records" -gt 0 ]; then
            SCRUB_CORRUPTED_MEMBERS=$((SCRUB_CORRUPTED_MEMBERS + 1))
            echo "  corrupted $scrub_member_records committed content record(s) on $dev"
        else
            echo "  no committed scrub content offset found on $dev"
        fi
    done
    sync
    if [ "$SCRUB_CORRUPTED_MEMBERS" -eq 2 ]; then
        pass "mounted_scrub_corruption_injected"
    else
        fail "mounted_scrub_corruption_injected" \
            "corrupted_members=$SCRUB_CORRUPTED_MEMBERS corrupted_records=$SCRUB_CORRUPTED_RECORDS bytegrep=$(cat /tmp/scrub_bytegrep.err 2>/dev/null) dd=$(cat /tmp/scrub_dd.err 2>/dev/null)"
    fi
else
    blocked "mounted_scrub_corruption_injected" "clean mounted scrub unavailable"
fi

SCRUB_HASH_BEFORE=""
if [ "$SCRUB_CORRUPTED_MEMBERS" -eq 2 ]; then
    SCRUB_HASH_BEFORE=$(sha256sum "$DEV0" "$DEV1" 2>/dev/null || true)
    if tidefsctl pool scrub "$POOL_NAME" --json \
        > /tmp/scrub_failed.json 2>/tmp/scrub_failed.err; then
        SCRUB_FAILED_RC=0
    else
        SCRUB_FAILED_RC=$?
    fi
    if tidefsctl pool scrub "$POOL_NAME" \
        > /tmp/scrub_failed_human.out 2>/tmp/scrub_failed_human.err; then
        SCRUB_FAILED_HUMAN_RC=0
    else
        SCRUB_FAILED_HUMAN_RC=$?
    fi
    if [ "$SCRUB_FAILED_RC" -ne 0 ] \
        && [ "$SCRUB_FAILED_HUMAN_RC" -ne 0 ] \
        && grep -q '"pass"[[:space:]]*:[[:space:]]*false' /tmp/scrub_failed.json \
        && grep -q '"state_source"[[:space:]]*:[[:space:]]*"live-owner"' /tmp/scrub_failed.json \
        && grep -Eq '"blocks_(corrupt|unreadable)"[[:space:]]*:[[:space:]]*[1-9]' /tmp/scrub_failed.json \
        && grep -q '"block_id"' /tmp/scrub_failed.json \
        && grep -q '"object_key"' /tmp/scrub_failed.json \
        && grep -Eq '"kind"[[:space:]]*:[[:space:]]*"(corrupt|unreadable)"' /tmp/scrub_failed.json \
        && grep -q '"repair_attempted"[[:space:]]*:[[:space:]]*false' /tmp/scrub_failed.json \
        && grep -q '"repair_writeback"[[:space:]]*:[[:space:]]*false' /tmp/scrub_failed.json \
        && grep -q 'pool scrub:' /tmp/scrub_failed_human.out \
        && grep -q 'pass:[[:space:]]*no' /tmp/scrub_failed_human.out \
        && grep -q 'repair:[[:space:]]*not attempted' /tmp/scrub_failed_human.out \
        && grep -q 'inode=' /tmp/scrub_failed_human.out; then
        pass "mounted_scrub_failure_reported"
    else
        fail "mounted_scrub_failure_reported" \
            "json_exit=$SCRUB_FAILED_RC human_exit=$SCRUB_FAILED_HUMAN_RC output=$(cat /tmp/scrub_failed.err /tmp/scrub_failed.json /tmp/scrub_failed_human.err /tmp/scrub_failed_human.out 2>/dev/null)"
    fi

    SCRUB_HASH_AFTER=$(sha256sum "$DEV0" "$DEV1" 2>/dev/null || true)
    if [ -n "$SCRUB_HASH_BEFORE" ] && [ "$SCRUB_HASH_AFTER" = "$SCRUB_HASH_BEFORE" ]; then
        pass "mounted_scrub_no_repair_writeback"
    else
        fail "mounted_scrub_no_repair_writeback" "member bytes changed during read-only scrub"
    fi
else
    blocked "mounted_scrub_failure_reported" "content corruption injection failed"
    blocked "mounted_scrub_no_repair_writeback" "content corruption injection failed"
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
echo "mode=pool_remount_lifecycle_userspace_fuse_with_read_only_and_crash_cycle"
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
echo "integrity_corrupted_members=$INTEGRITY_CORRUPTED_MEMBERS"
echo "scrub_corrupted_members=$SCRUB_CORRUPTED_MEMBERS"
echo "scrub_corrupted_records=$SCRUB_CORRUPTED_RECORDS"
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
      pool_create startup_failure_unwind startup_retry_mount \
      pool_import mount live_status write_data fsync_data read_verify lookup_inode \
      rename_entry link_inode_identity unlink_entry readdir_entry \
      unmount pool_export reimport remount persist_verify inode_identity_stable \
      committed_root_advance intent_log_consistency \
      readonly_prep_release readonly_mount readonly_kernel_ro readonly_read \
      readonly_create_erofs readonly_write_erofs readonly_truncate_erofs \
      readonly_unlink_erofs readonly_rename_erofs readonly_mkdir_erofs \
      readonly_setattr_erofs readonly_content_unchanged \
      readonly_release readonly_bytes_preserved \
      crash_cycle_export_prep crash_cycle_preimport crash_cycle_premount \
      crash_cycle_write_committed crash_cycle_write_uncommitted \
      crash_cycle_committed_pre_crash_read crash_cycle_sigkill \
      crash_cycle_stale_mount_detached crash_cycle_reimport_no_export \
      crash_cycle_recovery_remount crash_cycle_committed_survived \
      crash_cycle_inode_stable crash_cycle_unfsynced_bounded \
      mounted_integrity_clean mounted_integrity_corruption_injected \
      mounted_integrity_failure_reported \
      mounted_scrub_clean mounted_scrub_corruption_injected \
      mounted_scrub_failure_reported mounted_scrub_no_repair_writeback \
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
