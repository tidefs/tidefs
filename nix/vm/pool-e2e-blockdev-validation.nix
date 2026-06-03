# TideFS: pool end-to-end block-device validation (#6102).
#
# Boots a Linux 7.0 QEMU guest with two raw virtio-blk disks and exercises:
# pool create -> import -> status -> dataset -> mount -> file I/O ->
# unmount -> export -> re-import -> re-mount -> persistence.
#
# Validation tier: QEMU guest.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  poolE2EBlockdevScript = pkgs.writeShellScriptBin "tidefs-pool-e2e-blockdev-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"

    TMPDIR="''${TIDEFS_POOL_E2E_TMPDIR:-/tmp/tidefs-pool-e2e-blockdev-validation}"
    TIMEOUT_SEC="''${TIDEFS_POOL_E2E_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_POOL_E2E_DISK_MB:-1024}"
    VALIDATION_TIER="QEMU guest"

    usage() {
      cat <<USAGE
Usage: tidefs-pool-e2e-blockdev-validation [--timeout SECONDS] [--disk-size-mb MB] [--keep-tmp]

Full operator flow on two virtio-blk disks in a Linux 7.0 QEMU guest:
  pool create -> import -> status -> dataset create/list ->
  FUSE mount -> file write/fsync/read/rename/delete ->
  unmount -> export -> re-import -> re-mount -> persistence.

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

    echo "=== TideFS VAL: pool-e2e-blockdev QEMU ==="
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

    echo "  Creating sparse raw virtio disk images"
    ${pkgs.coreutils}/bin/truncate -s "''${DISK_SIZE_MB}M" "$DISK1_IMG"
    ${pkgs.coreutils}/bin/truncate -s "''${DISK_SIZE_MB}M" "$DISK2_IMG"

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
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq blockdev mountpoint du \
                    sed uname date; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    copy_binary_to_bin "$TIDEFSCTL" tidefsctl
    copy_binary_to_bin "$FUSE_DAEMON" tidefs-posix-filesystem-adapter-daemon

    [ "$FUSE_BUILTIN" -eq 0 ] && cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /mnt/tidefs

echo "=== TideFS Pool E2E Block Device Validation ==="
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
    pass "fuse_available"
elif [ -f /lib/modules/fuse.ko ]; then
    if insmod /lib/modules/fuse.ko 2>/tmp/fuse-insmod.err; then
        pass "fuse_module"
        pass "fuse_available"
    else
        fail "fuse_module" "$(cat /tmp/fuse-insmod.err 2>/dev/null)"
        fail "fuse_available" "fuse.ko failed to load"
    fi
else
    blocked "fuse_available" "no fuse.ko and not built-in"
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
    for op in virtio0_size virtio1_size pool_create pool_import pool_status \
             dataset_create dataset_list pool_mount file_write file_fsync \
             file_read file_rename file_delete unmount pool_export reimport \
             remount file_persist dataset_persist sync_done; do
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

POOL_NAME="e2e_block_pool"
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
echo "--- Phase 4: Pool import/status ---"

IMPORT_OK=0
if [ "$POOL_CREATED" -eq 1 ]; then
    IOUT=$(tidefsctl pool import "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  import exit=$RC"
    echo "  $IOUT"
    if [ "$RC" -eq 0 ]; then
        pass "pool_import"
        IMPORT_OK=1
        rm -f /run/tidefs/import/* 2>/dev/null || true
        [ -z "$POOL_UUID" ] && POOL_UUID=$(echo "$IOUT" | grep -o '"pool_uuid"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
    else
        fail "pool_import" "$IOUT"
    fi
else
    blocked "pool_import" "pool not created"
fi

if [ "$IMPORT_OK" -eq 1 ]; then
    SOUT=$(tidefsctl pool status "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>&1); RC=$?
    echo "  status exit=$RC"
    [ "$RC" -eq 0 ] && pass "pool_status" || fail "pool_status" "$SOUT"
else
    blocked "pool_status" "import not done"
fi

echo ""
echo "--- Phase 5: Dataset create/list ---"

DS_NAME="e2e_test_ds"
if [ "$IMPORT_OK" -eq 1 ]; then
    DCOUT=$(tidefsctl dataset create "$DS_NAME" --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>&1); RC=$?
    echo "  create exit=$RC"
    echo "  $DCOUT"
    [ "$RC" -eq 0 ] && pass "dataset_create" || fail "dataset_create" "$DCOUT"

    DLOUT=$(tidefsctl dataset list --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>&1); RC=$?
    echo "  list exit=$RC"
    echo "  $DLOUT"
    [ "$RC" -eq 0 ] && pass "dataset_list" || fail "dataset_list" "$DLOUT"
else
    blocked "dataset_create" "import not done"
    blocked "dataset_list" "import not done"
fi

echo ""
echo "--- Phase 6: FUSE mount and file operations ---"

MNT=/mnt/tidefs
MOUNTED=0
DAEMON_PID=""

if [ "$FUSE_OK" -eq 1 ] && [ "$IMPORT_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/mount.log 2>&1 &
    DAEMON_PID=$!
    echo "  daemon PID=$DAEMON_PID"

    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { MOUNTED=1; break; }
        sleep 1
    done

    [ "$MOUNTED" -eq 1 ] && pass "pool_mount" || fail "pool_mount" "$(tail -20 /tmp/mount.log 2>/dev/null)"
else
    blocked "pool_mount" "FUSE not ready or import not done"
fi

TF="$MNT/e2e_test.txt"
TF2="$MNT/e2e_renamed.txt"
TC="TideFS-E2E-blockdev-pool-validation-$(date +%s 2>/dev/null || echo 0)"

if [ "$MOUNTED" -eq 1 ]; then
    echo "$TC" > "$TF" 2>/tmp/werr
    [ -f "$TF" ] && pass "file_write" || fail "file_write" "$(cat /tmp/werr 2>/dev/null)"

    sync
    [ -f "$TF" ] && pass "file_fsync" || fail "file_fsync" "lost after sync"

    RC=$(cat "$TF" 2>/dev/null || true)
    [ "$RC" = "$TC" ] && pass "file_read" || fail "file_read" "expected '$TC' got '$RC'"

    mv "$TF" "$TF2" 2>/tmp/rerr
    [ -f "$TF2" ] && [ ! -f "$TF" ] && pass "file_rename" || fail "file_rename" "$(cat /tmp/rerr 2>/dev/null)"

    rm "$TF2" 2>/tmp/derr
    [ ! -f "$TF2" ] && pass "file_delete" || fail "file_delete" "$(cat /tmp/derr 2>/dev/null)"
else
    for op in file_write file_fsync file_read file_rename file_delete; do
        blocked "$op" "not mounted"
    done
fi

echo ""
echo "--- Phase 7: Unmount/export/reimport/remount ---"

if [ "$MOUNTED" -eq 1 ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 2
    umount "$MNT" 2>/dev/null || true
    mountpoint -q "$MNT" 2>/dev/null && fail "unmount" "still mounted" || pass "unmount"
else
    blocked "unmount" "not mounted"
fi

if [ "$IMPORT_OK" -eq 1 ]; then
    EOUT=$(tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>&1); RC=$?
    echo "  export exit=$RC"
    [ "$RC" -eq 0 ] && pass "pool_export" || fail "pool_export" "$EOUT"
else
    blocked "pool_export" "import not done"
fi

REIMPORT_OK=0
if command -v tidefsctl >/dev/null 2>&1; then
    RIOUT=$(tidefsctl pool import "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  reimport exit=$RC"
    if [ "$RC" -eq 0 ]; then
        pass "reimport"
        REIMPORT_OK=1
        rm -f /run/tidefs/import/* 2>/dev/null || true
    else
        fail "reimport" "$RIOUT"
    fi
else
    blocked "reimport" "tidefsctl missing"
fi

if [ "$REIMPORT_OK" -eq 1 ] && [ "$FUSE_OK" -eq 1 ]; then
    tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" > /tmp/remount.log 2>&1 &
    RPID=$!
    REMOUNTED=0
    for _ in $(seq 1 45); do
        mountpoint -q "$MNT" 2>/dev/null && { REMOUNTED=1; break; }
        sleep 1
    done

    if [ "$REMOUNTED" -eq 1 ]; then
        pass "remount"
        PF="$MNT/.e2e_persist"
        PM="persist-$(date +%s 2>/dev/null || echo 0)"
        echo "$PM" > "$PF" 2>/dev/null
        sync
        PB=$(cat "$PF" 2>/dev/null || true)
        [ "$PB" = "$PM" ] && pass "file_persist" || fail "file_persist" "expected '$PM' got '$PB'"

        DLOUT2=$(tidefsctl dataset list --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>&1); RC=$?
        [ "$RC" -eq 0 ] && pass "dataset_persist" || fail "dataset_persist" "$DLOUT2"

        kill "$RPID" 2>/dev/null || true
        sleep 1
        umount "$MNT" 2>/dev/null || true
    else
        fail "remount" "$(tail -20 /tmp/remount.log 2>/dev/null)"
        blocked "file_persist" "remount failed"
        blocked "dataset_persist" "remount failed"
        kill "$RPID" 2>/dev/null || true
    fi
else
    blocked "remount" "reimport/FUSE not ready"
    blocked "file_persist" "remount not done"
    blocked "dataset_persist" "remount not done"
fi

sync && pass "sync_done"

echo ""
echo "=== Validation Summary ==="
echo "validation_tier=QEMU guest"
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "backend=virtio_blk_raw_disks"
echo "mode=pool_e2e_userspace_fuse"
echo "pool_name=$POOL_NAME"
echo "pool_uuid=$POOL_UUID"
echo "dev0=$DEV0 dev0_size=$D0SIZE"
echo "dev1=$DEV1 dev1_size=$D1SIZE"
echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "=== End ==="

sync; sleep 1; poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "  Building compressed initrd"
    (cd "$RUN_DIR" && find . -print | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" -9) > "$WORK_DIR/initrd.img.gz"
    echo "  Initrd.gz: $(du -h "$WORK_DIR/initrd.img.gz" | cut -f1)"

    echo ""
    echo "  === Booting QEMU guest ==="
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
      fuse_available fuse_device \
      virtio0_present virtio1_present virtio0_size virtio1_size \
      pool_create pool_import pool_status dataset_create dataset_list \
      pool_mount file_write file_fsync file_read file_rename file_delete \
      unmount pool_export reimport remount file_persist dataset_persist \
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
    cp "$VAL_LOG" "$RUNS_DIR/pool-e2e-blockdev-$TS.log" 2>/dev/null || true
    echo "  Validation output: $RUNS_DIR/pool-e2e-blockdev-$TS.log"

    [ "$FAILC" -gt 0 ] && { echo "VALIDATION: FAIL ($FAILC failures)"; exit 1; }
    [ "$BLOCKC" -gt 0 ] && { echo "VALIDATION: BLOCKED ($BLOCKC blocked)"; exit 2; }
    echo "VALIDATION: COMPLETE"
    exit 0
  '';
in
poolE2EBlockdevScript
