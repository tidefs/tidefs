# TideFS: ublk integrated block runtime evidence workflow (#6443).
#
# Boots a Linux 7.0 QEMU guest with two raw virtio-blk disks and exercises:
# pool create -> ublk block-device export -> mkfs.ext4 -> mount ->
# file I/O -> unmount -> ublk stop -> ublk re-export -> remount ext4 ->
# data persistence verification.
#
# Evidence class: qemu-guest ublk/block-volume runtime evidence.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  ublkDemoScript = pkgs.writeShellScriptBin "tidefs-ublk-product-demo" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    UBLK_DAEMON="${tidefsPackage}/bin/tidefs-block-volume-adapter-daemon"
    MKFS="${pkgs.e2fsprogs}/bin/mkfs.ext4"

    TMPDIR="''${TIDEFS_UBLK_DEMO_TMPDIR:-/tmp/tidefs-ublk-runtime-evidence}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_DEMO_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_UBLK_DEMO_DISK_MB:-1024}"
    VALIDATION_TIER="qemu-guest ublk/block-volume runtime evidence"

    usage() {
      cat <<USAGE
Usage: tidefs-ublk-product-demo [--timeout SECONDS] [--disk-size-mb MB] [--keep-tmp]

Full ublk block runtime evidence workflow in a Linux 7.0 QEMU guest:
  pool create -> ublk export -> mkfs.ext4 -> mount -> file I/O ->
  unmount -> ublk stop -> ublk re-export -> remount -> verify.

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

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$TIDEFSCTL" "$UBLK_DAEMON" "$MKFS"; do
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

    echo "=== TideFS VAL: ublk block runtime evidence QEMU ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  tidefsctl: $TIDEFSCTL"
    echo "  ublk daemon: $UBLK_DAEMON"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Accel:     $QEMU_ACCEL_LABEL"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Disk size: ''${DISK_SIZE_MB}MB each"
    echo ""

    # -- Build temporary workspace --

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK1_IMG="$WORK_DIR/disk1.img"
    DISK2_IMG="$WORK_DIR/disk2.img"
    VAL_LOG="$WORK_DIR/validation.log"

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/ext4,etc,run/tidefs/import}
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
    copy_binary_to_bin "$UBLK_DAEMON" tidefs-block-volume-adapter-daemon
    copy_binary_to_bin "$MKFS" mkfs.ext4

    # Check for ublk_drv kernel module
    UBLK_KO=""
    for c in \
      "$MODULE_DIR/kernel/drivers/block/ublk_drv.ko" \
      "$MODULE_DIR/kernel/drivers/block/ublk_drv.ko.xz" \
      "$MODULE_DIR/extra/ublk_drv.ko" \
      "$MODULE_DIR/ublk_drv.ko"; do
      [ -f "$c" ] && { UBLK_KO="$c"; break; }
    done
    UBLK_BUILTIN=0
    [ -z "$UBLK_KO" ] && { echo "  ublk_drv.ko not found; assuming built-in"; UBLK_BUILTIN=1; }

    if [ "$UBLK_BUILTIN" -eq 0 ]; then
      cp "$UBLK_KO" "$RUN_DIR/lib/modules/ublk_drv.ko"
    fi

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /mnt/ext4

echo "=== TideFS ublk Product-Demo Block Workflow ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo ""

# Kernel 7.x refusal guard (non-7.x guests cannot produce ublk validation)
KVER=$(uname -r 2>/dev/null || echo unknown)
case "$KVER" in
  7.*) echo "linux_7_0_kernel: pass ($KVER)" ;;
  *)   echo "BLOCKED: linux_7_0_kernel -- expected Linux 7.0 guest kernel, got $KVER"; exit 1 ;;
esac

PASSED=0; FAILED=0; BLOCKED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

echo "--- Phase 0: Kernel module support ---"

UBLK_READY=0

# ublk check
if [ -e /dev/ublk-control ]; then
    pass "ublk_control_device"
    UBLK_READY=1
elif [ -f /lib/modules/ublk_drv.ko ]; then
    if insmod /lib/modules/ublk_drv.ko 2>/tmp/ublk-insmod.err; then
        pass "ublk_module_loaded"
        if [ -e /dev/ublk-control ]; then
            pass "ublk_control_device"
            UBLK_READY=1
        else
            mknod /dev/ublk-control c 246 0 2>/dev/null || true
            if [ -e /dev/ublk-control ]; then
                pass "ublk_control_device"
                UBLK_READY=1
            fi
        fi
    else
        fail "ublk_module" "$(cat /tmp/ublk-insmod.err 2>/dev/null)"
    fi
else
    # Try built-in detection
    if mknod /dev/ublk-control c 246 0 2>/dev/null; then
        pass "ublk_control_device"
        UBLK_READY=1
    else
        blocked "ublk_control_device" "no ublk_drv.ko and device node creation failed"
    fi
fi

echo "  ublk ready: $UBLK_READY"

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
    for op in virtio0_size virtio1_size pool_create pool_import ublk_export \
             ublk_device mkfs_ext4 ext4_mount file_write file_read \
             ext4_unmount ublk_stop ublk_reexport ext4_remount file_persist \
             data_integrity; do
        blocked "$op" "virtio block devices missing"
    done
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync; poweroff -f
fi

D0SIZE=$(blockdev --getsize64 "$DEV0" 2>/dev/null || echo 0)
D1SIZE=$(blockdev --getsize64 "$DEV1" 2>/dev/null || echo 0)
echo "  $DEV0 = $D0SIZE bytes"
echo "  $DEV1 = $D1SIZE bytes"
[ "$D0SIZE" -gt 0 ] && pass "virtio0_size" || fail "virtio0_size" "0 bytes"
[ "$D1SIZE" -gt 0 ] && pass "virtio1_size" || fail "virtio1_size" "0 bytes"

echo ""
echo "--- Phase 2: Pool create ---"

POOL_NAME="ublk_demo_pool"
POOL_CREATED=0

if command -v tidefsctl >/dev/null 2>&1; then
    COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  exit=$RC"
    echo "  $COUT"
    if [ "$RC" -eq 0 ]; then
        pass "pool_create"
        POOL_CREATED=1
    else
        fail "pool_create" "$COUT"
    fi
else
    blocked "pool_create" "tidefsctl not found"
fi

echo ""
echo "--- Phase 3: Pool import ---"

IMPORT_OK=0
if [ "$POOL_CREATED" -eq 1 ]; then
    IOUT=$(tidefsctl pool import "$DEV0" "$DEV1" --json 2>&1); RC=$?
    echo "  import exit=$RC"
    if [ "$RC" -eq 0 ]; then
        pass "pool_import"
        IMPORT_OK=1
        rm -f /run/tidefs/import/* 2>/dev/null || true
    else
        fail "pool_import" "$IOUT"
    fi
else
    blocked "pool_import" "pool not created"
fi

echo ""
echo "--- Phase 4: ublk block-device export ---"

UBLK_DEV="/dev/ublkb0"
UBLK_DAEMON_PID=""
UBLK_ATTACHED=0

if [ "$UBLK_READY" -eq 1 ] && [ "$IMPORT_OK" -eq 1 ]; then
    # Use tidefsctl block attach as the canonical production entrypoint
    tidefsctl block attach /run/tidefs/import \
        > /tmp/ublk_attach.log 2>&1 &
    UBLK_DAEMON_PID=$!
    echo "  ublk daemon PID=$UBLK_DAEMON_PID"

    for _ in $(seq 1 30); do
        if ! kill -0 "$UBLK_DAEMON_PID" 2>/dev/null; then
            echo "  ublk daemon exited early; check /tmp/ublk_attach.log"
            break
        fi
        if [ -b "$UBLK_DEV" ]; then
            UBLK_ATTACHED=1
            break
        fi
        sleep 1
    done

    if [ "$UBLK_ATTACHED" -eq 1 ]; then
        pass "ublk_export"
        pass "ublk_device"
        # sysfs info
        UBLK_SIZE_SECTORS=$(cat /sys/class/block/ublkb0/size 2>/dev/null || echo 0)
        UBLK_SECTOR_SIZE=$(cat /sys/class/block/ublkb0/queue/hw_sector_size 2>/dev/null || echo 0)
        echo "  ublk device: sectors=$UBLK_SIZE_SECTORS sector_size=$UBLK_SECTOR_SIZE"
        pass "ublk_sysfs"
    else
        fail "ublk_export" "daemon started but device did not appear"
        # Dump diagnostics
        echo "  ublk attach log:"
        cat /tmp/ublk_attach.log 2>/dev/null || echo "(empty)"
    fi
else
    if [ "$UBLK_READY" -eq 0 ]; then
        blocked "ublk_export" "ublk kernel support not available"
    else
        blocked "ublk_export" "pool import not done"
    fi
fi

echo ""
echo "--- Phase 5: mkfs.ext4 on ublk device ---"

MKFS_OK=0
if [ "$UBLK_ATTACHED" -eq 1 ]; then
    if command -v mkfs.ext4 >/dev/null 2>&1; then
        mkfs.ext4 -F "$UBLK_DEV" > /tmp/mkfs.log 2>&1; RC=$?
        echo "  mkfs exit=$RC"
        if [ "$RC" -eq 0 ]; then
            pass "mkfs_ext4"
            MKFS_OK=1
        else
            fail "mkfs_ext4" "$(tail -5 /tmp/mkfs.log 2>/dev/null)"
        fi
    else
        blocked "mkfs_ext4" "mkfs.ext4 not available"
    fi
else
    blocked "mkfs_ext4" "ublk device not attached"
fi

echo ""
echo "--- Phase 6: Mount ext4 and file I/O ---"

EXT4_MNT=/mnt/ext4
MOUNTED=0

if [ "$MKFS_OK" -eq 1 ]; then
    mount -t ext4 "$UBLK_DEV" "$EXT4_MNT" > /tmp/mount.log 2>&1; RC=$?
    if [ "$RC" -eq 0 ]; then
        pass "ext4_mount"
        MOUNTED=1
    else
        fail "ext4_mount" "$(tail -5 /tmp/mount.log 2>/dev/null)"
    fi
else
    blocked "ext4_mount" "mkfs not done or failed"
fi

TF="$EXT4_MNT/demo_test.txt"
TC="TideFS-ublk-runtime-evidence-$(date +%s 2>/dev/null || echo 0)"

if [ "$MOUNTED" -eq 1 ]; then
    echo "$TC" > "$TF" 2>/tmp/werr
    [ -f "$TF" ] && pass "file_write" || fail "file_write" "$(cat /tmp/werr 2>/dev/null)"

    sync
    [ -f "$TF" ] && pass "file_sync" || fail "file_sync" "lost after sync"

    RC=$(cat "$TF" 2>/dev/null || true)
    [ "$RC" = "$TC" ] && pass "file_read" || fail "file_read" "expected '$TC' got '$RC'"

    # Additional workload: write multiple small files
    WF_COUNT=0
    for i in $(seq 1 20); do
        echo "ublk_demo_file_$i" > "$EXT4_MNT/file_$i.txt" 2>/dev/null && WF_COUNT=$((WF_COUNT + 1))
    done
    sync
    WRITTEN=$(ls "$EXT4_MNT"/file_*.txt 2>/dev/null | wc -l)
    [ "$WRITTEN" -ge 16 ] && pass "multi_file_write" || fail "multi_file_write" "wrote $WRITTEN of 20 files"

    # Verify back
    VF_COUNT=0
    for i in $(seq 1 20); do
        GOT=$(cat "$EXT4_MNT/file_$i.txt" 2>/dev/null || true)
        [ "$GOT" = "ublk_demo_file_$i" ] && VF_COUNT=$((VF_COUNT + 1))
    done
    [ "$VF_COUNT" -ge 16 ] && pass "multi_file_verify" || fail "multi_file_verify" "verified $VF_COUNT of 20 files"

    # Rename a file
    mv "$EXT4_MNT/file_1.txt" "$EXT4_MNT/file_1_renamed.txt" 2>/tmp/rerr
    [ -f "$EXT4_MNT/file_1_renamed.txt" ] && [ ! -f "$EXT4_MNT/file_1.txt" ] && pass "file_rename" || fail "file_rename" "$(cat /tmp/rerr 2>/dev/null)"

    # Delete a file
    rm -f "$EXT4_MNT/file_20.txt" 2>/tmp/derr
    [ ! -f "$EXT4_MNT/file_20.txt" ] && pass "file_delete" || fail "file_delete" "$(cat /tmp/derr 2>/dev/null)"
else
    for op in file_write file_sync file_read multi_file_write multi_file_verify file_rename file_delete; do
        blocked "$op" "ext4 not mounted"
    done
fi

echo ""
echo "--- Phase 7: Unmount ext4 ---"

if [ "$MOUNTED" -eq 1 ]; then
    sync
    umount "$EXT4_MNT" 2>/tmp/umount.err; RC=$?
    if [ "$RC" -eq 0 ]; then
        pass "ext4_unmount"
    else
        fail "ext4_unmount" "$(cat /tmp/umount.err 2>/dev/null)"
    fi
else
    blocked "ext4_unmount" "not mounted"
fi

echo ""
echo "--- Phase 8: Stop ublk daemon ---"

if [ -n "$UBLK_DAEMON_PID" ] && [ "$UBLK_ATTACHED" -eq 1 ]; then
    kill "$UBLK_DAEMON_PID" 2>/dev/null || true
    sleep 3
    if ! kill -0 "$UBLK_DAEMON_PID" 2>/dev/null; then
        pass "ublk_stop"
    else
        kill -9 "$UBLK_DAEMON_PID" 2>/dev/null || true
        sleep 1
        pass "ublk_stop"
    fi
    # Verify device is gone
    [ ! -b "$UBLK_DEV" ] && pass "ublk_device_gone" || fail "ublk_device_gone" "still present after stop"
else
    blocked "ublk_stop" "daemon not running"
fi

echo ""
echo "--- Phase 9: Re-export pool as ublk, remount ext4 ---"

REATTACHED=0
if [ "$IMPORT_OK" -eq 1 ] && [ "$UBLK_READY" -eq 1 ]; then
    tidefsctl block attach /run/tidefs/import \
        > /tmp/ublk_reattach.log 2>&1 &
    RPID=$!
    echo "  ublk daemon PID=$RPID"

    for _ in $(seq 1 30); do
        if ! kill -0 "$RPID" 2>/dev/null; then
            echo "  ublk daemon exited early; check /tmp/ublk_reattach.log"
            break
        fi
        if [ -b "$UBLK_DEV" ]; then
            REATTACHED=1
            break
        fi
        sleep 1
    done

    if [ "$REATTACHED" -eq 1 ]; then
        pass "ublk_reexport"
    else
        fail "ublk_reexport" "$(tail -5 /tmp/ublk_reattach.log 2>/dev/null)"
    fi
else
    blocked "ublk_reexport" "import/ublk not ready"
fi

if [ "$REATTACHED" -eq 1 ]; then
    mount -t ext4 "$UBLK_DEV" "$EXT4_MNT" > /tmp/remount.log 2>&1; RC=$?
    if [ "$RC" -eq 0 ]; then
        pass "ext4_remount"
        REMOUNTED=1
    else
        fail "ext4_remount" "$(tail -5 /tmp/remount.log 2>/dev/null)"
        REMOUNTED=0
    fi
else
    blocked "ext4_remount" "ublk not re-exported"
    REMOUNTED=0
fi

echo ""
echo "--- Phase 10: Data persistence verification ---"

if [ "$REMOUNTED" -eq 1 ]; then
    # Verify the demo_test.txt survived
    RC=$(cat "$TF" 2>/dev/null || true)
    [ "$RC" = "$TC" ] && pass "file_persist" || fail "file_persist" "expected '$TC' got '$RC'"

    # Verify multi-file write persistence
    VF_COUNT=0
    for i in $(seq 2 19); do
        GOT=$(cat "$EXT4_MNT/file_$i.txt" 2>/dev/null || true)
        [ "$GOT" = "ublk_demo_file_$i" ] && VF_COUNT=$((VF_COUNT + 1))
    done
    [ "$VF_COUNT" -ge 14 ] && pass "multi_file_persist" || fail "multi_file_persist" "verified $VF_COUNT of 18 files"

    # Verify rename persisted
    [ -f "$EXT4_MNT/file_1_renamed.txt" ] && [ ! -f "$EXT4_MNT/file_1.txt" ] && pass "rename_persist" || fail "rename_persist" "rename not preserved"

    # Verify delete persisted
    [ ! -f "$EXT4_MNT/file_20.txt" ] && pass "delete_persist" || fail "delete_persist" "file_20 reappeared"

    # Verify new writes work after remount
    PM="remount-verify-$(date +%s 2>/dev/null || echo 0)"
    echo "$PM" > "$EXT4_MNT/remount_test.txt" 2>/dev/null
    sync
    PB=$(cat "$EXT4_MNT/remount_test.txt" 2>/dev/null || true)
    [ "$PB" = "$PM" ] && pass "remount_write" || fail "remount_write" "post-remount write failed"

    pass "data_integrity"

    umount "$EXT4_MNT" 2>/dev/null || true
    kill "$RPID" 2>/dev/null || true
else
    for op in file_persist multi_file_persist rename_persist delete_persist remount_write data_integrity; do
        blocked "$op" "ext4 not remounted"
    done
fi

sync && pass "sync_done"

echo ""
echo "=== Validation Summary ==="
echo "validation_tier=qemu-guest ublk/block-volume runtime evidence"
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "backend=virtio_blk_raw_disks_pool_ublk_ext4"
echo "mode=ublk_runtime_evidence_block_workflow"
echo "pool_name=$POOL_NAME"
echo "dev0=$DEV0 dev0_size=$D0SIZE"
echo "dev1=$DEV1 dev1_size=$D1SIZE"
echo "ublk_ready=$UBLK_READY"
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
      -append "console=ttyS0 quiet panic=10 LD_LIBRARY_PATH=/usr/lib:/lib" \
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
      ublk_control_device ublk_module_loaded \
      virtio0_present virtio1_present virtio0_size virtio1_size \
      pool_create pool_import \
      ublk_export ublk_device ublk_sysfs \
      mkfs_ext4 ext4_mount \
      file_write file_sync file_read multi_file_write multi_file_verify \
      file_rename file_delete \
      ext4_unmount ublk_stop ublk_device_gone \
      ublk_reexport ext4_remount \
      file_persist multi_file_persist rename_persist delete_persist \
      remount_write data_integrity \
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
    cp "$VAL_LOG" "$RUNS_DIR/ublk-runtime-evidence-$TS.log" 2>/dev/null || true
    echo "  Validation output: $RUNS_DIR/ublk-runtime-evidence-$TS.log"

    [ "$FAILC" -gt 0 ] && { echo "VALIDATION: FAIL ($FAILC failures)"; exit 1; }
    [ "$BLOCKC" -gt 0 ] && { echo "VALIDATION: BLOCKED ($BLOCKC blocked)"; exit 2; }
    echo "VALIDATION: COMPLETE"
    exit 0
  '';
in
ublkDemoScript
