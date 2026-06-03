# TideFS: FUSE long-haul product demo soak validation.
#
# Boots a Linux 7.0 QEMU guest, creates a TideFS pool, mounts via FUSE, runs
# sustained create/write/read/snapshot/recovery workload cycles, and produces
# tier-classified validation rows.
#
# Validation tier: Tier 3 mounted userspace/QEMU FUSE runtime.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  fuseProductDemoSoakScript = pkgs.writeShellScriptBin "tidefs-fuse-product-demo-soak" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"

    TMPDIR="''${TIDEFS_FUSE_DEMO_SOAK_TMPDIR:-/tmp/tidefs-fuse-product-demo-soak}"
    TIMEOUT_SEC="''${TIDEFS_FUSE_DEMO_SOAK_TIMEOUT:-3600}"
    SOAK_CYCLES="''${TIDEFS_FUSE_DEMO_SOAK_CYCLES:-20}"
    DISK_SIZE_MB="''${TIDEFS_FUSE_DEMO_SOAK_DISK_MB:-1024}"

    KEEP_TMP=0
    JSON_OUT=""

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --cycles) SOAK_CYCLES="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --output) JSON_OUT="$2"; shift 2 ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    if [ ! -x "$LDD_BIN" ]; then
      LDD_BIN="$(command -v ldd || true)"
    fi
    if [ -z "$LDD_BIN" ] || [ ! -x "$LDD_BIN" ]; then
      echo "ERROR: ldd not available for initrd dependency discovery" >&2
      exit 2
    fi

    QEMU_ACCEL="tcg"
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL="kvm:tcg"
    else
      echo "  /dev/kvm not available; falling back to QEMU TCG"
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$FUSE_DAEMON" "$TIDEFSCTL"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    echo "=== TideFS FUSE Product Demo Soak ==="
    echo "  Kernel:     $KERNEL_IMG"
    echo "  Cycles:     $SOAK_CYCLES"
    echo "  Timeout:    ''${TIMEOUT_SEC}s"
    echo "  Disk size:  ''${DISK_SIZE_MB}M x2"
    echo "  QEMU accel: $QEMU_ACCEL"

    # Resolve fuse.ko
    FUSE_KO=""
    for candidate in \
      "$MODULE_DIR/kernel/fs/fuse/fuse.ko" \
      "$MODULE_DIR/kernel/fs/fuse/fuse.ko.xz" \
      "$MODULE_DIR/extra/fuse.ko" \
      "$MODULE_DIR/fuse.ko"; do
      if [ -f "$candidate" ]; then
        FUSE_KO="$candidate"
        break
      fi
    done

    FUSE_BUILTIN=0
    if [ -z "$FUSE_KO" ]; then
      FUSE_BUILTIN=1
    fi

    # Set up temp directory
    WORK_DIR="$TMPDIR/soak-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK0_IMG="$WORK_DIR/disk0.img"
    DISK1_IMG="$WORK_DIR/disk1.img"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,store,usr/lib}
    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping temp directory: $WORK_DIR"
      else
        rm -rf "$WORK_DIR"
      fi
    }
    trap cleanup EXIT

    echo "  Creating raw virtio disk images..."
    truncate -s "''${DISK_SIZE_MB}M" "$DISK0_IMG"
    truncate -s "''${DISK_SIZE_MB}M" "$DISK1_IMG"

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq du dirname basename \
                    readlink tr cmp diff mountpoint umount uname date awk blockdev; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$FUSE_DAEMON" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
    chmod +x "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"

    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"

    echo "  Copying exact Nix store runtime dependencies..."
    DEPS=$("$LDD_BIN" "$BUSYBOX" "$FUSE_DAEMON" "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
    for lib in $DEPS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        mkdir -p "$RUN_DIR$lib_dir"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
      fi
    done

    # Nix-built ELF binaries embed the dynamic linker as an absolute
    # /nix/store path. Copy that exact path, including BusyBox's interpreter,
    # otherwise the kernel reports /init as ENOENT before the script runs.
    for binary in "$BUSYBOX" "$FUSE_DAEMON" "$TIDEFSCTL"; do
      LD_SO=$("$LDD_BIN" "$binary" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
      if [ -n "$LD_SO" ] && [ -f "$LD_SO" ]; then
        LD_DIR=$(dirname "$LD_SO")
        mkdir -p "$RUN_DIR$LD_DIR"
        cp "$LD_SO" "$RUN_DIR$LD_SO" 2>/dev/null || true
        chmod +x "$RUN_DIR$LD_SO" 2>/dev/null || true
      fi
    done

    if [ "$FUSE_BUILTIN" -eq 0 ]; then
      cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"
    fi

    # Init script
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS FUSE Product Demo Soak ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "soak_cycles=__SOAK_CYCLES__"

PASSED=0
FAILED=0
BLOCKED=0

pass()    {
    if [ "$#" -gt 1 ] && [ -n "$2" ]; then
        echo "PASS: $1 -- $2"
    else
        echo "PASS: $1"
    fi
    PASSED=$((PASSED + 1))
}
fail()    { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

MNT=/mnt/tidefs
POOL_NAME=demo_pool
DEV0=/dev/vda
DEV1=/dev/vdb
SOAK_N=__SOAK_CYCLES__

snapshot_count() {
    /bin/tidefsctl snapshot list --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>/dev/null | grep -c "soak-snap-" || true
}

# Phase 0: FUSE kernel module
FUSE_READY=0
if [ -f /lib/modules/fuse.ko ]; then
    if insmod /lib/modules/fuse.ko 2>/tmp/fuse_insmod.err; then
        pass "fuse_module_load"
        FUSE_READY=1
    else
        fail "fuse_module_load" "$(cat /tmp/fuse_insmod.err)"
    fi
elif grep -q fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_builtin"
    FUSE_READY=1
else
    blocked "fuse_module_load" "fuse.ko not found and FUSE not built-in"
fi

if [ ! -e /dev/fuse ]; then
    mknod /dev/fuse c 10 229 2>/dev/null || true
fi

if [ -e /dev/fuse ]; then
    pass "fuse_device"
else
    blocked "fuse_device" "/dev/fuse not available"
    FUSE_READY=0
fi

# Phase 1: pool create and FUSE mount through real guest block devices
DAEMON_PID=""
MOUNTED=0
POOL_CREATED=0

if [ "$FUSE_READY" -eq 1 ]; then
    mkdir -p "$MNT" /run/tidefs/import

    DEVICES_READY=0
    for i in $(seq 1 30); do
        if [ -b "$DEV0" ] && [ -b "$DEV1" ]; then
            DEVICES_READY=1
            break
        fi
        sleep 1
    done

    if [ "$DEVICES_READY" -eq 1 ]; then
        pass "virtio_block_devices"
        echo "  $DEV0 size=$(blockdev --getsize64 "$DEV0" 2>/dev/null || echo 0)"
        echo "  $DEV1 size=$(blockdev --getsize64 "$DEV1" 2>/dev/null || echo 0)"
    else
        fail "virtio_block_devices" "$DEV0/$DEV1 did not appear"
    fi

    if [ "$DEVICES_READY" -eq 1 ] && /bin/tidefsctl pool create "$POOL_NAME" --devices "$DEV0" "$DEV1" --json > /tmp/pool_create.log 2>&1; then
        pass "pool_create"
        POOL_CREATED=1
    else
        fail "pool_create" "$(tail -5 /tmp/pool_create.log 2>/dev/null)"
    fi

    if [ "$POOL_CREATED" -eq 1 ]; then
        /bin/tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" \
            > /tmp/daemon.log 2>&1 &
        DAEMON_PID=$!

        for i in $(seq 1 45); do
            if grep -q " $MNT " /proc/mounts 2>/dev/null; then
                MOUNTED=1
                break
            fi
            sleep 1
        done

        if [ "$MOUNTED" -eq 1 ]; then
            pass "fuse_mount"
        else
            fail "fuse_mount" "mount did not appear in /proc/mounts within 45s (daemon log: $(tail -20 /tmp/daemon.log 2>/dev/null))"
        fi
    else
        blocked "fuse_mount" "pool not created"
    fi
else
    blocked "pool_create" "FUSE device not available"
    blocked "fuse_mount" "FUSE device not available"
fi

# Phase 2: Product demo soak cycles
CYCLE_PASS=0
CYCLE_FAIL=0
SNAPSHOT_PASS=0
SNAPSHOT_BLOCK=0
RECOVERY_PASS=0

if [ "$MOUNTED" -eq 1 ]; then
    cycle=1
    while [ "$cycle" -le "$SOAK_N" ]; do
        echo "--- Cycle $cycle/$SOAK_N ---"

        CYCLE_OK=1
        CYCLE_DIR="$MNT/cycle-$cycle"
        mkdir -p "$CYCLE_DIR" 2>/dev/null || { fail "mkdir_cycle" "cycle $cycle: mkdir failed"; cycle=$((cycle+1)); continue; }

        # Sub-phase A: File create write verify
        WRITE_OK=1
        i=1
        while [ "$i" -le 5 ]; do
            FILE="$CYCLE_DIR/file_$i.txt"
            DATA="cycle-$cycle-file-$i-data-$(date +%s)"
            echo "$DATA" > "$FILE" 2>/tmp/werr || { WRITE_OK=0; fail "file_write" "cycle $cycle file $i: $(cat /tmp/werr)"; break; }
            i=$((i + 1))
        done
        sync

        if [ "$WRITE_OK" -eq 1 ]; then
            pass "cycle_write" "$cycle"

            READ_OK=1
            i=1
            while [ "$i" -le 5 ]; do
                FILE="$CYCLE_DIR/file_$i.txt"
                if [ -f "$FILE" ]; then
                    GOT=$(cat "$FILE" 2>/dev/null || echo "READ_FAIL")
                    if ! echo "$GOT" | grep -q "cycle-$cycle-file-$i"; then
                        READ_OK=0
                        fail "file_read" "cycle $cycle file $i: mismatch got=$GOT"
                        break
                    fi
                else
                    READ_OK=0
                    fail "file_read" "cycle $cycle file $i: file missing after write"
                    break
                fi
                i=$((i + 1))
            done

            if [ "$READ_OK" -eq 1 ]; then
                pass "cycle_read" "$cycle"
            fi
        else
            CYCLE_OK=0
        fi

        # Sub-phase B: Directory operations
        SUB_DIR="$CYCLE_DIR/subdir"
        if mkdir "$SUB_DIR" 2>/dev/null; then
            echo "nested-data-$cycle" > "$SUB_DIR/nested.txt" 2>/dev/null
            NESTED=$(cat "$SUB_DIR/nested.txt" 2>/dev/null || echo "")
            if [ "$NESTED" = "nested-data-$cycle" ]; then
                pass "dir_nested" "$cycle"
            else
                fail "dir_nested" "cycle $cycle: nested read mismatch got=$NESTED"
                CYCLE_OK=0
            fi
        else
            fail "dir_nested" "cycle $cycle: subdir mkdir failed"
            CYCLE_OK=0
        fi

        # Sub-phase C: Rename within cycle
        if mv "$CYCLE_DIR/file_1.txt" "$CYCLE_DIR/renamed_1.txt" 2>/dev/null; then
            if [ -f "$CYCLE_DIR/renamed_1.txt" ] && [ ! -f "$CYCLE_DIR/file_1.txt" ]; then
                pass "cycle_rename" "$cycle"
            else
                fail "rename" "cycle $cycle: rename state inconsistent"
                CYCLE_OK=0
            fi
        else
            fail "rename" "cycle $cycle: mv failed"
            CYCLE_OK=0
        fi

        # Sub-phase D: Unlink a file
        if [ -f "$CYCLE_DIR/file_5.txt" ]; then
            rm "$CYCLE_DIR/file_5.txt" 2>/dev/null
            if [ ! -f "$CYCLE_DIR/file_5.txt" ]; then
                pass "cycle_unlink" "$cycle"
            else
                fail "unlink" "cycle $cycle: file still present after rm"
                CYCLE_OK=0
            fi
        fi

        # Sub-phase E: Snapshot every 5 cycles through a single-writer control window
        REM5=$((cycle % 5))
        if [ "$REM5" -eq 0 ]; then
            SNAP_NAME="soak-snap-$cycle"
            if ! /bin/tidefsctl snapshot create --help 2>&1 | grep -q -- '--pool'; then
                blocked "snapshot_create" "tidefsctl snapshot lacks --pool/--devices support for block-device pools"
                SNAPSHOT_BLOCK=$((SNAPSHOT_BLOCK + 1))
                CYCLE_OK=0
            else
                sync
                if umount "$MNT" 2>/tmp/snap_um.err; then
                    pass "snapshot_unmount" "$cycle"
                else
                    fail "snapshot_unmount" "cycle $cycle: $(cat /tmp/snap_um.err)"
                    CYCLE_OK=0
                fi

                if [ -n "$DAEMON_PID" ]; then
                    kill "$DAEMON_PID" 2>/dev/null || true
                    sleep 2
                    kill -9 "$DAEMON_PID" 2>/dev/null || true
                    DAEMON_PID=""
                fi

                /bin/tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" --force > /tmp/pool_export.log 2>&1 || true
                rm -f /run/tidefs/import/* 2>/dev/null || true

                if /bin/tidefsctl snapshot create "$SNAP_NAME" --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" > /tmp/snap_create.log 2>&1; then
                    pass "snapshot_create" "$cycle"
                    SNAPSHOT_PASS=$((SNAPSHOT_PASS + 1))

                    if /bin/tidefsctl snapshot list --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" 2>/dev/null | grep -q "$SNAP_NAME"; then
                        pass "snapshot_list" "$cycle"
                    else
                        fail "snapshot_list" "cycle $cycle: $SNAP_NAME not in list"
                        CYCLE_OK=0
                    fi
                else
                    fail "snapshot_create" "cycle $cycle: $(tail -3 /tmp/snap_create.log 2>/dev/null)"
                    CYCLE_OK=0
                fi

                /bin/tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" --force > /tmp/pool_export.log 2>&1 || true
                rm -f /run/tidefs/import/* 2>/dev/null || true

                /bin/tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" \
                    > /tmp/daemon.log 2>&1 &
                DAEMON_PID=$!

                SNAP_REMOUNTED=0
                j=1
                while [ "$j" -le 30 ]; do
                    if grep -q " $MNT " /proc/mounts 2>/dev/null; then
                        SNAP_REMOUNTED=1
                        break
                    fi
                    sleep 1
                    j=$((j + 1))
                done

                if [ "$SNAP_REMOUNTED" -eq 1 ]; then
                    pass "snapshot_remount" "$cycle"
                else
                    fail "snapshot_remount" "cycle $cycle: remount failed after snapshot (daemon log: $(tail -20 /tmp/daemon.log 2>/dev/null))"
                    CYCLE_OK=0
                fi
            fi
        fi

        # Sub-phase F: Recovery (unmount + remount) every 4 cycles
        REM4=$((cycle % 4))
        if [ "$REM4" -eq 0 ] && [ "$cycle" -lt "$SOAK_N" ]; then
            echo "  Recovery phase: unmount + remount..."

            sync

            if umount "$MNT" 2>/tmp/um.err; then
                pass "cycle_unmount" "$cycle"
            else
                fail "unmount" "cycle $cycle: $(cat /tmp/um.err)"
                CYCLE_OK=0
                cycle=$((cycle+1))
                continue
            fi

            if [ -n "$DAEMON_PID" ]; then
                kill "$DAEMON_PID" 2>/dev/null || true
                sleep 2
                kill -9 "$DAEMON_PID" 2>/dev/null || true
                DAEMON_PID=""
            fi

            /bin/tidefsctl pool export "$POOL_NAME" --devices "$DEV0" "$DEV1" --force > /tmp/pool_export.log 2>&1 || true
            rm -f /run/tidefs/import/* 2>/dev/null || true

            /bin/tidefsctl pool mount "$POOL_NAME" "$MNT" --devices "$DEV0" "$DEV1" \
                > /tmp/daemon.log 2>&1 &
            DAEMON_PID=$!

            REMOUNTED=0
            j=1
            while [ "$j" -le 30 ]; do
                if grep -q " $MNT " /proc/mounts 2>/dev/null; then
                    REMOUNTED=1
                    break
                fi
                sleep 1
                j=$((j + 1))
            done

            if [ "$REMOUNTED" -eq 1 ]; then
                pass "cycle_remount" "$cycle"
                RECOVERY_PASS=$((RECOVERY_PASS + 1))

                # Verify data persisted across remount
                C1_DIR="$MNT/cycle-1"
                if [ -d "$C1_DIR" ]; then
                    if [ -f "$C1_DIR/renamed_1.txt" ]; then
                        pass "persist_rename" "$cycle"
                    else
                        fail "persist_rename" "cycle $cycle: renamed_1.txt lost"
                        CYCLE_OK=0
                    fi
                    fi2=2
                    while [ "$fi2" -le 4 ]; do
                        if [ -f "$C1_DIR/file_$fi2.txt" ]; then
                            :
                        else
                            fail "persist_file" "cycle $cycle: file_$fi2.txt lost"
                            CYCLE_OK=0
                        fi
                        fi2=$((fi2 + 1))
                    done
                else
                    fail "persist_dir" "cycle $cycle: cycle-1 directory lost"
                    CYCLE_OK=0
                fi

                if [ "$SNAPSHOT_PASS" -gt 0 ]; then
                    SNAP_COUNT=$(snapshot_count)
                    if [ "$SNAP_COUNT" -gt 0 ]; then
                        pass "snapshots_persist" "$cycle"
                    else
                        fail "snapshots_persist" "cycle $cycle: all snapshots lost"
                        CYCLE_OK=0
                    fi
                fi
            else
                fail "remount" "cycle $cycle: remount failed (daemon log: $(tail -20 /tmp/daemon.log 2>/dev/null))"
                CYCLE_OK=0
            fi
        fi

        if [ "$CYCLE_OK" -eq 1 ]; then
            CYCLE_PASS=$((CYCLE_PASS + 1))
        else
            CYCLE_FAIL=$((CYCLE_FAIL + 1))
        fi

        cycle=$((cycle + 1))
    done

    pass "soak_cycles" "total cycles: $CYCLE_PASS passed, $CYCLE_FAIL failed"
    SEND_STREAM=/tmp/tidefs-soak-send.vfssend1
    RECEIVE_DIR=/tmp/tidefs-soak-receive
    rm -f "$SEND_STREAM"
    rm -rf "$RECEIVE_DIR"
    if /bin/tidefsctl snapshot send --pool "$POOL_NAME" --devices "$DEV0" "$DEV1" --output "$SEND_STREAM" > /tmp/snap_send.log 2>&1; then
        pass "soak_send" "$(tail -1 /tmp/snap_send.log 2>/dev/null)"
        if /bin/tidefsctl snapshot receive --backing-dir "$RECEIVE_DIR" --input "$SEND_STREAM" > /tmp/snap_receive.log 2>&1; then
            pass "soak_receive" "$(tail -1 /tmp/snap_receive.log 2>/dev/null)"
            if [ "$SNAPSHOT_PASS" -gt 0 ]; then
                if /bin/tidefsctl snapshot list --backing-dir "$RECEIVE_DIR" 2>/dev/null | grep -q "soak-snap-"; then
                    pass "soak_receive_snapshots"
                else
                    fail "soak_receive_snapshots" "received filesystem has no soak snapshots"
                fi
            fi
        else
            fail "soak_receive" "$(tail -5 /tmp/snap_receive.log 2>/dev/null)"
        fi
    else
        fail "soak_send" "$(tail -5 /tmp/snap_send.log 2>/dev/null)"
    fi
    if [ "$SNAPSHOT_PASS" -gt 0 ]; then
        pass "soak_snapshots" "$SNAPSHOT_PASS snapshots created"
    elif [ "$SNAPSHOT_BLOCK" -gt 0 ]; then
        blocked "soak_snapshots" "0 snapshots created; $SNAPSHOT_BLOCK snapshot attempts blocked by missing tidefsctl --pool/--devices support"
    else
        fail "soak_snapshots" "0 snapshots created"
    fi
    pass "soak_recovery" "$RECOVERY_PASS recovery cycles completed"
else
    blocked "soak_cycles" "filesystem not mounted"
    blocked "soak_snapshots" "filesystem not mounted"
    blocked "soak_send" "filesystem not mounted"
    blocked "soak_receive" "filesystem not mounted"
    blocked "soak_recovery" "filesystem not mounted"
fi

# Phase 3: Final teardown
if grep -q " $MNT " /proc/mounts 2>/dev/null; then
    if [ "$SNAPSHOT_PASS" -gt 0 ]; then
        FINAL_SNAPS=$(snapshot_count)
        echo "  final snapshots: $FINAL_SNAPS"
        pass "final_snapshot_count" "$FINAL_SNAPS snapshots retained"
    fi

    sync

    if umount "$MNT" 2>/tmp/um.err; then
        pass "final_unmount"
    else
        fail "final_unmount" "$(cat /tmp/um.err)"
    fi
fi

if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    pass "daemon_stop"
fi

echo ""
echo "=== FUSE Product Demo Soak Summary ==="
echo "PASSED=$PASSED"
echo "FAILED=$FAILED"
echo "BLOCKED=$BLOCKED"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "validation_tier=Tier-3-mounted-userspace-QEMU-FUSE-runtime"
echo "test=fuse-product-demo-soak"
echo "soak_cycles_total=$SOAK_N"
echo "soak_cycles_passed=$CYCLE_PASS"
echo "soak_cycles_failed=$CYCLE_FAIL"
echo "snapshots_created=$SNAPSHOT_PASS"
echo "snapshots_blocked=$SNAPSHOT_BLOCK"
echo "recovery_cycles=$RECOVERY_PASS"
echo "=== End ==="

sync
sleep 1
poweroff -f
INITSCRIPT

    sed -i "s/__SOAK_CYCLES__/$SOAK_CYCLES/g" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

    # Run QEMU
    VAL_LOG="$RUN_DIR/qemu-boot.log"

    echo "  Booting QEMU VM..."
    QEMU_RC=0
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10 panic_on_oops=1" \
      -machine "accel=$QEMU_ACCEL" \
      -drive "file=$DISK0_IMG,format=raw,if=virtio,index=0" \
      -drive "file=$DISK1_IMG,format=raw,if=virtio,index=1" \
      -m 768M \
      -smp 2 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || QEMU_RC=$?

    echo "  QEMU boot completed with exit code $QEMU_RC"

    # Parse validation rows
    echo ""
    echo "=== FUSE Product Demo Soak Results ==="

    PASSC=0; FAILC=0; BLOCKC=0

    while IFS= read -r line; do
      case "$line" in
        "PASS: "*)  echo "  $line"; PASSC=$((PASSC + 1)) ;;
        "FAIL: "*)  echo "  $line"; FAILC=$((FAILC + 1)) ;;
        "BLOCKED: "*) echo "  $line"; BLOCKC=$((BLOCKC + 1)) ;;
      esac
    done < <(grep -E '^(PASS|FAIL|BLOCKED):' "$VAL_LOG" 2>/dev/null || true)

    echo ""
    echo "Validation: $PASSC passed, $FAILC failed, $BLOCKC blocked"
    echo "Validation log: $VAL_LOG"

    # Produce validation record
    COMMIT=$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)
    EPOCH=$(date -u +%Y%m%dT%H%M%SZ)
    VALIDATION_DIR="$RUN_DIR/validation"
    mkdir -p "$VALIDATION_DIR"
    cp "$VAL_LOG" "$VALIDATION_DIR/qemu-boot.log"
    cp "$RUN_DIR/init" "$VALIDATION_DIR/init-script"

    KERNEL_VERSION=$(grep 'kernel_version=' "$VAL_LOG" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '\r' || echo unknown)
    SOAK_CYCLES_PASSED=$(grep "soak_cycles_passed=" "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '\r' || echo "0")
    SOAK_CYCLES_FAILED=$(grep "soak_cycles_failed=" "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '\r' || echo "0")
    SNAPSHOTS_CREATED=$(grep "snapshots_created=" "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '\r' || echo "0")
    SNAPSHOTS_BLOCKED=$(grep "snapshots_blocked=" "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '\r' || echo "0")
    RECOVERY_COUNT=$(grep "recovery_cycles=" "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '\r' || echo "0")

    cat > "$VALIDATION_DIR/validation.json" << JSONEOF
{
  "run_id": "fuse-product-demo-soak-$EPOCH",
  "commit": "$COMMIT",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "$KERNEL_VERSION",
  "backend": "block-device",
  "validation_tier": "Tier-3-mounted-userspace-QEMU-FUSE-runtime",
  "test": "fuse-product-demo-soak",
  "qemu_exit_code": $QEMU_RC,
  "soak_cycles_requested": $SOAK_CYCLES,
  "soak_cycles_passed": $SOAK_CYCLES_PASSED,
  "soak_cycles_failed": $SOAK_CYCLES_FAILED,
  "snapshots_created": $SNAPSHOTS_CREATED,
  "snapshots_blocked": $SNAPSHOTS_BLOCKED,
  "recovery_cycles": $RECOVERY_COUNT,
  "e2e_row": "userspace-pool-lifecycle",
  "summary": {
    "passed": $PASSC,
    "failed": $FAILC,
    "blocked": $BLOCKC
  }
}
JSONEOF

    echo "Validation recorded: $VALIDATION_DIR"

    if [ -n "$JSON_OUT" ]; then
      mkdir -p "$(dirname "$JSON_OUT")"
      cp "$VALIDATION_DIR/validation.json" "$JSON_OUT"
      ARTIFACT_DIR="$JSON_OUT.artifacts"
      mkdir -p "$ARTIFACT_DIR"
      cp "$VAL_LOG" "$ARTIFACT_DIR/qemu-boot.log"
      cp "$RUN_DIR/init" "$ARTIFACT_DIR/init-script"
      cp "$VALIDATION_DIR/validation.json" "$ARTIFACT_DIR/validation.json"
      echo "Validation outputs written: $ARTIFACT_DIR"
    fi

    if grep -Eq 'Failed to execute /init|No working init found|Kernel panic - not syncing' "$VAL_LOG" 2>/dev/null; then
      echo "VALIDATION: FAIL -- guest did not reach init; see $VAL_LOG"
      exit 1
    fi

    if [ "$QEMU_RC" -eq 124 ]; then
      echo "VALIDATION: BLOCKED -- QEMU timed out after ''${TIMEOUT_SEC}s; see $VAL_LOG"
      exit 2
    fi

    if [ "$QEMU_RC" -ne 0 ]; then
      echo "VALIDATION: FAIL -- QEMU exited with code $QEMU_RC"
      exit 1
    fi

    if [ "$PASSC" -eq 0 ]; then
      echo "VALIDATION: BLOCKED -- no validation rows emitted; see $VAL_LOG"
      exit 2
    fi

    if [ "$FAILC" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILC validation rows failed"
      exit 1
    fi

    if [ "$BLOCKC" -gt 0 ]; then
      echo "VALIDATION: BLOCKED -- $BLOCKC validation rows blocked"
      exit 2
    fi

    echo "VALIDATION: PASS -- $PASSC validation rows passed"
    exit 0
  '';
in
fuseProductDemoSoakScript
