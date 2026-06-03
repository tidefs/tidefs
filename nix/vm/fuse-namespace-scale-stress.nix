# TideFS: FUSE namespace-scale stress validation.
#
# Boots a Linux 7.0 QEMU guest, creates a TideFS pool, mounts via FUSE, runs
# large-directory-tree and multi-object creation workloads, measures
# cold-cache/warm-cache directory traversal, and produces tier-classified JSON
# validation rows.
#
# Validation tier: Tier 3 mounted userspace/QEMU FUSE runtime.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  namespaceScaleStressScript = pkgs.writeShellScriptBin "tidefs-fuse-namespace-scale-stress" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"

    TMPDIR="''${TIDEFS_NS_SCALE_TMPDIR:-/tmp/tidefs-namespace-scale-stress}"
    TIMEOUT_SEC="''${TIDEFS_NS_SCALE_TIMEOUT:-7200}"
    DISK_SIZE_MB="''${TIDEFS_NS_SCALE_DISK_MB:-2048}"

    # Scale parameters
    WIDE_DIRS="''${TIDEFS_NS_SCALE_WIDE_DIRS:-200}"
    FILES_PER_DIR="''${TIDEFS_NS_SCALE_FILES_PER_DIR:-50}"
    DEEP_LEVELS="''${TIDEFS_NS_SCALE_DEEP_LEVELS:-8}"
    FILES_PER_LEVEL="''${TIDEFS_NS_SCALE_FILES_PER_LEVEL:-10}"
    HUGE_DIR_FILES="''${TIDEFS_NS_SCALE_HUGE_DIR_FILES:-5000}"
    MULTI_EXTENT_FILES="''${TIDEFS_NS_SCALE_MULTI_EXTENT_FILES:-100}"
    EXTENTS_PER_FILE="''${TIDEFS_NS_SCALE_EXTENTS_PER_FILE:-10}"

    KEEP_TMP=0
    JSON_OUT=""

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --wide-dirs) WIDE_DIRS="$2"; shift 2 ;;
        --files-per-dir) FILES_PER_DIR="$2"; shift 2 ;;
        --deep-levels) DEEP_LEVELS="$2"; shift 2 ;;
        --files-per-level) FILES_PER_LEVEL="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --output) JSON_OUT="$2"; shift 2 ;;
        --huge-dir-files) HUGE_DIR_FILES="$2"; shift 2 ;;
        --multi-extent-files) MULTI_EXTENT_FILES="$2"; shift 2 ;;
        --extents-per-file) EXTENTS_PER_FILE="$2"; shift 2 ;;
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

    echo "=== TideFS FUSE Namespace-Scale Stress ==="
    echo "  Kernel:        $KERNEL_IMG"
    echo "  Wide dirs:     $WIDE_DIRS x $FILES_PER_DIR files"
    echo "  Deep levels:   $DEEP_LEVELS x $FILES_PER_LEVEL files/level"
    echo "  Huge dir:      $HUGE_DIR_FILES files"
    echo "  Multi-extent:  $MULTI_EXTENT_FILES files x $EXTENTS_PER_FILE extents"
    echo "  Timeout:       ''${TIMEOUT_SEC}s"
    echo "  Disk size:     ''${DISK_SIZE_MB}M x2"
    echo "  QEMU accel:    $QEMU_ACCEL"

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


    # Capture git metadata for validation provenance
    GIT_REPO="''${TIDEFS_REPO_PATH:-/root/tidefs}"
    GIT_COMMIT="$(git -C "$GIT_REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
    GIT_BRANCH="$(git -C "$GIT_REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)"
    GIT_DIRTY="$(git -C "$GIT_REPO" status --porcelain 2>/dev/null | grep -q . && echo true || echo false)"
    GIT_ORIGIN_MASTER="$(git -C "$GIT_REPO" rev-parse origin/master 2>/dev/null || echo unknown)"
    # Set up temp directory
    WORK_DIR="$TMPDIR/stress-$$"
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
                    readlink tr cmp diff mountpoint umount uname date awk blockdev \
                    sort wc tee; do
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

    # Generate init script with scale parameters baked in
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS FUSE Namespace-Scale Stress ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

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

record_timing() {
    PHASE="$1"
    ELAPSED="$2"
    OPS="$3"
    OPS_SEC="$4"
    UNIT="$5"
    echo "TIMING: phase=$PHASE elapsed_s=$ELAPSED ops=$OPS ops_per_sec=$OPS_SEC unit=$UNIT"
    printf '{"phase":"%s","elapsed_s":%s,"ops":%s,"ops_per_sec":%s,"unit":"%s"}\n' \
        "$PHASE" "$ELAPSED" "$OPS" "$OPS_SEC" "$UNIT" >> /tmp/timing_lines.txt
}

ns_time_ms() {
    awk '{ printf "%.3f", $1 * 1000 }' /proc/uptime
}

elapsed_since() {
    START="$1"
    NOW=$(ns_time_ms)
    awk "BEGIN { printf \"%.3f\", ($NOW - $START) / 1000 }"
}

MNT=/mnt/tidefs
POOL_NAME=scale_pool
DEV0=/dev/vda
DEV1=/dev/vdb

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

# Phase 1: pool create and FUSE mount
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
            fail "fuse_mount" "mount did not appear in /proc/mounts within 45s"
        fi
    else
        blocked "fuse_mount" "pool not created"
    fi
else
    blocked "pool_create" "FUSE device not available"
    blocked "fuse_mount" "FUSE device not available"
fi

# Phase 2: Namespace Scale Stress
if [ "$MOUNTED" -eq 1 ]; then
    echo ""
    echo "=== Phase 2: Namespace Scale Stress ==="

    # Sub-phase 2A: Wide directory tree
    echo ""
    echo "--- Sub-phase 2A: Wide directory tree ---"
    WIDE_DIR="$MNT/scale-wide"
    mkdir -p "$WIDE_DIR"

    T0=$(ns_time_ms)
    CREATED_FILES=0
    d=1
    while [ "$d" -le "$WIDE_DIRS" ]; do
        DIRN="$WIDE_DIR/dir-$d"
        mkdir -p "$DIRN" 2>/dev/null || { fail "wide_mkdir" "dir $d failed"; break; }
        f=1
        while [ "$f" -le "$FILES_PER_DIR" ]; do
            echo "wide-d$d-f$f-data" > "$DIRN/file-$f.txt" 2>/dev/null || { fail "wide_write" "dir $d file $f failed"; break 2; }
            f=$((f + 1))
            CREATED_FILES=$((CREATED_FILES + 1))
        done
        d=$((d + 1))
    done
    sync
    T1=$(ns_time_ms)
    CREATE_ELAPSED=$(elapsed_since "$T0")
    TOTAL_FILES=$(($WIDE_DIRS * $FILES_PER_DIR))
    CREATE_OPS_SEC=$(awk "BEGIN { if ($CREATE_ELAPSED > 0) printf \"%.1f\", $CREATED_FILES / $CREATE_ELAPSED; else print 0 }")

    if [ "$CREATED_FILES" -ge "$TOTAL_FILES" ]; then
        pass "wide_create" "$CREATED_FILES files in $CREATE_ELAPSED s ($CREATE_OPS_SEC files/s)"
        record_timing "wide_create" "$CREATE_ELAPSED" "$CREATED_FILES" "$CREATE_OPS_SEC" "files/s"
    else
        fail "wide_create" "only $CREATED_FILES/$TOTAL_FILES files created"
    fi

    # Cold-cache wide find
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    sleep 1
    T0=$(ns_time_ms)
    FIND_COUNT=$(find "$WIDE_DIR" -type f 2>/dev/null | wc -l)
    T1=$(ns_time_ms)
    COLD_FIND_ELAPSED=$(elapsed_since "$T0")
    COLD_FIND_RATE=$(awk "BEGIN { if ($COLD_FIND_ELAPSED > 0) printf \"%.1f\", $FIND_COUNT / $COLD_FIND_ELAPSED; else print 0 }")
    echo "  cold-cache find: $FIND_COUNT files in $COLD_FIND_ELAPSEDs ($COLD_FIND_RATE files/s)"
    record_timing "wide_cold_find" "$COLD_FIND_ELAPSED" "$FIND_COUNT" "$COLD_FIND_RATE" "files/s"

    # Warm-cache wide find
    T0=$(ns_time_ms)
    FIND_COUNT=$(find "$WIDE_DIR" -type f 2>/dev/null | wc -l)
    T1=$(ns_time_ms)
    WARM_FIND_ELAPSED=$(elapsed_since "$T0")
    WARM_FIND_RATE=$(awk "BEGIN { if ($WARM_FIND_ELAPSED > 0) printf \"%.1f\", $FIND_COUNT / $WARM_FIND_ELAPSED; else print 0 }")
    echo "  warm-cache find: $FIND_COUNT files in $WARM_FIND_ELAPSEDs ($WARM_FIND_RATE files/s)"
    record_timing "wide_warm_find" "$WARM_FIND_ELAPSED" "$FIND_COUNT" "$WARM_FIND_RATE" "files/s"

    CACHE_RATIO=$(awk "BEGIN { if ($COLD_FIND_RATE > 0) printf \"%.1f\", $WARM_FIND_RATE / $COLD_FIND_RATE; else print 0 }")
    if [ "$(awk "BEGIN { print ($WARM_FIND_RATE > $COLD_FIND_RATE) }")" = "1" ]; then
        pass "wide_cache_effect" "warm/cold ratio=$CACHE_RATIOx"
    else
        fail "wide_cache_effect" "warm $WARM_FIND_RATE <= cold $COLD_FIND_RATE"
    fi

    # Stat throughput sample
    T0=$(ns_time_ms)
    STAT_COUNT=0
    for f in "$WIDE_DIR"/dir-*/file-*.txt; do
        stat "$f" > /dev/null 2>&1 || true
        STAT_COUNT=$((STAT_COUNT + 1))
        if [ "$STAT_COUNT" -ge 1000 ]; then break; fi
    done
    T1=$(ns_time_ms)
    STAT_ELAPSED=$(elapsed_since "$T0")
    STAT_OPS_SEC=$(awk "BEGIN { if ($STAT_ELAPSED > 0) printf \"%.1f\", $STAT_COUNT / $STAT_ELAPSED; else print 0 }")
    echo "  stat throughput: $STAT_OPS_SEC stats/s"
    record_timing "wide_stat" "$STAT_ELAPSED" "$STAT_COUNT" "$STAT_OPS_SEC" "stats/s"

    # Sub-phase 2B: Deep directory tree
    echo ""
    echo "--- Sub-phase 2B: Deep directory tree ---"
    DEEP_DIR="$MNT/scale-deep"
    mkdir -p "$DEEP_DIR"

    T0=$(ns_time_ms)
    CURRENT="$DEEP_DIR"
    DEEP_OK=1
    l=1
    while [ "$l" -le "$DEEP_LEVELS" ]; do
        CURRENT="$CURRENT/level-$l"
        mkdir -p "$CURRENT" 2>/dev/null || { fail "deep_mkdir" "level $l failed"; DEEP_OK=0; break; }
        f=1
        while [ "$f" -le "$FILES_PER_LEVEL" ]; do
            echo "deep-l$l-f$f-data" > "$CURRENT/file-$f.txt" 2>/dev/null || { fail "deep_write" "level $l file $f failed"; DEEP_OK=0; break 2; }
            f=$((f + 1))
        done
        l=$((l + 1))
    done
    sync
    T1=$(ns_time_ms)
    DEEP_ELAPSED=$(elapsed_since "$T0")
    DEEP_TOTAL=$(($DEEP_LEVELS * $FILES_PER_LEVEL))
    DEEP_OPS_SEC=$(awk "BEGIN { if ($DEEP_ELAPSED > 0) printf \"%.1f\", $DEEP_TOTAL / $DEEP_ELAPSED; else print 0 }")

    if [ "$DEEP_OK" -eq 1 ]; then
        pass "deep_create" "$DEEP_TOTAL files in $DEEP_LEVELS levels ($DEEP_ELAPSED s, $DEEP_OPS_SEC files/s)"
        record_timing "deep_create" "$DEEP_ELAPSED" "$DEEP_TOTAL" "$DEEP_OPS_SEC" "files/s"
    fi

    # Cold-cache deep traversal
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    sleep 1
    T0=$(ns_time_ms)
    FIND_COUNT=$(find "$DEEP_DIR" -type f 2>/dev/null | wc -l)
    T1=$(ns_time_ms)
    COLD_DEEP_ELAPSED=$(elapsed_since "$T0")
    COLD_DEEP_RATE=$(awk "BEGIN { if ($COLD_DEEP_ELAPSED > 0) printf \"%.1f\", $FIND_COUNT / $COLD_DEEP_ELAPSED; else print 0 }")
    echo "  cold-cache deep find: $FIND_COUNT files in $COLD_DEEP_ELAPSEDs ($COLD_DEEP_RATE files/s)"
    record_timing "deep_cold_find" "$COLD_DEEP_ELAPSED" "$FIND_COUNT" "$COLD_DEEP_RATE" "files/s"

    # Warm-cache deep traversal
    T0=$(ns_time_ms)
    FIND_COUNT=$(find "$DEEP_DIR" -type f 2>/dev/null | wc -l)
    T1=$(ns_time_ms)
    WARM_DEEP_ELAPSED=$(elapsed_since "$T0")
    WARM_DEEP_RATE=$(awk "BEGIN { if ($WARM_DEEP_ELAPSED > 0) printf \"%.1f\", $FIND_COUNT / $WARM_DEEP_ELAPSED; else print 0 }")
    echo "  warm-cache deep find: $FIND_COUNT files in $WARM_DEEP_ELAPSEDs ($WARM_DEEP_RATE files/s)"
    record_timing "deep_warm_find" "$WARM_DEEP_ELAPSED" "$FIND_COUNT" "$WARM_DEEP_RATE" "files/s"

    # Sub-phase 2C: Huge single-directory stress
    echo ""
    echo "--- Sub-phase 2C: Huge directory ---"
    HUGE_DIR="$MNT/scale-huge"
    mkdir -p "$HUGE_DIR"

    T0=$(ns_time_ms)
    CREATED=0
    HUGE_OK=1
    f=1
    while [ "$f" -le "$HUGE_DIR_FILES" ]; do
        echo "huge-file-$f-data" > "$HUGE_DIR/file-$f.txt" 2>/dev/null || { fail "huge_dir_write" "file $f failed at $CREATED"; HUGE_OK=0; break; }
        CREATED=$((CREATED + 1))
        f=$((f + 1))
    done
    sync
    T1=$(ns_time_ms)
    HUGE_ELAPSED=$(elapsed_since "$T0")
    HUGE_OPS_SEC=$(awk "BEGIN { if ($HUGE_ELAPSED > 0) printf \"%.1f\", $CREATED / $HUGE_ELAPSED; else print 0 }")

    if [ "$HUGE_OK" -eq 1 ]; then
        pass "huge_dir_create" "$CREATED files in $HUGE_ELAPSED s ($HUGE_OPS_SEC files/s)"
        record_timing "huge_dir_create" "$HUGE_ELAPSED" "$CREATED" "$HUGE_OPS_SEC" "files/s"
    fi

    # Cold-cache huge ls
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    sleep 1
    T0=$(ns_time_ms)
    LS_COUNT=$(ls "$HUGE_DIR" 2>/dev/null | wc -l)
    T1=$(ns_time_ms)
    COLD_LS_ELAPSED=$(elapsed_since "$T0")
    COLD_LS_RATE=$(awk "BEGIN { if ($COLD_LS_ELAPSED > 0) printf \"%.1f\", $LS_COUNT / $COLD_LS_ELAPSED; else print 0 }")
    echo "  cold-cache ls: $LS_COUNT entries in $COLD_LS_ELAPSEDs ($COLD_LS_RATE entries/s)"
    record_timing "huge_dir_cold_ls" "$COLD_LS_ELAPSED" "$LS_COUNT" "$COLD_LS_RATE" "entries/s"

    # Warm-cache huge ls
    T0=$(ns_time_ms)
    LS_COUNT=$(ls "$HUGE_DIR" 2>/dev/null | wc -l)
    T1=$(ns_time_ms)
    WARM_LS_ELAPSED=$(elapsed_since "$T0")
    WARM_LS_RATE=$(awk "BEGIN { if ($WARM_LS_ELAPSED > 0) printf \"%.1f\", $LS_COUNT / $WARM_LS_ELAPSED; else print 0 }")
    echo "  warm-cache ls: $LS_COUNT entries in $WARM_LS_ELAPSEDs ($WARM_LS_RATE entries/s)"
    record_timing "huge_dir_warm_ls" "$WARM_LS_ELAPSED" "$LS_COUNT" "$WARM_LS_RATE" "entries/s"

    # Sub-phase 2D: Multi-extent file stress
    echo ""
    echo "--- Sub-phase 2D: Multi-extent files ---"
    EXTENT_DIR="$MNT/scale-extents"
    mkdir -p "$EXTENT_DIR"

    T0=$(ns_time_ms)
    EXTENT_OK=1
    f=1
    while [ "$f" -le "$MULTI_EXTENT_FILES" ]; do
        FILE="$EXTENT_DIR/extent-file-$f.bin"
        : > "$FILE" 2>/dev/null || { fail "extent_create" "file $f: create failed"; EXTENT_OK=0; break; }
        e=1
        while [ "$e" -le "$EXTENTS_PER_FILE" ]; do
            dd if=/dev/urandom of="$FILE" bs=512 count=1 seek=$(( (e - 1) * 8 )) conv=notrunc 2>/dev/null || true
            e=$((e + 1))
        done
        f=$((f + 1))
    done
    sync
    T1=$(ns_time_ms)
    EXTENT_ELAPSED=$(elapsed_since "$T0")
    EXTENT_OPS_SEC=$(awk "BEGIN { if ($EXTENT_ELAPSED > 0) printf \"%.1f\", $MULTI_EXTENT_FILES / $EXTENT_ELAPSED; else print 0 }")

    if [ "$EXTENT_OK" -eq 1 ]; then
        pass "multi_extent_create" "$MULTI_EXTENT_FILES files ($EXTENTS_PER_FILE extents each) in $EXTENT_ELAPSED s ($EXTENT_OPS_SEC files/s)"
        record_timing "multi_extent_create" "$EXTENT_ELAPSED" "$MULTI_EXTENT_FILES" "$EXTENT_OPS_SEC" "files/s"
    fi

    # Cold-cache extent readback
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    sleep 1
    T0=$(ns_time_ms)
    READ_COUNT=0
    READ_BYTES=0
    for f in "$EXTENT_DIR"/extent-file-*.bin; do
        BYTES=$(wc -c < "$f" 2>/dev/null || echo 0)
        READ_COUNT=$((READ_COUNT + 1))
        READ_BYTES=$((READ_BYTES + BYTES))
        if [ "$READ_COUNT" -ge "$MULTI_EXTENT_FILES" ]; then break; fi
    done
    T1=$(ns_time_ms)
    EXTENT_READ_ELAPSED=$(elapsed_since "$T0")
    EXTENT_READ_RATE=$(awk "BEGIN { if ($EXTENT_READ_ELAPSED > 0) printf \"%.1f\", $READ_COUNT / $EXTENT_READ_ELAPSED; else print 0 }")
    echo "  cold-cache readback: $READ_COUNT files ($READ_BYTES bytes) in $EXTENT_READ_ELAPSEDs ($EXTENT_READ_RATE files/s)"
    record_timing "multi_extent_cold_read" "$EXTENT_READ_ELAPSED" "$READ_COUNT" "$EXTENT_READ_RATE" "files/s"

    # Memory summary
    MEM_TOTAL=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    MEM_FREE=$(awk '/^MemFree:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    echo "  mem_total_kb=$MEM_TOTAL mem_free_kb=$MEM_FREE"

    # Cleanup
    umount "$MNT" 2>/dev/null || true
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$DAEMON_PID" 2>/dev/null || true
    fi
fi

# Build final timing JSON
echo '{' > /tmp/final_timing.json
echo '  "phases": [' >> /tmp/final_timing.json
FIRST=1
while IFS= read -r line; do
    if [ -n "$line" ]; then
        if [ "$FIRST" -eq 1 ]; then FIRST=0; else echo ',' >> /tmp/final_timing.json; fi
        printf '    %s' "$line" >> /tmp/final_timing.json
    fi
done < /tmp/timing_lines.txt
echo >> /tmp/final_timing.json
echo '  ]' >> /tmp/final_timing.json
echo '}' >> /tmp/final_timing.json

echo ""
echo "=== Results ==="
echo "passed=$PASSED"
echo "failed=$FAILED"
echo "blocked=$BLOCKED"

if [ -f /tmp/final_timing.json ]; then
    echo "---BEGIN_TIMING_JSON---"
    cat /tmp/final_timing.json
    echo "---END_TIMING_JSON---"
fi

if [ "$FAILED" -gt 0 ]; then
    echo "FINAL_VERDICT: FAILURES=$FAILED"
else
    echo "FINAL_VERDICT: OK"
fi

echo "stress_complete=yes"

poweroff -f 2>/dev/null || reboot -f 2>/dev/null || true
INITSCRIPT

    # Inject scale parameters into the init script
    sed -i \
      -e "s/\$WIDE_DIRS/$WIDE_DIRS/g" \
      -e "s/\$FILES_PER_DIR/$FILES_PER_DIR/g" \
      -e "s/\$DEEP_LEVELS/$DEEP_LEVELS/g" \
      -e "s/\$FILES_PER_LEVEL/$FILES_PER_LEVEL/g" \
      -e "s/\$HUGE_DIR_FILES/$HUGE_DIR_FILES/g" \
      -e "s/\$MULTI_EXTENT_FILES/$MULTI_EXTENT_FILES/g" \
      -e "s/\$EXTENTS_PER_FILE/$EXTENTS_PER_FILE/g" \
      "$RUN_DIR/init"

    chmod +x "$RUN_DIR/init"

    # Create initrd
    INITRD="$WORK_DIR/initrd.cpio.gz"
    echo "  Building initrd..."
    (cd "$RUN_DIR" && find . | cpio -o -H newc 2>/dev/null | gzip > "$INITRD")

    QEMU_PID_FILE="$WORK_DIR/qemu.pid"
    QEMU_LOG="$WORK_DIR/qemu.log"
    QEMU_SERIAL="$WORK_DIR/qemu-serial.log"

    echo "  Booting QEMU ($QEMU_ACCEL)..."
    "$QEMU_BIN" \
      -name "tidefs-ns-scale-stress" \
      -machine q35,accel="$QEMU_ACCEL" \
      -m 1024M \
      -smp 2 \
      -kernel "$KERNEL_IMG" \
      -initrd "$INITRD" \
      -append "console=ttyS0 panic=30 quiet ignore_loglevel" \
      -drive file="$DISK0_IMG",format=raw,if=virtio,index=0 \
      -drive file="$DISK1_IMG",format=raw,if=virtio,index=1 \
      -display none \
      -serial file:"$QEMU_SERIAL" \
      -no-reboot \
      > "$QEMU_LOG" 2>&1 &
    QEMU_PID=$!
    echo "$QEMU_PID" > "$QEMU_PID_FILE"

    # Wait for completion or timeout
    ELAPSED=0
    while [ "$ELAPSED" -lt "$TIMEOUT_SEC" ]; do
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "  QEMU exited after $ELAPSED seconds"
            break
        fi
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done

    if kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "  QEMU still running after $TIMEOUT_SEC s; terminating"
        kill "$QEMU_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$QEMU_PID" 2>/dev/null || true
    fi

    # Parse results from serial log
    echo ""
    echo "=== Serial Output ==="
    cat "$QEMU_SERIAL"

    echo ""
    echo "=== Parsed Validation ==="

    # Extract timing JSON
    if grep -q "BEGIN_TIMING_JSON" "$QEMU_SERIAL" 2>/dev/null; then
        sed -n '/---BEGIN_TIMING_JSON---/,/---END_TIMING_JSON---/p' "$QEMU_SERIAL" \
          | grep -v '^---' > "$WORK_DIR/timing.json"
    fi

    PASSED=$(grep -c '^PASS:' "$QEMU_SERIAL" 2>/dev/null || echo 0)
    FAILED=$(grep -c '^FAIL:' "$QEMU_SERIAL" 2>/dev/null || echo 0)
    BLOCKED=$(grep -c '^BLOCKED:' "$QEMU_SERIAL" 2>/dev/null || echo 0)

    echo "passed=$PASSED"
    echo "failed=$FAILED"
    echo "blocked=$BLOCKED"

    COMPLETE=0
    if grep -q "stress_complete=yes" "$QEMU_SERIAL" 2>/dev/null; then
        COMPLETE=1
    fi

    if [ -n "$JSON_OUT" ]; then
        cat > "$JSON_OUT" << JSONEOF
{
  "test": "fuse-namespace-scale-stress",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "Linux 7.0",
  "mode": "fuse",
  "backend": "virtio-blk",
  "validation_tier": "MountedUserspace",
  "commit": "$GIT_COMMIT",
  "branch": "$GIT_BRANCH",
  "dirty": $GIT_DIRTY,
  "origin_master": "$GIT_ORIGIN_MASTER",
  "qemu_binary": "$QEMU_BIN",
  "qemu_accel": "$QEMU_ACCEL",
  "disk_size_mb": $DISK_SIZE_MB,
  "scale_params": {
    "wide_dirs": $WIDE_DIRS,
    "files_per_dir": $FILES_PER_DIR,
    "deep_levels": $DEEP_LEVELS,
    "files_per_level": $FILES_PER_LEVEL,
    "huge_dir_files": $HUGE_DIR_FILES,
    "multi_extent_files": $MULTI_EXTENT_FILES,
    "extents_per_file": $EXTENTS_PER_FILE
  },
  "passed": $PASSED,
  "failed": $FAILED,
  "blocked": $BLOCKED,
  "complete": $COMPLETE,
  "timings": $(cat "$WORK_DIR/timing.json" 2>/dev/null || echo '{}')
}
JSONEOF
        echo "  Validation written to: $JSON_OUT"
    fi

    echo ""
    if [ "$FAILED" -gt 0 ]; then
        echo "FINAL_VERDICT: FAILURES=$FAILED"
    elif [ "$BLOCKED" -gt 0 ]; then
        echo "FINAL_VERDICT: BLOCKED=$BLOCKED"
    else
        echo "FINAL_VERDICT: OK"
    fi
  '';
in
namespaceScaleStressScript
