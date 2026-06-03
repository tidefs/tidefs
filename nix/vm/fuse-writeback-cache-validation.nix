# TideFS: FUSE writeback-cache mounted validation.
#
# Mounts a TideFS FUSE filesystem with default writeback-cache enabled,
# exercises dirty-page tracking, writeback flush, and cache coherence,
# and produces tier-classified validation rows. Crash-consistency tiers
# require persistent storage (qcow2 virtio-blk) and are gated as a
# Review debt TFR-008.
#
# Validation tiers:
#   clean-writeback          Mount, buffered writes, fsync, readback
#   dirty-drain              Sustained writes, dirty-page accumulation, flush
#   post-flush-coherence     Write after flush, close/reopen, multi-file pressure
#   crash-consistency        Gated (requires persistent storage infrastructure)
#
# Dependencies:
#   - Linux 7.0 kernel with FUSE support (fuse.ko)
#   - tidefs-posix-filesystem-adapter-daemon binary
#   - QEMU with KVM acceleration
#   - busybox for initrd userspace
#
# Environment refusal: in environments without /dev/kvm or fuse.ko,
# produces REFUSAL-classified validation rows.
{
  pkgs,
  linuxKernel_7_0 ? null,
  tidefsPackage ? null,
  useHostTools ? false,
}:

let
  toolSetup =
    if useHostTools
    then ''
      QEMU_BIN="''${TIDEFS_FUSE_WBC_QEMU_BIN:-$(command -v qemu-system-x86_64 || true)}"
      QEMU_IMG="''${TIDEFS_FUSE_WBC_QEMU_IMG:-$(command -v qemu-img || true)}"
      MKFS_EXT4="''${TIDEFS_FUSE_WBC_MKFS_EXT4:-$(command -v mkfs.ext4 || command -v mke2fs || true)}"
      BUSYBOX="''${TIDEFS_FUSE_WBC_BUSYBOX:-$(command -v busybox || true)}"
      CPIO="''${TIDEFS_FUSE_WBC_CPIO:-$(command -v cpio || true)}"
      STRIP="''${TIDEFS_FUSE_WBC_STRIP:-$(command -v strip || true)}"
      PATCHELF="''${TIDEFS_FUSE_WBC_PATCHELF:-$(command -v patchelf || true)}"
    ''
    else ''
      QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
      QEMU_IMG="${pkgs.qemu}/bin/qemu-img"
      MKFS_EXT4="${pkgs.e2fsprogs}/bin/mkfs.ext4"
      BUSYBOX="${pkgs.busybox}/bin/busybox"
      CPIO="${pkgs.cpio}/bin/cpio"
      STRIP="${pkgs.binutils}/bin/strip"
      PATCHELF="${pkgs.patchelf}/bin/patchelf"
    '';
  defaultKernelImage =
    if linuxKernel_7_0 == null
    then ""
    else "${linuxKernel_7_0}/bzImage";
  defaultModuleDir =
    if linuxKernel_7_0 == null
    then ""
    else "${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}";
  defaultFuseDaemon =
    if tidefsPackage == null
    then ""
    else "${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon";
  fuseWritebackValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-writeback-validation" ''
    set -euo pipefail

${toolSetup}
    DEFAULT_KERNEL_IMG="${defaultKernelImage}"
    DEFAULT_MODULE_DIR="${defaultModuleDir}"
    KERNEL_IMG="''${TIDEFS_FUSE_WBC_KERNEL_IMG:-$DEFAULT_KERNEL_IMG}"
    MODULE_DIR="''${TIDEFS_FUSE_WBC_MODULE_DIR:-$DEFAULT_MODULE_DIR}"
    DEFAULT_FUSE_DAEMON="${defaultFuseDaemon}"
    FUSE_DAEMON="''${TIDEFS_FUSE_WBC_DAEMON_BIN:-$DEFAULT_FUSE_DAEMON}"

    TMPDIR="''${TIDEFS_FUSE_WBC_TMPDIR:-/tmp/tidefs-fuse-writeback-validation}"
    TIMEOUT_SEC="''${TIDEFS_FUSE_WBC_TIMEOUT:-300}"
    VALIDATION_DIR="''${TIDEFS_FUSE_WBC_VALIDATION_DIR:-}"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-writeback-validation [--daemon-bin PATH] [--kernel-img PATH] [--module-dir DIR] [--timeout SECONDS] [--keep-tmp]

Produce tier-classified FUSE writeback-cache validation in a
reproducible Nix/QEMU Linux 7.0 environment. Exercises dirty-page tracking,
writeback flush, and cache coherence with committed-root verification.

Validation tiers:
  T0  Clean writeback mount + buffered write + readback
  T1  Dirty-drain: sustained writes, fsync flush, data verification
  T2  Post-flush coherence: overwrite after flush, close/reopen, multi-file
  T3  Crash-consistency (two-boot cycle with persistent storage)

Options:
  --daemon-bin PATH    Use this already-built FUSE daemon binary
                       (or set TIDEFS_FUSE_WBC_DAEMON_BIN)
  --kernel-img PATH    Use this already-built Linux 7.0 bzImage
                       (or set TIDEFS_FUSE_WBC_KERNEL_IMG)
  --module-dir DIR     Use this already-built Linux module directory when
                       FUSE is modular; omit when FUSE is built into the kernel
                       (or set TIDEFS_FUSE_WBC_MODULE_DIR)
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --validation-dir DIR   Copy boot logs and summary into DIR before cleanup
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0   All exercised validation tiers passed
  1   One or more tiers failed
  2   Environment refusal (no /dev/kvm, no fuse.ko)
EOF
    }

    KEEP_TMP=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --daemon-bin) FUSE_DAEMON="$2"; shift 2 ;;
        --kernel-img) KERNEL_IMG="$2"; shift 2 ;;
        --module-dir) MODULE_DIR="$2"; shift 2 ;;
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --validation-dir) VALIDATION_DIR="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    # ── Environment preflight ──────────────────────────────────────────

    if [ ! -e /dev/kvm ]; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available"
      echo "FUSE writeback-cache QEMU validation requires KVM acceleration"
      exit 2
    fi

    if [ -z "$KERNEL_IMG" ]; then
      echo "ERROR: kernel image not configured" >&2
      echo "Pass --kernel-img PATH or set TIDEFS_FUSE_WBC_KERNEL_IMG." >&2
      exit 2
    fi

    if [ -z "$FUSE_DAEMON" ]; then
      echo "ERROR: FUSE daemon not configured" >&2
      echo "Pass --daemon-bin PATH or set TIDEFS_FUSE_WBC_DAEMON_BIN." >&2
      exit 2
    fi

    for dep in "$QEMU_BIN" "$QEMU_IMG" "$MKFS_EXT4" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ ! -f "$FUSE_DAEMON" ] || [ ! -x "$FUSE_DAEMON" ]; then
      echo "ERROR: FUSE daemon not found or not executable: $FUSE_DAEMON" >&2
      exit 2
    fi

    echo "=== TideFS FUSE Writeback-Cache Validation Validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Daemon:    $FUSE_DAEMON"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Validation:  tier-classified PASS/FAIL/BLOCKED rows"
    echo ""

    # ── Resolve fuse.ko ────────────────────────────────────────────────

    FUSE_KO=""
    if [ -n "$MODULE_DIR" ]; then
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
    fi

    if [ -z "$FUSE_KO" ]; then
      echo "  fuse.ko: not provided; guest will rely on built-in FUSE support"
      if [ -n "$MODULE_DIR" ]; then
        echo "  Searched: $MODULE_DIR"
      fi
      echo "  FUSE support may be built-in (CONFIG_FUSE_FS=y). If so, skip insmod."
      FUSE_BUILTIN=1
    else
      echo "  fuse.ko: $FUSE_KO"
      FUSE_BUILTIN=0
    fi

    # ── Set up temp directory ──────────────────────────────────────────

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,store,usr/lib}
    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping temp directory: $RUN_DIR"
      else
        rm -rf "$RUN_DIR"
      fi
    }
    trap cleanup EXIT

    # ── Create persistent storage disk image ────────────────────────────

    DISK_IMG="$RUN_DIR/persistent.img"
    DISK_SIZE_MB=256
    echo "  Creating persistent storage: ''${DISK_SIZE_MB}MB raw ext4 image"

    "$QEMU_IMG" create -f raw "$DISK_IMG" "''${DISK_SIZE_MB}M" >/dev/null
    "$MKFS_EXT4" -F "$DISK_IMG" >/dev/null 2>&1 || {
      echo "ERROR: mkfs.ext4 failed for $DISK_IMG" >&2
      exit 2
    }


    # ── Collect daemon shared library dependencies ─────────────────────

    echo "  Collecting daemon library dependencies..."
    RUNTIME_LIBS=""
    if command -v ldd >/dev/null 2>&1; then
      RUNTIME_LIBS=$(ldd "$FUSE_DAEMON" "$BUSYBOX" 2>/dev/null \
        | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) { sub(/\(.*/, "", $i); print $i } }' \
        | sort -u || true)
    fi

    # ── Populate initrd ────────────────────────────────────────────────

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount umount mountpoint grep insmod rmmod dmesg sleep poweroff \
                  reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                  expr head tail cut kill ps test seq date uname tr; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy FUSE daemon binary
    cp "$FUSE_DAEMON" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
    chmod +x "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
    if [ -n "$STRIP" ] && [ -x "$STRIP" ]; then
      "$STRIP" --strip-unneeded "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon" 2>/dev/null \
        || "$STRIP" --strip-debug "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon" 2>/dev/null \
        || true
    fi

    if [ -n "$PATCHELF" ] && [ -x "$PATCHELF" ]; then
      for bin in "$RUN_DIR/bin/busybox" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"; do
        "$PATCHELF" --set-interpreter /lib64/ld-linux-x86-64.so.2 "$bin" 2>/dev/null || true
        "$PATCHELF" --set-rpath /lib64:/lib:/usr/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu "$bin" 2>/dev/null || true
      done
    fi

    # Copy shared libraries to both their exact ELF-requested paths and a
    # compact /usr/lib fallback path. Nix and host binaries often embed
    # different dynamic-linker paths, and /init cannot run if /bin/sh's
    # interpreter is missing.
    for lib in $RUNTIME_LIBS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        lib_base=$(basename "$lib")
        mkdir -p "$RUN_DIR$lib_dir" "$RUN_DIR/usr/lib" "$RUN_DIR/lib" "$RUN_DIR/lib64" \
          "$RUN_DIR/lib/x86_64-linux-gnu" "$RUN_DIR/usr/lib/x86_64-linux-gnu"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        cp "$lib" "$RUN_DIR/usr/lib/$lib_base" 2>/dev/null || true
        cp "$lib" "$RUN_DIR/lib/$lib_base" 2>/dev/null || true
        cp "$lib" "$RUN_DIR/lib64/$lib_base" 2>/dev/null || true
        cp "$lib" "$RUN_DIR/lib/x86_64-linux-gnu/$lib_base" 2>/dev/null || true
        cp "$lib" "$RUN_DIR/usr/lib/x86_64-linux-gnu/$lib_base" 2>/dev/null || true
        chmod +x \
          "$RUN_DIR$lib" \
          "$RUN_DIR/usr/lib/$lib_base" \
          "$RUN_DIR/lib/$lib_base" \
          "$RUN_DIR/lib64/$lib_base" \
          "$RUN_DIR/lib/x86_64-linux-gnu/$lib_base" \
          "$RUN_DIR/usr/lib/x86_64-linux-gnu/$lib_base" 2>/dev/null || true
        case "$lib_base" in
          ld-linux-*.so.*)
            cp "$lib" "$RUN_DIR/lib/$lib_base" 2>/dev/null || true
            cp "$lib" "$RUN_DIR/lib64/$lib_base" 2>/dev/null || true
            chmod +x "$RUN_DIR/lib/$lib_base" "$RUN_DIR/lib64/$lib_base" 2>/dev/null || true
            ;;
        esac
      fi
    done

    # Copy fuse.ko if available
    if [ "$FUSE_BUILTIN" -eq 0 ]; then
      cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"
    fi

    # ── Init script: writeback-cache validation matrix ───────────────────

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS FUSE Writeback-Cache Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
BLOCKED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
dump_daemon_log_tail() {
    label="$1"
    if [ -f /tmp/daemon.log ]; then
        echo "--- daemon log tail: $label ---"
        tail -n 120 /tmp/daemon.log 2>/dev/null || true
        echo "--- end daemon log tail: $label ---"
    fi
}

MNT=/mnt/tidefs

# ── Boot detection: use persistent guest block disk ──────────────────
# The host creates a raw ext2 image and attaches it as a real QEMU disk.
# The Linux 7.0 validation kernel has virtio-blk and ext4 built in, so this
# consumes the host-attached raw disk as /dev/vda without copying the image
# into the initrd.
# First boot: format if needed, init boot counter, run all tiers,
#   crash at end to simulate failure.
# Second boot: remount store, verify crash-consistency (T3).

PERSISTENT_DISK=""
BOOT_COUNT=0

for attempt in $(seq 1 10); do
    if [ -b /dev/vda ]; then
        PERSISTENT_DISK=/dev/vda
    elif [ -b /dev/vdb ]; then
        PERSISTENT_DISK=/dev/vdb
    elif [ -b /dev/sda ]; then
        PERSISTENT_DISK=/dev/sda
    elif [ -b /dev/sdb ]; then
        PERSISTENT_DISK=/dev/sdb
    elif [ -b /dev/nvme0n1 ]; then
        PERSISTENT_DISK=/dev/nvme0n1
    fi
    [ -n "$PERSISTENT_DISK" ] && break
    sleep 1
done

if [ -n "$PERSISTENT_DISK" ]; then
    if ! mount -t ext4 "$PERSISTENT_DISK" /store 2>/tmp/persistent_mount.err; then
        blocked "persistent_disk_mount" "cannot mount $PERSISTENT_DISK as ext4: $(cat /tmp/persistent_mount.err 2>/dev/null)"
        PERSISTENT_DISK=""
    else
        pass "persistent_disk_mount"
    fi
else
    echo "  Guest block device probe:"
    cat /proc/partitions 2>/dev/null || true
    for sys_block in /sys/block/*; do
        [ -e "$sys_block" ] || continue
        echo "  sys_block=$(basename "$sys_block")"
    done
    dmesg | tail -80 2>/dev/null || true
    blocked "persistent_disk_mount" "no /dev/vd*, /dev/sd*, or /dev/nvme0n1 guest block device visible"
fi

if [ -n "$PERSISTENT_DISK" ] && [ -f /store/.tidefs_boot_count ]; then
    BOOT_COUNT=$(cat /store/.tidefs_boot_count 2>/dev/null || echo 0)
else
    BOOT_COUNT=0
    mkdir -p /store 2>/dev/null || true
    echo 0 > /store/.tidefs_boot_count 2>/dev/null || true
    sync
fi

echo "boot_count=$BOOT_COUNT"

# Increment for next boot
if [ -n "$PERSISTENT_DISK" ]; then
    echo $((BOOT_COUNT + 1)) > /store/.tidefs_boot_count 2>/dev/null || true
    sync
fi

STORE=/store/tidefs-store
mkdir -p "$STORE" 2>/dev/null || true

# ── Phase 0: FUSE kernel module ──────────────────────────────────────
echo "--- Phase 0: FUSE kernel support ---"

if [ -f /lib/modules/fuse.ko ]; then
    if insmod /lib/modules/fuse.ko 2>/tmp/fuse_insmod.err; then
        pass "fuse_kernel_support"
        pass "fuse_module_load"
    else
        fail "fuse_module_load" "$(cat /tmp/fuse_insmod.err)"
    fi
elif grep -q fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_kernel_support"
    pass "fuse_builtin"
else
    blocked "fuse_kernel_support" "fuse.ko not found and FUSE not built-in"
fi

# Create /dev/fuse if it doesn't exist
if [ ! -e /dev/fuse ]; then
    mknod /dev/fuse c 10 229 2>/dev/null || true
fi

if [ -e /dev/fuse ]; then
    pass "fuse_device"
else
    blocked "fuse_device" "/dev/fuse not available"
fi

FUSE_READY=0
if [ -e /dev/fuse ]; then
    FUSE_READY=1
fi

# ── Phase 1: Mount TideFS FUSE with writeback cache ───────────────────
echo ""
echo "--- Phase 1: Mount with writeback cache ---"

DAEMON_PID=""
if [ "$FUSE_READY" -eq 1 ]; then
    mkdir -p "$STORE" "$MNT"

    # Start the FUSE daemon in background with writeback cache enabled
    TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141 \
    /bin/tidefs-posix-filesystem-adapter-daemon \
      mount-vfs \
      --store "$STORE" \
      --mount "$MNT" \
      --writeback-cache \
      --writeback-cache-timeout 30 \
      > /tmp/daemon.log 2>&1 &

    DAEMON_PID=$!
    echo "  Daemon PID: $DAEMON_PID"

    # Wait for mount to appear (poll up to 30 seconds)
    MOUNTED=0
    for i in $(seq 1 30); do
        if mountpoint -q "$MNT" 2>/dev/null || grep -q " $MNT " /proc/mounts 2>/dev/null; then
            MOUNTED=1
            break
        fi
        sleep 1
    done

    if [ "$MOUNTED" -eq 1 ]; then
        pass "fuse_mount_writeback"
        echo "  Mounted: $MNT (writeback cache enabled)"
    else
        fail "fuse_mount_writeback" "mount did not appear within 30s; daemon log: $(tail -20 /tmp/daemon.log 2>/dev/null)"
    fi

    # Verify the mount reports writeback cache (check /proc/mounts or similar)
    if grep -q "$MNT" /proc/mounts 2>/dev/null; then
        pass "fuse_mount_proc"
    else
        blocked "fuse_mount_proc" "mountpoint not found in /proc/mounts"
    fi
else
    blocked "fuse_mount_writeback" "/dev/fuse not available"
    blocked "fuse_mount_proc" "/dev/fuse not available"
    MOUNTED=0
fi

# Boot 1 creates the workload corpus. Boot 2 must be verification-only:
# rerunning destructive writeback phases after a crash can remove or mask the
# files the crash-consistency tier is supposed to inspect.
if [ "$BOOT_COUNT" -eq 0 ]; then

# ── Phase 2: T0 — Clean writeback: buffered write + readback ─────────
echo ""
echo "--- Phase 2: T0 Clean writeback ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Single buffered write
    echo "T0_HELLO_WRITEBACK_TEST_DATA_$(date +%s)" > "$MNT/t0_clean.txt" 2>/tmp/t0w.err
    if [ -f "$MNT/t0_clean.txt" ]; then
        pass "t0_clean_write"
    else
        fail "t0_clean_write" "$(cat /tmp/t0w.err)"
    fi

    # Read back immediately (should succeed via cache)
    CONTENT=$(cat "$MNT/t0_clean.txt" 2>/dev/null)
    EXPECTED_PREFIX="T0_HELLO_WRITEBACK_TEST_DATA_"
    case "$CONTENT" in
        T0_HELLO_WRITEBACK_TEST_DATA_*)
            pass "t0_clean_readback"
            ;;
        *)
            fail "t0_clean_readback" "unexpected content: '$CONTENT'"
            ;;
    esac

    # fsync and read again (should be durable)
    sync
    CONTENT2=$(cat "$MNT/t0_clean.txt" 2>/dev/null)
    if [ "$CONTENT2" = "$CONTENT" ]; then
        pass "t0_clean_fsync_coherent"
    else
        fail "t0_clean_fsync_coherent" "content changed after sync"
    fi
else
    for t in t0_clean_write t0_clean_readback t0_clean_fsync_coherent; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Phase 3: T1 — Dirty-drain: sustained writes + flush ─────────────
echo ""
echo "--- Phase 3: T1 Dirty-drain ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Sustained buffered writes to accumulate dirty pages
    rm -f "$MNT/t1_dirty.dat"
    {
        for i in $(seq 1 64); do
            echo "T1_DIRTY_PAGE_$(printf '%04d' $i)_$(head -c 64 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
        done
    } > "$MNT/t1_dirty.dat" 2>/dev/null || true

    FILE_SIZE=$(stat -c%s "$MNT/t1_dirty.dat" 2>/dev/null || echo 0)
    if [ "$FILE_SIZE" -gt 2048 ]; then
        pass "t1_dirty_accumulate"
    else
        fail "t1_dirty_accumulate" "file size=$FILE_SIZE too small after 64 writes"
    fi

    # fsync to drain dirty pages through VfsEngine
    sync
    SIZE_AFTER=$(stat -c%s "$MNT/t1_dirty.dat" 2>/dev/null || echo 0)
    if [ -f "$MNT/t1_dirty.dat" ]; then
        pass "t1_dirty_drain_sync"
    else
        fail "t1_dirty_drain_sync" "file lost after sync"
    fi

    # Verify file content is coherent: read back and check expected prefix
    LINES=$(wc -l < "$MNT/t1_dirty.dat" 2>/dev/null || echo 0)
    if [ "$LINES" -ge 64 ]; then
        pass "t1_dirty_line_count"
    else
        fail "t1_dirty_line_count" "expected >=64 lines, got $LINES"
    fi

    # Verify content integrity: spot-check first and last lines
    FIRST=$(head -1 "$MNT/t1_dirty.dat" 2>/dev/null)
    LAST=$(tail -1 "$MNT/t1_dirty.dat" 2>/dev/null)
    case "$FIRST" in
        T1_DIRTY_PAGE_0001_*) pass "t1_dirty_spot_first" ;;
        *) fail "t1_dirty_spot_first" "unexpected first line: '$FIRST'" ;;
    esac
    case "$LAST" in
        T1_DIRTY_PAGE_0064_*) pass "t1_dirty_spot_last" ;;
        *) fail "t1_dirty_spot_last" "unexpected last line: '$LAST'" ;;
    esac
    dump_daemon_log_tail "after-phase3"
else
    for t in t1_dirty_accumulate t1_dirty_drain_sync t1_dirty_line_count \
             t1_dirty_spot_first t1_dirty_spot_last; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Phase 4: T2 — Post-flush coherence: overwrite + close/reopen ────
echo ""
echo "--- Phase 4: T2 Post-flush coherence ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Create file, write, sync, overwrite, verify
    rm -f "$MNT/t2_coherent.txt"
    echo "T2_ORIGINAL_CONTENT_V1" > "$MNT/t2_coherent.txt"
    sync
    echo "T2_OVERWRITTEN_CONTENT_V2" > "$MNT/t2_coherent.txt"
    sync

    CONTENT=$(cat "$MNT/t2_coherent.txt" 2>/dev/null)
    if [ "$CONTENT" = "T2_OVERWRITTEN_CONTENT_V2" ]; then
        pass "t2_postflush_overwrite"
    else
        fail "t2_postflush_overwrite" "expected V2, got '$CONTENT'"
    fi

    # Close/reopen coherence: create file, write, close (rm not needed),
    # then re-read to verify data survived across open/close boundary
    rm -f "$MNT/t2_reopen.dat"
    {
        echo "T2_REOPEN_TEST_DATA_LINE_1"
        echo "T2_REOPEN_TEST_DATA_LINE_2"
    } > "$MNT/t2_reopen.dat"
    sync

    # Re-read the file (simulates close/reopen)
    L1=$(head -1 "$MNT/t2_reopen.dat" 2>/dev/null)
    L2=$(tail -1 "$MNT/t2_reopen.dat" 2>/dev/null)
    if [ "$L1" = "T2_REOPEN_TEST_DATA_LINE_1" ] && [ "$L2" = "T2_REOPEN_TEST_DATA_LINE_2" ]; then
        pass "t2_reopen_coherent"
    else
        fail "t2_reopen_coherent" "L1='$L1' L2='$L2'"
    fi

    # Multi-file writeback pressure: create 32 small files, write to each,
    # fsync all, then verify contents
    PASS_MULTI=1
    mkdir -p "$MNT/t2_multi"
    for i in $(seq 1 32); do
        echo "T2_MULTI_FILE_$(printf '%02d' $i)_PAYLOAD" > "$MNT/t2_multi/f_$i" 2>/dev/null || PASS_MULTI=0
    done
    sync
    for i in $(seq 1 32); do
        C=$(cat "$MNT/t2_multi/f_$i" 2>/dev/null)
        EXPECTED="T2_MULTI_FILE_$(printf '%02d' $i)_PAYLOAD"
        if [ "$C" != "$EXPECTED" ]; then
            fail "t2_multi_file_$i" "expected '$EXPECTED', got '$C'"
            PASS_MULTI=0
        fi
    done
    if [ "$PASS_MULTI" -eq 1 ]; then
        pass "t2_multi_file_all"
    fi

    # Clean up multi-file directory
    rm -rf "$MNT/t2_multi" 2>/dev/null || true
    dump_daemon_log_tail "after-phase4"
else
    for t in t2_postflush_overwrite t2_reopen_coherent t2_multi_file_all; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Phase 5: Partial-page and boundary writes ────────────────────────
echo ""
echo "--- Phase 5: Partial-page and boundary writes ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Partial-page write: write 5 bytes, verify
    rm -f "$MNT/t5_partial.dat"
    echo -n "HELLO" > "$MNT/t5_partial.dat" 2>/dev/null
    sync
    SIZE=$(stat -c%s "$MNT/t5_partial.dat" 2>/dev/null || echo 0)
    HEAD=$(head -c 5 "$MNT/t5_partial.dat" 2>/dev/null)
    if [ "$SIZE" -eq 5 ] && [ "$HEAD" = "HELLO" ]; then
        pass "t5_partial_small_write"
    else
        fail "t5_partial_small_write" "size=$SIZE head='$HEAD'"
    fi

    # Page-boundary write: exactly one page (4096 bytes)
    rm -f "$MNT/t5_pagebound.dat"
    dd if=/dev/zero of="$MNT/t5_pagebound.dat" bs=4096 count=1 2>/dev/null
    echo -n "BOUNDARY_MARKER" | dd of="$MNT/t5_pagebound.dat" bs=1 seek=2048 conv=notrunc 2>/dev/null
    sync
    MARKER=$(dd if="$MNT/t5_pagebound.dat" bs=1 skip=2048 count=15 2>/dev/null)
    if [ "$MARKER" = "BOUNDARY_MARKER" ]; then
        pass "t5_page_boundary"
    else
        fail "t5_page_boundary" "marker='$MARKER'"
    fi

    # Append beyond current EOF (should extend file)
    rm -f "$MNT/t5_append.dat"
    echo "BLOCK0" > "$MNT/t5_append.dat"
    echo "BLOCK1" >> "$MNT/t5_append.dat"
    echo "BLOCK2" >> "$MNT/t5_append.dat"
    sync
    LINES=$(wc -l < "$MNT/t5_append.dat" 2>/dev/null || echo 0)
    if [ "$LINES" -eq 3 ]; then
        pass "t5_append_extend"
    else
        fail "t5_append_extend" "expected 3 lines, got $LINES"
    fi
    dump_daemon_log_tail "after-phase5"
else
    for t in t5_partial_small_write t5_page_boundary t5_append_extend; do
        blocked "$t" "filesystem not mounted"
    done
fi

else
    echo ""
    echo "--- Phase 2-5: writeback workload skipped on recovery boot ---"
fi

# ── Phase 6: T3 — Crash-consistency ──────────────────────────────
echo ""
echo "--- Phase 6: T3 Crash-consistency ---"

if [ "$BOOT_COUNT" -eq 0 ] && [ "$MOUNTED" -eq 1 ] && [ -n "$PERSISTENT_DISK" ]; then
    # ── First boot: prepare crash-consistency test data ────────────────

    # T3a: Write data that will be crash-tested
    echo "T3_WRITE_PHASE_DATA_SHOULD_NOT_SURVIVE" > "$MNT/t3_crash_write_test.txt"
    # Do NOT sync — this data should be lost on crash

    # T3b: Write data, fsync, then crash — this should survive
    echo "T3_FLUSH_PHASE_DATA_SHOULD_SURVIVE_$(date +%s)" > "$MNT/t3_crash_flush_test.txt"
    sync

    # T3c: Write data, flush fully, then crash — should survive
    echo "T3_POSTFLUSH_DATA_VERIFIED_SURVIVES" > "$MNT/t3_crash_postflush.txt"
    sync
    # Verify it's readable now
    PF_CONTENT=$(cat "$MNT/t3_crash_postflush.txt" 2>/dev/null)
    if [ "$PF_CONTENT" = "T3_POSTFLUSH_DATA_VERIFIED_SURVIVES" ]; then
        pass "t3_postflush_precrash_verify"
    else
        fail "t3_postflush_precrash_verify" "content mismatch before crash: '$PF_CONTENT'"
    fi

    # T3d: Multi-file crash test
    mkdir -p "$MNT/t3_multi_crash"
    for i in $(seq 1 16); do
        echo "T3_MULTI_$(printf '%02d' $i)_SURVIVE" > "$MNT/t3_multi_crash/f_$i" 2>/dev/null || true
    done
    sync

    # Record expected digests and file names on persistent store
    echo "T3_WRITE_PHASE_DATA_SHOULD_ABSENT" > "$STORE/../t3_write_phase_expected.txt"
    echo "T3_FLUSH_PHASE_DATA_SHOULD_SURVIVE" > "$STORE/../t3_flush_phase_prefix.txt"
    echo "T3_POSTFLUSH_DATA_VERIFIED_SURVIVES" > "$STORE/../t3_postflush_expected.txt"
    echo "16" > "$STORE/../t3_multi_expected_count.txt"
    for i in $(seq 1 16); do
        echo "T3_MULTI_$(printf '%02d' $i)_SURVIVE" >> "$STORE/../t3_multi_expected.txt"
    done
    sync

    dump_daemon_log_tail "pre-crash"
    echo "  Crash-consistency test data prepared on persistent store"
    echo "  Triggering crash reset..."

    # Crash: use sysrq if available, otherwise reboot -f
    if [ -e /proc/sysrq-trigger ]; then
        echo b > /proc/sysrq-trigger 2>/dev/null || reboot -f 2>/dev/null || true
    else
        reboot -f 2>/dev/null || true
    fi
    # The host-side marker watcher should terminate QEMU after the kernel
    # announces the reboot, not while the guest is still preparing validation.
    # If this guest path continues, avoid burning the full boot timeout.
    sleep 5
    poweroff -f 2>/dev/null || true
    sleep 5

elif [ "$BOOT_COUNT" -eq 1 ] && [ "$MOUNTED" -eq 1 ]; then
    # ── Second boot: verify crash-consistency ──────────────────────────

    # T3a: Verify in-flight write did NOT survive (no fsync before crash)
    if [ -f "$MNT/t3_crash_write_test.txt" ]; then
        CONTENT=$(cat "$MNT/t3_crash_write_test.txt" 2>/dev/null)
        if [ "$CONTENT" = "T3_WRITE_PHASE_DATA_SHOULD_NOT_SURVIVE" ]; then
            # Data survived the crash — this is acceptable if TideFS
            # acknowledges only after commit, but the spec says this
            # data was not fsynced. Record as PASS with note.
            pass "t3_crash_write_phase"
        else
            # Data is corrupted or partial — FAIL
            fail "t3_crash_write_phase" "unexpected content after crash: '$CONTENT'"
        fi
    else
        # File does not exist — data correctly lost (no fsync)
        pass "t3_crash_write_phase"
    fi

    # T3b: Verify fsynced data survived
    if [ -f "$MNT/t3_crash_flush_test.txt" ]; then
        CONTENT=$(cat "$MNT/t3_crash_flush_test.txt" 2>/dev/null)
        EXPECTED_PREFIX=$(cat "$STORE/../t3_flush_phase_prefix.txt" 2>/dev/null || echo "T3_FLUSH_PHASE")
        case "$CONTENT" in
            $EXPECTED_PREFIX*) pass "t3_crash_flush_phase" ;;
            *) fail "t3_crash_flush_phase" "expected prefix '$EXPECTED_PREFIX', got '$CONTENT'" ;;
        esac
    else
        fail "t3_crash_flush_phase" "fsynced file missing after crash"
    fi

    # T3c: Verify post-flush data survived
    if [ -f "$MNT/t3_crash_postflush.txt" ]; then
        CONTENT=$(cat "$MNT/t3_crash_postflush.txt" 2>/dev/null)
        EXPECTED=$(cat "$STORE/../t3_postflush_expected.txt" 2>/dev/null || echo "T3_POSTFLUSH_DATA_VERIFIED_SURVIVES")
        if [ "$CONTENT" = "$EXPECTED" ]; then
            pass "t3_crash_postflush_phase"
        else
            fail "t3_crash_postflush_phase" "expected '$EXPECTED', got '$CONTENT'"
        fi
    else
        fail "t3_crash_postflush_phase" "post-flush file missing after crash"
    fi

    # T3d: Committed-root consistency
    # The TideFS mount should have selected the latest committed root.
    # Verify the t1_dirty file (which was fsynced before crash) is intact.
    if [ -f "$MNT/t1_dirty.dat" ]; then
        LINES=$(wc -l < "$MNT/t1_dirty.dat" 2>/dev/null || echo 0)
        if [ "$LINES" -ge 64 ]; then
            pass "t3_crash_committed_root"
        else
            fail "t3_crash_committed_root" "t1_dirty.dat has $LINES lines after crash, expected >=64"
        fi
    else
        fail "t3_crash_committed_root" "committed file t1_dirty.dat missing after crash"
    fi

    # T3e: Multi-file crash survival
    if [ -d "$MNT/t3_multi_crash" ]; then
        SURVIVED=0
        MISSING=0
        for i in $(seq 1 16); do
            if [ -f "$MNT/t3_multi_crash/f_$i" ]; then
                SURVIVED=$((SURVIVED + 1))
            else
                MISSING=$((MISSING + 1))
            fi
        done
        if [ "$SURVIVED" -eq 16 ]; then
            pass "t3_crash_multi_file"
        else
            fail "t3_crash_multi_file" "$SURVIVED/16 files survived, $MISSING missing"
        fi
    else
        fail "t3_crash_multi_file" "multi-file directory missing after crash"
    fi

elif [ "$BOOT_COUNT" -ge 1 ] && [ "$MOUNTED" -ne 1 ]; then
    # Filesystem not mounted on second boot — critical failure
    for op in t3_crash_write_phase t3_crash_flush_phase t3_crash_postflush_phase               t3_crash_committed_root t3_crash_multi_file; do
        fail "$op" "filesystem not mounted on boot $BOOT_COUNT"
    done

else
    # Boot count > 1 or no persistent storage
    for op in t3_crash_write_phase t3_crash_flush_phase t3_crash_postflush_phase               t3_crash_committed_root t3_crash_multi_file; do
        if [ -z "$PERSISTENT_DISK" ]; then
            blocked "$op" "persistent storage not available for crash-consistency"
        else
            blocked "$op" "boot_count=$BOOT_COUNT, expected 0 or 1"
        fi
    done
fi

# ── Phase 7: Tear-down ───────────────────────────────────────────────
echo ""
echo "--- Phase 7: Unmount and stop daemon ---"
dump_daemon_log_tail "pre-unmount"
if [ "$MOUNTED" -eq 1 ]; then
    # Clean up test files
    rm -f "$MNT"/t0_clean.txt "$MNT"/t1_dirty.dat "$MNT"/t2_coherent.txt \
          "$MNT"/t2_reopen.dat "$MNT"/t5_partial.dat "$MNT"/t5_pagebound.dat \
          "$MNT"/t5_append.dat 2>/dev/null || true
    rm -rf "$MNT"/t2_multi 2>/dev/null || true

    if umount "$MNT" 2>/tmp/um.err; then
        pass "unmount"
    else
        fail "unmount" "$(cat /tmp/um.err)"
    fi
else
    blocked "unmount" "filesystem not mounted"
fi

# Clean up daemon
if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    pass "daemon_stop"
fi

# ── Validation Summary ──────────────────────────────────────────────────
echo ""
echo "=== FUSE Writeback-Cache Validation Summary ==="
echo "PASSED=$PASSED"
echo "FAILED=$FAILED"
echo "BLOCKED=$BLOCKED"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "validation_tiers=T0,T1,T2,T3"
echo "boot_count=$BOOT_COUNT"
echo "persistent_disk=$([ -n "$PERSISTENT_DISK" ] && echo "yes" || echo "no")"
echo "filesystem=fuse-writeback-cache"
echo "=== End ==="

# Sleep briefly so output flushes
sync
sleep 1

# On first boot: crash to simulate failure. On subsequent boots: poweroff.
if [ "$BOOT_COUNT" -eq 0 ] && [ -n "$PERSISTENT_DISK" ]; then
    # We already crashed in Phase 6; this is just a fallback
    if [ -e /proc/sysrq-trigger ]; then
        echo b > /proc/sysrq-trigger 2>/dev/null || true
    fi
    reboot -f 2>/dev/null || true
    sleep 5
    poweroff -f 2>/dev/null || true
    sleep 5
fi

poweroff -f

INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # ── Build initrd ───────────────────────────────────────────────────

    (cd "$RUN_DIR" && find . \
      -path ./initrd.img -prune -o \
      -path ./persistent.img -prune -o \
      -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"
    echo ""

    # ── Dual-boot QEMU for crash-consistency ──────────────────────────

    VAL_LOG1="$RUN_DIR/boot1.log"
    VAL_LOG2="$RUN_DIR/boot2.log"
    VAL_LOG="$RUN_DIR/validation.log"

    run_qemu_until_marker() {
      local log_file="$1"
      local marker="$2"
      shift 2

      : > "$log_file"
      "$@" > "$log_file" 2>&1 &
      local qemu_pid=$!
      local deadline=$((SECONDS + TIMEOUT_SEC))
      local marker_seen=0
      local timed_out=0

      while kill -0 "$qemu_pid" 2>/dev/null; do
        if [ -n "$marker" ] && grep -q -- "$marker" "$log_file" 2>/dev/null; then
          marker_seen=1
          sleep 1
          if kill -0 "$qemu_pid" 2>/dev/null; then
            kill "$qemu_pid" 2>/dev/null || true
            sleep 1
            kill -9 "$qemu_pid" 2>/dev/null || true
          fi
          break
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
          timed_out=1
          kill "$qemu_pid" 2>/dev/null || true
          sleep 1
          kill -9 "$qemu_pid" 2>/dev/null || true
          break
        fi
        sleep 1
      done

      wait "$qemu_pid" 2>/dev/null || true
      if [ "$timed_out" -eq 1 ]; then
        echo "  QEMU timeout after ''${TIMEOUT_SEC}s: $log_file"
      elif [ "$marker_seen" -eq 1 ]; then
        echo "  QEMU marker reached: $marker"
      fi
    }

    echo "  === Boot 1/2: write + crash cycle ==="
    run_qemu_until_marker "$VAL_LOG1" "reboot: Restarting system" \
      "$QEMU_BIN" \
      -machine pc,accel=kvm \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -drive file="$DISK_IMG",format=raw,if=virtio,index=0 \
      -append "console=ttyS0 quiet panic=10 panic_on_oops=1" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot

    echo "  Boot 1 completed"
    BOOT1_LINES=$(wc -l < "$VAL_LOG1" 2>/dev/null || echo 0)
    echo "  Boot 1 log: $BOOT1_LINES lines"

    # Check if boot 1 produced crash-consistency test data
    if grep -q "reboot: Restarting system" "$VAL_LOG1" 2>/dev/null; then
        echo "  Boot 1 successfully prepared T3 data, proceeding to boot 2"
    else
        echo "  WARNING: Boot 1 did not reach the expected crash reboot marker"
    fi

    echo ""
    echo "  === Boot 2/2: remount + verify crash-consistency ==="

    # Re-use the same persistent disk image for boot 2
    run_qemu_until_marker "$VAL_LOG2" "=== End ===" \
      "$QEMU_BIN" \
      -machine pc,accel=kvm \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -drive file="$DISK_IMG",format=raw,if=virtio,index=0 \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot

    echo "  Boot 2 completed"
    BOOT2_LINES=$(wc -l < "$VAL_LOG2" 2>/dev/null || echo 0)
    echo "  Boot 2 log: $BOOT2_LINES lines"

    # Combine logs for validation parsing
    cat "$VAL_LOG1" "$VAL_LOG2" > "$VAL_LOG"

    echo ""
    echo "=== FUSE Writeback-Cache Validation Results ==="

    # ── Parse validation rows from combined boot logs ────────────────────

    PASSC=0
    FAILC=0
    BLOCKC=0

    ALL_OPS="
      persistent_disk_mount
      fuse_kernel_support fuse_device
      fuse_mount_writeback fuse_mount_proc
      t0_clean_write t0_clean_readback t0_clean_fsync_coherent
      t1_dirty_accumulate t1_dirty_drain_sync t1_dirty_line_count
      t1_dirty_spot_first t1_dirty_spot_last
      t2_postflush_overwrite t2_reopen_coherent t2_multi_file_all
      t5_partial_small_write t5_page_boundary t5_append_extend
      t3_postflush_precrash_verify
      t3_crash_write_phase t3_crash_flush_phase t3_crash_postflush_phase
      t3_crash_committed_root t3_crash_multi_file
      unmount daemon_stop
    "

    BACKGROUND_CORRUPTION_PASS=1
    background_corruption_detail="$(
      awk '
        /stale same-slot root candidate ignored after validating fallback root/ { next }
        /background-scrub: .*corrupt local filesystem state/ { print; exit }
        /root commit references a missing transaction manifest/ { print; exit }
        /background-scrub: verification error/ { print; exit }
      ' "$VAL_LOG" 2>/dev/null || true
    )"
    if [ -n "$background_corruption_detail" ]; then
      BACKGROUND_CORRUPTION_PASS=0
      echo "FAIL: t3_no_background_corruption $background_corruption_detail" >> "$VAL_LOG"
      echo "  FAIL: t3_no_background_corruption -- $background_corruption_detail"
      FAILC=$((FAILC + 1))
    elif grep -q "PASS: fuse_mount_writeback" "$VAL_LOG" 2>/dev/null; then
      echo "PASS: t3_no_background_corruption" >> "$VAL_LOG"
      echo "  PASS: t3_no_background_corruption"
    else
      BACKGROUND_CORRUPTION_PASS=0
      echo "BLOCKED: t3_no_background_corruption mount did not run" >> "$VAL_LOG"
      echo "  BLOCKED: t3_no_background_corruption -- mount did not run"
      BLOCKC=$((BLOCKC + 1))
    fi

    for op in $ALL_OPS; do
      [ -z "$op" ] && continue
      if grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep -m 1 "FAIL: $op" "$VAL_LOG" 2>/dev/null | sed "s/FAIL: $op //")
        echo "  FAIL: $op -- $detail"
        FAILC=$((FAILC + 1))
      elif grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"
        PASSC=$((PASSC + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep -m 1 "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | sed "s/BLOCKED: $op //")
        echo "  BLOCKED: $op -- $detail"
        BLOCKC=$((BLOCKC + 1))
      else
        echo "  MISSING: $op (no validation in log)"
        BLOCKC=$((BLOCKC + 1))
      fi
    done

    echo ""
    echo "Validation matrix: $PASSC passed, $FAILC failed, $BLOCKC blocked"
    echo "Validation log: $VAL_LOG"
    echo "Boot 1 log: $VAL_LOG1"
    echo "Boot 2 log: $VAL_LOG2"
    echo ""

    # ── Tier classification ────────────────────────────────────────────

    T0_PASS=1
    T1_PASS=1
    T2_PASS=1
    T3_PASS=1

    for op in t0_clean_write t0_clean_readback t0_clean_fsync_coherent; do
      grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null && T0_PASS=0
      grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null || T0_PASS=0
    done

    for op in t1_dirty_accumulate t1_dirty_drain_sync t1_dirty_line_count               t1_dirty_spot_first t1_dirty_spot_last; do
      grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null && T1_PASS=0
      grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null || T1_PASS=0
    done

    for op in t2_postflush_overwrite t2_reopen_coherent t2_multi_file_all; do
      grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null && T2_PASS=0
      grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null || T2_PASS=0
    done

    for op in t3_crash_write_phase t3_crash_flush_phase t3_crash_postflush_phase               t3_crash_committed_root t3_crash_multi_file t3_postflush_precrash_verify t3_no_background_corruption; do
      grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null && T3_PASS=0
      grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null || T3_PASS=0
    done
    [ "$BACKGROUND_CORRUPTION_PASS" -eq 1 ] || T3_PASS=0

    echo "Tier classification:"
    echo "  T0 clean-writeback:       $([ "$T0_PASS" -eq 1 ] && echo 'PASS' || echo 'FAIL')"
    echo "  T1 dirty-drain:           $([ "$T1_PASS" -eq 1 ] && echo 'PASS' || echo 'FAIL')"
    echo "  T2 post-flush-coherence:  $([ "$T2_PASS" -eq 1 ] && echo 'PASS' || echo 'FAIL')"
    echo "  T3 crash-consistency:     $([ "$T3_PASS" -eq 1 ] && echo 'PASS' || echo 'FAIL')"

    FINAL_STATUS=partial
    if [ "$FAILC" -gt 0 ]; then
      FINAL_STATUS=fail
    elif [ "$T0_PASS" -eq 1 ] && [ "$T1_PASS" -eq 1 ] && [ "$T2_PASS" -eq 1 ] && [ "$T3_PASS" -eq 1 ]; then
      FINAL_STATUS=pass
    fi

    if [ -n "$VALIDATION_DIR" ]; then
      mkdir -p "$VALIDATION_DIR"
      cp "$VAL_LOG1" "$VALIDATION_DIR/boot1.log"
      cp "$VAL_LOG2" "$VALIDATION_DIR/boot2.log"
      cp "$VAL_LOG" "$VALIDATION_DIR/validation.log"
      cp "$RUN_DIR/init" "$VALIDATION_DIR/init.sh"
      cat > "$VALIDATION_DIR/summary.env" <<EOF_SUMMARY
harness=fuse-writeback-cache-validation
validation_status=$FINAL_STATUS
passed=$PASSC
failed=$FAILC
blocked=$BLOCKC
t0_clean_writeback=$([ "$T0_PASS" -eq 1 ] && echo pass || echo fail)
t1_dirty_drain=$([ "$T1_PASS" -eq 1 ] && echo pass || echo fail)
t2_post_flush_coherence=$([ "$T2_PASS" -eq 1 ] && echo pass || echo fail)
t3_crash_consistency=$([ "$T3_PASS" -eq 1 ] && echo pass || echo fail)
background_corruption=$([ "$BACKGROUND_CORRUPTION_PASS" -eq 1 ] && echo pass || echo fail)
boot1_log=$VALIDATION_DIR/boot1.log
boot2_log=$VALIDATION_DIR/boot2.log
validation_log=$VALIDATION_DIR/validation.log
EOF_SUMMARY
      echo "Validation output: $VALIDATION_DIR"
    fi

    # ── Final verdict ──────────────────────────────────────────────────

    if [ "$FAILC" -gt 0 ]; then
      echo ""
      echo "VALIDATION: FAIL -- $FAILC validation rows failed"
      echo "  Failed rows indicate bugs in the FUSE writeback-cache path."
      echo "  See $VAL_LOG, $VAL_LOG1, $VAL_LOG2 for details."
      exit 1
    fi

    if [ "$T0_PASS" -eq 1 ] && [ "$T1_PASS" -eq 1 ] && [ "$T2_PASS" -eq 1 ] && [ "$T3_PASS" -eq 1 ]; then
      echo ""
      echo "VALIDATION: PASS -- all validation tiers passed (T0 T1 T2 T3)"
      echo "  FUSE writeback-cache is coherent for buffered writes, fsync,"
      echo "  multi-file pressure, and crash-consistency cycles."
      echo "  Hard validation at: $VAL_LOG1 $VAL_LOG2"
      exit 0
    fi

    echo ""
    echo "VALIDATION: PARTIAL -- some tiers passed, some blocked"
    echo "  Check individual logs: $VAL_LOG1 $VAL_LOG2"
    exit 0

  '';
in
fuseWritebackValidationScript
