# TideFS: FUSE fsx (with mmap) validation in QEMU.
#
# Mounts a TideFS FUSE filesystem inside a Linux 7.0 QEMU VM,
# runs the TideFS fsx exerciser with mmap operations, and produces
# tier-classified validation rows.
#
# Multi-seed corpus mode (--seeds <s1 s2 ...> or --seeds-file <path>):
#   Runs fsx once per seed against separate test files, records
#   per-seed pass/fail, and produces a seed-corpus manifest.
#
# Validation tier:
#   MountedUserspace  fsx results from live FUSE mount (QEMU)
{
  pkgs,
  patchelf,
  glibc,
  bash,
  linuxKernel_7_0,
  tidefsPackage,
  tidefsFsx,
  tidefsMmapWorkload ? null,
  flakeLock ? null,
}:

let
  fuseFsxValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-fsx-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    PATCHELF="${patchelf}/bin/patchelf"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    GLIBC_LIB="${glibc}/lib"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    FSX_BIN="${tidefsFsx}/bin/fsx"
    MMAP_BIN="${tidefsMmapWorkload}/bin/tidefs-mmap-workload"
    XTAST_BIN="${tidefsPackage}/bin/tidefs-xtask"
    FLAKE_LOCK="${flakeLock}"  # Nix store path to flake.lock

    TMPDIR="''${TIDEFS_FUSE_FSX_TMPDIR:-/tmp/tidefs-fuse-fsx-validation}"
    TIMEOUT_SEC="''${TIDEFS_FUSE_FSX_TIMEOUT:-300}"
    N_OPS="''${TIDEFS_FUSE_FSX_NOPS:-128}"
    SEEDS=""          # space-separated seed list (empty = single random-seed run)

    KEEP_TMP=0
    JSON_OUT=""

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --seeds) SEEDS="$2"; shift 2 ;;
        --seeds-file)
          if [ -f "$2" ]; then
            SEEDS="$(grep -v '^#' "$2" | grep -v '^$' | tr '\n' ' ' | sed 's/  */ /g' | xargs)"
          fi
          shift 2
          ;;
        --nops) N_OPS="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --output) JSON_OUT="$2"; shift 2 ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    # ── Environment preflight ──────────────────────────────────────────
    if [ ! -e /dev/kvm ]; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available" >&2
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$TIDEFSCTL" "$FSX_BIN"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    echo "=== TideFS FUSE fsx Validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  fsx:       $FSX_BIN"
    echo "  nops:      $N_OPS"
    if [ -n "$SEEDS" ]; then
      echo "  seeds:     $SEEDS (count=$(echo "$SEEDS" | wc -w))"
    else
      echo "  seed:      (random)"
    fi
    echo "  timeout:   ''${TIMEOUT_SEC}s"

    # ── Resolve fuse.ko ────────────────────────────────────────────────
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

    # ── Set up temp directory ──────────────────────────────────────────
    RUN_DIR="$TMPDIR/fsx-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,store,usr/lib}
    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping temp directory: $RUN_DIR"
      else
        rm -rf "$RUN_DIR"
      fi
    }
    trap cleanup EXIT

    # ── Populate initrd ────────────────────────────────────────────────
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                  reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                  expr head tail cut kill ps test seq du dirname basename \
                  readlink tr cmp diff mountpoint uname date umount truncate; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"
    cp "$FSX_BIN" "$RUN_DIR/bin/fsx"
    chmod +x "$RUN_DIR/bin/fsx"
    if [ -n "$MMAP_BIN" ] && [ -f "$MMAP_BIN" ]; then
      cp "$MMAP_BIN" "$RUN_DIR/bin/tidefs-mmap-workload"
      chmod +x "$RUN_DIR/bin/tidefs-mmap-workload"
    fi

    # Copy shared libraries BEFORE patchelf so ldd works on the original binaries
    if command -v ldd >/dev/null 2>&1; then
      for lib in $(ldd "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true); do
        [ -f "$lib" ] && cp "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      done
      # Also copy busybox dependencies
      for lib in $(ldd "$RUN_DIR/bin/busybox" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true); do
        [ -f "$lib" ] && cp "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      done
      LD_SO=$(ldd "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
      if [ -n "$LD_SO" ] && [ -f "$LD_SO" ]; then
        cp "$LD_SO" "$RUN_DIR/lib/" 2>/dev/null || true
        chmod +x "$RUN_DIR/lib/$(basename "$LD_SO")" 2>/dev/null || true
      fi
    else
      # ldd unavailable: copy glibc and essential runtime libraries
      for lib in ld-linux-x86-64.so.2 libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 libresolv.so.2 librt.so.1; do
        SRC=$(ls "$GLIBC_LIB"/$lib 2>/dev/null | head -1)
        if [ -n "$SRC" ] && [ -f "$SRC" ]; then
          cp "$SRC" "$RUN_DIR/usr/lib/" 2>/dev/null || true
        fi
      done
      # copy ld-linux to /lib as well (kernel needs it for the interpreter)
      LD_SO=$(ls "$GLIBC_LIB"/ld-linux-x86-64.so.2 2>/dev/null | head -1)
      if [ -n "$LD_SO" ] && [ -f "$LD_SO" ]; then
        cp "$LD_SO" "$RUN_DIR/lib/" 2>/dev/null || true
        chmod +x "$RUN_DIR/lib/ld-linux-x86-64.so.2" 2>/dev/null || true
      fi
      # Copy fuse3 library if present
      for fuse_lib in "$(dirname "$TIDEFSCTL")/../lib/libfuse3.so"* /nix/store/*/lib/libfuse3.so*; do
        if [ -f "$fuse_lib" ]; then
          cp "$fuse_lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
          break
        fi
      done
    fi


    # Fix ELF interpreter paths for initrd: reset to /lib/ld-linux-x86-64.so.2
    for bin in "$RUN_DIR/bin/busybox" "$RUN_DIR/bin/tidefsctl" "$RUN_DIR/bin/fsx"; do
      if [ -f "$bin" ]; then
        "$PATCHELF" --set-interpreter /lib/ld-linux-x86-64.so.2 "$bin" 2>/dev/null || true
        "$PATCHELF" --set-rpath /usr/lib:/lib "$bin" 2>/dev/null || true
      fi
    done

    if [ "$FUSE_BUILTIN" -eq 0 ]; then
      cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"
    fi

    # ── Init script ────────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS FUSE fsx Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASSED=0
FAILED=0
BLOCKED=0

pass()    { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()    { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

wait_for_pid_exit() {
    PID_TO_WAIT=$1
    WAIT_SECONDS=$2
    for _ in $(seq 1 "$WAIT_SECONDS"); do
        ! kill -0 "$PID_TO_WAIT" 2>/dev/null && return 0
        sleep 1
    done
    ! kill -0 "$PID_TO_WAIT" 2>/dev/null
}

stop_exact_mount_owner() {
    OWNER_PID=$1
    [ -n "$OWNER_PID" ] || return 0
    kill -0 "$OWNER_PID" 2>/dev/null || { wait "$OWNER_PID" 2>/dev/null || true; return 0; }
    kill "$OWNER_PID" 2>/dev/null || true
    if ! wait_for_pid_exit "$OWNER_PID" 10; then
        kill -KILL "$OWNER_PID" 2>/dev/null || true
    fi
    wait "$OWNER_PID" 2>/dev/null || true
}

MNT=/mnt/tidefs
DEVICE=/store/tidefs-device.tidefs
POOL=fsx_validation_pool
FSX_N=__FSX_NOPS__
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141

# ── Phase 0: FUSE kernel module ──────────────────────────────────────
FUSE_READY=0
if [ -f /lib/modules/fuse.ko ]; then
    if insmod /lib/modules/fuse.ko 2>/tmp/fuse_insmod.err; then
        pass "fuse_module_load"
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
    FUSE_READY=1
else
    blocked "fuse_device" "/dev/fuse not available"
fi

# ── Phase 1: Mount TideFS FUSE ──────────────────────────────────────
DAEMON_PID=""
MOUNTED=0
if [ "$FUSE_READY" -eq 1 ]; then
    mkdir -p "$MNT"
    truncate -s 1073741824 "$DEVICE"
    /bin/tidefsctl pool create "$POOL" --file-devices --devices "$DEVICE"
    /bin/tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" \
      > /tmp/daemon.log 2>&1 &
    DAEMON_PID=$!

    for i in $(seq 1 30); do
        if mountpoint -q "$MNT" 2>/dev/null; then
            MOUNTED=1
            break
        fi
        sleep 1
    done

    if [ "$MOUNTED" -eq 1 ]; then
        pass "fuse_mount"
    else
        fail "fuse_mount" "mountpoint did not appear within 30s (daemon log: $(tail -5 /tmp/daemon.log 2>/dev/null))"
    fi
else
    blocked "fuse_mount" "FUSE device not available"
fi

# ── Phase 2: fsx seed corpus ────────────────────────────────────────
# When SEEDS_STR is non-empty, loop over each seed deterministically.
# When empty, fall back to the original single-run random-seed mode.
SEEDS_STR="__FSX_SEEDS__"
if [ "$MOUNTED" -eq 1 ]; then
    if [ -n "$SEEDS_STR" ]; then
        for seed in $SEEDS_STR; do
            FSX_PATH="$MNT/fsx-seed-$seed"
            echo "=== fsx seed=$seed nops=$FSX_N ==="
            /bin/fsx -N "$FSX_N" -S "$seed" "$FSX_PATH" > "/tmp/fsx-seed-$seed.out" 2>&1
            RC=$?
            if [ "$RC" -eq 0 ]; then
                pass "fsx_seed_$seed" "PASS"
            else
                fail "fsx_seed_$seed" "exit=$RC"
            fi
        done
        echo "=== seed_corpus seeds_run=$(echo "$SEEDS_STR" | wc -w) ==="
    else
        FSX_PATH="$MNT/fsx-test-file"
        echo "Running fsx -N $FSX_N $FSX_PATH"
        /bin/fsx -N "$FSX_N" "$FSX_PATH" > /tmp/fsx.out 2>&1
        FSX_RC=$?
        echo "=== fsx output ==="
        cat /tmp/fsx.out
        echo "=== end fsx output ==="
        echo "=== full daemon log ==="
        cat /tmp/daemon.log 2>/dev/null || echo "(no daemon log)"
        echo "=== end daemon log ==="
        if [ "$FSX_RC" -eq 0 ]; then
            FSX_LINE=$(grep '^fsx:' /tmp/fsx.out | tail -1 || echo "no summary line")
            pass "fsx_mmap" "fsx: $FSX_LINE"
        else
            FSX_LINE=$(grep '^fsx:' /tmp/fsx.out | tail -1 || echo "no summary line")
            fail "fsx_mmap" "fsx exit=$FSX_RC: $FSX_LINE"
        fi
    fi
else
    if [ -n "$SEEDS_STR" ]; then
        for seed in $SEEDS_STR; do
            blocked "fsx_seed_$seed" "filesystem not mounted"
        done
    else
        blocked "fsx_mmap" "filesystem not mounted"
    fi
fi

# ── Phase 2b: mmap workload ──────────────────────────────────────────
MMAP_WORKLOAD_OK=0
if [ "$MOUNTED" -eq 1 ] && [ -x /bin/tidefs-mmap-workload ]; then
    MMAP_DIR="$MNT/mmap-workload"
    mkdir -p "$MMAP_DIR"

    echo "Running tidefs-mmap-workload $MMAP_DIR"
    if /bin/tidefs-mmap-workload "$MMAP_DIR" > /tmp/mmap.out 2>&1; then
        MMAP_RC=0
    else
        MMAP_RC=$?
    fi
    echo "=== mmap workload output ==="
    cat /tmp/mmap.out
    echo "=== end mmap workload output ==="
    PASS_LINES=$(grep -c '"outcome":"pass"' /tmp/mmap.out 2>/dev/null || true)
    FAIL_LINES=$(grep -c '"outcome":"fail"' /tmp/mmap.out 2>/dev/null || true)
    if [ "$MMAP_RC" -eq 0 ] && [ "$FAIL_LINES" -eq 0 ] && [ "$PASS_LINES" -gt 0 ]; then
        pass "mmap_workload" "$PASS_LINES tests passed"
        MMAP_WORKLOAD_OK=1
    else
        fail "mmap_workload" "exit=$MMAP_RC pass=$PASS_LINES fail=$FAIL_LINES"
    fi
elif [ "$MOUNTED" -eq 1 ]; then
    blocked "mmap_workload" "mmap workload binary not available"
else
    blocked "mmap_workload" "filesystem not mounted"
fi

# ── Phase 3: Clean unmount and Pool export ───────────────────────────
EXPORTED=0
if [ "$MOUNTED" -eq 1 ]; then
    if timeout -k 2 30 /bin/tidefsctl pool export "$POOL" --devices "$DEVICE" \
        > /tmp/export.out 2>/tmp/export.err; then
        EXPORT_RC=0
    else
        EXPORT_RC=$?
    fi
    if wait_for_pid_exit "$DAEMON_PID" 30; then
        if wait "$DAEMON_PID"; then
            DAEMON_RC=0
        else
            DAEMON_RC=$?
        fi
    else
        DAEMON_RC=124
    fi
    echo "=== initial export output ==="
    cat /tmp/export.out /tmp/export.err 2>/dev/null || true
    echo "=== initial mount daemon log ==="
    cat /tmp/daemon.log 2>/dev/null || true
    if [ "$EXPORT_RC" -eq 0 ] && [ "$DAEMON_RC" -eq 0 ] \
        && ! mountpoint -q "$MNT" 2>/dev/null; then
        pass "unmount"
        pass "pool_export"
        EXPORTED=1
        MOUNTED=0
    else
        fail "unmount" "export=$EXPORT_RC daemon=$DAEMON_RC mounted=$(mountpoint -q "$MNT" 2>/dev/null && echo yes || echo no)"
        fail "pool_export" "$(cat /tmp/export.out /tmp/export.err 2>/dev/null)"
        umount -l "$MNT" 2>/dev/null || true
        stop_exact_mount_owner "$DAEMON_PID"
        MOUNTED=0
    fi
    DAEMON_PID=""
else
    blocked "unmount" "filesystem not mounted"
    blocked "pool_export" "filesystem not mounted"
    stop_exact_mount_owner "$DAEMON_PID"
    DAEMON_PID=""
fi

# ── Phase 4: Pool reimport and remount ────────────────────────────────
REMOUNTED=0
REMOUNT_PID=""
if [ "$EXPORTED" -eq 1 ] && [ "$FUSE_READY" -eq 1 ]; then
    /bin/tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" \
        > /tmp/remount.log 2>&1 &
    REMOUNT_PID=$!
    for _ in $(seq 1 30); do
        if mountpoint -q "$MNT" 2>/dev/null; then
            REMOUNTED=1
            break
        fi
        ! kill -0 "$REMOUNT_PID" 2>/dev/null && break
        sleep 1
    done
    if [ "$REMOUNTED" -eq 1 ]; then
        if grep -q 'pool ".*" imported' /tmp/remount.log 2>/dev/null; then
            pass "pool_reimport"
        else
            fail "pool_reimport" "mount became ready without import record: $(tail -20 /tmp/remount.log 2>/dev/null)"
        fi
        pass "remount"
    else
        fail "pool_reimport" "$(tail -20 /tmp/remount.log 2>/dev/null)"
        fail "remount" "mountpoint did not reappear within 30s"
        stop_exact_mount_owner "$REMOUNT_PID"
        REMOUNT_PID=""
    fi
else
    blocked "pool_reimport" "clean export or FUSE unavailable"
    blocked "remount" "clean export or FUSE unavailable"
fi

# ── Phase 5: Exact mmap persistence after remount ─────────────────────
if [ "$REMOUNTED" -eq 1 ] && [ -x /bin/tidefs-mmap-workload ]; then
    if /bin/tidefs-mmap-workload --verify-persistence "$MNT/mmap-workload" \
        > /tmp/mmap-persist.out 2>&1; then
        PERSIST_RC=0
    else
        PERSIST_RC=$?
    fi
    echo "=== mmap persistence output ==="
    cat /tmp/mmap-persist.out
    echo "=== end mmap persistence output ==="
    PERSIST_PASS_LINES=$(grep -c '"outcome":"pass"' /tmp/mmap-persist.out 2>/dev/null || true)
    PERSIST_FAIL_LINES=$(grep -c '"outcome":"fail"' /tmp/mmap-persist.out 2>/dev/null || true)
    if [ "$MMAP_WORKLOAD_OK" -eq 1 ] && [ "$PERSIST_RC" -eq 0 ] \
        && [ "$PERSIST_PASS_LINES" -eq 2 ] && [ "$PERSIST_FAIL_LINES" -eq 0 ]; then
        pass "mmap_persistence" "two exact pages survived export/reimport/remount"
    else
        fail "mmap_persistence" "initial=$MMAP_WORKLOAD_OK exit=$PERSIST_RC pass=$PERSIST_PASS_LINES fail=$PERSIST_FAIL_LINES"
    fi
elif [ "$REMOUNTED" -eq 1 ]; then
    blocked "mmap_persistence" "mmap workload binary not available"
else
    blocked "mmap_persistence" "filesystem not remounted"
fi

# ── Phase 6: Final clean export ───────────────────────────────────────
if [ "$REMOUNTED" -eq 1 ]; then
    if timeout -k 2 30 /bin/tidefsctl pool export "$POOL" --devices "$DEVICE" \
        > /tmp/final-export.out 2>/tmp/final-export.err; then
        FINAL_EXPORT_RC=0
    else
        FINAL_EXPORT_RC=$?
    fi
    if wait_for_pid_exit "$REMOUNT_PID" 30; then
        if wait "$REMOUNT_PID"; then
            REMOUNT_RC=0
        else
            REMOUNT_RC=$?
        fi
    else
        REMOUNT_RC=124
    fi
    echo "=== final export output ==="
    cat /tmp/final-export.out /tmp/final-export.err 2>/dev/null || true
    echo "=== remount daemon log ==="
    cat /tmp/remount.log 2>/dev/null || true
    if [ "$FINAL_EXPORT_RC" -eq 0 ] && [ "$REMOUNT_RC" -eq 0 ] \
        && ! mountpoint -q "$MNT" 2>/dev/null; then
        pass "final_export"
    else
        fail "final_export" "export=$FINAL_EXPORT_RC daemon=$REMOUNT_RC mounted=$(mountpoint -q "$MNT" 2>/dev/null && echo yes || echo no)"
        umount -l "$MNT" 2>/dev/null || true
        stop_exact_mount_owner "$REMOUNT_PID"
    fi
    REMOUNT_PID=""
else
    blocked "final_export" "filesystem not remounted"
fi

# ── Validation Summary ──────────────────────────────────────────────────
echo ""
echo "=== FUSE fsx Validation Summary ==="
echo "PASSED=$PASSED"
echo "FAILED=$FAILED"
echo "BLOCKED=$BLOCKED"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "validation_tier=mounted-userspace"
echo "filesystem=fuse-fsx-mmap"
echo "=== End ==="

sync
sleep 1
poweroff -f
INITSCRIPT

    sed -i "s/__FSX_NOPS__/$N_OPS/g; s/__FSX_SEEDS__/$SEEDS/g" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    # ── Build initrd ───────────────────────────────────────────────────
    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

    # ── Run QEMU ──────────────────────────────────────────────────────
    VAL_LOG="$RUN_DIR/qemu-boot.log"

    echo "  Booting QEMU VM..."
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10 panic_on_oops=1" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo "  QEMU boot completed"

    # ── Parse validation rows ────────────────────────────────────────────
    echo ""
    echo "=== FUSE fsx Validation Results ==="

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

    # ── Produce validation record ────────────────────────────────────────
    COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
    EPOCH=$(date -u +%Y%m%dT%H%M%SZ)
    VALIDATION_DIR="$RUN_DIR/validation"
    mkdir -p "$VALIDATION_DIR"
    cp "$VAL_LOG" "$VALIDATION_DIR/qemu-boot.log"
    cp "$RUN_DIR/init" "$VALIDATION_DIR/init-script"

    # ── Seed corpus mode: enrich validation with per-seed results ──
    if [ -n "$SEEDS" ]; then
      SEED_PASSC=0; SEED_FAILC=0
      SEED_JSON="["
      FIRST=1
      for seed in $SEEDS; do
        RESULT="UNKNOWN"
        if grep -q "^PASS: fsx_seed_$seed" "$VAL_LOG" 2>/dev/null; then
          RESULT="PASS"; SEED_PASSC=$((SEED_PASSC + 1))
        elif grep -q "^FAIL: fsx_seed_$seed" "$VAL_LOG" 2>/dev/null; then
          RESULT="FAIL"; SEED_FAILC=$((SEED_FAILC + 1))
        elif grep -q "^BLOCKED: fsx_seed_$seed" "$VAL_LOG" 2>/dev/null; then
          RESULT="BLOCKED"
        fi
        if [ "$FIRST" -eq 1 ]; then FIRST=0; else SEED_JSON="$SEED_JSON,"; fi
        SEED_JSON="$SEED_JSON{\"seed\":\"$seed\",\"result\":\"$RESULT\"}"
      done
      SEED_JSON="$SEED_JSON]"
      cat > "$VALIDATION_DIR/seed-corpus.json" << SEEDEOF
{
  "run_id": "fuse-fsx-seed-corpus-$EPOCH",
  "commit": "$COMMIT",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "$(grep 'kernel_version=' "$VAL_LOG" 2>/dev/null | head -1 | cut -d= -f2 || echo unknown)",
  "backend": "file",
  "validation_tier": "mounted-userspace",
  "test": "fuse-fsx-seed-corpus",
  "nops_per_seed": $N_OPS,
  "seed_count": $(echo "$SEEDS" | wc -w),
  "seeds": $SEED_JSON,
  "summary": {
    "seeds_passed": $SEED_PASSC,
    "seeds_failed": $SEED_FAILC,
    "seeds_total": $(echo "$SEEDS" | wc -w)
  }
}
SEEDEOF
      echo "Seed corpus validation: $VALIDATION_DIR/seed-corpus.json"
    fi

    cat > "$VALIDATION_DIR/validation.json" << JSONEOF
{
  "run_id": "fuse-fsx-$EPOCH",
  "commit": "$COMMIT",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "$(grep 'kernel_version=' "$VAL_LOG" 2>/dev/null | head -1 | cut -d= -f2 || echo unknown)",
  "backend": "file",
  "validation_tier": "mounted-userspace",
  "test": "fuse-fsx-mmap",
  "nops": $N_OPS,
  "summary": {
    "passed": $PASSC,
    "failed": $FAILC,
    "blocked": $BLOCKC
  }
}
JSONEOF

    echo "Validation recorded: $VALIDATION_DIR"

    # ── Collect QEMU pin manifest for reproducibility ──────────────────
    PIN_MANIFEST="$VALIDATION_DIR/qemu-pin-manifest.json"
    if [ -x "$XTAST_BIN" ] && [ -f "$FLAKE_LOCK" ]; then
      echo "Collecting QEMU pin manifest via tidefs-xtask..."
      "$XTAST_BIN" collect-qemu-pin-manifest \
        --validation-id fuse-fsx-mmap \
        --kernel "$KERNEL_IMG" \
        --initrd "$RUN_DIR/initrd.img" \
        --flake-lock "$FLAKE_LOCK" \
        --rebuild-recipe "nix build .#packages.x86_64-linux.fuseFsxValidation -L" \
        --output "$PIN_MANIFEST" \
        --commit "$COMMIT" \
        --nix-derivation "$KERNEL_IMG" \
        2>/dev/null && echo "Pin manifest collected: $PIN_MANIFEST" || {
          echo "xtask pin manifest collection failed; using fallback"
          # Fallback: use sha256sum-based minimal manifest
          KERN_SHA=$(sha256sum "$KERNEL_IMG" 2>/dev/null | cut -d' ' -f1 || echo unknown)
          INITRD_SHA=$(sha256sum "$RUN_DIR/initrd.img" 2>/dev/null | cut -d' ' -f1 || echo unknown)
          cat > "$PIN_MANIFEST" << PINEOF
{
  "validation_id": "fuse-fsx-mmap",
  "commit": "$COMMIT",
  "kernel_sha256": "$KERN_SHA",
  "initrd_sha256": "$INITRD_SHA",
  "kernel_path": "$KERNEL_IMG",
  "initrd_path": "$RUN_DIR/initrd.img",
  "rebuild_recipe": "nix build .#packages.x86_64-linux.fuseFsxValidation -L",
  "collected_at": $(date -u +%s)
}
PINEOF
          echo "Pin manifest collected (fallback): $PIN_MANIFEST"
        }
    else
      echo "Pin manifest skipped (xtask=$XTAST_BIN flake_lock=$FLAKE_LOCK)"
    fi

    if [ -n "$JSON_OUT" ]; then
      cp "$VALIDATION_DIR/validation.json" "$JSON_OUT"
    fi

    if [ -n "$SEEDS" ] && [ "$SEED_FAILC" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $SEED_FAILC seeds failed"
      exit 1
    fi
    if [ "$FAILC" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILC validation rows failed"
      exit 1
    fi

    if [ "$BLOCKC" -gt 0 ] && [ "$PASSC" -eq 0 ]; then
      echo "VALIDATION: BLOCKED"
      exit 2
    fi

    if [ "$PASSC" -eq 0 ]; then
      echo "VALIDATION: FAIL -- guest emitted no recognized validation rows"
      exit 1
    fi

    echo "VALIDATION: PASS"
    exit 0
  '';
in
fuseFsxValidationScript
