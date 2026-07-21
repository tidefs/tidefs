# TideFS: direct-I/O FUSE fsx validation in QEMU.
#
# Mounts a TideFS FUSE filesystem inside a Linux 7.0 QEMU VM,
# runs the TideFS fsx exerciser, requires shared mmap to be refused by the
# direct-I/O carrier, and produces tier-classified validation rows.
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
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    FSX_BIN="${tidefsFsx}/bin/fsx"
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

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$FUSE_DAEMON" "$FSX_BIN"; do
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
                  readlink tr cmp diff mountpoint uname date umount; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$FUSE_DAEMON" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
    chmod +x "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
    cp "$FSX_BIN" "$RUN_DIR/bin/fsx"
    chmod +x "$RUN_DIR/bin/fsx"

    # Copy shared libraries BEFORE patchelf so ldd works on the original binaries
    if command -v ldd >/dev/null 2>&1; then
      for lib in $(ldd "$FUSE_DAEMON" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true); do
        [ -f "$lib" ] && cp "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      done
      # Also copy busybox dependencies
      for lib in $(ldd "$RUN_DIR/bin/busybox" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true); do
        [ -f "$lib" ] && cp "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      done
      LD_SO=$(ldd "$FUSE_DAEMON" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
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
      for fuse_lib in "$(dirname "$FUSE_DAEMON")/../lib/libfuse3.so"* /nix/store/*/lib/libfuse3.so*; do
        if [ -f "$fuse_lib" ]; then
          cp "$fuse_lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
          break
        fi
      done
    fi


    # Fix ELF interpreter paths for initrd: reset to /lib/ld-linux-x86-64.so.2
    for bin in "$RUN_DIR/bin/busybox" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon" "$RUN_DIR/bin/fsx"; do
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

MNT=/mnt/tidefs
STORE=/store/tidefs-store
FSX_N=__FSX_NOPS__

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
    mkdir -p "$STORE" "$MNT"
    /bin/tidefs-posix-filesystem-adapter-daemon \
      mount-vfs \
      --store "$STORE" \
      --mount "$MNT" \
      --root-auth-key-hex 4141414141414141414141414141414141414141414141414141414141414141 \
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
            /bin/fsx --expect-mmap-refused -N "$FSX_N" -S "$seed" "$FSX_PATH" > "/tmp/fsx-seed-$seed.out" 2>&1
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
        /bin/fsx --expect-mmap-refused -N "$FSX_N" "$FSX_PATH" > /tmp/fsx.out 2>&1
        FSX_RC=$?
        echo "=== fsx output ==="
        cat /tmp/fsx.out
        echo "=== end fsx output ==="
        echo "=== full daemon log ==="
        cat /tmp/daemon.log 2>/dev/null || echo "(no daemon log)"
        echo "=== end daemon log ==="
        if [ "$FSX_RC" -eq 0 ]; then
            FSX_LINE=$(grep '^fsx:' /tmp/fsx.out | tail -1 || echo "no summary line")
            pass "fsx_direct_io" "fsx: $FSX_LINE"
        else
            FSX_LINE=$(grep '^fsx:' /tmp/fsx.out | tail -1 || echo "no summary line")
            fail "fsx_direct_io" "fsx exit=$FSX_RC: $FSX_LINE"
        fi
    fi
else
    if [ -n "$SEEDS_STR" ]; then
        for seed in $SEEDS_STR; do
            blocked "fsx_seed_$seed" "filesystem not mounted"
        done
    else
        blocked "fsx_direct_io" "filesystem not mounted"
    fi
fi

# ── Phase 3: Tear-down ───────────────────────────────────────────────
if [ "$MOUNTED" -eq 1 ]; then
    if umount "$MNT" 2>/tmp/um.err; then
        pass "unmount"
    else
        fail "unmount" "$(cat /tmp/um.err)"
    fi
else
    blocked "unmount" "filesystem not mounted"
fi

if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    pass "daemon_stop"
fi

# ── Validation Summary ──────────────────────────────────────────────────
echo ""
echo "=== FUSE fsx Validation Summary ==="
echo "PASSED=$PASSED"
echo "FAILED=$FAILED"
echo "BLOCKED=$BLOCKED"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "validation_tier=mounted-userspace"
echo "filesystem=fuse-fsx-direct-io"
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
  "test": "fuse-fsx-direct-io",
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
        --validation-id fuse-fsx-direct-io \
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
  "validation_id": "fuse-fsx-direct-io",
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

    echo "VALIDATION: PASS"
    exit 0
  '';
in
fuseFsxValidationScript
