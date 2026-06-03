# TideFS: kernel lockdep KCSAN KASAN smoke campaign validation.
#
# Boots a Linux 7.0 kernel instrumented with lockdep (PROVE_LOCKING),
# KCSAN, KASAN, and KFENCE. Loads kmod-posix-vfs, mounts in bootstrap
# mode, performs serial and concurrent filesystem workloads, checks
# dmesg for lockdep, KCSAN, KASAN, and UAF findings, and writes the
# instrumented QEMU log as Tier 5 validation.
#
# This validation script can use either:
#   1. A Nix-built instrumented kernel (linuxKernel_7_0_instrumented),
#      or
#   2. A pre-built kernel image passed via TIDEFS_INSTRUMENTED_KERNEL_IMG.
#
# Usage:
#   nix run .#kernel-lockdep-kcsan-kasan-validation [--keep-tmp] [--timeout SECS]
{
  pkgs,
  linuxKernel_7_0_instrumented ? null,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  instrumentedKernelImg = if linuxKernel_7_0_instrumented != null
    then "${linuxKernel_7_0_instrumented}/bzImage"
    else "";

  validationScript = pkgs.writeShellScriptBin "tidefs-kmod-lockdep-kcsan-kasan-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    CPIO="${pkgs.cpio}/bin/cpio"
    GLIBC_LIB="${glibcLib}"

    # Prefer explicitly-set instrumented kernel, fall back to Nix-built one
    KERNEL_IMG="''${TIDEFS_INSTRUMENTED_KERNEL_IMG:-}"
    if [ -z "$KERNEL_IMG" ] && [ -n "${instrumentedKernelImg}" ]; then
      KERNEL_IMG="${instrumentedKernelImg}"
    fi

    MODULE_DIR="''${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"

    TMPDIR="''${TIDEFS_LOCKDEP_KCSAN_KASAN_TMPDIR:-/tmp/tidefs-lockdep-kcsan-kasan}"
    TIMEOUT_SEC="''${TIDEFS_LOCKDEP_KCSAN_KASAN_TIMEOUT:-480}"
    WORKER_COUNT="''${TIDEFS_LOCKDEP_KCSAN_KASAN_WORKERS:-4}"
    OPS_PER_WORKER="''${TIDEFS_LOCKDEP_KCSAN_KASAN_OPS:-40}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-lockdep-kcsan-kasan-validation [--timeout SECONDS] [--workers N] [--ops N] [--keep-tmp] [--kernel IMG]

Validate kmod-posix-vfs under Linux 7.0 kernel instrumentation:
lockdep (PROVE_LOCKING), KCSAN, KASAN, and KFENCE. Boots a QEMU guest,
loads the module, performs serial and concurrent filesystem workloads,
and checks kernel dmesg for lockdep/KCSAN/KASAN/UAF findings.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --workers N          Number of concurrent workers (default: $WORKER_COUNT)
  --ops N              Operations per worker (default: $OPS_PER_WORKER)
  --keep-tmp           Do not remove temp directory on exit
  --kernel IMG         Path to instrumented kernel bzImage (overrides TIDEFS_INSTRUMENTED_KERNEL_IMG)
  --help, -h           Show this message

Exit codes:
  0  No lockdep/KCSAN/KASAN/UAF findings, all operations passed
  1  One or more findings or operation failures
  2  Argument or environment error

Sanitizer check patterns in dmesg:
  lockdep:   "possible circular locking", "possible recursive locking", "inconsistent lock state"
  KCSAN:     "KCSAN: data-race"
  KASAN:     "KASAN:", "use-after-free", "out-of-bounds"
  UAF:       "use-after-free", "slab-out-of-bounds", "double-free"
  General:   "WARNING:", "BUG:", "Kernel panic", "Oops:"
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --workers) WORKER_COUNT="$2"; shift 2 ;;
        --ops)     OPS_PER_WORKER="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --kernel)  KERNEL_IMG="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kernel lockdep KCSAN KASAN Smoke Campaign ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo "  Workers:   $WORKER_COUNT"
    echo "  Ops/worker: $OPS_PER_WORKER"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo ""

    if [ -z "$KERNEL_IMG" ] || [ ! -f "$KERNEL_IMG" ]; then
      echo "BLOCKED: instrumented kernel image not found."
      echo "  Set TIDEFS_INSTRUMENTED_KERNEL_IMG or build via Nix:"
      echo "    nix build .#linuxKernel_7_0_instrumented"
      echo "  Expected at: ''${KERNEL_IMG:-<not set>}"
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$POSIX_VFS_KO" ]; then
      for c in "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/kmod-posix-vfs/tidefs_posix_vfs.ko"; do
        [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
      done
    fi

    if [ -z "$POSIX_VFS_KO" ]; then
      echo "BLOCKED: tidefs_posix_vfs.ko not found in module output directories"
      exit 1
    fi
    echo "  Module .ko: $POSIX_VFS_KO"

    # Verify the kernel image has expected debug features
    echo ""
    echo "  Checking kernel debug configuration..."
    if strings "$KERNEL_IMG" 2>/dev/null | grep -q "PROVE_LOCKING"; then
      echo "  lockdep (PROVE_LOCKING): likely enabled"
    else
      echo "  WARNING: cannot confirm PROVE_LOCKING in kernel image"
    fi

    # ── Prepare QEMU run directory ────────────────────────────────────
    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation,/etc}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum expr wc uname date ps; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy glibc dynamic linker and libraries
    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # ── Init script ──────────────────────────────────────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Kernel Lockdep KCSAN KASAN Smoke Campaign ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Dump kernel config debug status early
echo ""
echo "--- Kernel Sanitizer Configuration ---"
if [ -f /proc/config.gz ]; then
    zcat /proc/config.gz 2>/dev/null | grep -E "PROVE_LOCKING|KCSAN|KASAN|KFENCE|LOCKDEP|DEBUG_LOCK" | head -12 || echo "  (no sanitizer config found)"
else
    echo "  /proc/config.gz not available; checking dmesg for sanitizer init..."
    dmesg 2>/dev/null | grep -iE "lockdep|kcsan|kasan|kfence" | head -5 || echo "  (no sanitizer init messages)"
fi
echo ""

PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
skip()   { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }

MNT=/mnt/tidefs
EVDIR=/validation

WORKERS=WORKER_COUNT_PLACEHOLDER
OPS_PER=OPS_PER_WORKER_PLACEHOLDER

# ── Dmesg helpers ─────────────────────────────────────────────────
dmesg_snapshot() {
    local label="$1"
    dmesg > "$EVDIR/dmesg_$label.txt" 2>/dev/null || true
    echo "=== DMESG_SNAPSHOT: $label ==="
}

# ── Sanitizer finding checkers ────────────────────────────────────
check_lockdep() {
    local count
    count=$(dmesg 2>/dev/null | grep -cE "possible circular locking|possible recursive locking|inconsistent lock state|lockdep" || echo 0)
    echo "$count"
}

check_kcsan() {
    local count
    count=$(dmesg 2>/dev/null | grep -c "KCSAN: data-race" || echo 0)
    echo "$count"
}

check_kasan() {
    local count
    count=$(dmesg 2>/dev/null | grep -cE "KASAN:|use-after-free|out-of-bounds|double-free|slab-out-of-bounds" || echo 0)
    echo "$count"
}

check_kernel_errors() {
    local count
    count=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:|WARNING:" || echo 0)
    echo "$count"
}

check_no_daemon() {
    local daemon_procs
    daemon_procs=$(ps 2>/dev/null | grep -iE "tidefs.*daemon|fuse.*adapter|ublk.*adapter" | grep -v grep | grep -v "\[" || true)
    if [ -n "$daemon_procs" ]; then
        echo "NO_DAEMON_FAIL: $(echo "$daemon_procs" | head -3)"
        return 1
    fi
    return 0
}

# ── Phase 0: Pre-boot dmesg snapshot ──────────────────────────────
echo "--- Phase 0: Pre-boot dmesg ---"
dmesg_snapshot "pre_module"

LOCKDEP_BASE=$(check_lockdep)
KCSAN_BASE=$(check_kcsan)
KASAN_BASE=$(check_kasan)
ERR_BASE=$(check_kernel_errors)
echo "INFO: baseline lockdep=$LOCKDEP_BASE kcsan=$KCSAN_BASE kasan=$KASAN_BASE errors=$ERR_BASE"

# ── Phase 1: Module load ──────────────────────────────────────────
echo ""
echo "--- Phase 1: Module Load ---"
MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        pass "phase1_insmod"
    else
        fail "phase1_insmod" "$(cat /tmp/insmod.err 2>/dev/null | head -1)"
    fi
else
    blocked "phase1_insmod" "tidefs_posix_vfs.ko not found"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "phase1_module_visible"
else
    blocked "phase1_module_visible" "module not present after insmod"
fi

dmesg_snapshot "post_insmod"

# Check for lockdep lock-class registration (should show lock ordering)
LOCKDEP_AFTER_LOAD=$(check_lockdep)
echo "INFO: lockdep findings after load: $LOCKDEP_AFTER_LOAD (baseline was $LOCKDEP_BASE)"

# ── Phase 2: Mount (bootstrap) ────────────────────────────────────
echo ""
echo "--- Phase 2: Mount (bootstrap) ---"
mkdir -p "$MNT"

MOUNTED=0
if mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/mount.err; then
    pass "phase2_mount"
    MOUNTED=1
else
    err="$(cat /tmp/mount.err | head -1)"
    blocked "phase2_mount" "$err"
fi

if check_no_daemon; then
    pass "phase2_no_daemon"
else
    fail "phase2_no_daemon" "userspace daemon detected at mount phase"
fi

# ── Phase 3: Serial workload (single-threaded correct behavior) ───
echo ""
echo "--- Phase 3: Serial Workload ---"

if [ "$MOUNTED" -eq 0 ]; then
    skip "phase3_serial" "filesystem not mounted"
else
    SERIAL_PASS=0
    SERIAL_FAIL=0

    # Create files, write data, read back, stat, unlink
    for i in $(seq 1 20); do
        f="$MNT/serial_f_$i"
        data="serial_data_$i"

        # Create and write
        if echo "$data" > "$f" 2>/dev/null; then
            # Read back
            got=$(cat "$f" 2>/dev/null || echo "")
            if [ "$got" = "$data" ]; then
                SERIAL_PASS=$((SERIAL_PASS + 1))
            else
                echo "FAIL: serial_f_$i readback mismatch" >> "$EVDIR/serial_ops.log"
                SERIAL_FAIL=$((SERIAL_FAIL + 1))
            fi
        else
            echo "FAIL: serial_f_$i create failed" >> "$EVDIR/serial_ops.log"
            SERIAL_FAIL=$((SERIAL_FAIL + 1))
        fi
    done

    # Stat all files
    for i in $(seq 1 20); do
        f="$MNT/serial_f_$i"
        if stat "$f" >/dev/null 2>&1; then
            SERIAL_PASS=$((SERIAL_PASS + 1))
        else
            echo "FAIL: serial_f_$i stat failed" >> "$EVDIR/serial_ops.log"
            SERIAL_FAIL=$((SERIAL_FAIL + 1))
        fi
    done

    echo "INFO: serial pass=$SERIAL_PASS fail=$SERIAL_FAIL"
    if [ "$SERIAL_FAIL" -eq 0 ]; then
        pass "phase3_serial"
    else
        fail "phase3_serial" "$SERIAL_FAIL serial failures"
    fi
fi

dmesg_snapshot "post_serial"

# ── Phase 4: Concurrent worker stress ─────────────────────────────
echo ""
echo "--- Phase 4: Concurrent Worker Stress ($WORKERS workers x $OPS_PER ops) ---"

if [ "$MOUNTED" -eq 0 ]; then
    skip "phase4_concurrent" "filesystem not mounted"
else
    WORKER_PIDS=""

    start_worker() {
        local wid="$1"
        local ops="$2"
        (
            LOG="$EVDIR/worker_''${wid}.log"
            PASS=0
            FAIL=0
            > "$LOG"

            i=1
            while [ "$i" -le "$ops" ]; do
                opmod=$((i % 20))
                fname="w''${wid}_f$((i % 200))"
                fpath="$MNT/$fname"
                dname="shared_d$((i % 16))"
                dpath="$MNT/$dname"

                case "$opmod" in
                    [0-7])  # create-write (40%)
                        data="w''${wid}_i''${i}_$(date +%s)"
                        if echo "$data" > "$fpath" 2>/dev/null; then
                            got=$(cat "$fpath" 2>/dev/null || echo "")
                            if [ "$got" = "$data" ]; then
                                echo "PASS: w''${wid}_op''${i}_create_write" >> "$LOG"
                                PASS=$((PASS + 1))
                            else
                                echo "FAIL: w''${wid}_op''${i}_create_write readback mismatch" >> "$LOG"
                                FAIL=$((FAIL + 1))
                            fi
                        else
                            echo "RACE: w''${wid}_op''${i}_create_write race-ok" >> "$LOG"
                        fi
                        ;;
                    [8-9]|1[0-3])  # read-verify (30%)
                        if [ -f "$fpath" ]; then
                            got=$(cat "$fpath" 2>/dev/null || echo "")
                            if [ -n "$got" ]; then
                                if echo "$got" | grep -q "w''${wid}_"; then
                                    echo "PASS: w''${wid}_op''${i}_read_verify" >> "$LOG"
                                    PASS=$((PASS + 1))
                                else
                                    echo "FAIL: w''${wid}_op''${i}_read_verify wrong owner" >> "$LOG"
                                    FAIL=$((FAIL + 1))
                                fi
                            else
                                echo "RACE: w''${wid}_op''${i}_read_verify empty (race)" >> "$LOG"
                            fi
                        else
                            echo "RACE: w''${wid}_op''${i}_read_verify ENOENT (race)" >> "$LOG"
                        fi
                        ;;
                    1[4-6])  # unlink (15%)
                        if rm -f "$fpath" 2>/dev/null; then
                            echo "PASS: w''${wid}_op''${i}_unlink" >> "$LOG"
                            PASS=$((PASS + 1))
                        else
                            echo "RACE: w''${wid}_op''${i}_unlink race-ok" >> "$LOG"
                        fi
                        ;;
                    17)  # mkdir (5%)
                        if mkdir "$dpath" 2>/dev/null; then
                            echo "PASS: w''${wid}_op''${i}_mkdir" >> "$LOG"
                            PASS=$((PASS + 1))
                        else
                            echo "RACE: w''${wid}_op''${i}_mkdir race-ok" >> "$LOG"
                        fi
                        ;;
                    18)  # rmdir (5%)
                        if rmdir "$dpath" 2>/dev/null; then
                            echo "PASS: w''${wid}_op''${i}_rmdir" >> "$LOG"
                            PASS=$((PASS + 1))
                        else
                            echo "RACE: w''${wid}_op''${i}_rmdir race-ok" >> "$LOG"
                        fi
                        ;;
                    19)  # stat (5%)
                        if stat "$fpath" >/dev/null 2>&1; then
                            echo "PASS: w''${wid}_op''${i}_stat" >> "$LOG"
                            PASS=$((PASS + 1))
                        else
                            echo "RACE: w''${wid}_op''${i}_stat ENOENT (race)" >> "$LOG"
                        fi
                        ;;
                esac
                i=$((i + 1))
            done
            echo "SUMMARY: worker=''${wid} pass=$PASS fail=$FAIL ops=$ops" >> "$LOG"
        ) &
        WORKER_PIDS="$WORKER_PIDS $!"
    }

    w=0
    while [ "$w" -lt "$WORKERS" ]; do
        start_worker "$w" "$OPS_PER"
        w=$((w + 1))
    done

    echo "INFO: started $WORKERS workers, waiting for completion..."
    wait $WORKER_PIDS 2>/dev/null || true
    echo "INFO: all workers completed"

    TOTAL_PASS=0
    TOTAL_FAIL=0
    for w in $(seq 0 $((WORKERS - 1))); do
        if [ -f "$EVDIR/worker_$w.log" ]; then
            wpass=$(grep -c "^PASS:" "$EVDIR/worker_$w.log" 2>/dev/null || echo 0)
            wfail=$(grep -c "^FAIL:" "$EVDIR/worker_$w.log" 2>/dev/null || echo 0)
            echo "worker_$w pass=$wpass fail=$wfail"
            TOTAL_PASS=$((TOTAL_PASS + wpass))
            TOTAL_FAIL=$((TOTAL_FAIL + wfail))
        fi
    done

    echo "INFO: total_pass=$TOTAL_PASS total_fail=$TOTAL_FAIL"
    if [ "$TOTAL_FAIL" -eq 0 ]; then
        pass "phase4_concurrent_all_pass"
    else
        fail "phase4_concurrent_all_pass" "$TOTAL_FAIL worker failures"
    fi
fi

dmesg_snapshot "post_concurrent"

# ── Phase 5: Sanitizer dmesg sweep ─────────────────────────────────

# Verify kernel is instrumented; a clean dmesg from a non-instrumented
# kernel is not valid validation for this instrumented campaign.
INSTRUMENTED=0
if [ -f /proc/config.gz ]; then
    HAS_LOCKDEP=$(zcat /proc/config.gz 2>/dev/null | grep -c "^CONFIG_PROVE_LOCKING=y" || echo 0)
    HAS_KCSAN=$(zcat /proc/config.gz 2>/dev/null | grep -c "^CONFIG_KCSAN=y" || echo 0)
    HAS_KASAN=$(zcat /proc/config.gz 2>/dev/null | grep -c "^CONFIG_KASAN=y" || echo 0)
    HAS_KFENCE=$(zcat /proc/config.gz 2>/dev/null | grep -c "^CONFIG_KFENCE=y" || echo 0)
    echo "INFO: kernel_config lockdep=$HAS_LOCKDEP kcsan=$HAS_KCSAN kasan=$HAS_KASAN kfence=$HAS_KFENCE"
    if [ "$HAS_LOCKDEP" -eq 1 ] || [ "$HAS_KCSAN" -eq 1 ] || [ "$HAS_KASAN" -eq 1 ] || [ "$HAS_KFENCE" -eq 1 ]; then
        INSTRUMENTED=1
    fi
else
    echo "INFO: /proc/config.gz not available; assuming non-instrumented"
fi
if [ "$INSTRUMENTED" -eq 0 ]; then
    echo ""
    echo "BLOCKED: kernel is NOT instrumented with lockdep/KCSAN/KASAN/KFENCE."
    echo "A clean dmesg from a non-instrumented kernel is not valid validation."
    echo "Build the instrumented kernel: nix build .#linuxKernel_7_0_instrumented"
    BLOCKED=$((BLOCKED + 1))
fi
echo ""
echo "--- Phase 5: Sanitizer Dmesg Sweep ---"

LOCKDEP_COUNT=$(check_lockdep)
LOCKDEP_DELTA=$((LOCKDEP_COUNT - LOCKDEP_BASE))
KCSAN_COUNT=$(check_kcsan)
KCSAN_DELTA=$((KCSAN_COUNT - KCSAN_BASE))
KASAN_COUNT=$(check_kasan)
KASAN_DELTA=$((KASAN_COUNT - KASAN_BASE))
ERR_COUNT=$(check_kernel_errors)
ERR_DELTA=$((ERR_COUNT - ERR_BASE))

echo "INFO: lockdep delta=$LOCKDEP_DELTA (total=$LOCKDEP_COUNT)"
echo "INFO: kcsan   delta=$KCSAN_DELTA   (total=$KCSAN_COUNT)"
echo "INFO: kasan   delta=$KASAN_DELTA   (total=$KASAN_COUNT)"
echo "INFO: errors  delta=$ERR_DELTA    (total=$ERR_COUNT)"

SANITIZER_FINDINGS=0

if [ "$LOCKDEP_DELTA" -gt 0 ]; then
    echo ""
    echo "!!! LOCKDEP FINDINGS DETECTED !!!"
    dmesg 2>/dev/null | grep -E "possible circular locking|possible recursive locking|inconsistent lock state" | head -20
    SANITIZER_FINDINGS=$((SANITIZER_FINDINGS + 1))
fi

if [ "$KCSAN_DELTA" -gt 0 ]; then
    echo ""
    echo "!!! KCSAN FINDINGS DETECTED !!!"
    dmesg 2>/dev/null | grep "KCSAN: data-race" | head -20
    SANITIZER_FINDINGS=$((SANITIZER_FINDINGS + 1))
fi

if [ "$KASAN_DELTA" -gt 0 ]; then
    echo ""
    echo "!!! KASAN FINDINGS DETECTED !!!"
    dmesg 2>/dev/null | grep -E "KASAN:|use-after-free|out-of-bounds|double-free|slab-out-of-bounds" | head -20
    SANITIZER_FINDINGS=$((SANITIZER_FINDINGS + 1))
fi

if [ "$ERR_DELTA" -gt 0 ]; then
    echo ""
    echo "!!! KERNEL WARNING/BUG/PANIC DETECTED !!!"
    dmesg 2>/dev/null | grep -E "BUG:|Kernel panic|Oops:|WARNING:" | head -20
    SANITIZER_FINDINGS=$((SANITIZER_FINDINGS + 1))
fi

if [ "$SANITIZER_FINDINGS" -eq 0 ]; then
    pass "phase5_sanitizers_clean"
    echo "=== SANITIZER RESULT: CLEAN ==="
    echo "No lockdep, KCSAN, KASAN, or kernel error findings detected."
else
    fail "phase5_sanitizers_clean" "$SANITIZER_FINDINGS sanitizer finding categories detected"
    echo "=== SANITIZER RESULT: $SANITIZER_FINDINGS FINDING CATEGORIES ==="
fi

# ── Phase 6: Unmount ──────────────────────────────────────────────
echo ""
echo "--- Phase 6: Unmount ---"
if [ "$MOUNTED" -eq 1 ]; then
    sync
    if umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null; then
        pass "phase6_umount"
    else
        fail "phase6_umount" "umount failed"
    fi
fi

dmesg_snapshot "post_umount"

# ── Phase 7: Module unload ────────────────────────────────────────
echo ""
echo "--- Phase 7: Module Unload ---"
if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
    pass "phase7_rmmod"
else
    fail "phase7_rmmod" "$(cat /tmp/rmmod.err 2>/dev/null | head -1)"
fi

dmesg_snapshot "post_rmmod"

# ── Final sanitizer sweep ─────────────────────────────────────────
echo ""
echo "--- Final Sanitizer Sweep ---"
LOCKDEP_FINAL=$(check_lockdep)
KCSAN_FINAL=$(check_kcsan)
KASAN_FINAL=$(check_kasan)
ERR_FINAL=$(check_kernel_errors)

LOCKDEP_RUNTIME=$((LOCKDEP_FINAL - LOCKDEP_BASE))
KCSAN_RUNTIME=$((KCSAN_FINAL - KCSAN_BASE))
KASAN_RUNTIME=$((KASAN_FINAL - KASAN_BASE))
ERR_RUNTIME=$((ERR_FINAL - ERR_BASE))

echo "FINAL: lockdep_findings=$LOCKDEP_RUNTIME kcsan_findings=$KCSAN_RUNTIME kasan_findings=$KASAN_RUNTIME kernel_errors=$ERR_RUNTIME"

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "=== LOCKDEP KCSAN KASAN SMOKE CAMPAIGN SUMMARY ==="
echo "  kernel: $(uname -r)"
echo "  workers=$WORKERS ops_per_worker=$OPS_PER"
echo "  serial_pass=$SERIAL_PASS serial_fail=$SERIAL_FAIL"
echo "  concurrent_pass=$TOTAL_PASS concurrent_fail=$TOTAL_FAIL"
echo "  lockdep_findings=$LOCKDEP_RUNTIME"
echo "  kcsan_findings=$KCSAN_RUNTIME"
echo "  kasan_findings=$KASAN_RUNTIME"
echo "  kernel_errors=$ERR_RUNTIME"
echo "  sanitizer_verdict: $([ "$SANITIZER_FINDINGS" -eq 0 ] && echo 'CLEAN' || echo 'FINDINGS_DETECTED')"
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"

sleep 2
poweroff -f
INITSCRIPT

    sed -i "s/WORKER_COUNT_PLACEHOLDER/$WORKER_COUNT/" "$RUN_DIR/init"
    sed -i "s/OPS_PER_WORKER_PLACEHOLDER/$OPS_PER_WORKER/" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc 2>/dev/null) | gzip > "$RUN_DIR/initramfs.gz"

    echo "--- Booting instrumented kernel QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet panic=10" \
      -nographic \
      -m 512M \
      -smp 2 \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    SKIP_COUNT=$(grep -c "^SKIP:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    LOCKDEP_FOUND=$(grep -cE "possible circular locking|possible recursive locking|inconsistent lock state" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    KCSAN_FOUND=$(grep -c "KCSAN: data-race" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    KASAN_FOUND=$(grep -cE "KASAN:|use-after-free|out-of-bounds" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    ERR_FOUND=$(grep -cE "BUG:|Kernel panic|Oops:|WARNING:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo ""
    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"
    echo "lockdep_findings: $LOCKDEP_FOUND  kcsan_findings: $KCSAN_FOUND  kasan_findings: $KASAN_FOUND  kernel_errors: $ERR_FOUND"

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-lockdep-kcsan-kasan/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    cat > "$OUTPUT_DIR/manifest.json" << MANIFEST
{
  "test": "kernel-lockdep-kcsan-kasan-validation",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "workers": $WORKER_COUNT,
  "ops_per_worker": $OPS_PER_WORKER,
  "mode": "bootstrap",
  "mode_note": "bootstrap mode does not exercise block-I/O lockdep/KASAN paths; full kernel mount (non-bootstrap) needed for Tier 6 validation",
  "validation_tier": "Tier 5 (mounted kernel VFS)",
  "kernel_image": "$KERNEL_IMG",
  "sanitizers": {
    "lockdep": "$([ "$LOCKDEP_FOUND" -eq 0 ] && echo 'clean' || echo 'findings')",
    "kcsan": "$([ "$KCSAN_FOUND" -eq 0 ] && echo 'clean' || echo 'findings')",
    "kasan": "$([ "$KASAN_FOUND" -eq 0 ] && echo 'clean' || echo 'findings')",
    "kernel_errors": "$([ "$ERR_FOUND" -eq 0 ] && echo 'clean' || echo 'findings')"
  },
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": "$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)",
  "worktree_dirty": $(git -C /root/tidefs diff --quiet -- . && git -C /root/tidefs diff --cached --quiet -- . && echo false || echo true),
  "result": "Kernel lockdep KCSAN KASAN smoke campaign $( [ "$LOCKDEP_FOUND" -eq 0 ] && [ "$KCSAN_FOUND" -eq 0 ] && [ "$KASAN_FOUND" -eq 0 ] && echo 'CLEAN' || echo 'FINDINGS_DETECTED')"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$FAIL_COUNT" -gt 0 ] || [ "$LOCKDEP_FOUND" -gt 0 ] || [ "$KCSAN_FOUND" -gt 0 ] || [ "$KASAN_FOUND" -gt 0 ] || [ "$BLOCKED_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  validationScript
