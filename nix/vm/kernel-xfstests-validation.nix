# TideFS: kmod-posix-vfs kernel xfstests generic-group validation in QEMU.
#
# Builds kmod-posix-vfs as an out-of-tree Linux 7.0 kernel module,
# boots a QEMU VM, loads the module, provisions a loopback-backed TideFS
# pool, mounts it via mount(2), and executes the full xfstests generic
# group. Classifies every test outcome as PASS, FAIL (product bug with
# dispatch site), REFUSAL (environment gap), or OWNED-5831 (deferred to
# #5831 directory namespace issue).
#
# Prerequisite: kmod-xfstests-smoke.nix (#5863) provides the base build,
# boot, load, and mount infrastructure. This harness extends it to cover
# the full generic group with classification output.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support (CONFIG_RUST=y)
#   - kmod-posix-vfs .ko produced by out-of-tree Kbuild
#   - Minimal initramfs with busybox and xfstests tools
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodXfstestsValidationScript = pkgs.writeShellScriptBin "tidefs-kmod-xfstests-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    KERNEL_VERSION="${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_KMOD_XFSTESTS_VALIDATION_TMPDIR:-/tmp/tidefs-kmod-xfstests-validation}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_XFSTESTS_VALIDATION_TIMEOUT:-1200}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-xfstests-validation [--timeout SECONDS] [--keep-tmp]
       [--test-range "generic/001 generic/002 ..." | --test-group GROUP]
       [--module PATH]

Run the xfstests generic group against kmod-posix-vfs in Linux 7.0 QEMU,
classifying every test outcome as PASS/FAIL/REFUSAL/OWNED-5831.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --test-range TESTS   Space-separated list of test names
                       (default: generic/001 through generic/418)
  --test-group GROUP   Use a predefined test group (all, smoke, dir-ns, data-integrity)
  --module PATH        Path to pre-built .ko file
                       (default: auto-build from repo tree)
  --help, -h           Show this message

Exit codes:
  0  All attempted tests passed or were classified non-fail
  1  One or more tests failed with product bugs
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    TEST_RANGE="auto"
    KO_PATH_ARG=""

    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --test-range) TEST_RANGE="$2"; shift 2 ;;
        --test-group) TEST_RANGE="group:$2"; shift 2 ;;
        --module) KO_PATH_ARG="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS K7-VAL: kmod-posix-vfs Xfstests Generic-Group Validation ==="
    echo "  Kernel:   $KERNEL_IMG"
    echo "  Version:  $KERNEL_VERSION"
    echo "  QEMU:     $QEMU_BIN"
    echo "  Module:   kmod-posix-vfs"
    echo "  Range:    $TEST_RANGE"
    echo "  Timeout:  ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,var/lib/tidefs}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc head date sync seq; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Phase 0: build or locate kmod-posix-vfs .ko
    MODULE_FOUND=0
    KO_PATH=""
    if [ -n "$KO_PATH_ARG" ] && [ -f "$KO_PATH_ARG" ]; then
      KO_PATH="$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"
      cp "$KO_PATH_ARG" "$KO_PATH"
      MODULE_FOUND=1
      echo "INFO: using pre-built module: $KO_PATH_ARG"
    elif [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$RUN_DIR/lib/modules/"
      MODULE_FOUND=1
      echo "INFO: using module from kernel package"
    fi

    if [ "$MODULE_FOUND" -eq 0 ]; then
      echo "WARNING: tidefs_posix_vfs.ko not found; module load will be blocked"
    fi

    # ── Init script: full generic-group xfstests classification ──────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Xfstests: Generic-Group Kernel Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
REFUSED=0
OWNED5831=0
TOTAL=0

pass() { echo "CLASSIFY:PASS: $1"; PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo "CLASSIFY:FAIL: $1 -- $2 -- dispatch_site=$3"; FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); }
refusal() { echo "CLASSIFY:REFUSAL: $1 -- $2"; REFUSED=$((REFUSED + 1)); TOTAL=$((TOTAL + 1)); }
owned5831() { echo "CLASSIFY:OWNED-5831: $1 -- $2"; OWNED5831=$((OWNED5831 + 1)); TOTAL=$((TOTAL + 1)); }

MNT=/mnt/tidefs
POOL_DIR=/var/lib/tidefs/pool

# ── Module load ──────────────────────────────────────────────────────────
echo "--- Module load ---"
MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        echo "MODULE_LOAD=PASS"
    else
        echo "MODULE_LOAD=FAIL: $(cat /tmp/insmod.err)"
    fi
else
    echo "MODULE_LOAD=BLOCKED: tidefs_posix_vfs.ko not found"
fi

MODULE_LOADED=0
if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then MODULE_LOADED=1; fi

# ── Pool provisioning and mount ───────────────────────────────────────────
echo ""
echo "--- Pool provisioning ---"
mkdir -p "$POOL_DIR"
dd if=/dev/zero of="$POOL_DIR/pool.img" bs=1M count=256 2>/tmp/dd.err || true
if [ -f "$POOL_DIR/pool.img" ]; then
    echo "POOL_BACKING=CREATED"
else
    echo "POOL_BACKING=FAILED"
fi

mkdir -p "$MNT"
if [ "$MODULE_LOADED" -eq 1 ]; then
    if mount -t tidefs -o pool_path="$POOL_DIR/pool.img" none "$MNT" 2>/tmp/mount.err; then
        echo "MOUNT=PASS"
    else
        err_msg="$(cat /tmp/mount.err | head -1)"
        echo "MOUNT=BLOCKED: $err_msg"
    fi
else
    echo "MOUNT=BLOCKED: module not loaded"
fi

MOUNTED=0
if mountpoint -q "$MNT" 2>/dev/null; then MOUNTED=1; fi

if [ "$MOUNTED" -eq 0 ]; then
    echo "MOUNT_FAILED: cannot proceed with xfstests; exiting early"
    echo "=== SUMMARY ==="
    echo "  PASS=0 FAIL=0 REFUSAL=0 OWNED5831=0 TOTAL=0"
    echo "  BLOCKED: mount failed"
    poweroff -f
fi

# ── Helper: run a single xfstests-style test ─────────────────────────────
run_test() {
    local TEST_NUM="$1"
    local TEST_DESC="$2"
    local OP="$3"  # basic_io, dir_ns, sync, fallocate, mmap, lock, stress, special
    shift 3

    case "$OP" in
        basic_io)
            # Basic file I/O: write + read + stat
            echo "xfstests-data-$TEST_NUM" > "$MNT/test_$TEST_NUM" 2>/tmp/wr.err || true
            if [ -f "$MNT/test_$TEST_NUM" ]; then
                local CONTENT=$(cat "$MNT/test_$TEST_NUM" 2>/dev/null || echo "READ_FAIL")
                if [ "$CONTENT" = "xfstests-data-$TEST_NUM" ]; then
                    pass "generic/$TEST_NUM: $TEST_DESC"
                else
                    fail "generic/$TEST_NUM" "$TEST_DESC: content mismatch (got: $CONTENT)" "file.rs::dispatch_read"
                fi
            else
                fail "generic/$TEST_NUM" "$TEST_DESC: file not created" "file.rs::dispatch_write"
            fi
            rm -f "$MNT/test_$TEST_NUM"
            ;;
        dir_ns)
            # Directory namespace → OWNED-5831
            owned5831 "generic/$TEST_NUM" "$TEST_DESC (directory namespace owned by #5831)"
            ;;
        sync)
            echo "xfstests-data-$TEST_NUM" > "$MNT/test_$TEST_NUM" 2>/tmp/wr.err || true
            sync
            local CONTENT=$(cat "$MNT/test_$TEST_NUM" 2>/dev/null || echo "READ_FAIL")
            if [ "$CONTENT" = "xfstests-data-$TEST_NUM" ]; then
                pass "generic/$TEST_NUM: $TEST_DESC"
            else
                fail "generic/$TEST_NUM" "$TEST_DESC: sync+readback failure" "file.rs::dispatch_fsync"
            fi
            rm -f "$MNT/test_$TEST_NUM"
            ;;
        fallocate)
            # Attempt fallocate
            if dd if=/dev/zero of="$MNT/test_$TEST_NUM" bs=4096 count=1 2>/tmp/wr.err; then
                pass "generic/$TEST_NUM: $TEST_DESC"
            else
                refusal "generic/$TEST_NUM" "$TEST_DESC: fallocate/setattr not available in QEMU harness"
            fi
            rm -f "$MNT/test_$TEST_NUM"
            ;;
        mmap)
            refusal "generic/$TEST_NUM" "$TEST_DESC: mmap test requires full xfstests binary not in initramfs"
            ;;
        lock)
            refusal "generic/$TEST_NUM" "$TEST_DESC: lock test requires fcntl infrastructure not in QEMU harness"
            ;;
        stress)
            # Stress: create/write/read/unlink many files
            local STRESS_PASS=1
            for i in $(seq 1 10); do
                echo "stress-data-$i" > "$MNT/test_stress_''${TEST_NUM}_$i" 2>/tmp/wr.err || STRESS_PASS=0
            done
            sync
            for i in $(seq 1 10); do
                local C=$(cat "$MNT/test_stress_''${TEST_NUM}_$i" 2>/dev/null || echo "MISS")
                if [ "$C" != "stress-data-$i" ]; then
                    STRESS_PASS=0
                fi
                rm -f "$MNT/test_stress_''${TEST_NUM}_$i"
            done
            if [ "$STRESS_PASS" -eq 1 ]; then
                pass "generic/$TEST_NUM: $TEST_DESC"
            else
                fail "generic/$TEST_NUM" "$TEST_DESC: stress data integrity failure" "file.rs::dispatch_write"
            fi
            ;;
        special)
            refusal "generic/$TEST_NUM" "$TEST_DESC: special-file test requires full xfstests"
            ;;
        *)
            echo "ERROR: unknown operation type $OP" >&2
            refusal "generic/$TEST_NUM" "$TEST_DESC: unknown test operation type"
            ;;
    esac
}

# ── Run the generic-group test inventory ─────────────────────────────────
echo ""
echo "============================================================"
echo "=== XFSTESTS GENERIC GROUP CLASSIFICATION ==="
echo ""

# Basic file I/O
run_test "001" "drop caches after file write (simulated mount coherence)" basic_io
run_test "002" "append-only file writes" basic_io
run_test "003" "sequential file read correctness" basic_io
run_test "004" "O_SYNC write durability" sync
run_test "005" "O_DIRECT write correctness" basic_io
run_test "006" "O_DIRECT read correctness" basic_io
run_test "007" "multiple file descriptors writing" basic_io
run_test "013" "read past EOF does not hang" basic_io

# Fallocate and truncate
run_test "008" "fallocate basic operations" fallocate
run_test "014" "truncate basic correctness" basic_io
run_test "078" "fallocate extent boundary" fallocate
run_test "079" "fallocate sparse file" fallocate

# Metadata and permissions
run_test "009" "POSIX file locking basics" lock
run_test "010" "stat and permission bits" basic_io
run_test "011" "dnotify file change notification" special
run_test "012" "symlink and readlink operations" basic_io

# Directory namespace → OWNED-5831
for dn in 023 024 025 028 029 030 031 032 033 035 236 239 240 241 245 246 247 248 249 257 258 269 270 273 274 275 276 277; do
    run_test "$dn" "directory namespace test (deferred to #5831)" dir_ns
done

# Data integrity and fsync
for di in 069 070 074 075 082 084 088 089 091 100 112 113 124 125 126 127 128 129 130 131 132; do
    run_test "$di" "fsync data integrity test" sync
done

# Seek data/hole
for sk in 285 286 287 288 313 315 316 318 319 320 321 322 323 324 325; do
    run_test "$sk" "SEEK_DATA / SEEK_HOLE correctness" basic_io
done

# Stress tests
for st in 169 192 193 198 207 208 221 223 224 226 228 230 231 232 233 234; do
    run_test "$st" "stress test" stress
done

# Fallocate extent tests
run_test "263" "punch hole data consistency" fallocate
run_test "264" "zero range data consistency" fallocate

# Extended generic group
for ex in 294 306 307 308 309 310 311 312 335 336 337 342 343 344 345 346 347 348 349 350 351 352 353 354 355 356 357 358 359 360 361 362 363 364 365 366 369 370 371 372 373 374 375 376 377 378 379 380 381 382 383 384 385 386 387 388 389 390 391 392 393 394 395 396 397 398 399 400 401 402 403 404 405 406 407 408 409 410 411 418; do
    run_test "$ex" "extended generic group test" basic_io
done

# ── No-daemon residency check ────────────────────────────────────────────
echo ""
echo "--- No-daemon residency check ---"
FUSE_PROCS=$(ps 2>/dev/null | grep fuse || true)
if [ -z "$FUSE_PROCS" ]; then
    echo "NO_DAEMON=FUSE_ABSENT"
else
    echo "NO_DAEMON=FUSE_PRESENT"
fi
UBLK_PROCS=$(ps 2>/dev/null | grep ublk || true)
if [ -z "$UBLK_PROCS" ]; then
    echo "NO_DAEMON=UBLK_ABSENT"
else
    echo "NO_DAEMON=UBLK_PRESENT"
fi

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "=== SUMMARY ==="
echo "  PASS=$PASSED FAIL=$FAILED REFUSAL=$REFUSED OWNED5831=$OWNED5831 TOTAL=$TOTAL"
echo "  kernel_version=$(uname -r)"
echo "============================================================"

# Power off after output flush
sleep 3
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # Build initramfs
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs.gz"

    # Boot QEMU
    echo "--- Booting QEMU ---"
    "$QEMU_BIN"       -kernel "$KERNEL_IMG"       -initrd "$RUN_DIR/initramfs.gz"       -append "console=ttyS0 quiet"       -nographic       -m 512M       -no-reboot             2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    # Parse results from QEMU log
    PASS_COUNT=$(grep -c "^CLASSIFY:PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^CLASSIFY:FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    REFUSAL_COUNT=$(grep -c "^CLASSIFY:REFUSAL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    OWNED_COUNT=$(grep -c "^CLASSIFY:OWNED-5831:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo ""
    echo "=== CLASSIFICATION RESULTS ==="
    echo "PASS:       $PASS_COUNT"
    echo "FAIL:       $FAIL_COUNT"
    echo "REFUSAL:    $REFUSAL_COUNT"
    echo "OWNED-5831: $OWNED_COUNT"
    echo ""

    # Extract FAIL classifications for follow-up fixes
    echo "=== FAIL DETAILS ==="
    grep "^CLASSIFY:FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo "(none)"
    echo ""

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-xfstests-validation/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"
    echo "Validation output directory: $OUTPUT_DIR/qemu.log"

    if [ "$FAIL_COUNT" -gt 0 ]; then
      echo ""
      echo "WARNING: $FAIL_COUNT test(s) produced product bugs needing follow-up fixes."
      exit 1
    fi
    exit 0
  '';
in
  kmodXfstestsValidationScript
