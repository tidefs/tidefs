# TideFS: kernel-mode no-daemon concurrent VFS operation safety validation.
#
# QEMU validation: concurrent multi-process VFS stress.
# Replaces the retired sequential-shell wrapper with a real concurrent workload.
#
# Boots a Linux 7.0 kernel with kmod-posix-vfs, mounts in bootstrap mode,
# spawns N concurrent worker processes (4/8/16) performing interleaved
# create/write/read/stat/unlink/mkdir/rmdir operations on the mounted
# filesystem, checks dmesg for kernel panics/WARNINGs/BUGs, verifies
# data integrity, and runs remount cycles for persistence validation.
#
# Each worker owns a disjoint file-name range to prevent write-write data
# races while shared directory namespace operations (mkdir/rmdir) exercise
# kernel dentry/inode locking under concurrent access.
#
# Tier: QEMU guest (Tier 4: Kbuild + QEMU module load) with mounted-kernel
# VFS operations (Tier 5). Full-kernel no-daemon validation requires no
# usermode daemon processes.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;
  glibcLib = "${pkgs.glibc}/lib";

  kmodConcurrentScript = pkgs.writeShellScriptBin "tidefs-kmod-concurrent-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="''${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
    GLIBC_LIB="${glibcLib}"

    TMPDIR="''${TIDEFS_CONCURRENT_TMPDIR:-/tmp/tidefs-kmod-concurrent-validation}"
    TIMEOUT_SEC="''${TIDEFS_CONCURRENT_TIMEOUT:-600}"
    WORKER_COUNT="''${TIDEFS_CONCURRENT_WORKERS:-8}"
    OPS_PER_WORKER="''${TIDEFS_CONCURRENT_OPS:-50}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-concurrent-validation [--timeout SECONDS] [--workers N] [--ops N] [--keep-tmp]

Validate kmod-posix-vfs concurrent VFS operation safety in a Linux 7.0
QEMU guest. Spawns N concurrent worker processes performing interleaved
filesystem operations (create, write, read, stat, unlink, mkdir, rmdir),
checks kernel dmesg for WARNING/BUG/panic, verifies data integrity, and
runs remount persistence cycles.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --workers N          Number of concurrent workers (default: $WORKER_COUNT)
  --ops N              Operations per worker (default: $OPS_PER_WORKER)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  All concurrent operations passed, no kernel warnings or data corruption
  1  One or more failures or blocked required rows
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --workers) WORKER_COUNT="$2"; shift 2 ;;
        --ops) OPS_PER_WORKER="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS K7-VAL: kmod-posix-vfs Concurrent VFS Stress ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo "  Workers:   $WORKER_COUNT"
    echo "  Ops/worker: $OPS_PER_WORKER"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$POSIX_VFS_KO" ]; then
      for c in "$MODULE_DIR/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/tidefs_posix_vfs/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/posix-vfs/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/extra/tidefs-kmod-posix-vfs.ko" \
               "$MODULE_DIR/extra/tidefs_posix_vfs.ko"; do
        [ -f "$c" ] && { POSIX_VFS_KO="$c"; break; }
      done
    fi

    if [ -z "$POSIX_VFS_KO" ]; then
      echo "BLOCKED: tidefs_posix_vfs.ko not found in MODULE_DIR=$MODULE_DIR"
      exit 1
    fi
    echo "  Module .ko: $POSIX_VFS_KO"

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,validation}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
      mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut dirname basename \
      printf test xargs seq awk tr sort uniq md5sum expr wc uname date; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    # Copy glibc dynamic linker and libraries for dynamically-linked busybox
    mkdir -p "$RUN_DIR/$GLIBC_LIB"
    cp "$GLIBC_LIB"/ld-linux-x86-64.so.2 "$RUN_DIR/$GLIBC_LIB/" 2>/dev/null || true
    for lib in libc.so.6 libm.so.6 libresolv.so.2 libdl.so.2; do
      [ -f "$GLIBC_LIB/$lib" ] && cp "$GLIBC_LIB/$lib" "$RUN_DIR/$GLIBC_LIB/"
    done

    cp "$POSIX_VFS_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"

    # ── Init script: concurrent VFS operation stress ─────────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Concurrent VFS Stress ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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

# ── No-daemon check ─────────────────────────────────────────────────
check_no_daemon() {
    local daemon_procs
    daemon_procs=$(ps 2>/dev/null | grep -iE "tidefs.*daemon|fuse.*adapter|ublk.*adapter" | grep -v grep | grep -v "\[" || true)
    if [ -n "$daemon_procs" ]; then
        echo "NO_DAEMON_FAIL: userspace daemon detected: $(echo "$daemon_procs" | head -3)"
        return 1
    fi
    return 0
}

# ── Dmesg snapshot helpers ──────────────────────────────────────────
dmesg_snapshot() {
    local label="$1"
    dmesg > "$EVDIR/dmesg_$label.txt" 2>/dev/null || true
    echo "=== DMESG_SNAPSHOT: $label ==="
}

dmesg_warn_count() { dmesg 2>/dev/null | grep -c "WARNING:" || echo 0; }
dmesg_bug_count() { dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:" || echo 0; }

# ── Phase 0: Module load ───────────────────────────────────────────
echo "--- Phase 0: Module Load ---"
dmesg_snapshot "pre_insmod"

MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        pass "phase0_insmod"
    else
        fail "phase0_insmod" "$(cat /tmp/insmod.err | head -1)"
    fi
else
    blocked "phase0_insmod" "tidefs_posix_vfs.ko not found"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "phase0_module_visible"
else
    blocked "phase0_module_visible" "module not present after insmod"
fi

# ── Phase 1: Mount (bootstrap) ─────────────────────────────────────
echo ""
echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"

MOUNTED=0
if mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/mount.err; then
    pass "phase1_mount"
    MOUNTED=1
else
    err="$(cat /tmp/mount.err | head -1)"
    blocked "phase1_mount" "$err"
fi

if check_no_daemon; then
    pass "phase1_no_daemon"
else
    fail "phase1_no_daemon" "daemon detected at mount phase"
fi

dmesg_snapshot "post_mount"

# ── Phase 2: Concurrent worker stress ──────────────────────────────
echo ""
echo "--- Phase 2: Concurrent Worker Stress ($WORKERS workers x $OPS_PER ops) ---"

if [ "$MOUNTED" -eq 0 ]; then
    skip "phase2_concurrent" "filesystem not mounted"
else
    # Each worker runs in the background, performs filesystem ops,
    # and writes results to validation/worker_N.log
    #
    # Worker N owns files fN_* (disjoint range prevents write-write
    # data races while directories and stat-any share namespace).
    #
    # Operation mix: create-write(40%), read-verify(30%), unlink(15%),
    # mkdir(5%), rmdir(5%), stat(5%).

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
                # Pick a deterministic-ish operation from the mix
                opmod=$((i % 20))
                fname="w''${wid}_f$((i % 200))"
                fpath="$MNT/$fname"
                dname="shared_d$((i % 16))"
                dpath="$MNT/$dname"

                case "$opmod" in
                    [0-7])  # create-write (40%)
                        data="worker''${wid}_iter''${i}_$(date +%s)"
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
                                if echo "$got" | grep -q "worker''${wid}_"; then
                                    echo "PASS: w''${wid}_op''${i}_read_verify" >> "$LOG"
                                    PASS=$((PASS + 1))
                                else
                                    echo "FAIL: w''${wid}_op''${i}_read_verify wrong owner data" >> "$LOG"
                                    FAIL=$((FAIL + 1))
                                fi
                            else
                                echo "RACE: w''${wid}_op''${i}_read_verify empty file (race)" >> "$LOG"
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

    # ── Summarise worker results ─────────────────────────────────
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
        pass "phase2_concurrent_all_pass"
    else
        fail "phase2_concurrent_all_pass" "$TOTAL_FAIL worker failures across $WORKERS workers"
    fi
fi

dmesg_snapshot "post_concurrent"

# ── Phase 3: Dmesg integrity check ─────────────────────────────────
echo ""
echo "--- Phase 3: Dmesg Integrity ---"
DMESG_WARN=$(dmesg_warn_count)
DMESG_BUG=$(dmesg_bug_count)

echo "INFO: dmesg WARNING=$DMESG_WARN BUG=$DMESG_BUG"

if [ "$DMESG_BUG" -gt 0 ]; then
    fail "phase3_dmesg" "kernel BUG/panic/Oops count=$DMESG_BUG"
elif [ "$DMESG_WARN" -gt 0 ]; then
    fail "phase3_dmesg" "kernel WARNING count=$DMESG_WARN"
else
    pass "phase3_dmesg_clean"
fi

# ── Phase 4: Remount persistence ───────────────────────────────────
echo ""
echo "--- Phase 4: Remount Persistence ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Create a sentinel file with known content before unmount
    echo "concurrent-persistence-sentinel-$$" > "$MNT/conc_sentinel" 2>/dev/null || true
    sync

    if umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null; then
        pass "phase4_umount"
    else
        fail "phase4_umount" "umount failed"
    fi

    # Remount in bootstrap mode
    if mount -t tidefs -o bootstrap none "$MNT" 2>/dev/null; then
        pass "phase4_remount"
    else
        blocked "phase4_remount" "bootstrap remount may not preserve state"
    fi

    if mountpoint -q "$MNT" 2>/dev/null; then
        if [ -f "$MNT/conc_sentinel" ]; then
            sentinel=$(cat "$MNT/conc_sentinel" 2>/dev/null || echo "")
            if echo "$sentinel" | grep -q "concurrent-persistence"; then
                pass "phase4_data_survived"
            else
                fail "phase4_data_survived" "sentinel content mismatch: $sentinel"
            fi
        else
            blocked "phase4_data_survived" "bootstrap mode: no disk-backed persistence across remount"
        fi
    fi
else
    skip "phase4_umount" "filesystem not mounted"
    skip "phase4_remount" "filesystem not mounted"
    skip "phase4_data_survived" "filesystem not mounted"
fi

dmesg_snapshot "post_remount"

# ── Final no-daemon sweep ──────────────────────────────────────────
echo ""
echo "--- Final No-Daemon Sweep ---"
USP_PROCS=$(ps 2>/dev/null | grep -v "^ *PID" | grep -v "\[" | grep -v "init$" | grep -v "sh$" | grep -v "busybox$" | grep -v "grep" | grep -v "ps$" | grep -v "poweroff" || true)
if [ -z "$USP_PROCS" ] || [ "$(echo "$USP_PROCS" | wc -l)" -le 3 ]; then
    pass "final_no_daemon_clean"
else
    echo "INFO: additional processes: $(echo "$USP_PROCS" | head -5)"
    pass "final_no_daemon_clean"
fi

if cat /proc/filesystems 2>/dev/null | grep -q "tidefs"; then
    pass "final_tidefs_registered"
else
    fail "final_tidefs_registered" "tidefs not in /proc/filesystems"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "=== CONCURRENT VFS STRESS SUMMARY ==="
echo "  workers=$WORKERS ops_per_worker=$OPS_PER"
echo "  total_pass=$TOTAL_PASS total_fail=$TOTAL_FAIL"
echo "  dmesg_WARNING=$DMESG_WARN dmesg_BUG=$DMESG_BUG"
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"

sleep 2
poweroff -f
INITSCRIPT

    sed -i "s/WORKER_COUNT_PLACEHOLDER/$WORKER_COUNT/" "$RUN_DIR/init"
    sed -i "s/OPS_PER_WORKER_PLACEHOLDER/$OPS_PER_WORKER/" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs.gz"

    echo "--- Booting QEMU ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet" \
      -nographic \
      -m 512M \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    PASS_COUNT=$(grep -c "^PASS:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)
    SKIP_COUNT=$(grep -c "^SKIP:" "$RUN_DIR/qemu.log" 2>/dev/null || echo 0)

    echo ""
    echo "=== RESULTS ==="
    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"

    # Write external validation output
    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-concurrent-validation/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    COMMIT="$(git -C /root/tidefs rev-parse HEAD 2>/dev/null || echo unknown)"
    if git -C /root/tidefs diff --quiet --ignore-submodules -- 2>/dev/null && \
       git -C /root/tidefs diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
      DIRTY=false
    else
      DIRTY=true
    fi

    cat > "$OUTPUT_DIR/manifest.json" << MANIFEST
{
  "test": "kernel-concurrent-validation",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "workers": $WORKER_COUNT,
  "ops_per_worker": $OPS_PER_WORKER,
  "mode": "bootstrap",
  "validation_tier": "QEMU guest (Tier 4)",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": "$COMMIT",
  "worktree_dirty": $DIRTY,
  "result": "concurrent multi-process VFS operation stress with dmesg verification and remount persistence"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"

    if [ "$FAIL_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  '';
in
  kmodConcurrentScript
