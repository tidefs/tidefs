# TideFS: kernel VFS throughput latency baseline gate.
#
# Boots Linux 7.0 QEMU, loads kmod-posix-vfs in bootstrap mode, and measures
# sequential read/write throughput plus stat latency with a simple
# busybox-based benchmark harness.
#
# Tier: Tier 5 mounted Linux 7.0 kernel VFS (QEMU guest + kernel
# module load + mounted VFS read/write + no-daemon residency).
{
  pkgs,
  linuxKernel_7_0,
}:

let
  glibcLib = "${pkgs.glibc}/lib";

  kmodPerfScript = pkgs.writeShellScriptBin "tidefs-kmod-perf-baseline" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="''${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
    POSIX_VFS_KO="''${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
    GLIBC_LIB="${glibcLib}"

    TMPDIR="''${TIDEFS_PERF_TMPDIR:-/tmp/tidefs-kmod-perf-baseline}"
    QEMU_MEM="''${TIDEFS_PERF_QEMU_MEM:-512M}"
    TIMEOUT_SEC=600
    SOURCE_DIR="''${TIDEFS_SOURCE_DIR:-}"
    if [ -z "$SOURCE_DIR" ]; then
      SOURCE_DIR="''${TIDEFS_REPO_ROOT:-}"
    fi
    if [ -z "$SOURCE_DIR" ]; then
      SOURCE_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
    fi
    SOURCE_COMMIT="''${TIDEFS_SOURCE_COMMIT:-}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-perf-baseline [--keep-tmp] [--self-test-parser]

Kernel VFS throughput latency baseline.
Boots Linux 7.0 QEMU, mounts kmod-posix-vfs in bootstrap mode, runs
sequential read/write throughput and stat latency measurements.

Options:
  --keep-tmp           Do not remove temp directory on exit
  --self-test-parser   Run parser fixtures without booting QEMU
  --help, -h           Show this message

Exit codes:
  0  Baseline measurements completed
  1  One or more failures
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    SELF_TEST_PARSER=0
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --keep-tmp) KEEP_TMP=1; shift ;;
        --self-test-parser) SELF_TEST_PARSER=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    count_log_prefix() {
      awk -v prefix="$2" 'index($0, prefix) == 1 { n++ } END { print n + 0 }' "$1" 2>/dev/null || echo 0
    }

    first_log_value() {
      awk -F= -v key="$2" '{
        lhs = $1
        sub(/^[[:space:]]+/, "", lhs)
        sub(/[[:space:]]+$/, "", lhs)
        if (lhs == key) { print $2; exit }
      }' "$1" 2>/dev/null || true
    }

    is_positive_number() {
      awk -v n="$1" 'BEGIN { exit !(n ~ /^[0-9]+([.][0-9]+)?$/ && n > 0) }'
    }

    git_dirty_json_bool() {
      if git -C "$SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
         [ -z "$(git -C "$SOURCE_DIR" status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
        echo false
      else
        echo true
      fi
    }

    git_commit_value() {
      if [ -n "$SOURCE_COMMIT" ]; then
        echo "$SOURCE_COMMIT"
      else
        git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || echo unknown
      fi
    }

    analyze_qemu_log() {
      local log_file="$1"
      local qemu_exit="$2"

      PASS_COUNT=$(count_log_prefix "$log_file" "PASS:")
      FAIL_COUNT=$(count_log_prefix "$log_file" "FAIL:")
      BLOCKED_COUNT=$(count_log_prefix "$log_file" "BLOCKED:")
      SKIP_COUNT=$(count_log_prefix "$log_file" "SKIP:")

      WRITE_TP=$(first_log_value "$log_file" "write_throughput_MBps")
      READ_TP=$(first_log_value "$log_file" "read_throughput_MBps")
      STAT_LAT=$(first_log_value "$log_file" "stat_avg_latency_us")

      WRITE_TP_VAL="''${WRITE_TP:-0}"
      READ_TP_VAL="''${READ_TP:-0}"
      STAT_LAT_VAL="''${STAT_LAT:-0}"

      QEMU_SUCCESS=false
      QEMU_TIMED_OUT=false
      LOG_EMPTY=false
      REQUIRED_METRICS_PRESENT=false
      VERDICT_STATUS=PASS
      VERDICT_REASON=complete
      VERDICT_EXIT=0

      [ "$qemu_exit" -eq 0 ] && QEMU_SUCCESS=true
      if [ "$qemu_exit" -eq 124 ] || [ "$qemu_exit" -eq 137 ]; then
        QEMU_TIMED_OUT=true
      fi
      [ ! -s "$log_file" ] && LOG_EMPTY=true

      if is_positive_number "$WRITE_TP_VAL" &&
         is_positive_number "$READ_TP_VAL" &&
         is_positive_number "$STAT_LAT_VAL"; then
        REQUIRED_METRICS_PRESENT=true
      fi

      if [ "$qemu_exit" -ne 0 ]; then
        VERDICT_STATUS=BLOCKED
        VERDICT_REASON=qemu_exit_$qemu_exit
        VERDICT_EXIT=2
        if [ "$QEMU_TIMED_OUT" = true ]; then
          VERDICT_REASON=qemu_timeout
        fi
      elif [ "$LOG_EMPTY" = true ]; then
        VERDICT_STATUS=BLOCKED
        VERDICT_REASON=empty_qemu_log
        VERDICT_EXIT=2
      elif [ "$PASS_COUNT" -eq 0 ]; then
        VERDICT_STATUS=BLOCKED
        VERDICT_REASON=zero_pass_rows
        VERDICT_EXIT=2
      elif [ "$FAIL_COUNT" -gt 0 ]; then
        VERDICT_STATUS=FAIL
        VERDICT_REASON=fail_rows
        VERDICT_EXIT=1
      elif [ "$BLOCKED_COUNT" -gt 0 ]; then
        VERDICT_STATUS=BLOCKED
        VERDICT_REASON=blocked_rows
        VERDICT_EXIT=2
      elif [ "$REQUIRED_METRICS_PRESENT" != true ]; then
        VERDICT_STATUS=BLOCKED
        VERDICT_REASON=missing_required_metrics
        VERDICT_EXIT=2
      fi
    }

    expect_parser_verdict() {
      local name="$1"
      local expected_status="$2"
      local expected_reason="$3"
      local expected_exit="$4"

      if [ "$VERDICT_STATUS" != "$expected_status" ] ||
         [ "$VERDICT_REASON" != "$expected_reason" ] ||
         [ "$VERDICT_EXIT" -ne "$expected_exit" ]; then
        echo "parser self-test failed: $name" >&2
        echo "  expected: $expected_status/$expected_reason/$expected_exit" >&2
        echo "  actual:   $VERDICT_STATUS/$VERDICT_REASON/$VERDICT_EXIT" >&2
        exit 1
      fi
    }

    self_test_parser() {
      local test_dir
      test_dir="$(mktemp -d)"
      trap 'rm -rf "$test_dir"' RETURN

      : > "$test_dir/empty.log"
      analyze_qemu_log "$test_dir/empty.log" 0
      expect_parser_verdict empty-log BLOCKED empty_qemu_log 2

      cat > "$test_dir/timeout.log" <<'EOF'
=== TideFS Kernel VFS Throughput Latency Baseline ===
kernel_version=7.0.0
--- Phase 0: Module Load ---
EOF
      analyze_qemu_log "$test_dir/timeout.log" 124
      expect_parser_verdict timeout-log BLOCKED qemu_timeout 2

      cat > "$test_dir/qemu-exit-nonzero.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_latency_us=30
EOF
      analyze_qemu_log "$test_dir/qemu-exit-nonzero.log" 1
      expect_parser_verdict qemu-exit-nonzero BLOCKED qemu_exit_1 2

      cat > "$test_dir/zero-pass.log" <<'EOF'
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_latency_us=30
EOF
      analyze_qemu_log "$test_dir/zero-pass.log" 0
      expect_parser_verdict zero-pass BLOCKED zero_pass_rows 2

      cat > "$test_dir/missing-metrics.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
EOF
      analyze_qemu_log "$test_dir/missing-metrics.log" 0
      expect_parser_verdict missing-metrics BLOCKED missing_required_metrics 2

      cat > "$test_dir/pass.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
  write_throughput_MBps=10.00
  read_throughput_MBps=20.00
  stat_avg_latency_us=30
EOF
      analyze_qemu_log "$test_dir/pass.log" 0
      expect_parser_verdict pass-log PASS complete 0

      echo "parser self-test: ok"
    }

    if [ "$SELF_TEST_PARSER" -eq 1 ]; then
      self_test_parser
      exit 0
    fi

    echo "=== TideFS Kernel VFS Throughput Latency Baseline ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Module:    kmod-posix-vfs"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ -z "$POSIX_VFS_KO" ]; then
      for c in "$MODULE_DIR/tidefs_posix_vfs.ko" \
               "$MODULE_DIR/tidefs_posix_vfs/tidefs_posix_vfs.ko"; do
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
      printf test xargs seq awk tr sort uniq md5sum expr mountpoint umount wc uname date \
      time; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

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

echo "=== TideFS Kernel VFS Throughput Latency Baseline ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0; FAILED=0; BLOCKED=0; SKIPPED=0
write_throughput_mbps=0
read_throughput_mbps=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
skip()   { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }

MNT=/mnt/tidefs
EVDIR=/validation

dmesg_snapshot() { dmesg > "$EVDIR/dmesg_$1.txt" 2>/dev/null || true; }
dmesg_bug_count()  { dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic|Oops:|Call Trace" || echo 0; }

check_no_daemon() {
    ps 2>/dev/null | grep -iqE "tidefs.*daemon|fuse.*adapter|ublk.*adapter" && return 1
    return 0
}

# Phase 0: Module Load
echo "--- Phase 0: Module Load ---"
dmesg_snapshot "pre_insmod"

MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    insmod "$MODULE_PATH" 2>/tmp/insmod.err && pass "phase0_insmod" || fail "phase0_insmod" "$(head -1 /tmp/insmod.err)"
else
    blocked "phase0_insmod" "tidefs_posix_vfs.ko not found"
fi

# Phase 1: Mount
echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"
MOUNTED=0
if mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/mount.err; then
    pass "phase1_mount"
    MOUNTED=1
else
    blocked "phase1_mount" "$(head -1 /tmp/mount.err)"
fi

check_no_daemon && pass "phase1_no_daemon" || fail "phase1_no_daemon" "userspace daemon detected"
dmesg_snapshot "post_mount"

# Phase 2: Sequential Write Throughput
echo "--- Phase 2: Sequential Write Throughput ---"
if [ "$MOUNTED" -eq 0 ]; then
    skip "phase2_write" "filesystem not mounted"
    skipped_write=1
else
    # Write a 1MB file in 4K blocks and measure wall-clock time
    echo "Writing 1MB file (256 x 4K blocks)..."
    sync
    start_ns=$(date +%s%N 2>/dev/null || echo 0)
    i=0; BLOCKS=256; BLKSIZE=4096
    while [ $i -lt $BLOCKS ]; do
        dd if=/dev/zero of="$MNT/perf_write_test" bs=$BLKSIZE count=1 seek=$i conv=notrunc 2>/dev/null
        i=$((i + 1))
    done
    sync
    end_ns=$(date +%s%N 2>/dev/null || echo 0)
    duration_s=0; write_throughput_mbps=0
    if [ "$start_ns" -gt 0 ] && [ "$end_ns" -gt 0 ]; then
        duration_ns=$((end_ns - start_ns))
        duration_s=$(awk "BEGIN {printf \"%.3f\", $duration_ns / 1000000000}" 2>/dev/null || echo "0")
        if [ "$duration_ns" -gt 0 ]; then
            write_throughput_mbps=$(awk "BEGIN {printf \"%.2f\", 1000000000 / $duration_ns}" 2>/dev/null || echo "0")
        fi
    fi
    echo "  write_duration_s=$duration_s"
    echo "  write_throughput_MBps=$write_throughput_mbps"
    ws=$(stat -c %s "$MNT/perf_write_test" 2>/dev/null || echo 0)
    [ "$ws" -ge 1048576 ] && pass "phase2_write_data" || fail "phase2_write_data" "file_size=$ws"
fi

# Phase 3: Sequential Read Throughput
echo "--- Phase 3: Sequential Read Throughput ---"
if [ "$MOUNTED" -eq 0 ]; then
    skip "phase3_read" "filesystem not mounted"
else
    echo "Reading 1MB file (256 x 4K blocks)..."
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    start_ns=$(date +%s%N 2>/dev/null || echo 0)
    dd if="$MNT/perf_write_test" of=/dev/null bs=4096 count=256 2>/dev/null
    end_ns=$(date +%s%N 2>/dev/null || echo 0)
    duration_s=0; read_throughput_mbps=0
    if [ "$start_ns" -gt 0 ] && [ "$end_ns" -gt 0 ]; then
        duration_ns=$((end_ns - start_ns))
        duration_s=$(awk "BEGIN {printf \"%.3f\", $duration_ns / 1000000000}" 2>/dev/null || echo "0")
        if [ "$duration_ns" -gt 0 ]; then
            read_throughput_mbps=$(awk "BEGIN {printf \"%.2f\", 1000000000 / $duration_ns}" 2>/dev/null || echo "0")
        fi
    fi
    echo "  read_duration_s=$duration_s"
    echo "  read_throughput_MBps=$read_throughput_mbps"
    pass "phase3_read"
fi

# Phase 4: Stat Latency
echo "--- Phase 4: Stat Latency ---"
if [ "$MOUNTED" -eq 0 ]; then
    skip "phase4_stat" "filesystem not mounted"
else
    # Measure stat latency over 100 iterations
    echo "Running 100 stat calls..."
    sync
    start_ns=$(date +%s%N 2>/dev/null || echo 0)
    i=0
    while [ $i -lt 100 ]; do
        stat "$MNT/perf_write_test" >/dev/null 2>&1
        i=$((i + 1))
    done
    end_ns=$(date +%s%N 2>/dev/null || echo 0)
    duration_s=0; avg_us=0
    if [ "$start_ns" -gt 0 ] && [ "$end_ns" -gt 0 ]; then
        duration_ns=$((end_ns - start_ns))
        avg_ns=$((duration_ns / 100))
        avg_us=$(awk "BEGIN {printf \"%.2f\", $avg_ns / 1000}" 2>/dev/null || echo "0")
        duration_s=$(awk "BEGIN {printf \"%.3f\", $duration_ns / 1000000000}" 2>/dev/null || echo "0")
    fi
    echo "  stat_avg_latency_us=$avg_us"
    echo "  stat_total_duration_s=$duration_s"
    pass "phase4_stat"
fi

# Phase 5: Dmesg Integrity
echo "--- Phase 5: Dmesg Integrity ---"
DB=$(dmesg_bug_count)
echo "BUG=$DB"
[ "$DB" -gt 0 ] && fail "phase5_dmesg" "BUG=$DB" || pass "phase5_dmesg_clean"
dmesg_snapshot "final"

# Phase 6: Unmount and Cleanup
echo "--- Phase 6: Unmount ---"
sync
if grep -q tidefs /proc/mounts 2>/dev/null; then
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
    pass "phase6_umount"
else
    fail "phase6_umount" "mount already gone"
fi

echo "--- Phase 7: Module Unload ---"
rmmod tidefs_posix_vfs 2>/tmp/rm.err && pass "phase7_rmmod" || fail "phase7_rmmod" "$(head -1 /tmp/rm.err)"

echo ""
echo "============================================================"
echo "=== PERFORMANCE BASELINE SUMMARY ==="
echo "  write_throughput_MBps=$write_throughput_mbps"
echo "  read_throughput_MBps=$read_throughput_mbps"
echo "  stat_avg_latency_us=$avg_us"
echo "  dmesg_BUG=$DB"
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED SKIP=$SKIPPED"
echo "============================================================"
sleep 2
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . | cpio -o -H newc) | gzip > "$RUN_DIR/initramfs.gz"

    echo "--- Booting QEMU ---"
    QEMU_EXIT=0
    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initramfs.gz" \
      -append "console=ttyS0 quiet" \
      -nographic \
      -m "$QEMU_MEM" \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log"
    QEMU_EXIT="''${PIPESTATUS[0]}"
    set -e

    echo "--- QEMU exited with code $QEMU_EXIT ---"
    analyze_qemu_log "$RUN_DIR/qemu.log" "$QEMU_EXIT"

    echo "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  BLOCKED: $BLOCKED_COUNT  SKIP: $SKIP_COUNT"
    echo "QEMU success: $QEMU_SUCCESS  Required metrics: $REQUIRED_METRICS_PRESENT  Verdict: $VERDICT_STATUS ($VERDICT_REASON)"

    OUTPUT_DIR="/root/ai/tmp/tidefs-validation/kernel-vfs-perf-baseline/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"

    cat > "$OUTPUT_DIR/validation-manifest.json" << MANIFEST
{
  "test": "kernel-vfs-perf-baseline",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "bootstrap",
  "validation_tier": "Tier 5 mounted Linux 7.0 kernel VFS",
  "qemu_exit": $QEMU_EXIT,
  "qemu_success": $QEMU_SUCCESS,
  "qemu_timed_out": $QEMU_TIMED_OUT,
  "log_empty": $LOG_EMPTY,
  "required_metrics_present": $REQUIRED_METRICS_PRESENT,
  "metrics": {
    "write_throughput_MBps": "$WRITE_TP_VAL",
    "read_throughput_MBps": "$READ_TP_VAL",
    "stat_avg_latency_us": "$STAT_LAT_VAL"
  },
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": "$(git_commit_value)",
  "worktree_dirty": $(git_dirty_json_bool),
  "module_source": "configured external module path",
  "status": "$VERDICT_STATUS",
  "result": "kernel VFS throughput latency baseline $VERDICT_STATUS: $VERDICT_REASON; write $WRITE_TP_VAL MB/s, read $READ_TP_VAL MB/s, stat $STAT_LAT_VAL us avg latency"
}
MANIFEST

    echo "Validation output directory: $OUTPUT_DIR"
    exit "$VERDICT_EXIT"
  '';
in
  kmodPerfScript
