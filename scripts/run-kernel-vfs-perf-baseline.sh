#!/usr/bin/env bash
# run-kernel-vfs-perf-baseline.sh -- build and execute the kernel VFS
# throughput latency baseline without requiring Nix flake integration.
#
# Usage:
#   scripts/run-kernel-vfs-perf-baseline.sh [--keep-tmp] [--timeout SECONDS]
#
# Boots Linux 7.0 QEMU with kmod-posix-vfs, mounts a TideFS pool in
# bootstrap mode, and measures sequential read/write throughput and
# stat latency. Validation is written to
# /root/ai/tmp/tidefs-validation/kernel-vfs-perf-baseline/.
#
# Validation tier: Tier 5 mounted Linux 7.0 kernel VFS (QEMU + module
# load + mounted VFS read/write + no-daemon residency).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATION_DIR="/root/ai/tmp/tidefs-validation/kernel-vfs-perf-baseline"
TMPDIR="${TIDEFS_KERNEL_PERF_TMPDIR:-/tmp/tidefs-kernel-perf-baseline}"
TIMEOUT_SEC="${TIDEFS_KERNEL_PERF_TIMEOUT:-600}"

KEEP_TMP=0
SELF_TEST_PARSER=0

count_log_prefix() {
  awk -v prefix="$2" '{
    line = $0
    sub(/^[[:space:]]+/, "", line)
    if (index(line, prefix) == 1) n++
  } END { print n + 0 }' "$1" 2>/dev/null || echo 0
}

first_log_value() {
  awk -v key="$2" '{
    sep = index($0, "=")
    if (sep == 0) next
    lhs = substr($0, 1, sep - 1)
    rhs = substr($0, sep + 1)
    sub(/^[[:space:]]+/, "", lhs)
    sub(/[[:space:]]+$/, "", lhs)
    sub(/^[[:space:]]+/, "", rhs)
    sub(/[[:space:]]+$/, "", rhs)
    if (lhs == key) { print rhs; exit }
  }' "$1" 2>/dev/null || true
}

is_positive_number() {
  awk -v n="$1" 'BEGIN { exit !(n ~ /^[0-9]+([.][0-9]+)?$/ && n > 0) }'
}

json_string() {
  local value="${1-}"

  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\b'/\\b}"
  value="${value//$'\f'/\\f}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "$value"
}

git_dirty_json_bool() {
  if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
     [ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
    echo false
  else
    echo true
  fi
}

qemu_accel_value() {
  if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo kvm
  else
    echo tcg
  fi
}

write_blocked_manifest() {
  local reason="$1"
  local run_id
  local output_dir

  mkdir -p "$VALIDATION_DIR"
  run_id="$(date -u +%Y-%m-%dT%H%M%SZ)"
  output_dir="$VALIDATION_DIR/$run_id"
  mkdir -p "$output_dir"

  cat > "$output_dir/validation-manifest.json" << MANIFEST
{
  "test": "kernel-vfs-perf-baseline",
  "date": "$run_id",
  "mode": "bootstrap",
  "validation_tier": "Tier 5 mounted Linux 7.0 kernel VFS",
  "qemu_accel": "$(qemu_accel_value)",
  "qemu_exit": null,
  "qemu_success": false,
  "qemu_timed_out": false,
  "log_empty": true,
  "required_metrics_present": false,
  "metrics": {
    "write_duration_ms": "0",
    "read_duration_ms": "0",
    "write_throughput_MBps": "0",
    "read_throughput_MBps": "0",
    "stat_avg_us": "0"
  },
  "pass": 0,
  "fail": 0,
  "blocked": 1,
  "skip": 0,
  "commit": $(json_string "$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"),
  "worktree_dirty": $(git_dirty_json_bool),
  "module_source": "configured external module path",
  "status": "BLOCKED",
  "result": $(json_string "kernel VFS perf baseline BLOCKED: $reason")
}
MANIFEST

  echo "Validation output directory: $output_dir"
}

analyze_qemu_log() {
  local log_file="$1"
  local qemu_exit="$2"

  PASS_COUNT=$(count_log_prefix "$log_file" "PASS:")
  FAIL_COUNT=$(count_log_prefix "$log_file" "FAIL:")
  BLOCKED_COUNT=$(count_log_prefix "$log_file" "BLOCKED:")
  SKIP_COUNT=$(count_log_prefix "$log_file" "SKIP:")

  WD=$(first_log_value "$log_file" "write_duration_ms")
  RD=$(first_log_value "$log_file" "read_duration_ms")
  WTP=$(first_log_value "$log_file" "write_throughput_MBps")
  RTP=$(first_log_value "$log_file" "read_throughput_MBps")
  SU=$(first_log_value "$log_file" "stat_avg_us")
  if [ -z "$SU" ]; then
    SU=$(first_log_value "$log_file" "stat_avg_latency_us")
  fi

  WD="${WD:-0}"
  RD="${RD:-0}"
  WTP="${WTP:-0}"
  RTP="${RTP:-0}"
  SU="${SU:-0}"

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

  if is_positive_number "$WTP" && is_positive_number "$RTP" && is_positive_number "$SU"; then
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
  local want_status="$2"
  local want_reason="$3"
  local want_exit="$4"

  if [ "$VERDICT_STATUS" != "$want_status" ] ||
     [ "$VERDICT_REASON" != "$want_reason" ] ||
     [ "$VERDICT_EXIT" -ne "$want_exit" ]; then
    echo "parser self-test failed for $name: got status=$VERDICT_STATUS reason=$VERDICT_REASON exit=$VERDICT_EXIT" >&2
    echo "expected status=$want_status reason=$want_reason exit=$want_exit" >&2
    exit 1
  fi
}

expect_parser_metrics() {
  local name="$1"
  local want_write_tp="$2"
  local want_read_tp="$3"
  local want_stat_us="$4"

  if [ "$WTP" != "$want_write_tp" ] ||
     [ "$RTP" != "$want_read_tp" ] ||
     [ "$SU" != "$want_stat_us" ] ||
     [ "$REQUIRED_METRICS_PRESENT" != true ]; then
    echo "parser self-test failed for $name: got write=$WTP read=$RTP stat=$SU required=$REQUIRED_METRICS_PRESENT" >&2
    echo "expected write=$want_write_tp read=$want_read_tp stat=$want_stat_us required=true" >&2
    exit 1
  fi
}

expect_parser_metric_values() {
  local name="$1"
  local want_write_tp="$2"
  local want_read_tp="$3"
  local want_stat_us="$4"

  if [ "$WTP" != "$want_write_tp" ] ||
     [ "$RTP" != "$want_read_tp" ] ||
     [ "$SU" != "$want_stat_us" ]; then
    echo "parser self-test failed for $name: got write=$WTP read=$RTP stat=$SU" >&2
    echo "expected write=$want_write_tp read=$want_read_tp stat=$want_stat_us" >&2
    exit 1
  fi
}

expect_parser_counts() {
  local name="$1"
  local want_pass="$2"
  local want_fail="$3"
  local want_blocked="$4"
  local want_skip="$5"

  if [ "$PASS_COUNT" -ne "$want_pass" ] ||
     [ "$FAIL_COUNT" -ne "$want_fail" ] ||
     [ "$BLOCKED_COUNT" -ne "$want_blocked" ] ||
     [ "$SKIP_COUNT" -ne "$want_skip" ]; then
    echo "parser self-test failed for $name: got pass=$PASS_COUNT fail=$FAIL_COUNT blocked=$BLOCKED_COUNT skip=$SKIP_COUNT" >&2
    echo "expected pass=$want_pass fail=$want_fail blocked=$want_blocked skip=$want_skip" >&2
    exit 1
  fi
}

expect_parser_state() {
  local name="$1"
  local want_qemu_success="$2"
  local want_qemu_timed_out="$3"
  local want_log_empty="$4"
  local want_required_metrics="$5"

  if [ "$QEMU_SUCCESS" != "$want_qemu_success" ] ||
     [ "$QEMU_TIMED_OUT" != "$want_qemu_timed_out" ] ||
     [ "$LOG_EMPTY" != "$want_log_empty" ] ||
     [ "$REQUIRED_METRICS_PRESENT" != "$want_required_metrics" ]; then
    echo "parser self-test failed for $name: got qemu_success=$QEMU_SUCCESS timed_out=$QEMU_TIMED_OUT log_empty=$LOG_EMPTY required=$REQUIRED_METRICS_PRESENT" >&2
    echo "expected qemu_success=$want_qemu_success timed_out=$want_qemu_timed_out log_empty=$want_log_empty required=$want_required_metrics" >&2
    exit 1
  fi
}

expect_json_string() {
  local name="$1"
  local input="$2"
  local expected="$3"
  local actual

  actual="$(json_string "$input")"
  if [ "$actual" != "$expected" ]; then
    echo "json string self-test failed for $name: got $actual expected $expected" >&2
    exit 1
  fi
}

self_test_parser() {
  local test_dir
  test_dir="$(mktemp -d)"
  trap 'rm -rf "$test_dir"' RETURN

  expect_json_string quote-and-backslash 'quote"slash\' '"quote\"slash\\"'
  expect_json_string control-bytes $'line\nnext\tcarriage\rreturn' '"line\nnext\tcarriage\rreturn"'

  : > "$test_dir/empty.log"
  analyze_qemu_log "$test_dir/empty.log" 0
  expect_parser_verdict empty-log BLOCKED empty_qemu_log 2
  expect_parser_counts empty-log 0 0 0 0
  expect_parser_state empty-log true false true false

  cat > "$test_dir/timeout.log" <<'EOF'
=== TideFS Kernel VFS Throughput Latency Baseline ===
kernel=7.0.0
--- Phase 0: Module Load ---
EOF
  analyze_qemu_log "$test_dir/timeout.log" 124
  expect_parser_verdict timeout-log BLOCKED qemu_timeout 2
  expect_parser_counts timeout-log 0 0 0 0
  expect_parser_state timeout-log false true false false

  cat > "$test_dir/timeout-complete-log.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_us=30
EOF
  analyze_qemu_log "$test_dir/timeout-complete-log.log" 137
  expect_parser_verdict timeout-complete-log BLOCKED qemu_timeout 2
  expect_parser_counts timeout-complete-log 3 0 0 0
  expect_parser_state timeout-complete-log false true false true

  cat > "$test_dir/qemu-exit-nonzero.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_us=30
EOF
  analyze_qemu_log "$test_dir/qemu-exit-nonzero.log" 1
  expect_parser_verdict qemu-exit-nonzero BLOCKED qemu_exit_1 2
  expect_parser_counts qemu-exit-nonzero 3 0 0 0
  expect_parser_state qemu-exit-nonzero false false false true

  cat > "$test_dir/zero-pass.log" <<'EOF'
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_us=30
EOF
  analyze_qemu_log "$test_dir/zero-pass.log" 0
  expect_parser_verdict zero-pass BLOCKED zero_pass_rows 2
  expect_parser_counts zero-pass 0 0 0 0
  expect_parser_state zero-pass true false false true

  cat > "$test_dir/missing-metrics.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
EOF
  analyze_qemu_log "$test_dir/missing-metrics.log" 0
  expect_parser_verdict missing-metrics BLOCKED missing_required_metrics 2
  expect_parser_counts missing-metrics 3 0 0 0
  expect_parser_state missing-metrics true false false false

  cat > "$test_dir/invalid-metrics.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
write_throughput_MBps=nan
read_throughput_MBps=0
stat_avg_us=-1
EOF
  analyze_qemu_log "$test_dir/invalid-metrics.log" 0
  expect_parser_verdict invalid-metrics BLOCKED missing_required_metrics 2
  expect_parser_metric_values invalid-metrics nan 0 -1
  expect_parser_counts invalid-metrics 3 0 0 0
  expect_parser_state invalid-metrics true false false false

  cat > "$test_dir/value-delimiter-metrics.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
write_throughput_MBps=10.00=trailing
read_throughput_MBps=20.00=trailing
stat_avg_us=30=trailing
EOF
  analyze_qemu_log "$test_dir/value-delimiter-metrics.log" 0
  expect_parser_verdict value-delimiter-metrics BLOCKED missing_required_metrics 2
  expect_parser_metric_values value-delimiter-metrics 10.00=trailing 20.00=trailing 30=trailing
  expect_parser_counts value-delimiter-metrics 3 0 0 0
  expect_parser_state value-delimiter-metrics true false false false

  cat > "$test_dir/fail-row.log" <<'EOF'
PASS: insmod
PASS: mount
FAIL: stat latency regression
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_us=30
EOF
  analyze_qemu_log "$test_dir/fail-row.log" 0
  expect_parser_verdict fail-row FAIL fail_rows 1
  expect_parser_counts fail-row 2 1 0 0
  expect_parser_state fail-row true false false true

  cat > "$test_dir/indented-rows.log" <<'EOF'
  PASS: insmod
  PASS: mount
  FAIL: stat latency regression
  BLOCKED: missing kernel tracepoint
  SKIP: optional cache warmup unavailable
  write_throughput_MBps = 10.00
  read_throughput_MBps = 20.00
  stat_avg_us = 30
EOF
  analyze_qemu_log "$test_dir/indented-rows.log" 0
  expect_parser_verdict indented-rows FAIL fail_rows 1
  expect_parser_metrics indented-rows 10.00 20.00 30
  expect_parser_counts indented-rows 2 1 1 1
  expect_parser_state indented-rows true false false true

  cat > "$test_dir/blocked-row.log" <<'EOF'
PASS: insmod
PASS: mount
BLOCKED: missing kernel tracepoint
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_us=30
EOF
  analyze_qemu_log "$test_dir/blocked-row.log" 0
  expect_parser_verdict blocked-row BLOCKED blocked_rows 2
  expect_parser_counts blocked-row 2 0 1 0
  expect_parser_state blocked-row true false false true

  cat > "$test_dir/pass.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
  write_throughput_MBps = 10.00
  read_throughput_MBps = 20.00
  stat_avg_us = 30
EOF
  analyze_qemu_log "$test_dir/pass.log" 0
  expect_parser_verdict pass-log PASS complete 0
  expect_parser_metrics pass-log 10.00 20.00 30
  expect_parser_counts pass-log 3 0 0 0
  expect_parser_state pass-log true false false true

  cat > "$test_dir/skip-row.log" <<'EOF'
PASS: insmod
PASS: mount
SKIP: optional cache warmup unavailable
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_us=30
EOF
  analyze_qemu_log "$test_dir/skip-row.log" 0
  expect_parser_verdict skip-row PASS complete 0
  expect_parser_metrics skip-row 10.00 20.00 30
  expect_parser_counts skip-row 2 0 0 1
  expect_parser_state skip-row true false false true

  cat > "$test_dir/stat-latency-alias.log" <<'EOF'
PASS: insmod
PASS: mount
PASS: no_daemon
write_throughput_MBps=10.00
read_throughput_MBps=20.00
stat_avg_latency_us=30
EOF
  analyze_qemu_log "$test_dir/stat-latency-alias.log" 0
  expect_parser_verdict stat-latency-alias PASS complete 0
  expect_parser_metrics stat-latency-alias 10.00 20.00 30
  expect_parser_counts stat-latency-alias 3 0 0 0
  expect_parser_state stat-latency-alias true false false true

  echo "parser self-test: ok"
}

usage() {
  cat <<EOF
Usage: scripts/run-kernel-vfs-perf-baseline.sh [--keep-tmp] [--timeout SECONDS]

Boot Linux 7.0 QEMU with kmod-posix-vfs, mount a TideFS pool in bootstrap
mode, and measure sequential read/write throughput and stat latency.
Validation output directory:
  $VALIDATION_DIR

Options:
  --keep-tmp         Do not remove temp directory on exit
  --timeout SECONDS  QEMU boot timeout (default: $TIMEOUT_SEC)
  --self-test-parser Run parser fixtures without booting QEMU
  --help, -h         Show this message

Exit codes:
  0  Baseline measurements completed
  1  One or more failures
  2  Environment or dependency error
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --keep-tmp) KEEP_TMP=1; shift ;;
    --timeout)
      if [ "$#" -lt 2 ] || [[ "$2" == -* ]]; then
        echo "ERROR: --timeout requires SECONDS" >&2
        usage >&2
        exit 2
      fi
      TIMEOUT_SEC="$2"
      shift 2
      ;;
    --self-test-parser) SELF_TEST_PARSER=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage >&2; exit 2 ;;
  esac
done

if [ "$SELF_TEST_PARSER" -eq 1 ]; then
  self_test_parser
  exit 0
fi

# ---- Dependency resolution -------------------------------------------

find_qemu() {
  for c in /usr/local/bin/qemu-system-x86_64 /run/current-system/sw/bin/qemu-system-x86_64; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  command -v qemu-system-x86_64 2>/dev/null || echo ""
}

QEMU_BIN="$(find_qemu)"
BUSYBOX="$(command -v busybox 2>/dev/null || echo /run/current-system/sw/bin/busybox)"
KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
CPIO="$(command -v cpio 2>/dev/null || echo /run/current-system/sw/bin/cpio)"

# Module search: prefer explicit configuration, then a generic scratch module-out.
MODULE_DIR="${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
MODULE_KO="${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
if [ -z "$MODULE_KO" ]; then
  for c in "$MODULE_DIR/tidefs_posix_vfs.ko" \
           "$MODULE_DIR/tidefs_posix_vfs/tidefs_posix_vfs.ko"; do
    [ -f "$c" ] && { MODULE_KO="$c"; break; }
  done
fi

echo "=== TideFS Kernel VFS Throughput Latency Baseline ==="
echo "  Validation:   $VALIDATION_DIR"
echo "  Timeout:    ${TIMEOUT_SEC}s"
echo "  QEMU:       $QEMU_BIN"
echo "  Kernel:     $KERNEL_IMG"
echo "  Module:     ${MODULE_KO:-NOT FOUND}"
echo ""

# ---- Validate dependencies -------------------------------------------

MISSING=""
for dep in QEMU_BIN BUSYBOX CPIO; do
  val="${!dep}"
  if [ -z "$val" ] || [ ! -x "$val" ]; then
    MISSING="$MISSING $dep=${val:-<empty>}"
  fi
done
for dep in KERNEL_IMG MODULE_KO; do
  val="${!dep}"
  if [ -z "$val" ] || [ ! -f "$val" ]; then
    MISSING="$MISSING $dep=${val:-<empty>}"
  fi
done
if [ -n "$MISSING" ]; then
  echo "FATAL: missing dependencies:$MISSING" >&2
  write_blocked_manifest missing_dependency
  exit 2
fi

# Check for KVM acceleration
KVM_FLAG=""
QEMU_ACCEL="tcg"
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  KVM_FLAG="-enable-kvm -cpu host"
  QEMU_ACCEL="kvm"
  echo "  KVM:        enabled"
else
  echo "  KVM:        not available (software emulation, expect slow boot)"
fi

# ---- Prepare initramfs -----------------------------------------------

RUN_DIR="$TMPDIR/run-$$"
echo "  Run dir:    $RUN_DIR"
mkdir -p "$RUN_DIR"/{bin,lib/modules,mnt/tidefs,validation}
trap 'if [ $KEEP_TMP -eq 0 ]; then rm -rf "$RUN_DIR"; fi' EXIT

# Busybox and applets
cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
chmod +x "$RUN_DIR/bin/busybox"
for a in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
  mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut date time; do
  ln -sf busybox "$RUN_DIR/bin/$a"
done

# Copy the kernel module
cp "$MODULE_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"
echo "  Module .ko: $(ls -sh "$MODULE_KO" | awk '{print $1}')"

# ---- Init script -----------------------------------------------------

cat > "$RUN_DIR/init" << 'INIT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Kernel VFS Throughput Latency Baseline ==="
echo "kernel=$(uname -r)"
echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASS=0; FAIL=0; BLOCK=0
pass()   { echo "PASS: $1"; PASS=$((PASS+1)); }
fail()   { echo "FAIL: $1 -- $2"; FAIL=$((FAIL+1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCK=$((BLOCK+1)); }

MNT=/mnt/tidefs

echo "--- Phase 0: Module Load ---"
insmod /lib/modules/tidefs_posix_vfs.ko 2>/tmp/err && pass insmod || { blocked insmod "$(cat /tmp/err)"; }

echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"
M=0
mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/err && { pass mount; M=1; } || { blocked mount "$(cat /tmp/err)"; }

# No-daemon check
ps 2>/dev/null | grep -iqE "tidefs.*daemon|fuse.*adapter|ublk.*adapter" && fail no_daemon "userspace daemon detected" || pass no_daemon

# Phase 2: Write throughput (1 MB, 4K blocks)
if [ "$M" -eq 1 ]; then
  echo "--- Phase 2: Sequential Write (1MB, 4K blocks) ---"
  sync
  S=$(date +%s%N 2>/dev/null || echo 0)
  i=0; while [ $i -lt 256 ]; do
    dd if=/dev/zero of="$MNT/pf" bs=4096 count=1 seek=$i conv=notrunc 2>/dev/null
    i=$((i+1))
  done
  sync
  E=$(date +%s%N 2>/dev/null || echo 0)
  if [ "$S" -gt 0 ] && [ "$E" -gt 0 ]; then
    DMS=$(( (E - S) / 1000000 ))
    DUS=$(( (E - S) / 1000 ))
    echo "write_duration_ms=$DMS"
    echo "write_duration_us=$DUS"
    if [ "$DMS" -gt 0 ]; then
      TP=$(awk "BEGIN {printf \"%.2f\", 1.0 / ($DMS / 1000.0)}" 2>/dev/null || echo "0")
      echo "write_throughput_MBps=$TP"
    fi
  fi
  WS=$(stat -c %s "$MNT/pf" 2>/dev/null || echo 0)
  [ "$WS" -ge 1048576 ] && pass write_data || fail write_data "file_size=$WS"

  echo "--- Phase 3: Sequential Read (1MB, 4K blocks) ---"
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  S=$(date +%s%N 2>/dev/null || echo 0)
  dd if="$MNT/pf" of=/dev/null bs=4096 count=256 2>/dev/null
  E=$(date +%s%N 2>/dev/null || echo 0)
  if [ "$S" -gt 0 ] && [ "$E" -gt 0 ]; then
    DMS=$(( (E - S) / 1000000 ))
    DUS=$(( (E - S) / 1000 ))
    echo "read_duration_ms=$DMS"
    echo "read_duration_us=$DUS"
    if [ "$DMS" -gt 0 ]; then
      TP=$(awk "BEGIN {printf \"%.2f\", 1.0 / ($DMS / 1000.0)}" 2>/dev/null || echo "0")
      echo "read_throughput_MBps=$TP"
    fi
  fi
  pass read_data

  echo "--- Phase 4: Stat Latency (100 calls) ---"
  sync
  S=$(date +%s%N 2>/dev/null || echo 0)
  i=0; while [ $i -lt 100 ]; do stat "$MNT/pf" >/dev/null 2>&1; i=$((i+1)); done
  E=$(date +%s%N 2>/dev/null || echo 0)
  if [ "$S" -gt 0 ] && [ "$E" -gt 0 ]; then
    AVGUS=$(( (E - S) / 100000 ))
    echo "stat_avg_us=$AVGUS"
  fi
  pass stat_latency
fi

echo "--- Phase 5: Dmesg Integrity ---"
DB=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic" || echo 0)
echo "dmesg_BUG=$DB"
[ "$DB" -gt 0 ] && fail dmesg "BUG=$DB" || pass dmesg_clean

echo "--- Phase 6: Unmount + Unload ---"
sync
umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
pass umount
rmmod tidefs_posix_vfs 2>/dev/null && pass rmmod || fail rmmod

echo ""
echo "=== SUMMARY ==="
echo "PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCK"
sleep 1
poweroff -f
INIT

chmod +x "$RUN_DIR/init"

# ---- Build initramfs -------------------------------------------------

echo "--- Building initramfs ---"
(cd "$RUN_DIR" && find . ! -path ./validation/\* | cpio -o -H newc 2>/dev/null) | gzip > "$RUN_DIR/initramfs.gz"
echo "  Initramfs: $(ls -sh "$RUN_DIR/initramfs.gz" | awk '{print $1}')"

# ---- Record environment ----------------------------------------------

mkdir -p "$VALIDATION_DIR"
RUN_ID="$(date -u +%Y-%m-%dT%H%M%SZ)"
RUN_DIR_VALIDATION="$VALIDATION_DIR/$RUN_ID"
mkdir -p "$RUN_DIR_VALIDATION"

cat > "$RUN_DIR_VALIDATION/environment.txt" << ENVEOF
timestamp=$RUN_ID
commit=$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)
dirty=$(git_dirty_json_bool)
kernel_img=$KERNEL_IMG
module_ko=$MODULE_KO
qemu_bin=$QEMU_BIN
qemu_accel=$QEMU_ACCEL
kvm_available=$(test -e /dev/kvm && echo true || echo false)
ENVEOF

# ---- Run QEMU --------------------------------------------------------

echo "--- Booting QEMU (timeout ${TIMEOUT_SEC}s) ---"
RUN_LOG="$RUN_DIR_VALIDATION/qemu.log"

set +e
# shellcheck disable=SC2086
timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
  -kernel "$KERNEL_IMG" \
  -initrd "$RUN_DIR/initramfs.gz" \
  -append "console=ttyS0 quiet" \
  -nographic \
  -m 512M \
  -no-reboot \
  $KVM_FLAG \
  > "$RUN_LOG" 2>&1
QEMU_EXIT=$?
set -e

echo "  QEMU exit: $QEMU_EXIT"

# ---- Extract results -------------------------------------------------

analyze_qemu_log "$RUN_LOG" "$QEMU_EXIT"

echo ""
echo "=== Results ==="
echo "  PASS:   $PASS_COUNT"
echo "  FAIL:   $FAIL_COUNT"
echo "  BLOCKED: $BLOCKED_COUNT"
echo "  SKIP:   $SKIP_COUNT"
echo "  Write:  ${WD}ms (${WTP} MB/s)"
echo "  Read:   ${RD}ms (${RTP} MB/s)"
echo "  Stat:   ${SU}us avg"
echo "  QEMU success: $QEMU_SUCCESS"
echo "  Required metrics: $REQUIRED_METRICS_PRESENT"
echo "  Verdict reason: $VERDICT_REASON"

# ---- Validation manifest -----------------------------------------------

cat > "$RUN_DIR_VALIDATION/validation-manifest.json" << MANIFEST
{
  "test": "kernel-vfs-perf-baseline",
  "date": "$RUN_ID",
  "mode": "bootstrap",
  "validation_tier": "Tier 5 mounted Linux 7.0 kernel VFS",
  "qemu_accel": "$QEMU_ACCEL",
  "qemu_exit": $QEMU_EXIT,
  "qemu_success": $QEMU_SUCCESS,
  "qemu_timed_out": $QEMU_TIMED_OUT,
  "log_empty": $LOG_EMPTY,
  "required_metrics_present": $REQUIRED_METRICS_PRESENT,
  "metrics": {
    "write_duration_ms": $(json_string "$WD"),
    "read_duration_ms": $(json_string "$RD"),
    "write_throughput_MBps": $(json_string "$WTP"),
    "read_throughput_MBps": $(json_string "$RTP"),
    "stat_avg_us": $(json_string "$SU")
  },
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "skip": $SKIP_COUNT,
  "commit": $(json_string "$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"),
  "worktree_dirty": $(git_dirty_json_bool),
  "module_source": "configured external module path",
  "status": $(json_string "$VERDICT_STATUS"),
  "result": $(json_string "kernel VFS perf baseline $VERDICT_STATUS: $VERDICT_REASON; write=${WD}ms (${WTP}MB/s) read=${RD}ms (${RTP}MB/s) stat=${SU}us")
}
MANIFEST

echo ""
echo "  Validation output directory: $RUN_DIR_VALIDATION"
ls -la "$RUN_DIR_VALIDATION/"

# ---- Verdict ---------------------------------------------------------

echo "  Verdict: $VERDICT_STATUS ($VERDICT_REASON)"
exit "$VERDICT_EXIT"
