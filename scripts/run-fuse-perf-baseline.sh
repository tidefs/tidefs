#!/usr/bin/env bash
# run-fuse-perf-baseline.sh -- single-node FUSE performance baseline
#
# Builds the FUSE daemon, mounts a TideFS pool, runs multi-block-size fio
# sweep + metadata micro-benchmark, writes structured validation JSON to
# /root/ai/tmp/tidefs-validation/fuse-perf-baseline/fuse-fio-benchmark.json.
#
# Usage:
#   ./scripts/run-fuse-perf-baseline.sh [--keep-mount] [--skip-build]
#
# Environment:
#   TIDEFS_FIO_BASELINE_OUT_DIR  output dir override (default: /root/ai/tmp/tidefs-validation/fuse-perf-baseline)
#   TIDEFS_FIO_BASELINE_TEMP     work dir (default: /tmp/tidefs-fuse-perf-baseline)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${TIDEFS_FIO_BASELINE_OUT_DIR:-/root/ai/tmp/tidefs-validation/fuse-perf-baseline}"
TEMP_DIR="${TIDEFS_FIO_BASELINE_TEMP:-/tmp/tidefs-fuse-perf-baseline}"
DAEMON_BIN="$REPO_ROOT/target/debug/tidefs-posix-filesystem-adapter-daemon"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/ai/tmp/tidefs-fuse-perf-target}"
STORE_DIR="$TEMP_DIR/store"
MOUNT_DIR="$TEMP_DIR/mnt"
DAEMON_LOG="$TEMP_DIR/daemon.log"
VALIDATION_FILE="$OUT_DIR/fuse-fio-benchmark.json"
KEEP_MOUNT=0
SKIP_BUILD=0

for arg in "$@"; do
    case "$arg" in
        --keep-mount) KEEP_MOUNT=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        *) echo "unknown arg: $arg"; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR" "$TEMP_DIR"

cleanup() {
    if [ "$KEEP_MOUNT" -eq 0 ]; then
        fusermount -u "$MOUNT_DIR" 2>/dev/null || umount -l "$MOUNT_DIR" 2>/dev/null || true
        sleep 1
        [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── build daemon ─────────────────────────────────────────────────
if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "=== building daemon ==="
    export CARGO_TARGET_DIR="$CARGO_TARGET_DIR"
    cargo build -p tidefs-posix-filesystem-adapter-daemon --bin tidefs-posix-filesystem-adapter-daemon 2>&1 | tail -5
    if [ ! -f "$DAEMON_BIN" ]; then
        # cargo may strip bin name; look for it
        DAEMON_BIN="$(find "$CARGO_TARGET_DIR" -name "tidefs-posix-filesystem-adapter-daemon" -type f 2>/dev/null | head -1)"
        if [ -z "$DAEMON_BIN" ] || [ ! -f "$DAEMON_BIN" ]; then
            echo "ERROR: daemon binary not found after build"
            exit 1
        fi
    fi
    echo "daemon: $DAEMON_BIN"
else
    if [ ! -f "$DAEMON_BIN" ]; then
        echo "ERROR: --skip-build but daemon not found at $DAEMON_BIN"
        exit 1
    fi
fi

# ── setup and mount ──────────────────────────────────────────────
echo "=== mounting FUSE ==="
rm -rf "$STORE_DIR" "$MOUNT_DIR" 2>/dev/null || true
mkdir -p "$STORE_DIR" "$MOUNT_DIR"

export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141"
"$DAEMON_BIN" mount-vfs --store "$STORE_DIR" --mount "$MOUNT_DIR" --no-writeback-cache >> "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
echo "daemon PID: $DAEMON_PID"

# Wait for mount
for i in $(seq 1 30); do
    sleep 1
    if mountpoint -q "$MOUNT_DIR" 2>/dev/null || grep -q " $MOUNT_DIR " /proc/mounts 2>/dev/null; then
        echo "mount ready after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: mount not ready after 30s"
        cat "$DAEMON_LOG" 2>/dev/null | tail -20
        exit 1
    fi
done

# ── collect environment info ─────────────────────────────────────
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo 'unknown')"
KERNEL="$(uname -r)"
HOSTNAME="$(hostname)"
FIO_VERSION="$(fio --version 2>/dev/null || echo 'unknown')"

VALIDATION='{
  "test": "tidefs-fuse-perf-baseline",
  "version": 2,
  "timestamp": "'$TIMESTAMP'",
  "commit": "'$COMMIT'",
  "kernel": "'$KERNEL'",
  "hostname": "'$HOSTNAME'",
  "fio_version": "'$FIO_VERSION'",
  "mode": "fuse",
  "backend": "in-memory-object-store",
  "tier": "mounted-userspace",
  "results": [],
  "passed": 0,
  "product_failures": 0,
  "harness_failures": 0,
  "environment_refusals": 0,
  "skipped": 0,
  "benchmarks": [],
  "metadata_bench": null
}'

VALID_STATUSES='pass product-fail harness-fail environment-refusal skip'

record() {
    local name="$1" status="$2" output="${3:-}"
    case " $VALID_STATUSES " in *" $status "*) ;; *) echo "invalid status: $status" >&2; return 1 ;; esac
    VALIDATION="$(echo "$VALIDATION" | jq --arg n "$name" --arg s "$status" --arg o "$output" \
        '.results += [{"name":$n,"status":$s,"output":$o}]')"
}

# ── fio benchmark sweep ──────────────────────────────────────────
FIO_TESTFILE="$MOUNT_DIR/tidefs-fio-benchmark-file"
FIO_COMMON="--output-format=json --group_reporting --norandommap --randrepeat=0 --refill_buffers --direct=0"

BLOCK_SPECS=("4k 4M" "64k 16M" "128k 32M" "1m 64M")
WORKLOADS=("sequential-write rw=write iodepth=1" "sequential-read rw=read iodepth=1" "random-write rw=randwrite iodepth=1" "random-read rw=randread iodepth=1" "sync-write rw=write iodepth=1 fsync=1")

echo "=== running fio sweep ==="
for bs_entry in "${BLOCK_SPECS[@]}"; do
    read -r bs_label bs_size <<< "$bs_entry"
    for wl_entry in "${WORKLOADS[@]}"; do
        read -r wl_name wl_rw wl_args <<< "$wl_entry"
        name="${wl_name}-${bs_label}"
        extra="${wl_args}"
        [ "$extra" = "iodepth=1" ] && extra=""
        fio_args="--name=$name --filename=$FIO_TESTFILE --bs=$bs_label --$wl_rw --size=$bs_size --iodepth=1 $extra $FIO_COMMON"
        echo "  $name (bs=$bs_label size=$bs_size)"

        if ! stdout="$(fio $fio_args 2>&1)"; then
            record "fio_$name" "product-fail" "${stdout:0:2000}"
            continue
        fi

        record "fio_$name" "pass" "${stdout:0:2000}"

        # Extract KPIs from fio JSON
        if kpis_json="$(echo "$stdout" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    jobs = d.get('jobs', [])
    if not jobs:
        sys.exit(0)
    j = jobs[0]
    rd = j.get('read', {})
    wr = j.get('write', {})
    bw = rd.get('bw_bytes', 0) + wr.get('bw_bytes', 0)
    iops = rd.get('iops', 0) + wr.get('iops', 0)
    lat_src = rd if rd.get('iops', 0) >= wr.get('iops', 0) else wr
    lat_ns = lat_src.get('lat_ns', {})
    lat_pct = lat_ns.get('percentile', {})
    entry = {
        'name': '$name',
        'bw_bytes_per_sec': bw,
        'iops': iops,
        'lat_ns_mean': lat_ns.get('mean', 0),
        'lat_ns_p50': lat_pct.get('50.000000', 0),
        'lat_ns_p95': lat_pct.get('95.000000', 0),
        'lat_ns_p99': lat_pct.get('99.000000', 0),
        'block_size': '$bs_label',
        'workload': '$wl_name',
    }
    print(json.dumps(entry))
except Exception as e:
    print(json.dumps({'error': str(e), 'name': '$name'}), file=sys.stderr)
    sys.exit(0)
" 2>/dev/null)"; then
            VALIDATION="$(echo "$VALIDATION" | jq --argjson bm "$kpis_json" '.benchmarks += [$bm]')"
        else
            record "fio_${name}_parse" "harness-fail" "failed to parse fio JSON"
        fi
    done
    rm -f "$FIO_TESTFILE" 2>/dev/null || true
done

# ── metadata benchmark ───────────────────────────────────────────
echo "=== metadata benchmark ==="
META_DIR="$MOUNT_DIR/tidefs-meta-bench"
mkdir -p "$META_DIR"
NUM_FILES=200

start_s="$(date +%s.%N)"
for i in $(seq 0 $((NUM_FILES - 1))); do
    touch "$META_DIR/f$(printf '%04d' "$i")"
done
create_s="$(echo "$(date +%s.%N) - $start_s" | bc -l)"
record "meta_create" "pass" "$NUM_FILES files in $(printf '%.2f' "$create_s")s ($(printf '%.0f' "$(echo "$NUM_FILES / $create_s" | bc -l)") files/s)"

start_s="$(date +%s.%N)"
for i in $(seq 0 $((NUM_FILES - 1))); do
    stat "$META_DIR/f$(printf '%04d' "$i")" > /dev/null
done
stat_s="$(echo "$(date +%s.%N) - $start_s" | bc -l)"
record "meta_stat" "pass" "$NUM_FILES stats in $(printf '%.2f' "$stat_s")s ($(printf '%.0f' "$(echo "$NUM_FILES / $stat_s" | bc -l)") stats/s)"

start_s="$(date +%s.%N)"
for i in $(seq 0 $((NUM_FILES - 1))); do
    rm "$META_DIR/f$(printf '%04d' "$i")"
done
unlink_s="$(echo "$(date +%s.%N) - $start_s" | bc -l)"
record "meta_unlink" "pass" "$NUM_FILES unlinks in $(printf '%.2f' "$unlink_s")s ($(printf '%.0f' "$(echo "$NUM_FILES / $unlink_s" | bc -l)") unlinks/s)"
rmdir "$META_DIR"

VALIDATION="$(echo "$VALIDATION" | jq \
    --argjson nc "$NUM_FILES" \
    --argjson cs "$(printf '%.3f' "$create_s")" \
    --argjson cps "$(printf '%.1f' "$(echo "$NUM_FILES / $create_s" | bc -l)")" \
    --argjson ss "$(printf '%.3f' "$stat_s")" \
    --argjson sps "$(printf '%.1f' "$(echo "$NUM_FILES / $stat_s" | bc -l)")" \
    --argjson us "$(printf '%.3f' "$unlink_s")" \
    --argjson ups "$(printf '%.1f' "$(echo "$NUM_FILES / $unlink_s" | bc -l)")" \
    '.metadata_bench = {
        "num_files": $nc,
        "create_s": $cs, "create_files_per_sec": $cps,
        "stat_s": $ss, "stat_per_sec": $sps,
        "unlink_s": $us, "unlink_per_sec": $ups
    }')"

# ── compute summary counts ───────────────────────────────────────
VALIDATION="$(echo "$VALIDATION" | jq '
    .passed = ([.results[] | select(.status == "pass")] | length) |
    .product_failures = ([.results[] | select(.status == "product-fail")] | length) |
    .harness_failures = ([.results[] | select(.status == "harness-fail")] | length) |
    .environment_refusals = ([.results[] | select(.status == "environment-refusal")] | length) |
    .skipped = ([.results[] | select(.status == "skip")] | length)
')"

# ── write validation ───────────────────────────────────────────────
echo "$VALIDATION" | jq . > "$VALIDATION_FILE"
echo "=== done ==="
echo "validation: $VALIDATION_FILE"
echo "passed: $(echo "$VALIDATION" | jq -r .passed)"
echo "failed: $(echo "$VALIDATION" | jq -r '.product_failures + .harness_failures')"

# ── unmount and cleanup ──────────────────────────────────────────
if [ "$KEEP_MOUNT" -eq 0 ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 1
    fusermount -u "$MOUNT_DIR" 2>/dev/null || umount -l "$MOUNT_DIR" 2>/dev/null || true
fi
