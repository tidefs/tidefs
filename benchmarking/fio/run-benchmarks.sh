#!/usr/bin/env bash
# TideFS fio benchmarking harness — runs FUSE or ublk profiles
# Usage:
#   FUSE:  ./run-benchmarks.sh fuse /path/to/mount [profile]
#   ublk:  ./run-benchmarks.sh ublk /dev/ublkbN [profile]
#
# Profiles: smoke (default), quick-required, pressure, all
set -euo pipefail

MODE="${1:-}"
TARGET="${2:-}"
PROFILE="${3:-smoke}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOBS_DIR="$SCRIPT_DIR/jobs"
OUT_DIR="${TIDEFS_FIO_OUT_DIR:-/tmp/tidefs-fio-benchmarks}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

usage() {
    cat << EOF
TideFS fio benchmarking harness

Usage: $0 <mode> <target> [profile]

Modes:
  fuse        Benchmark a FUSE mount point
  ublk        Benchmark a ublk block device

Profiles:
  smoke          Shortest local fio sampling profile (default)
  quick-required Broader local fio sampling profile
  pressure       Stress and degradation
  all            Run all profiles

Environment:
  TIDEFS_FIO_OUT_DIR   Output directory (default: /tmp/tidefs-fio-benchmarks)
  TIDEFS_FIO_SIZE_MULT Size multiplier for small-device tuning (default: 1)

Examples:
  $0 fuse /mnt/tidefs smoke
  $0 ublk /dev/ublkb0 quick-required
  $0 fuse /mnt/tidefs all
EOF
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

if [ "$MODE" != "fuse" ] && [ "$MODE" != "ublk" ]; then
    echo "ERROR: mode must be 'fuse' or 'ublk'"
    usage
fi

# Validate target
if [ "$MODE" = "fuse" ]; then
    if [ ! -d "$TARGET" ]; then
        echo "ERROR: FUSE target '$TARGET' is not a directory"
        exit 1
    fi
    FILENAME="$TARGET/tidefs-fio-benchmark-file"
    # For FUSE, we use a single file inside the mount
    FIO_TARGET_ARG="--filename=$FILENAME"
else
    if [ ! -b "$TARGET" ]; then
        echo "ERROR: ublk target '$TARGET' is not a block device"
        exit 1
    fi
    FILENAME="$TARGET"
    FIO_TARGET_ARG="--filename=$FILENAME"
fi

RUN_DIR="$OUT_DIR/${TIMESTAMP}-${MODE}-${PROFILE}"
mkdir -p "$RUN_DIR"

# Common fio options
FIO_OPTS="--output-format=json --group_reporting --norandommap --randrepeat=0 --refill_buffers"
[ "$MODE" = "fuse" ] && FIO_OPTS="$FIO_OPTS --direct=0"

echo "=== TideFS fio benchmarking ==="
echo "mode:       $MODE"
echo "target:     $TARGET"
echo "profile:    $PROFILE"
echo "output:     $RUN_DIR"
echo "timestamp:  $TIMESTAMP"
echo "fio_version: $(fio --version 2>/dev/null || echo 'unknown')"
echo "kernel:     $(uname -r)"
echo "target_type: $([ "$MODE" = "fuse" ] && echo 'directory' || echo 'block_device')"

# Record environment
{
    echo "mode=$MODE"
    echo "target=$TARGET"
    echo "profile=$PROFILE"
    echo "timestamp=$TIMESTAMP"
    echo "fio_version=$(fio --version 2>/dev/null || echo 'unknown')"
    echo "kernel_release=$(uname -r)"
    echo "hostname=$(hostname)"
    if [ "$MODE" = "fuse" ]; then
        echo "mount_options=$(mount | grep "on $TARGET " | awk '{print $6}' || echo 'unknown')"
        echo "filesystem_type=$(mount | grep "on $TARGET " | awk '{print $5}' || echo 'unknown')"
    else
        echo "block_device_size=$(lsblk -bno SIZE "$TARGET" 2>/dev/null || echo 'unknown')"
    fi
} > "$RUN_DIR/environment.env"

cleanup_fuse_file() {
    if [ "$MODE" = "fuse" ] && [ -f "$FILENAME" ]; then
        rm -f "$FILENAME" 2>/dev/null || true
    fi
}
trap cleanup_fuse_file EXIT

# Job file discovery
list_jobs() {
    local prof="$1"
    if [ "$prof" = "all" ]; then
        find "$JOBS_DIR" -name '*.fio' -type f | sort
    else
        find "$JOBS_DIR/$prof" -name '*.fio' -type f 2>/dev/null | sort
    fi
}

# Remove stale test file between jobs for FUSE
reset_target() {
    if [ "$MODE" = "fuse" ]; then
        rm -f "$FILENAME" 2>/dev/null || true
    fi
}

TOTAL_JOBS=0
PASSED_JOBS=0
FAILED_JOBS=0
declare -a FAILED_NAMES

echo ""
echo "=== running jobs ==="

while IFS= read -r job_file; do
    [ -z "$job_file" ] && continue
    reset_target

    JOB_NAME="$(basename "$job_file" .fio)"
    JOB_PROFILE="$(basename "$(dirname "$job_file")")"
    JOB_OUT="$RUN_DIR/${JOB_PROFILE}__${JOB_NAME}.json"
    JOB_LOG="$RUN_DIR/${JOB_PROFILE}__${JOB_NAME}.log"

    echo ""
    echo "--- $JOB_PROFILE/$JOB_NAME ---"
    TOTAL_JOBS=$((TOTAL_JOBS + 1))

    if fio $FIO_OPTS $FIO_TARGET_ARG "$job_file" --output="$JOB_OUT" 2>&1 | tee "$JOB_LOG"; then
        FIO_EXIT="${PIPESTATUS[0]}"
        if [ "$FIO_EXIT" -eq 0 ]; then
            echo "  result: PASS"
            PASSED_JOBS=$((PASSED_JOBS + 1))
        else
            echo "  result: FAIL (exit $FIO_EXIT)"
            FAILED_JOBS=$((FAILED_JOBS + 1))
            FAILED_NAMES+=("$JOB_PROFILE/$JOB_NAME")
        fi
    else
        echo "  result: FAIL"
        FAILED_JOBS=$((FAILED_JOBS + 1))
        FAILED_NAMES+=("$JOB_PROFILE/$JOB_NAME")
    fi

    reset_target
done < <(list_jobs "$PROFILE")

# Generate summary
echo ""
echo "=== summary ==="
echo "total_jobs=$TOTAL_JOBS"
echo "passed_jobs=$PASSED_JOBS"
echo "failed_jobs=$FAILED_JOBS"

if [ $FAILED_JOBS -gt 0 ]; then
    echo "failed_names=${FAILED_NAMES[*]}"
fi

# Compute aggregate metrics from JSON outputs
if [ $PASSED_JOBS -gt 0 ]; then
    echo ""
    echo "=== aggregate metrics ==="
    python3 - "$RUN_DIR" << 'PYEOF'
import json, sys, os, glob

run_dir = sys.argv[1]
metrics = {}

for f in sorted(glob.glob(os.path.join(run_dir, "*.json"))):
    try:
        data = json.load(open(f))
        for job in data.get("jobs", []):
            jname = job.get("jobname", "unknown")
            for rw in ("read", "write", "trim"):
                d = job.get(rw, {})
                iops = d.get("iops", 0)
                bw = d.get("bw_bytes", 0)
                lat = d.get("lat_ns", {})
                if iops > 0 or bw > 0:
                    print(f"perf.{jname}.{rw}.iops={iops}")
                    print(f"perf.{jname}.{rw}.bw_bytes={bw}")
                    if lat:
                        print(f"perf.{jname}.{rw}.lat_ns_mean={lat.get('mean', 0)}")
                        print(f"perf.{jname}.{rw}.lat_ns_p99={lat.get('percentile', {}).get('99.000000', 0)}")
    except Exception as e:
        print(f"# warn: failed to parse {f}: {e}", file=sys.stderr)
PYEOF
fi

# Final verdict
echo ""
if [ $FAILED_JOBS -eq 0 ]; then
    echo "verdict: PASS"
    exit 0
else
    echo "verdict: FAIL"
    exit 1
fi
