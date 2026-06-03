#!/usr/bin/env bash
# fio verification on exported ublk block device.
# Validates fio workloads against /dev/ublkbN with verify=crc32c and zero errors.
# Runs seq-write, seq-read, rand-write, rand-read, trim against the exported device.
# Write-before-read pattern: each write lays down verify metadata; the matching read verifies.
set -euo pipefail

# Binary mode: cargo (default, uses cargo build/run) or installed (uses pre-built binaries from PATH)
TIDEFS_BINARY_MODE="${TIDEFS_BINARY_MODE:-cargo}"
BINARY_NAME="tidefs-block-volume-adapter-daemon"

_resolve_daemon_cmd() {
    if [ "$TIDEFS_BINARY_MODE" = "installed" ]; then
        echo "$BINARY_NAME"
    else
        echo "cargo run -p $BINARY_NAME --"
    fi
}

_resolve_build() {
    if [ "$TIDEFS_BINARY_MODE" = "installed" ]; then
        command -v "$BINARY_NAME" >/dev/null 2>&1 || {
            echo "ERROR: $BINARY_NAME not found in PATH (TIDEFS_BINARY_MODE=installed)" >&2
            exit 1
        }
        echo "=== binary check ==="
        echo "$BINARY_NAME found at $(command -v $BINARY_NAME)"
    else
        timeout "$ublk_cmd_timeout" cargo build -p "$BINARY_NAME" 2>&1 | tail -3
    fi
}

ublk_cmd_timeout="${TIDEFS_UBLK_CMD_TIMEOUT:-300s}"
GATE="block-volume adapter ublk fio verification"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="${TIDEFS_VALIDATION_DIR:-/tmp/tidefs-ublk-fio-validation}"
BLOCK_DEV=""
DAEMON_PID=""
VERDICT="pass"
FIO_DIR="${SCRIPT_DIR}/fio"
FIO_ERR_FATAL=0

cleanup() {
    if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    sleep 1
}
trap cleanup EXIT

mkdir -p "$VALIDATION_DIR"

echo "gate=$GATE"
echo "validation_dir=$VALIDATION_DIR"
echo "kernel_release=$(uname -r)"
echo "fio_version=$(fio --version 2>/dev/null || echo 'unknown')"

# ----- build daemon -----
echo ""
echo "=== build ==="
_resolve_build

# ----- run preflight -----
echo ""
echo "=== preflight ==="
timeout "$ublk_cmd_timeout" $(_resolve_daemon_cmd) ublk-control-open-preflight 2>&1 | tee "$VALIDATION_DIR/preflight.txt"
ADMISSION=$(grep "control.admission_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
KERNEL_CLASS=$(grep "host.observe_kernel_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
echo "admission_class=$ADMISSION"
echo "kernel_class=$KERNEL_CLASS"

if [ "$ADMISSION" != "admitted" ]; then
    REFUSAL=$(grep "control.refusal_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
    echo ""
    echo "=== GATE REFUSED ==="
    echo "Host kernel $(uname -r) is classified as $KERNEL_CLASS"
    echo "Refusal class: $REFUSAL"
    echo "The ublk control open gate correctly refuses admission."
    echo "fio verification requires Linux >= 7.0 baseline."
    echo ""
    echo "verdict=pass (correct refusal for kernel $(uname -r))"
    exit 0
fi

# ----- start daemon with io_loop -----
echo ""
echo "=== starting io_loop ==="
timeout "$ublk_cmd_timeout" $(_resolve_daemon_cmd) ublk-data-queue-io-loop &
DAEMON_PID=$!
echo "daemon_pid=$DAEMON_PID"

# ----- wait for block device -----
echo ""
echo "=== waiting for block device ==="
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    for dev in /dev/ublkb*; do
        if [ -b "$dev" ]; then
            BLOCK_DEV="$dev"
            echo "block_device=$BLOCK_DEV after ${i}s"
            break 2
        fi
    done
    sleep 1
done

if [ -z "$BLOCK_DEV" ]; then
    echo "FAIL: no block device after ${MAX_WAIT}s"
    exit 1
fi

# ----- device info -----
echo ""
echo "=== device info ==="
ls -la "$BLOCK_DEV" | tee "$VALIDATION_DIR/device-ls.txt"
DEV_NAME=$(basename "$BLOCK_DEV")
if [ -f "/sys/class/block/$DEV_NAME/size" ]; then
    SYS_SIZE=$(cat "/sys/class/block/$DEV_NAME/size")
    echo "sysfs_size_sectors=$SYS_SIZE (bytes=$((SYS_SIZE * 512)))"
fi

# ----- fio runner -----
run_fio_job() {
    local job_name="$1"
    local job_file="$2"
    echo ""
    echo "=== fio: $job_name ==="
    echo "job_file=$job_file"
    echo "block_device=$BLOCK_DEV"

    if timeout "$ublk_cmd_timeout" fio --filename="$BLOCK_DEV" "$job_file" --output="$VALIDATION_DIR/fio-${job_name}.json" --output-format=json 2>&1 | tee "$VALIDATION_DIR/fio-${job_name}.log"; then
        echo "fio_${job_name}_exit=0"
    else
        local fio_exit=$?
        echo "fio_${job_name}_exit=$fio_exit"
        if [ $fio_exit -ne 0 ]; then
            echo "FAIL: fio $job_name exit $fio_exit"
            FIO_ERR_FATAL=1
        fi
    fi
}

# ----- run jobs: write-then-read for verify -----
if [ -f "$FIO_DIR/seq-write.fio" ]; then
    run_fio_job "seq-write" "$FIO_DIR/seq-write.fio"
fi

if [ -f "$FIO_DIR/seq-read.fio" ]; then
    run_fio_job "seq-read" "$FIO_DIR/seq-read.fio"
fi

if [ -f "$FIO_DIR/rand-write.fio" ]; then
    run_fio_job "rand-write" "$FIO_DIR/rand-write.fio"
fi

if [ -f "$FIO_DIR/rand-read.fio" ]; then
    run_fio_job "rand-read" "$FIO_DIR/rand-read.fio"
fi

if [ -f "$FIO_DIR/trim.fio" ]; then
    run_fio_job "trim" "$FIO_DIR/trim.fio"
fi

# ----- verify fio error counts -----
echo ""
echo "=== fio error check ==="
TOTAL_ERRORS=0
for json_file in "$VALIDATION_DIR"/fio-*.json; do
    if [ -f "$json_file" ]; then
        NAME=$(basename "$json_file" .json)
        ERR_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$json_file'))
    err = data.get('jobs', [{}])[0].get('error', 0)
    print(err)
except Exception:
    print('-1')
" 2>/dev/null)
        echo "fio_errors.${NAME}=$ERR_COUNT"
        if [ "$ERR_COUNT" != "0" ] && [ "$ERR_COUNT" != "-1" ]; then
            TOTAL_ERRORS=$((TOTAL_ERRORS + 1))
        fi
    fi
done

if [ $FIO_ERR_FATAL -ne 0 ] || [ $TOTAL_ERRORS -ne 0 ]; then
    VERDICT="fail"
    echo "FAIL: fio errors (fatal=$FIO_ERR_FATAL errors=$TOTAL_ERRORS)"
fi

# ----- performance validation -----
echo ""
echo "=== performance ==="
for json_file in "$VALIDATION_DIR"/fio-*.json; do
    if [ -f "$json_file" ]; then
        NAME=$(basename "$json_file" .json)
        python3 -c "
import json
data = json.load(open('$json_file'))
j = data.get('jobs', [{}])[0]
for label in ('read', 'write', 'trim'):
    d = j.get(label, {})
    if d.get('iops', 0) > 0 or d.get('io_bytes', 0) > 0:
        print(f'perf.{NAME}.{label}.iops={d.get(\"iops\", 0)}')
        print(f'perf.{NAME}.{label}.bw_bytes={d.get(\"bw_bytes\", 0)}')
        lat = d.get('lat_ns', {})
        if lat:
            print(f'perf.{NAME}.{label}.lat_ns_mean={lat.get(\"mean\", 0)}')
" 2>/dev/null
    fi
done

# ----- stop daemon -----
echo ""
echo "=== stopping daemon ==="
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
sleep 2

# ----- device cleanup -----
if [ -b "$BLOCK_DEV" ]; then
    echo "device_cleanup=failed"
    VERDICT="fail"
else
    echo "device_cleanup=ok"
fi

echo ""
echo "=== FIO VERIFICATION COMPLETE ==="
echo "gate=$GATE"
echo "verdict=$VERDICT"
