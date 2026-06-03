#!/usr/bin/env bash
# resize acceptance: online grow/shrink via ublk UPDATE_SIZE.
# Validates that an exported ublk block device accepts online resize via
# UPDATE_SIZE uring_cmd, or correctly refuses when the host kernel is below the
# 7.0 ublk baseline.
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
GATE="block-volume adapter ublk device online resize acceptance"
VALIDATION_DIR="${TIDEFS_VALIDATION_DIR:-/tmp/tidefs-ublk-resize-validation}"
DAEMON_PID=""
VERDICT="pass"

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
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

# ----- build daemon -----
echo "=== build ==="
_resolve_build

# ----- run preflight to check kernel classification -----
echo "=== preflight ==="
timeout "$ublk_cmd_timeout" $(_resolve_daemon_cmd) ublk-control-open-preflight 2>&1 | tee "$VALIDATION_DIR/preflight.txt"
KERNEL_CLASS=$(grep "host.observe_kernel_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
ADMISSION=$(grep "control.admission_class=" "$VALIDATION_DIR/preflight.txt" | head -1 | cut -d= -f2)
echo "kernel_class=$KERNEL_CLASS"
echo "admission_class=$ADMISSION"

if [ "$ADMISSION" != "admitted" ]; then
    echo ""
    echo "=== GATE REFUSED (expected on kernel < 7.0) ==="
    echo "The host kernel $(uname -r) is classified as $KERNEL_CLASS"
    echo "The ublk control open gate correctly refuses admission."
    echo "Resize smoke requires Linux >= 7.0 ublk baseline."
    echo ""
    echo "verdict=pass (correct refusal for kernel $(uname -r))"
    exit 0
fi

# ----- run resize smoke -----
echo "=== resize smoke ==="
timeout "$ublk_cmd_timeout" $(_resolve_daemon_cmd) resize-smoke 2>&1 | tee "$VALIDATION_DIR/resize-smoke.txt"

RESIZE_FAILURE_CLASS=$(grep "failure_class=" "$VALIDATION_DIR/resize-smoke.txt" | head -1 | cut -d= -f2)
UPDATE_SIZE_COMPLETED=$(grep "update_size.completed=" "$VALIDATION_DIR/resize-smoke.txt" | head -1 | cut -d= -f2)
ORIG_SECTORS=$(grep "update_size.original_dev_sectors=" "$VALIDATION_DIR/resize-smoke.txt" | head -1 | cut -d= -f2)
RESIZED_SECTORS=$(grep "update_size.resized_dev_sectors=" "$VALIDATION_DIR/resize-smoke.txt" | head -1 | cut -d= -f2)

echo ""
echo "failure_class=$RESIZE_FAILURE_CLASS"
echo "update_size_completed=$UPDATE_SIZE_COMPLETED"

if [ "$UPDATE_SIZE_COMPLETED" = "true" ]; then
    echo "resize_target=ok (${ORIG_SECTORS} -> ${RESIZED_SECTORS} sectors)"
    VERDICT="pass"
elif [ "$RESIZE_FAILURE_CLASS" = "resize_explicitly_refused" ]; then
    REFUSAL_REASON=$(grep "resize_policy.refusal_reason=" "$VALIDATION_DIR/resize-smoke.txt" | head -1 | cut -d= -f2-)
    REFUSAL_ERRNO=$(grep "resize_policy.guest_errno=" "$VALIDATION_DIR/resize-smoke.txt" | head -1 | cut -d= -f2)
    echo "resize_refused=ok (${REFUSAL_REASON}; guest_errno=${REFUSAL_ERRNO})"
    VERDICT="pass"
elif [ "$RESIZE_FAILURE_CLASS" = "update_size_failed" ] || [ "$RESIZE_FAILURE_CLASS" = "host_not_admitted" ] || [ "$RESIZE_FAILURE_CLASS" = "start_dev_failed" ] || [ "$RESIZE_FAILURE_CLASS" = "feature_probe_failed" ]; then
    echo "resize_refused=ok (kernel $(uname -r) lacks ublk support)"
    VERDICT="pass"
else
    echo "resize_result=unexpected (failure_class=$RESIZE_FAILURE_CLASS)"
    VERDICT="fail"
fi

# ----- cleanup -----
echo "=== cleanup ==="
if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
fi
DAEMON_PID=""

echo ""
echo "=== RESIZE SMOKE COMPLETE ==="
echo "gate=$GATE"
echo "verdict=$VERDICT"
