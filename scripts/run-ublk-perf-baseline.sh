#!/usr/bin/env bash
# run-ublk-perf-baseline.sh -- build and execute the ublk performance baseline
# harness without requiring a flake.nix app entry.
#
# Usage:
#   scripts/run-ublk-perf-baseline.sh [--keep-tmp] [--timeout SECONDS]
#
# Builds nix/vm/ublk-performance-baseline-validation.nix against the current
# flake's packages, then runs the resulting QEMU harness.  Validation is written
# to /root/ai/tmp/tidefs-validation/ublk-perf-baseline/.
#
# Validation tier: Tier 3 QEMU guest ublk/block-volume runtime.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATION_ID="${TIDEFS_UBLK_PERF_VALIDATION_ID:-ublk-perf-baseline}"
VALIDATION_DIR="${TIDEFS_UBLK_PERF_VALIDATION_DIR:-/root/ai/tmp/tidefs-validation/${VALIDATION_ID}}"
TMPDIR="${TIDEFS_UBLK_PERF_TMPDIR:-/tmp/tidefs-ublk-perf-baseline}"
TIMEOUT_SEC="${TIDEFS_UBLK_PERF_TIMEOUT:-600}"
BENCHMARK_JSON="$VALIDATION_DIR/validation.json"

KEEP_TMP=0
PASSTHRU_ARGS=()

usage() {
  cat <<EOF
Usage: scripts/run-ublk-perf-baseline.sh [--keep-tmp] [--timeout SECONDS]

Build and run the ublk single-node throughput/latency performance baseline
in a Linux 7.0 QEMU guest.  Validation output directory:
  $VALIDATION_DIR

Options:
  --keep-tmp         Do not remove temp directory on exit
  --timeout SECONDS  QEMU boot timeout (default: $TIMEOUT_SEC)
  --help, -h         Show this message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --keep-tmp) KEEP_TMP=1; PASSTHRU_ARGS+=("--keep-tmp"); shift ;;
    --timeout) TIMEOUT_SEC="$2"; PASSTHRU_ARGS+=("--timeout" "$2"); shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage >&2; exit 2 ;;
  esac
done

echo "=== TideFS ublk Performance Baseline Runner ==="
echo "  Validation dir: $VALIDATION_DIR"
echo "  Timeout:      ${TIMEOUT_SEC}s"
echo ""

# Build the harness derivation through the bounded Nix/QEMU wrapper.  The
# package attr uses a scoped runtime package instead of the full workspace.
echo "--- Building harness derivation ---"
NIX_BUILD_LOG="$TMPDIR/nix-build.log"
mkdir -p "$TMPDIR"
set +e
TIDEFS_NIX_QEMU_ROOT_DIR="$TMPDIR/nix-qemu-roots" \
TIDEFS_NIX_QEMU_TIMEOUT="${TIDEFS_UBLK_PERF_BUILD_TIMEOUT:-7200}" \
  "$REPO_ROOT/scripts/tidefs-nix-qemu-build" \
    --repo "$REPO_ROOT" \
    --target ublkPerformanceBaseline \
    --name ublk-performance-baseline \
    > "$NIX_BUILD_LOG" 2>&1
BUILD_EXIT=$?
set -e

cat "$NIX_BUILD_LOG"
if [ "$BUILD_EXIT" -ne 0 ]; then
  echo "FATAL: harness derivation build failed (exit $BUILD_EXIT)" >&2
  exit "$BUILD_EXIT"
fi

HARNESS_DRV="$(awk -F= '/^tidefs_nix_qemu.result_link=/{print $2}' "$NIX_BUILD_LOG" | tail -1)"
if [ -z "$HARNESS_DRV" ]; then
  echo "FATAL: could not determine harness result link from $NIX_BUILD_LOG" >&2
  exit 1
fi

HARNESS_BIN="$HARNESS_DRV/bin/tidefs-ublk-perf-baseline"

if [ ! -x "$HARNESS_BIN" ]; then
  echo "FATAL: harness binary not found at $HARNESS_BIN" >&2
  echo "nix-build log (tail 20):"
  tail -20 "$NIX_BUILD_LOG" >&2 || true
  exit 1
fi

echo "  Harness built: $HARNESS_BIN"
echo ""

# Create validation directory
mkdir -p "$VALIDATION_DIR"

# Record environment
{
  echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "validation_id=$VALIDATION_ID"
  echo "commit=$(git -C "$REPO_ROOT" rev-parse HEAD)"
  echo "dirty=true"
  echo "kernel_package=linuxKernel_7_0"
  echo "harness_bin=$HARNESS_BIN"
  echo "qemu_accel=$(test -e /dev/kvm && echo kvm || echo tcg)"
} > "$VALIDATION_DIR/environment.txt"

# Run the harness
echo "--- Running harness ---"
RUN_LOG="$VALIDATION_DIR/run.log"
RUN_EXIT="$VALIDATION_DIR/exit-code"

set +e
"$HARNESS_BIN" "${PASSTHRU_ARGS[@]}" > "$RUN_LOG" 2>&1
HARNESS_EXIT=$?
set -e

echo "$HARNESS_EXIT" > "$RUN_EXIT"

echo ""
echo "--- Results ---"
echo "  Exit code: $HARNESS_EXIT"
echo "  Run log:   $RUN_LOG"
echo ""

# Show summary from run log
if grep -q "SUMMARY:" "$RUN_LOG" 2>/dev/null; then
  grep "SUMMARY:" "$RUN_LOG" | tail -1
elif grep -q "ENVIRONMENT REFUSAL" "$RUN_LOG" 2>/dev/null; then
  echo "ENVIRONMENT REFUSAL detected"
  grep "ENVIRONMENT REFUSAL" "$RUN_LOG" | head -5
elif grep -q "BLOCKED:" "$RUN_LOG" 2>/dev/null; then
  echo "BLOCKED conditions detected"
  grep "BLOCKED:" "$RUN_LOG" | head -10
fi

echo ""
echo "  Validation output directory: $VALIDATION_DIR"
if awk '
  { sub(/\r$/, "", $0) }
  /BEGIN UBLK PERF BENCHMARK JSON/ { in_json = 1; next }
  /END UBLK PERF BENCHMARK JSON/ { in_json = 0; next }
  in_json { print }
' "$RUN_LOG" > "$BENCHMARK_JSON" 2>/dev/null; then
  if [ -s "$BENCHMARK_JSON" ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$BENCHMARK_JSON" >/dev/null 2>&1; then
    echo "  Benchmark JSON: $BENCHMARK_JSON"
  else
    echo "  WARNING: benchmark JSON markers were found but the extracted file was empty or invalid" >&2
    rm -f "$BENCHMARK_JSON"
  fi
else
  echo "  WARNING: benchmark JSON markers were not found in run log" >&2
fi

ls -la "$VALIDATION_DIR/" 2>/dev/null || echo "  (directory empty or missing)"

if [ "$HARNESS_EXIT" -eq 0 ]; then
  echo "  Verdict: PASS"
elif [ "$HARNESS_EXIT" -eq 2 ]; then
  echo "  Verdict: ENVIRONMENT REFUSAL"
else
  echo "  Verdict: FAIL (exit $HARNESS_EXIT)"
fi

exit "$HARNESS_EXIT"
