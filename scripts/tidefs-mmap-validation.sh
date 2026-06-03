#!/usr/bin/env bash
set -euo pipefail

# tidefs-mmap-validation.sh -- mmap/page-cache validation collection for TideFS FUSE
#
# Mounts TideFS via FUSE on a temp directory, compiles and runs the
# mmap workload program, collects JSON results, and produces a
# tier-classified validation matrix.
#
# Usage:
#   ./tidefs-mmap-validation.sh [--daemon-bin <path>] [--writeback-cache]
#
# Environment:
#   TIDEFS_DAEMON_BIN  path to tidefs-posix-filesystem-adapter-daemon (optional)
#   CARGO_TARGET_DIR    used to locate daemon binary when TIDEFS_DAEMON_BIN unset

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD_SRC="$SCRIPT_DIR/tidefs-mmap-workload.c"
WORKLOAD_BIN=""

DAEMON_BIN="${TIDEFS_DAEMON_BIN:-}"
WRITEBACK_FLAG=""

_cleanup() {
    local exit_code=$?
    # Unmount if still mounted
    if [[ -n "${_mount_dir:-}" ]] && mountpoint -q "$_mount_dir" 2>/dev/null; then
        fusermount -u "$_mount_dir" 2>/dev/null || true
    fi
    # Kill daemon if still running
    if [[ -n "${_daemon_pid:-}" ]] && kill -0 "$_daemon_pid" 2>/dev/null; then
        kill -TERM "$_daemon_pid" 2>/dev/null || true
        wait "$_daemon_pid" 2>/dev/null || true
    fi
    # Remove temp dirs
    if [[ -n "${_work_dir:-}" ]]; then
        rm -rf "$_work_dir" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap _cleanup EXIT INT TERM

usage() {
    cat >&2 <<'EOF'
Usage: tidefs-mmap-validation.sh [--daemon-bin <path>] [--writeback-cache]

Options:
  --daemon-bin <path>   Path to tidefs-posix-filesystem-adapter-daemon binary
  --writeback-cache      Enable FUSE writeback-cache (default: off)

Environment:
  TIDEFS_DAEMON_BIN      Same as --daemon-bin
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon-bin) DAEMON_BIN="$2"; shift 2 ;;
        --writeback-cache) WRITEBACK_FLAG="-owriteback_cache"; shift ;;
        --help|-h) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

# --- locate daemon binary ---
find_daemon_bin() {
    local candidate

    # Try CARGO_TARGET_DIR first
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        for sub in debug release; do
            candidate="$CARGO_TARGET_DIR/$sub/tidefs-posix-filesystem-adapter-daemon"
            if [[ -x "$candidate" ]]; then
                echo "$candidate"
                return 0
            fi
        done
    fi

    # Try common workspace target paths
    local workspace_root
    workspace_root="$(cd "$SCRIPT_DIR/.." && pwd)"
    for sub in debug release; do
        candidate="$workspace_root/target/$sub/tidefs-posix-filesystem-adapter-daemon"
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    # Try /tmp target dir (worker pattern)
    for sub in debug release; do
        candidate="/tmp/tidefs-workers/s12/cargo-target/$sub/tidefs-posix-filesystem-adapter-daemon"
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    # Fall back to $PATH
    if command -v tidefs-posix-filesystem-adapter-daemon >/dev/null 2>&1; then
        echo "tidefs-posix-filesystem-adapter-daemon"
        return 0
    fi

    return 1
}

# --- compile workload ---
compile_workload() {
    local cc="${CC:-cc}"
    WORKLOAD_BIN="$(mktemp -t tidefs-mmap-workload.XXXXXX)"
    "$cc" -Wall -O2 -o "$WORKLOAD_BIN" "$WORKLOAD_SRC" 2>&1 || {
        echo "{\"commit\":\"unknown\",\"collected_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"environment\":\"compile-failed\",\"rows\":[{\"name\":\"workload-compile\",\"outcome\":\"blocked\",\"tier\":\"mounted-userspace\",\"output_note\":\"cc compile failed\"}]}"
        exit 1
    }
}

# --- main ---
main() {
    local commit_sha
    commit_sha="$(cd "$SCRIPT_DIR/.." && git rev-parse HEAD 2>/dev/null || echo "unknown")"

    if [[ -z "$DAEMON_BIN" ]]; then
        DAEMON_BIN="$(find_daemon_bin)" || {
            cat <<'EOF'
{"commit":"EOF
            echo -n "$commit_sha"
            cat <<'EOF'
","collected_at":"EOF
            date -u +%Y-%m-%dT%H:%M:%SZ
            cat <<'EOF'
","environment":"daemon-not-found","rows":[]}
EOF
            exit 2
        }
    fi

    compile_workload

    # Create temp work directory
    _work_dir="$(mktemp -d -t tidefs-mmap-validation.XXXXXX)"
    local store_dir="$_work_dir/store"
    _mount_dir="$_work_dir/mnt"
    local test_dir="$_mount_dir/mmaptest"

    mkdir -p "$store_dir" "$_mount_dir"

    # Start daemon
    local root_auth_key_hex="0000000000000000000000000000000000000000000000000000000000000001"

    "$DAEMON_BIN" mount-vfs \
        --store "$store_dir" \
        --mount "$_mount_dir" \
        --root-auth-key-hex "$root_auth_key_hex" \
        ${WRITEBACK_FLAG:+"$WRITEBACK_FLAG"} \
        > /tmp/tidefs-mmap-daemon.log 2>&1 &
    _daemon_pid=$!

    # Wait for mount to become ready
    local waited=0
    while ! mountpoint -q "$_mount_dir" 2>/dev/null; do
        sleep 0.2
        waited=$((waited + 1))
        if [[ $waited -gt 50 ]]; then
            echo "{\"commit\":\"$commit_sha\",\"collected_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"environment\":\"mount-timeout\",\"rows\":[]}"
            exit 1
        fi
    done

    # Determine writeback-cache status
    local wb_status="off"
    if [[ -n "$WRITEBACK_FLAG" ]]; then
        wb_status="on"
    fi

    local wb_rows="[]"
    if [[ "$wb_status" == "on" ]]; then
        wb_rows='[{"name":"writeback-cache-on","outcome":"blocked","tier":"mounted-userspace","output_note":"writeback-cache enabled; mmap tests run but writeback correctness not verified"},{"name":"writeback-cache-off","outcome":"blocked","tier":"mounted-userspace","output_note":"not exercised in this run"}]'
    else
        wb_rows='[{"name":"writeback-cache-on","outcome":"blocked","tier":"mounted-userspace","output_note":"writeback-cache disabled; re-run with --writeback-cache to collect validation"},{"name":"writeback-cache-off","outcome":"blocked","tier":"mounted-userspace","output_note":"not yet verified"}]'
    fi

    # Run the workload
    local workload_json
    workload_json="$("$WORKLOAD_BIN" "$test_dir" 2>/tmp/tidefs-mmap-workload-err.log)" || true

    # Merge writeback rows with workload rows
    local all_rows
    all_rows="$(echo "$wb_rows" | sed 's/^\[//;s/\]$//'),$(echo "$workload_json" | sed 's/^\[//;s/\]$//')"

    cat <<JSONEND
{
  "commit": "$commit_sha",
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "host-userspace FUSE mount (writeback-cache=$wb_status)",
  "rows": [$all_rows]
}
JSONEND

    echo "Validation collected. See /tmp/tidefs-mmap-daemon.log for daemon output." >&2
}

main "$@"
