#!/usr/bin/env bash
# TideFS host-validation QEMU capacity gate.
#
# Provides bounded concurrent QEMU execution across Nexus workers so that
# multiple slots do not oversubscribe the host.  Uses file-descriptor locks
# under a shared gate directory for cross-process coordination.
#
# Usage:
#   tidefs-host-validation-gate.sh acquire [--timeout SECONDS] [--slot NAME]
#       Acquire a capacity slot.  Prints "acquired SLOT_ID TOKEN" on stdout
#       and holds the lock until this shell exits or the caller explicitly
#       releases.  Exits non-zero on timeout.
#
#   tidefs-host-validation-gate.sh release TOKEN
#       Release a previously acquired slot.  (Usually the lock is released
#       implicitly when the acquiring process exits; this is a convenience.)
#
#   tidefs-host-validation-gate.sh status
#       Print current capacity usage: total slots, occupied, free, and
#       per-slot metadata.
#
#   tidefs-host-validation-gate.sh wait-and-run [--timeout SECONDS] [--slot NAME] -- COMMAND...
#       Acquire a slot, run COMMAND, release slot on exit (even on failure).
#       All COMMAND arguments after -- are passed through.

set -euo pipefail

# ── configuration ──────────────────────────────────────────────────────────
GATE_DIR="${TIDEFS_HOST_VALIDATION_GATE_DIR:-/tmp/tidefs-workers/host-validation-gate}"
MAX_CAPACITY="${TIDEFS_HOST_VALIDATION_MAX_CAPACITY:-2}"
DEFAULT_TIMEOUT="${TIDEFS_HOST_VALIDATION_TIMEOUT:-3600}"
# ───────────────────────────────────────────────────────────────────────────

# Ensure the gate directory and per-slot lock files exist.
_init_gate_dir() {
    mkdir -p "$GATE_DIR"
    for ((i = 0; i < MAX_CAPACITY; i++)); do
        local slot_file="$GATE_DIR/slot-$i"
        if [[ ! -f "$slot_file" ]]; then
            printf '{"slot":%d,"status":"free","owner":"","pid":0,"started_at":0}\n' "$i" > "$slot_file"
        fi
    done
}

# Write metadata into a slot file while holding its lock.
_write_slot_meta() {
    local slot_id="$1" status="$2" owner="$3" pid="$4" started_at="$5"
    local slot_file="$GATE_DIR/slot-$slot_id"
    printf '{"slot":%d,"status":"%s","owner":"%s","pid":%d,"started_at":%s}\n' \
        "$slot_id" "$status" "$owner" "$pid" "$started_at" > "$slot_file"
}

# Try to acquire a specific slot.  Returns 0 on success (fd stored in
# ACQUIRED_FD), 1 if the slot is already held.
_try_acquire_slot() {
    local slot_id="$1" owner="$2"
    local slot_file="$GATE_DIR/slot-$slot_id"
    local fd
    exec {fd}<>"$slot_file" 2>/dev/null || return 1

    if ! flock -n "$fd" 2>/dev/null; then
        exec {fd}>&-
        return 1
    fi

    # We hold the lock — write metadata.
    local now
    now=$(date +%s)
    _write_slot_meta "$slot_id" "occupied" "$owner" "$$" "$now"

    # Return the fd number so caller can hold the lock or release it.
    ACQUIRED_FD="$fd"
    return 0
}

# Acquire any free slot, blocking up to timeout_seconds.
_acquire_any() {
    local timeout_secs="$1" owner="$2"
    local deadline
    deadline=$(($(date +%s) + timeout_secs))

    while true; do
        for ((i = 0; i < MAX_CAPACITY; i++)); do
            if _try_acquire_slot "$i" "$owner"; then
                echo "acquired $i $owner"
                return 0
            fi
        done

        local now
        now=$(date +%s)
        if (( now >= deadline )); then
            echo "timeout: no capacity slot available after ${timeout_secs}s" >&2
            return 1
        fi

        # Exponential-ish backoff: 1s → 2s → 4s → 8s, capped at 30s
        local remaining=$((deadline - now))
        local wait_sec=1
        if (( remaining > 30 )); then wait_sec=8; fi
        if (( wait_sec > remaining )); then wait_sec=$remaining; fi
        sleep "$wait_sec"
    done
}

# ── subcommands ────────────────────────────────────────────────────────────

cmd_acquire() {
    local timeout_secs="$DEFAULT_TIMEOUT" owner=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout) timeout_secs="$2"; shift 2 ;;
            --slot)    owner="$2"; shift 2 ;;
            *) echo "unknown acquire option: $1" >&2; exit 2 ;;
        esac
    done
    [[ -z "$owner" ]] && owner="unknown"
    _init_gate_dir
    _acquire_any "$timeout_secs" "$owner"
}

cmd_release() {
    local token="$1"
    # Release is implicit: we just locate the slot by token and mark it free.
    # In practice the lock is held by the acquiring process and released when
    # that process exits; this subcommand handles explicit release.
    _init_gate_dir
    for ((i = 0; i < MAX_CAPACITY; i++)); do
        local slot_file="$GATE_DIR/slot-$i"
        local meta
        meta=$(cat "$slot_file" 2>/dev/null || true)
        local status
        status=$(echo "$meta" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)
        local owner
        owner=$(echo "$meta" | python3 -c "import sys,json; print(json.load(sys.stdin).get('owner',''))" 2>/dev/null || true)
        if [[ "$status" == "occupied" && "$owner" == "$token" ]]; then
            # Try to acquire the lock briefly just to write free status.
            local fd
            exec {fd}<>"$slot_file" 2>/dev/null || continue
            if flock -n "$fd" 2>/dev/null; then
                _write_slot_meta "$i" "free" "" 0 0
                exec {fd}>&-
                echo "released slot $i (token $token)"
                return 0
            fi
            exec {fd}>&-
        fi
    done
    echo "token $token not found among occupied slots" >&2
    return 1
}

cmd_status() {
    _init_gate_dir
    local occupied=0 free=0
    printf '{"gate_dir":"%s","max_capacity":%d,"slots":[' "$GATE_DIR" "$MAX_CAPACITY"
    local first=true
    for ((i = 0; i < MAX_CAPACITY; i++)); do
        local slot_file="$GATE_DIR/slot-$i"
        local meta
        meta=$(cat "$slot_file" 2>/dev/null || printf '{"slot":%d,"status":"free","owner":"","pid":0,"started_at":0}' "$i")
        if $first; then first=false; else printf ','; fi
        printf '%s' "$meta"
        local status
        status=$(echo "$meta" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)
        if [[ "$status" == "occupied" ]]; then occupied=$((occupied + 1)); else free=$((free + 1)); fi
    done
    printf '],"occupied":%d,"free":%d}\n' "$occupied" "$free"
}

cmd_wait_and_run() {
    local timeout_secs="$DEFAULT_TIMEOUT" owner=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout) timeout_secs="$2"; shift 2 ;;
            --slot)    owner="$2"; shift 2 ;;
            --)        shift; break ;;
            *) echo "unknown wait-and-run option: $1" >&2; exit 2 ;;
        esac
    done
    [[ -z "$owner" ]] && owner="unknown"
    if [[ $# -eq 0 ]]; then
        echo "wait-and-run requires a command after --" >&2
        exit 2
    fi

    _init_gate_dir

    # Acquire a slot in a subshell that holds the fd, then exec the command.
    # We use a trick: open the slot fd in the parent, then run the command
    # as a child that inherits the fd (keeping the lock alive).
    local acquired_slot=-1 acquired_fd=-1
    local deadline
    deadline=$(($(date +%s) + timeout_secs))

    while true; do
        for ((i = 0; i < MAX_CAPACITY; i++)); do
            local slot_file="$GATE_DIR/slot-$i"
            local fd
            exec {fd}<>"$slot_file" 2>/dev/null || continue
            if flock -n "$fd" 2>/dev/null; then
                acquired_slot=$i
                acquired_fd=$fd
                break 2
            fi
            exec {fd}>&-
        done

        local now
        now=$(date +%s)
        if (( now >= deadline )); then
            echo "wait-and-run timeout: no capacity slot available after ${timeout_secs}s" >&2
            exit 1
        fi
        local remaining=$((deadline - now))
        local wait_sec=1
        if (( remaining > 30 )); then wait_sec=8; fi
        if (( wait_sec > remaining )); then wait_sec=$remaining; fi
        sleep "$wait_sec"
    done

    # Write metadata while holding the lock.
    local now
    now=$(date +%s)
    _write_slot_meta "$acquired_slot" "occupied" "$owner" "$$" "$now"

    # Run the command.  The lock fd ($acquired_fd) remains open, so the lock
    # is held for the duration of the command.
    echo "[host-validation-gate] acquired slot $acquired_slot (max $MAX_CAPACITY), running: $*" >&2
    set +e
    "$@"
    local rc=$?
    set -e

    # Release: mark slot free and close fd.
    _write_slot_meta "$acquired_slot" "free" "" 0 0
    exec {acquired_fd}>&-

    echo "[host-validation-gate] released slot $acquired_slot, exit=$rc" >&2
    return $rc
}

# ── dispatch ───────────────────────────────────────────────────────────────

case "${1:-}" in
    acquire)
        shift
        cmd_acquire "$@"
        ;;
    release)
        shift
        cmd_release "$@"
        ;;
    status)
        cmd_status
        ;;
    wait-and-run)
        shift
        cmd_wait_and_run "$@"
        ;;
    *)
        echo "usage: $0 {acquire|release|status|wait-and-run} [args...]" >&2
        exit 2
        ;;
esac
