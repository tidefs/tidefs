#!/usr/bin/env bash
# check-advancement.sh — run workspace advancement criteria checks
#
# Usage:
#   scripts/check-advancement.sh              # one-shot, human-readable
#   scripts/check-advancement.sh --ci         # machine-readable KEY=VALUE
#   scripts/check-advancement.sh --interval N # repeat every N seconds
#
# Exit code: 0 when all checks pass, non-zero on first failure or usage error.

set -euo pipefail

# ---- helpers -----------------------------------------------------------

die() {
    echo "check-advancement: $*" >&2
    exit 2
}

# ---- workspace-root discovery ------------------------------------------

find_workspace_root() {
    local dir
    dir="$(realpath "${1:-$PWD}")"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/Cargo.toml" ]] && grep -q '^\[workspace\]' "$dir/Cargo.toml" 2>/dev/null; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}

# ---- check runners -----------------------------------------------------
#
# Each check uses one of two modes derived from the original advancement-criteria
# shell pipelines:
#
#   error_grep:  grep -q "$grep_pattern" && echo FAIL || echo PASS
#                → if the pattern IS found, the check FAILS.
#                Used for: cargo check (look for "error: could not compile").
#
#   ok_grep:     grep -q "$grep_pattern" && echo PASS || echo FAIL
#                → if the pattern IS found, the check PASSES.
#                Used for: cargo test (look for "test result: ok").

run_check_error_grep() {
    local label="$1" cmd="$2" fail_pattern="$3"
    local output rc

    output="$(eval "$cmd" 2>&1)" || true
    if echo "$output" | grep -q "$fail_pattern"; then
        echo "FAIL"
        return 1
    fi
    echo "PASS"
    return 0
}

run_check_ok_grep() {
    local label="$1" cmd="$2" ok_pattern="$3"
    local output rc

    output="$(eval "$cmd" 2>&1)" || true
    if echo "$output" | grep -q "$ok_pattern"; then
        echo "PASS"
        return 0
    fi
    echo "FAIL"
    return 1
}

# CI variants — same logic, KEY=VALUE output + timing
_run_ci() {
    local mode="$1" label="$2" cmd="$3" pattern="$4"
    local output rc start_ns end_ns elapsed_ms

    start_ns="$(date +%s%N)"
    output="$(eval "$cmd" 2>&1)" || true
    end_ns="$(date +%s%N)"
    elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"

    echo "CHECK=${label}"
    echo "DURATION_MS=${elapsed_ms}"

    case "$mode" in
        error_grep)
            if echo "$output" | grep -q "$pattern"; then
                echo "RESULT=FAIL"
                return 1
            fi
            echo "RESULT=PASS"
            return 0
            ;;
        ok_grep)
            if echo "$output" | grep -q "$pattern"; then
                echo "RESULT=PASS"
                return 0
            fi
            echo "RESULT=FAIL"
            return 1
            ;;
    esac
}

run_check_ci_error_grep() {
    _run_ci error_grep "$@"
}
run_check_ci_ok_grep() {
    _run_ci ok_grep "$@"
}

# ---- main --------------------------------------------------------------

main() {
    local interval=0
    CI_MODE=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ci) CI_MODE=1 ;;
            --interval)
                shift
                interval="${1:-0}"
                if ! [[ "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 ]]; then
                    die "--interval requires a positive integer (seconds)"
                fi
                ;;
            *) die "unknown flag: $1" ;;
        esac
        shift
    done

    # Discover workspace root
    local ws_root
    ws_root="$(find_workspace_root)" || die "could not find workspace root (no Cargo.toml with [workspace] found)"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/ai/state/tidefs/cargo-target}"

    if [[ "${CI_MODE:-0}" -eq 1 ]]; then
        echo "WORKSPACE=${ws_root}"
        echo "TARGET_DIR=${CARGO_TARGET_DIR}"
    else
        echo "Workspace: ${ws_root}"
        echo "Target:    ${CARGO_TARGET_DIR}"
        echo ""
    fi

    local iteration=1
    local overall=0

    while true; do
        if [[ "$interval" -gt 0 ]] && [[ "${CI_MODE:-0}" -ne 1 ]]; then
            echo "--- iteration ${iteration} ($(date '+%H:%M:%S')) ---"
        fi
        if [[ "${CI_MODE:-0}" -eq 1 ]]; then
            echo "ITERATION=${iteration}"
        fi

        local failed=0

        # ---- userspace-filesystem checks ----------------------------------

        local phase_label="userspace-filesystem"

        # Check 1: workspace compiles without "error: could not compile"
        local c1_label="cargo-check-workspace"
        local c1_cmd="cd '${ws_root}' && cargo check --workspace 2>&1"
        local c1_pattern="error: could not compile"

        if [[ "${CI_MODE:-0}" -eq 1 ]]; then
            if ! run_check_ci_error_grep "$c1_label" "$c1_cmd" "$c1_pattern"; then
                failed=1
            fi
        else
            printf "%-45s " "${c1_label}:"
            if ! run_check_error_grep "$c1_label" "$c1_cmd" "$c1_pattern"; then
                failed=1
            fi
        fi

        # Check 2: write_durability tests produce "test result: ok"
        local c2_label="write-durability"
        local c2_cmd="cd '${ws_root}' && cargo test -p tidefs-validation -- write_durability 2>&1"
        local c2_pattern="test result: ok"

        if [[ "$failed" -eq 0 ]]; then
            if [[ "${CI_MODE:-0}" -eq 1 ]]; then
                if ! run_check_ci_ok_grep "$c2_label" "$c2_cmd" "$c2_pattern"; then
                    failed=1
                fi
            else
                printf "%-45s " "${c2_label}:"
                if ! run_check_ok_grep "$c2_label" "$c2_cmd" "$c2_pattern"; then
                    failed=1
                fi
            fi
        else
            if [[ "${CI_MODE:-0}" -eq 1 ]]; then
                echo "CHECK=${c2_label}"
                echo "RESULT=SKIP"
                echo "DURATION_MS=0"
            else
                printf "%-45s %s\n" "${c2_label}:" "SKIP (previous check failed)"
            fi
        fi

        if [[ "$failed" -ne 0 ]]; then
            overall=1
            if [[ "$interval" -eq 0 ]]; then
                exit 1
            fi
        fi

        if [[ "$interval" -eq 0 ]]; then
            break
        fi

        iteration=$((iteration + 1))
        sleep "$interval"
    done

    exit $overall
}

main "$@"
