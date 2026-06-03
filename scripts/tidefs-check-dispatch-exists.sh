#!/usr/bin/env bash
# Check whether a TideFS dispatch function already exists in the codebase.
#
# Searches the VFS adapter (FuseVfsAdapter) and VFS engine trait for an
# already-implemented dispatch function.  Helps workers avoid creating
# tracker issues for work that is already done, preventing token waste
# and duplicate implementation.
#
# Usage:
#   tidefs-check-dispatch-exists.sh <name>          human-readable output
#   tidefs-check-dispatch-exists.sh --json <name>   machine-readable JSON
#
# <name> may be given as "dispatch_readlink" or just "readlink".
# The script strips an optional "dispatch_" prefix before searching.
#
# Exit codes:
#   0   Found in at least one target file (already implemented).
#   1   Not found in any target file (genuinely missing).
#   2   Usage error (missing argument, unknown flag).

set -euo pipefail

# ── resolve repo root ─────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ADAPTER="${REPO_ROOT}/apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs"
ENGINE="${REPO_ROOT}/crates/tidefs-vfs-engine/src/lib.rs"

JSON_OUT=0
NAME=""

# ── parse arguments ───────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            JSON_OUT=1
            shift
            ;;
        --help|-h)
            echo "Usage: $(basename "$0") [--json] <dispatch-name>"
            echo ""
            echo "Check whether a dispatch function already exists in the TideFS codebase."
            echo ""
            echo "  dispatch-name   e.g. \"readlink\" or \"dispatch_readlink\""
            echo "  --json          emit JSON instead of human-readable text"
            exit 0
            ;;
        -*)
            echo "Unknown flag: $1" >&2
            exit 2
            ;;
        *)
            if [[ -z "$NAME" ]]; then
                NAME="$1"
            else
                echo "Unexpected extra argument: $1" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [[ -z "$NAME" ]]; then
    echo "Usage: $(basename "$0") [--json] <dispatch-name>" >&2
    exit 2
fi

# ── normalize name ────────────────────────────────────────────────────
# Strip optional "dispatch_" prefix so both "dispatch_readlink" and
# "readlink" are accepted.
NORM="${NAME#dispatch_}"

# ── search targets ────────────────────────────────────────────────────
# We look for both the private dispatch_<name> helper and the public
# FUSE callback fn <name> in the adapter, and the engine trait method
# fn <name> in the engine.

adapter_dispatch_lines=""
adapter_callback_lines=""
engine_lines=""

if [[ -f "$ADAPTER" ]]; then
    adapter_dispatch_lines="$(rg -n "fn dispatch_${NORM}\b" "$ADAPTER" 2>/dev/null || true)"
    adapter_callback_lines="$(rg -n "fn ${NORM}\b" "$ADAPTER" 2>/dev/null || true)"
fi

if [[ -f "$ENGINE" ]]; then
    engine_lines="$(rg -n "fn ${NORM}\b" "$ENGINE" 2>/dev/null || true)"
fi

# ── determine result ──────────────────────────────────────────────────
FOUND=0
ADAPTER_DISPATCH_MATCHES=()
ADAPTER_CALLBACK_MATCHES=()
ENGINE_MATCHES=()

if [[ -n "$adapter_dispatch_lines" ]]; then
    FOUND=1
    mapfile -t ADAPTER_DISPATCH_MATCHES <<< "$adapter_dispatch_lines"
fi
if [[ -n "$adapter_callback_lines" ]]; then
    FOUND=1
    mapfile -t ADAPTER_CALLBACK_MATCHES <<< "$adapter_callback_lines"
fi
if [[ -n "$engine_lines" ]]; then
    FOUND=1
    mapfile -t ENGINE_MATCHES <<< "$engine_lines"
fi

# ── output ────────────────────────────────────────────────────────────
if [[ "$JSON_OUT" -eq 1 ]]; then
    if [[ "$FOUND" -eq 1 ]]; then
        # Build JSON arrays manually to avoid jq dependency.
        echo -n '{'
        echo -n '"status":"found",'
        echo -n '"name":"'"${NORM}"'",'
        echo -n '"adapter_dispatch":['
        first=1
        for line in "${ADAPTER_DISPATCH_MATCHES[@]}"; do
            if [[ -z "$line" ]]; then continue; fi
            ln="${line%%:*}"
            txt="${line#*:}"
            txt="${txt#"${txt%%[![:space:]]*}"}"  # trim leading whitespace
            [[ $first -eq 1 ]] || echo -n ','
            first=0
            printf '{"file":"%s","line":%s,"text":%s}' \
                "$ADAPTER" "$ln" "$(printf '%s' "$txt" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().rstrip("\n")))')"
        done
        echo -n '],'
        echo -n '"adapter_callback":['
        first=1
        for line in "${ADAPTER_CALLBACK_MATCHES[@]}"; do
            if [[ -z "$line" ]]; then continue; fi
            ln="${line%%:*}"
            txt="${line#*:}"
            txt="${txt#"${txt%%[![:space:]]*}"}"
            [[ $first -eq 1 ]] || echo -n ','
            first=0
            printf '{"file":"%s","line":%s,"text":%s}' \
                "$ADAPTER" "$ln" "$(printf '%s' "$txt" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().rstrip("\n")))')"
        done
        echo -n '],'
        echo -n '"engine_trait":['
        first=1
        for line in "${ENGINE_MATCHES[@]}"; do
            if [[ -z "$line" ]]; then continue; fi
            ln="${line%%:*}"
            txt="${line#*:}"
            txt="${txt#"${txt%%[![:space:]]*}"}"
            [[ $first -eq 1 ]] || echo -n ','
            first=0
            printf '{"file":"%s","line":%s,"text":%s}' \
                "$ENGINE" "$ln" "$(printf '%s' "$txt" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().rstrip("\n")))')"
        done
        echo -n ']'
        echo '}'
    else
        echo "{\"status\":\"not_found\",\"name\":\"${NORM}\"}"
    fi
else
    # Human-readable output.
    if [[ "$FOUND" -eq 1 ]]; then
        echo "dispatch_${NORM}: FOUND (already implemented)"
        echo ""
        if [[ ${#ADAPTER_DISPATCH_MATCHES[@]} -gt 0 ]]; then
            echo "  Adapter dispatch (fuse_vfs_adapter.rs):"
            for line in "${ADAPTER_DISPATCH_MATCHES[@]}"; do
                [[ -z "$line" ]] && continue
                echo "    $line"
            done
        fi
        if [[ ${#ADAPTER_CALLBACK_MATCHES[@]} -gt 0 ]]; then
            echo "  Adapter FUSE callback (fuse_vfs_adapter.rs):"
            for line in "${ADAPTER_CALLBACK_MATCHES[@]}"; do
                [[ -z "$line" ]] && continue
                # Filter out dispatch_ lines already shown above
                [[ "$line" =~ dispatch_ ]] && continue
                echo "    $line"
            done
        fi
        if [[ ${#ENGINE_MATCHES[@]} -gt 0 ]]; then
            echo "  Engine trait (vfs-engine/src/lib.rs):"
            for line in "${ENGINE_MATCHES[@]}"; do
                [[ -z "$line" ]] && continue
                echo "    $line"
            done
        fi
    else
        echo "dispatch_${NORM}: NOT FOUND (safe to implement)"
    fi
fi

exit $(( 1 - FOUND ))
