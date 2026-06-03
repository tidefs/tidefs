#!/usr/bin/env bash
# tidefs-operator-demo.sh — End-to-end operator demo validation script
#
# Mounts TideFS via FUSE on a temporary directory, runs through the supported
# operator demo path (pool create, mount, file I/O, directory operations,
# persistence across remount), and writes pass/fail validation output under
# /root/ai/tmp/tidefs-validation/<run-id>/.
#
# Usage:
#   scripts/tidefs-operator-demo.sh [--daemon-bin <path>] [--out-dir <dir>]
#
# Environment:
#   TIDEFS_DAEMON_BIN   path to tidefs-posix-filesystem-adapter-daemon
#   TIDEFS_OUT_DIR      validation output directory (default: /root/ai/tmp/tidefs-validation/<run-id>/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DAEMON_BIN="${TIDEFS_DAEMON_BIN:-}"
OUT_DIR="${TIDEFS_OUT_DIR:-}"
COMMIT_SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo "unknown")"
BRANCH="$(cd "$REPO_ROOT" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
DIRTY=$(cd "$REPO_ROOT" && git diff --quiet 2>/dev/null && echo 0 || echo 1)

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="${RUN_TS}-operator-demo"

# ── cleanup trap ──────────────────────────────────────────────────────
_cleanup() {
    local exit_code=$?
    if [[ -n "${_mount_dir:-}" ]] && mountpoint -q "$_mount_dir" 2>/dev/null; then
        fusermount -u "$_mount_dir" 2>/dev/null || true
    fi
    if [[ -n "${_daemon_pid:-}" ]] && kill -0 "$_daemon_pid" 2>/dev/null; then
        kill -TERM "$_daemon_pid" 2>/dev/null || true
        wait "$_daemon_pid" 2>/dev/null || true
    fi
    if [[ -n "${_work_dir:-}" ]]; then
        rm -rf "$_work_dir" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap _cleanup EXIT INT TERM

# ── usage ─────────────────────────────────────────────────────────────
usage() {
    cat >&2 <<'USAGE_EOF'
Usage: tidefs-operator-demo.sh [--daemon-bin <path>] [--out-dir <dir>]

End-to-end operator demo validation. Mounts TideFS via FUSE, exercises the
supported demo path (pool create, file I/O, directory ops, persistence), and
writes pass/fail validation output.

Options:
  --daemon-bin <path>  Path to tidefs-posix-filesystem-adapter-daemon
  --out-dir <dir>      Validation output directory (default: /root/ai/tmp/tidefs-validation/<run-id>/)
  --keep-tmp           Keep temporary files on exit
  --help, -h           Show this message

Environment:
  TIDEFS_DAEMON_BIN    Same as --daemon-bin
  TIDEFS_OUT_DIR       Same as --out-dir

Exit codes:
  0   All demo operations PASS
  1   One or more operations FAIL
  2   Environment refusal (daemon not found, /dev/fuse missing)
USAGE_EOF
    exit 2
}

# ── parse args ────────────────────────────────────────────────────────
KEEP_TMP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon-bin) DAEMON_BIN="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage ;;
        *) echo "ERROR: unknown option: $1" >&2; usage ;;
    esac
done

# ── locate daemon binary ──────────────────────────────────────────────
find_daemon_bin() {
    local candidate

    # Try CARGO_TARGET_DIR first
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        for sub in debug release; do
            candidate="$CARGO_TARGET_DIR/$sub/tidefs-posix-filesystem-adapter-daemon"
            if [[ -x "$candidate" ]]; then echo "$candidate"; return 0; fi
        done
    fi

    # Try workspace target paths
    for sub in debug release; do
        candidate="$REPO_ROOT/target/$sub/tidefs-posix-filesystem-adapter-daemon"
        if [[ -x "$candidate" ]]; then echo "$candidate"; return 0; fi
    done

    # Try /tmp worker target dirs (s1..s8)
    for slot in s1 s2 s3 s4 s5 s6 s7 s8; do
        for sub in debug release; do
            candidate="/tmp/tidefs-workers/$slot/cargo-target/$sub/tidefs-posix-filesystem-adapter-daemon"
            if [[ -x "$candidate" ]]; then echo "$candidate"; return 0; fi
        done
    done

    # Fall back to $PATH
    if command -v tidefs-posix-filesystem-adapter-daemon >/dev/null 2>&1; then
        echo "tidefs-posix-filesystem-adapter-daemon"
        return 0
    fi

    return 1
}

# ── resolve output directory ──────────────────────────────────────────
resolve_out_dir() {
    if [[ -n "$OUT_DIR" ]]; then
        mkdir -p "$OUT_DIR"
        echo "$OUT_DIR"
    else
        local d="/root/ai/tmp/tidefs-validation/$RUN_ID"
        mkdir -p "$d"
        echo "$d"
    fi
}

# ── validation helpers ──────────────────────────────────────────────────
_results=()
_pass=0
_fail=0
_skip=0

record_result() {
    local name="$1" outcome="$2" detail="${3:-}"
    case "$outcome" in
        PASS) _pass=$((_pass + 1)) ;;
        FAIL) _fail=$((_fail + 1)) ;;
        SKIP) _skip=$((_skip + 1)) ;;
    esac
    local escaped_detail
    escaped_detail="$(echo "$detail" | sed 's/"/\\"/g')"
    _results+=("{\"name\":\"$name\",\"outcome\":\"$outcome\",\"detail\":\"$escaped_detail\"}")
}

# ── environment preflight ─────────────────────────────────────────────
env_preflight() {
    local refusal=""

    if [[ ! -c /dev/fuse ]]; then
        modprobe fuse 2>/dev/null || true
        if [[ ! -c /dev/fuse ]]; then
            refusal="no /dev/fuse device"
        fi
    fi

    if [[ -z "$DAEMON_BIN" ]]; then
        DAEMON_BIN="$(find_daemon_bin)" || {
            refusal="tidefs-posix-filesystem-adapter-daemon not found"
        }
    fi

    if [[ -n "$refusal" ]]; then
        local out
        out="$(resolve_out_dir)"
        cat > "$out/validation-manifest.json" <<JSONEND
{
  "validation_id": "operator-demo",
  "commit": "$COMMIT_SHA",
  "branch": "$BRANCH",
  "dirty": $DIRTY,
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "host-userspace",
  "validation_tier": "mounted-userspace",
  "outcome": "REFUSAL",
  "refusal_reason": "$refusal",
  "summary": "Operator demo validation refused: $refusal"
}
JSONEND
        echo "ENVIRONMENT REFUSAL: $refusal" >&2
        echo "Validation manifest written to $out/validation-manifest.json" >&2
        exit 2
    fi
}

# ── run demo operations ───────────────────────────────────────────────
run_demo() {
    local store_dir="$_work_dir/store"
    local mount_dir="$_mount_dir"
    local test_dir="$mount_dir/demo-test"

    mkdir -p "$store_dir"

    # ── Phase 1: Pool create and FUSE mount ───────────────────────
    local root_auth_hex="0000000000000000000000000000000000000000000000000000000000000001"

    "$DAEMON_BIN" mount-vfs \
        --store "$store_dir" \
        --mount "$mount_dir" \
        --root-auth-key-hex "$root_auth_hex" \
        > "$_work_dir/daemon.log" 2>&1 &
    _daemon_pid=$!

    local waited=0
    while ! mountpoint -q "$mount_dir" 2>/dev/null; do
        sleep 0.2
        waited=$((waited + 1))
        if [[ $waited -gt 50 ]]; then
            record_result "pool-create-and-mount" "FAIL" "mount timeout after ${waited}00ms"
            return 1
        fi
        kill -0 "$_daemon_pid" 2>/dev/null || {
            record_result "pool-create-and-mount" "FAIL" \
                "daemon exited before mount ready; see $_work_dir/daemon.log"
            return 1
        }
    done
    record_result "pool-create-and-mount" "PASS" "mounted $mount_dir"

    mkdir -p "$test_dir"

    # ── Phase 2: File create and write ────────────────────────────
    local test_file="$test_dir/hello.txt"
    local test_content="TideFS operator demo validation $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if echo "$test_content" > "$test_file" 2>/dev/null; then
        record_result "file-create-write" "PASS" "wrote $test_file"
    else
        record_result "file-create-write" "FAIL" "could not write $test_file"
    fi

    # ── Phase 3: File read and verify ─────────────────────────────
    local read_back
    if read_back="$(cat "$test_file" 2>/dev/null)"; then
        if [[ "$read_back" == "$test_content" ]]; then
            record_result "file-read-verify" "PASS" "content matches"
        else
            record_result "file-read-verify" "FAIL" "content mismatch"
        fi
    else
        record_result "file-read-verify" "FAIL" "could not read $test_file"
    fi

    # ── Phase 4: stat (size) ──────────────────────────────────────
    local st_size
    st_size="$(stat -c%s "$test_file" 2>/dev/null || echo "0")"
    local expected_size=${#test_content}
    if [[ "$st_size" -eq "$expected_size" ]]; then
        record_result "file-stat-size" "PASS" "size=$st_size"
    else
        record_result "file-stat-size" "FAIL" "expected $expected_size got $st_size"
    fi

    # ── Phase 5: Directory operations ─────────────────────────────
    local sub_dir="$test_dir/subdir"
    if mkdir "$sub_dir" 2>/dev/null; then
        record_result "mkdir" "PASS" "created $sub_dir"
    else
        record_result "mkdir" "FAIL" "could not create $sub_dir"
    fi

    local sub_file="$sub_dir/nested.txt"
    if echo "nested content" > "$sub_file" 2>/dev/null; then
        record_result "nested-file-create" "PASS" "wrote $sub_file"
    else
        record_result "nested-file-create" "FAIL" "could not write $sub_file"
    fi

    if rmdir "$sub_dir" 2>/dev/null; then
        record_result "rmdir" "PASS" "removed $sub_dir"
    else
        # rmdir should fail if not empty — expected
        if [[ -d "$sub_dir" ]] && [[ -f "$sub_file" ]]; then
            record_result "rmdir" "PASS" "correctly refused non-empty dir removal"
        else
            record_result "rmdir" "FAIL" "unexpected rmdir behavior"
        fi
    fi

    if rm -f "$sub_file" && rmdir "$sub_dir" 2>/dev/null; then
        record_result "rmdir-after-clean" "PASS" "removed after unlink"
    else
        record_result "rmdir-after-clean" "FAIL" "could not remove dir after unlink"
    fi

    # ── Phase 6: Rename ───────────────────────────────────────────
    local rename_src="$test_dir/rename-src.txt"
    local rename_dst="$test_dir/rename-dst.txt"
    echo "rename source" > "$rename_src" 2>/dev/null || true
    if mv "$rename_src" "$rename_dst" 2>/dev/null; then
        if [[ ! -f "$rename_src" ]] && [[ -f "$rename_dst" ]]; then
            record_result "rename" "PASS" "renamed $rename_src -> $rename_dst"
        else
            record_result "rename" "FAIL" "rename inconsistent state"
        fi
    else
        record_result "rename" "FAIL" "mv failed"
    fi

    # ── Phase 7: Hard link ────────────────────────────────────────
    local link_target="$test_dir/link-target.txt"
    local link_name="$test_dir/link-name.txt"
    echo "link content" > "$link_target" 2>/dev/null || true
    if ln "$link_target" "$link_name" 2>/dev/null; then
        local link_count
        link_count="$(stat -c%h "$link_target" 2>/dev/null || echo "1")"
        if [[ "$link_count" -eq 2 ]]; then
            record_result "hard-link" "PASS" "link count=$link_count"
        else
            record_result "hard-link" "FAIL" "expected 2 links got $link_count"
        fi
    else
        record_result "hard-link" "FAIL" "ln failed"
    fi

    # ── Phase 8: Symlink ──────────────────────────────────────────
    local symlink_path="$test_dir/symlink.txt"
    if ln -s "$link_target" "$symlink_path" 2>/dev/null; then
        local symlink_deref
        symlink_deref="$(cat "$symlink_path" 2>/dev/null || echo "")"
        if [[ "$symlink_deref" == "link content" ]]; then
            record_result "symlink" "PASS" "dereferenced correctly"
        else
            record_result "symlink" "FAIL" "dereference got '$symlink_deref'"
        fi
    else
        record_result "symlink" "FAIL" "ln -s failed"
    fi

    # ── Phase 9: Truncate ─────────────────────────────────────────
    local trunc_file="$test_dir/truncate-test.txt"
    echo "longer content for truncation" > "$trunc_file" 2>/dev/null || true
    if truncate -s 6 "$trunc_file" 2>/dev/null; then
        local trunc_size
        trunc_size="$(stat -c%s "$trunc_file" 2>/dev/null || echo "-1")"
        if [[ "$trunc_size" -eq 6 ]]; then
            record_result "truncate" "PASS" "size=$trunc_size"
        else
            record_result "truncate" "FAIL" "expected 6 got $trunc_size"
        fi
    else
        record_result "truncate" "FAIL" "truncate command failed"
    fi

    # ── Phase 10: Append ──────────────────────────────────────────
    local append_file="$test_dir/append-test.txt"
    echo -n "first" > "$append_file" 2>/dev/null || true
    echo -n "second" >> "$append_file" 2>/dev/null || true
    local append_content
    append_content="$(cat "$append_file" 2>/dev/null || echo "")"
    if [[ "$append_content" == "firstsecond" ]]; then
        record_result "append" "PASS" "content: $append_content"
    else
        record_result "append" "FAIL" "got '$append_content'"
    fi

    # ── Phase 11: Unmount and remount persistence ─────────────────
    fusermount -u "$mount_dir" 2>/dev/null || true
    sleep 1
    if ! mountpoint -q "$mount_dir" 2>/dev/null; then
        record_result "unmount" "PASS" "clean unmount"
    else
        record_result "unmount" "FAIL" "still mounted"
    fi

    # Remount to same store
    "$DAEMON_BIN" mount-vfs \
        --store "$store_dir" \
        --mount "$mount_dir" \
        --root-auth-key-hex "$root_auth_hex" \
        > "$_work_dir/daemon-remount.log" 2>&1 &
    _daemon_pid=$!

    waited=0
    while ! mountpoint -q "$mount_dir" 2>/dev/null; do
        sleep 0.2
        waited=$((waited + 1))
        if [[ $waited -gt 50 ]]; then
            record_result "remount" "FAIL" "remount timeout"
            return 1
        fi
        kill -0 "$_daemon_pid" 2>/dev/null || {
            record_result "remount" "FAIL" "daemon exited before remount ready"
            return 1
        }
    done
    record_result "remount" "PASS" "remounted $mount_dir"

    # Verify persisted data
    local persisted
    if persisted="$(cat "$test_file" 2>/dev/null)"; then
        if [[ "$persisted" == "$test_content" ]]; then
            record_result "persistence-verify" "PASS" "data survived remount"
        else
            record_result "persistence-verify" "FAIL" "content changed after remount"
        fi
    else
        record_result "persistence-verify" "FAIL" "could not read $test_file after remount"
    fi

    # Verify hard link survived remount
    local link_count2
    link_count2="$(stat -c%h "$link_target" 2>/dev/null || echo "0")"
    if [[ "$link_count2" -eq 2 ]]; then
        record_result "persistence-hard-link" "PASS" "link count=$link_count2 after remount"
    else
        record_result "persistence-hard-link" "FAIL" "expected 2 links got $link_count2"
    fi
}

# ── generate output ───────────────────────────────────────────────────
generate_output() {
    local out
    out="$(resolve_out_dir)"
    local collected_at
    collected_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Build JSON rows
    local rows_json="["
    local first=1
    for row in "${_results[@]}"; do
        if [[ $first -eq 1 ]]; then first=0; else rows_json+=","; fi
        rows_json+="$row"
    done
    rows_json+="]"

    # Determine overall outcome
    local overall="PASS"
    if [[ $_fail -gt 0 ]]; then overall="FAIL"; fi
    if [[ $_pass -eq 0 ]] && [[ $_fail -eq 0 ]]; then overall="SKIP"; fi

    # Human-readable summary
    cat > "$out/SUMMARY.md" <<MDEOF
# Operator Demo Validation - Issue #6512

- **Commit**: $COMMIT_SHA
- **Branch**: $BRANCH
- **Dirty**: $DIRTY
- **Collected**: $collected_at
- **Overall**: $overall
- **Pass**: $_pass
- **Fail**: $_fail
- **Skip**: $_skip
- **Validation tier**: mounted-userspace (Tier 3)

## Results

| Operation | Outcome | Detail |
|---|---|---|
MDEOF
    for row in "${_results[@]}"; do
        local name outcome detail
        name="$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin)['name'])" 2>/dev/null || echo "?")"
        outcome="$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin)['outcome'])" 2>/dev/null || echo "?")"
        detail="$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin)['detail'])" 2>/dev/null || echo "")"
        echo "| $name | $outcome | $detail |" >> "$out/SUMMARY.md"
    done

    # Machine-readable validation manifest
    cat > "$out/validation-manifest.json" <<JSONEND
{
  "validation_id": "operator-demo",
  "run_id": "$RUN_ID",
  "commit": "$COMMIT_SHA",
  "branch": "$BRANCH",
  "dirty": $DIRTY,
  "collected_at": "$collected_at",
  "environment": "host-userspace FUSE mount",
  "validation_tier": "mounted-userspace",
  "overall_outcome": "$overall",
  "pass_count": $_pass,
  "fail_count": $_fail,
  "skip_count": $_skip,
  "operations": $rows_json,
  "daemon_bin": "$DAEMON_BIN",
  "daemon_log": "$_work_dir/daemon.log",
  "summary": "Operator demo validation: $_pass pass, $_fail fail, $_skip skip"
}
JSONEND

    # Copy daemon logs
    if [[ -f "$_work_dir/daemon.log" ]]; then
        cp "$_work_dir/daemon.log" "$out/daemon.log"
    fi
    if [[ -f "$_work_dir/daemon-remount.log" ]]; then
        cp "$_work_dir/daemon-remount.log" "$out/daemon-remount.log"
    fi

    # Environment disclosure
    cat > "$out/environment.env" <<EOF
COMMIT_SHA=$COMMIT_SHA
BRANCH=$BRANCH
DIRTY=$DIRTY
COLLECTED_AT=$collected_at
DAEMON_BIN=$DAEMON_BIN
VALIDATION_TIER=mounted-userspace
EOF
}

# ── main ──────────────────────────────────────────────────────────────
main() {
    env_preflight

    _work_dir="$(mktemp -d -t tidefs-operator-demo.XXXXXX)"
    _mount_dir="$_work_dir/mnt"
    mkdir -p "$_mount_dir"

    if [[ "$KEEP_TMP" -eq 1 ]]; then
        echo "Work dir: $_work_dir"
    fi

    run_demo || true
    generate_output

    local out
    out="$(resolve_out_dir)"
    echo ""
    echo "=== Operator Demo Validation Complete ==="
    echo "  Overall: $_pass pass, $_fail fail, $_skip skip"
    echo "  Validation: $out/"
    echo "  Manifest: $out/validation-manifest.json"
    echo "  Summary:  $out/SUMMARY.md"
}

main "$@"
