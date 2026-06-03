# ci-test-runner.sh — workspace-wide test runner with per-crate JSON aggregation
#
# Usage:
#   scripts/ci-test-runner.sh                           # run all, human-readable
#   scripts/ci-test-runner.sh --json summary.json       # run all, write JSON
#   scripts/ci-test-runner.sh --json -                  # run all, JSON to stdout
#   scripts/ci-test-runner.sh --crates tidefs-auth,tidefs-btree  # specific crates
#   scripts/ci-test-runner.sh --exclude tidefs-demo     # exclude crates
#
# Environment:
#   CARGO_TARGET_DIR   override the default target directory
#   CARGO_TEST_FLAGS   extra flags passed to `cargo test` (e.g. --release)
#
# Exit code: 0 when all crates pass, 1 when any crate fails or has compile errors.

set -euo pipefail

# ---- helpers -----------------------------------------------------------

die() {
    echo "ci-test-runner: $*" >&2
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

# ---- cargo metadata enumeration ----------------------------------------

# Enumerate workspace member crate names, sorted alphabetically.
# Returns newline-delimited list of crate names.
enumerate_crates() {
    local ws_root="$1"
    cargo metadata --manifest-path "$ws_root/Cargo.toml" \
        --format-version=1 --no-deps 2>/dev/null \
        | jq -r '.packages[] | .name' \
        | sort
}

# ---- test result parsing -----------------------------------------------

# Parse the "test result:" summary line from cargo test output.
# Sets global variables: TEST_PASSED, TEST_FAILED, TEST_IGNORED, TEST_MEASURED, TEST_FILTERED
parse_test_summary() {
    local output="$1"
    TEST_PASSED=0
    TEST_FAILED=0
    TEST_IGNORED=0
    TEST_MEASURED=0
    TEST_FILTERED=0

    # Match the last "test result:" line (aggregate, not per-target)
    local summary
    summary="$(echo "$output" | grep '^test result:' | tail -1)" || return 1

    # Parse: "test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
    # or:    "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out"
    if [[ "$summary" =~ ([0-9]+)\ passed ]]; then
        TEST_PASSED="${BASH_REMATCH[1]}"
    fi
    if [[ "$summary" =~ ([0-9]+)\ failed ]]; then
        TEST_FAILED="${BASH_REMATCH[1]}"
    fi
    if [[ "$summary" =~ ([0-9]+)\ ignored ]]; then
        TEST_IGNORED="${BASH_REMATCH[1]}"
    fi
    if [[ "$summary" =~ ([0-9]+)\ measured ]]; then
        TEST_MEASURED="${BASH_REMATCH[1]}"
    fi
    if [[ "$summary" =~ ([0-9]+)\ filtered\ out ]]; then
        TEST_FILTERED="${BASH_REMATCH[1]}"
    fi
    return 0
}

# Determine if a test run produced a "test result:" line (had test targets).
has_test_results() {
    local output="$1"
    echo "$output" | grep -q '^test result:'
}

# Determine if output contains a compile error.
has_compile_error() {
    local output="$1"
    echo "$output" | grep -q '^error: could not compile'
}

# ---- per-crate test execution ------------------------------------------

# Run cargo test for a single crate and capture results.
# Arguments: crate_name
# Sets global variables on success or returns 1 on fatal error.
run_crate_test() {
    local crate="$1"
    local ws_root="$2"
    local extra_flags="${CARGO_TEST_FLAGS:-}"

    local start_ns end_ns elapsed_ms
    start_ns="$(date +%s%N)"

    local output rc
    set +e
    output="$(cd "$ws_root" && cargo test --no-fail-fast -p "$crate" $extra_flags 2>&1)"
    rc=$?
    set -e

    end_ns="$(date +%s%N)"
    elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"
    CRATE_DURATION_MS="$elapsed_ms"

    # Determine test counts from the aggregate summary line
    if has_test_results "$output"; then
        parse_test_summary "$output" || true
    else
        TEST_PASSED=0
        TEST_FAILED=0
        TEST_IGNORED=0
        TEST_MEASURED=0
        TEST_FILTERED=0
    fi

    if [[ "$rc" -ne 0 ]]; then
        if has_compile_error "$output"; then
            CRATE_STATUS="compile_error"
        else
            CRATE_STATUS="fail"
        fi
    else
        CRATE_STATUS="pass"
    fi

    # Capture the last 4 meaningful lines of output for failure detail
    CRATE_FAILURE_DETAIL=""
    if [[ "$CRATE_STATUS" != "pass" ]]; then
        # Grab up to the last error line + a few lines of context
        local err_section
        err_section="$(echo "$output" | grep -n '^error' | tail -1 | cut -d: -f1)" || true
        if [[ -n "$err_section" ]]; then
            local start_line
            start_line="$(( err_section > 1 ? err_section - 1 : 1 ))"
            CRATE_FAILURE_DETAIL="$(echo "$output" | tail -n +"$start_line" | tail -20 | jq -Rs .)"
        else
            CRATE_FAILURE_DETAIL="$(echo "$output" | tail -20 | jq -Rs .)"
        fi
    fi

    return 0
}

# ---- JSON emission -----------------------------------------------------

# Emit a single JSON result object.
emit_json_result() {
    local name="$1" status="$2" passed="$3" failed="$4" ignored="$5"
    local measured="$6" filtered="$7" duration_ms="$8" failure_detail="${9:-}"

    local failure_json="null"
    if [[ -n "$failure_detail" ]]; then
        failure_json="$failure_detail"
    fi

    jq -n \
        --arg name "$name" \
        --arg status "$status" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson ignored "$ignored" \
        --argjson measured "$measured" \
        --argjson filtered "$filtered" \
        --argjson duration_ms "$duration_ms" \
        --argjson failure_detail "$failure_json" \
        '{
            crate: $name,
            status: $status,
            tests: {
                passed: $passed,
                failed: $failed,
                ignored: $ignored,
                measured: $measured,
                filtered: $filtered
            },
            duration_ms: $duration_ms,
            failure_detail: $failure_detail
        }'
}

# ---- main --------------------------------------------------------------

main() {
    local json_output=""
    local crate_filter=""
    local crate_exclude=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)
                shift
                json_output="${1:-}"
                if [[ -z "$json_output" ]]; then
                    die "--json requires a file path (or '-' for stdout)"
                fi
                ;;
            --crates)
                shift
                crate_filter="${1:-}"
                if [[ -z "$crate_filter" ]]; then
                    die "--crates requires a comma-separated list"
                fi
                ;;
            --exclude)
                shift
                crate_exclude="${1:-}"
                if [[ -z "$crate_exclude" ]]; then
                    die "--exclude requires a comma-separated list"
                fi
                ;;
            *)
                die "unknown flag: $1"
                ;;
        esac
        shift || true
    done

    # Discover workspace root
    local ws_root
    ws_root="$(find_workspace_root)" || die "could not find workspace root"

    # Set target directory
    # Set target directory — prefer the env-provided path, but fall back to
    # a writable directory under the workspace if the default is read-only.
    local target_dir="${CARGO_TARGET_DIR:-}"
    local use_target_dir
    if [[ -n "$target_dir" ]] && mkdir -p "$target_dir" 2>/dev/null && [[ -w "$target_dir" ]]; then
        use_target_dir="$target_dir"
    else
        use_target_dir="$ws_root/target"
        mkdir -p "$use_target_dir" 2>/dev/null || {
            echo "ci-test-runner: target dir $use_target_dir is not writable, using /tmp" >&2
            use_target_dir="$(mktemp -d /tmp/ci-test-runner-target-XXXXXX)"
        }
    fi
    export CARGO_TARGET_DIR="$use_target_dir"

    # Enumerate crates
    local all_crates
    all_crates="$(enumerate_crates "$ws_root")"

    # Apply filters
    local crates=()
    if [[ -n "$crate_filter" ]]; then
        IFS=',' read -ra filter_names <<< "$crate_filter"
        for name in "${filter_names[@]}"; do
            name="$(echo "$name" | xargs)" # trim whitespace
            if echo "$all_crates" | grep -qxF "$name"; then
                crates+=("$name")
            else
                echo "ci-test-runner: warning: crate '$name' not found in workspace, skipping" >&2
            fi
        done
    else
        while IFS= read -r name; do
            crates+=("$name")
        done <<< "$all_crates"
    fi

    # Apply exclusions
    if [[ -n "$crate_exclude" ]]; then
        IFS=',' read -ra exclude_names <<< "$crate_exclude"
        local filtered=()
        for name in "${crates[@]}"; do
            local excluded=0
            for ex in "${exclude_names[@]}"; do
                ex="$(echo "$ex" | xargs)"
                if [[ "$name" == "$ex" ]]; then
                    excluded=1
                    break
                fi
            done
            if [[ "$excluded" -eq 0 ]]; then
                filtered+=("$name")
            fi
        done
        crates=("${filtered[@]}")
    fi

    local crate_count="${#crates[@]}"
    if [[ "$crate_count" -eq 0 ]]; then
        die "no crates to test after filtering"
    fi

    # Header
    if [[ "$json_output" != "-" ]]; then
        echo "Workspace: $ws_root"
        echo "Target:    $CARGO_TARGET_DIR"
        echo "Crates:    $crate_count"
        echo ""
    fi

    local json_results="["
    local first_json=1
    local overall_failed=0
    local pass_count=0
    local fail_count=0
    local compile_error_count=0
    local total_tests=0

    for crate in "${crates[@]}"; do
        if [[ "$json_output" != "-" ]]; then
            printf "%-55s " "${crate}:"
        fi

        run_crate_test "$crate" "$ws_root"
        local status="$CRATE_STATUS"
        local duration="$CRATE_DURATION_MS"

        local total_crate_tests="$(( TEST_PASSED + TEST_FAILED + TEST_IGNORED + TEST_MEASURED ))"
        total_tests="$(( total_tests + total_crate_tests ))"

        case "$status" in
            pass)
                pass_count=$((pass_count + 1))
                ;;
            fail)
                fail_count=$((fail_count + 1))
                overall_failed=1
                ;;
            compile_error)
                compile_error_count=$((compile_error_count + 1))
                overall_failed=1
                ;;
        esac

        if [[ "$json_output" != "-" ]]; then
            local label
            case "$status" in
                pass)          label="PASS" ;;
                fail)          label="FAIL ($TEST_FAILED failed)" ;;
                compile_error) label="COMPILE ERROR" ;;
                *)             label="$status" ;;
            esac
            printf "%-30s %s\n" "$label" "${duration}ms"
        fi

        # Build JSON
        local result_json
        result_json="$(emit_json_result "$crate" "$status" "$TEST_PASSED" "$TEST_FAILED" \
            "$TEST_IGNORED" "$TEST_MEASURED" "$TEST_FILTERED" "$duration" "$CRATE_FAILURE_DETAIL")"

        if [[ "$first_json" -eq 1 ]]; then
            first_json=0
        else
            json_results+=","
        fi
        json_results+="$result_json"
    done

    json_results+="]"

    # Summary
    if [[ "$json_output" != "-" ]]; then
        echo ""
        echo "---"
        echo "Total crates:    $crate_count"
        echo "Passed:          $pass_count"
        echo "Failed:          $fail_count"
        echo "Compile errors:  $compile_error_count"
        echo "Total tests:     $total_tests"
    fi

    # Emit JSON
    if [[ -n "$json_output" ]]; then
        if [[ "$json_output" == "-" ]]; then
            echo "$json_results" | jq .
        else
            local dir
            dir="$(dirname "$json_output")"
            mkdir -p "$dir" 2>/dev/null || true
            echo "$json_results" | jq . > "$json_output"
            if [[ "$json_output" != "-" ]]; then
                echo ""
                echo "JSON summary written to: $json_output"
            fi
        fi
    fi

    exit $overall_failed
}

main "$@"
