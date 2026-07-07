#!/usr/bin/env bash
# Compare per-crate clippy warning counts against docs/clippy-baseline.json.

set -euo pipefail

die() {
    echo "clippy-baseline: $*" >&2
    exit 2
}

usage() {
    cat <<'EOF'
Usage:
  scripts/clippy-baseline.sh check-changed [--base <ref>] [--json <path>]
  scripts/clippy-baseline.sh check-workspace [--json <path>]
  scripts/clippy-baseline.sh snapshot [--crates <a,b>] [--json <path>]
  scripts/clippy-baseline.sh list-changed [--base <ref>]

Modes:
  check-changed    Run clippy on crates changed since <ref> and fail when a
                   crate exceeds docs/clippy-baseline.json.
  check-workspace  Run clippy on every workspace crate and compare baseline.
  snapshot         Emit current warning counts without comparing them.
  list-changed     Print changed workspace crate names and exit.

Environment:
  CLIPPY_BASELINE_FILE  Baseline file path, default docs/clippy-baseline.json.
EOF
}

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

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

json_string_array_from_lines() {
    jq -R -s 'split("\n") | map(select(. != ""))'
}

load_packages() {
    local ws_root="$1" metadata_file="$2"

    cargo metadata \
        --manifest-path "$ws_root/Cargo.toml" \
        --locked \
        --format-version=1 \
        --no-deps > "$metadata_file"
}

all_crates() {
    local metadata_file="$1"

    jq -r '.packages[] | select(.source == null) | .name' "$metadata_file" | sort -u
}

crate_paths_tsv() {
    local ws_root="$1" metadata_file="$2"

    jq -r '.packages[] | select(.source == null) | [.name, .manifest_path] | @tsv' "$metadata_file" |
        while IFS=$'\t' read -r crate manifest; do
            local crate_dir rel_dir
            crate_dir="$(dirname "$manifest")"
            rel_dir="$(realpath --relative-to="$ws_root" "$crate_dir")"
            printf '%s\t%s\n' "$crate" "$rel_dir"
        done |
        sort -k1,1
}

changed_files_since_base() {
    local base_ref="$1"

    if [[ -z "$base_ref" ]]; then
        base_ref="origin/master"
    fi

    if git merge-base --is-ancestor "$base_ref" HEAD >/dev/null 2>&1; then
        git diff --name-only "$base_ref"...HEAD
    else
        git diff --name-only "$base_ref" HEAD
    fi
}

policy_path_changed() {
    local changed_file="$1"

    case "$changed_file" in
        Cargo.toml|Cargo.lock|docs/clippy-baseline.json|scripts/clippy-baseline.sh|.github/workflows/clippy.yml)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

changed_crates() {
    local ws_root="$1" metadata_file="$2" base_ref="$3"
    local changed_file crate rel_dir row
    local -a changed_files package_rows selected

    mapfile -t changed_files < <(changed_files_since_base "$base_ref")
    if [[ "${#changed_files[@]}" -eq 0 ]]; then
        return 0
    fi

    for changed_file in "${changed_files[@]}"; do
        if policy_path_changed "$changed_file"; then
            all_crates "$metadata_file"
            return 0
        fi
    done

    mapfile -t package_rows < <(crate_paths_tsv "$ws_root" "$metadata_file")
    selected=()

    for changed_file in "${changed_files[@]}"; do
        for row in "${package_rows[@]}"; do
            IFS=$'\t' read -r crate rel_dir <<< "$row"
            if [[ "$changed_file" == "$rel_dir" || "$changed_file" == "$rel_dir/"* ]]; then
                selected+=("$crate")
            fi
        done
    done

    if [[ "${#selected[@]}" -gt 0 ]]; then
        printf '%s\n' "${selected[@]}" | sort -u
    fi
}

crates_from_csv() {
    local csv="$1"

    tr ',' '\n' <<< "$csv" |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
        sed '/^$/d' |
        sort -u
}

count_json_warnings() {
    local json_file="$1"

    jq -Rn '
      [inputs
       | fromjson?
       | select(.reason == "compiler-message")
       | .message
       | select(.level == "warning")]
      | length
    ' < "$json_file"
}

diagnostic_json_excerpt() {
    local json_file="$1"

    jq -Rn '
      [inputs
       | fromjson?
       | select(.reason == "compiler-message")
       | .message
       | select(.level == "error")
       | ((.rendered // "") as $rendered
          | if ($rendered | length) > 0 then $rendered else (.message // "") end)
       | select(. != "")]
      | join("\n\n")
    ' < "$json_file" | tail -n "${CLIPPY_BASELINE_ERROR_LINES:-80}"
}

run_clippy_for_crate() {
    local ws_root="$1" crate="$2" out_json="$3" err_log="$4"

    set +e
    (
        cd "$ws_root"
        cargo clippy -p "$crate" --locked --all-targets --message-format=json
    ) > "$out_json" 2> "$err_log"
    local rc=$?
    set -e

    return "$rc"
}

result_object() {
    local crate="$1" status="$2" warnings="$3" baseline="$4" exit_code="$5" stderr_excerpt="$6" diagnostic_excerpt="$7"

    local baseline_json
    if [[ "$baseline" == "null" ]]; then
        baseline_json="null"
    else
        baseline_json="$baseline"
    fi

    jq -n \
        --arg crate "$crate" \
        --arg status "$status" \
        --argjson warnings "$warnings" \
        --argjson baseline "$baseline_json" \
        --argjson exit_code "$exit_code" \
        --arg stderr_excerpt "$stderr_excerpt" \
        --arg diagnostic_excerpt "$diagnostic_excerpt" \
        '{
          crate: $crate,
          status: $status,
          warnings: $warnings,
          baseline_warnings: $baseline,
          cargo_exit_code: $exit_code,
          stderr_excerpt: $stderr_excerpt,
          diagnostic_excerpt: $diagnostic_excerpt
        }'
}

write_summary() {
    local mode="$1" base_ref="$2" json_output="$3" result_dir="$4" selected_file="$5" ws_root="$6"
    local generated_at head_sha selected_json results_json results_file failures total selected_count

    generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    head_sha="$(git -C "$ws_root" rev-parse HEAD)"
    selected_json="$(json_string_array_from_lines < "$selected_file")"

    if compgen -G "$result_dir/*.json" >/dev/null; then
        # Pipe via cat to avoid E2BIG when many result files exist
        results_json="$(cat "$result_dir"/*.json | jq -s '.')"
    else
        results_json="[]"
    fi

    results_file="$tmpdir/results.json"
    printf '%s' "$results_json" > "$results_file"

    failures="$(jq '[.[] | select(.status != "pass")] | length' <<< "$results_json")"
    total="$(jq 'length' <<< "$results_json")"
    selected_count="$(jq 'length' <<< "$selected_json")"

    jq -n \
        --argjson schema_version 1 \
        --arg mode "$mode" \
        --arg generated_at "$generated_at" \
        --arg base_ref "$base_ref" \
        --arg head_sha "$head_sha" \
        --argjson selected_crates "$selected_json" \
        --slurpfile results "$results_file" \
        --argjson total "$total" \
        --argjson selected_count "$selected_count" \
        --argjson failures "$failures" \
        '{
          schema_version: $schema_version,
          mode: $mode,
          generated_at: $generated_at,
          base_ref: $base_ref,
          head_sha: $head_sha,
          selected_crates: $selected_crates,
          totals: {
            selected_crates: $selected_count,
            checked_crates: $total,
            failures: $failures
          },
          results: $results[0]
        }' > "$json_output"

    echo "clippy-baseline: checked $total crate(s), failures=$failures"
}

main() {
    local mode="${1:-}"
    [[ -n "$mode" ]] || { usage >&2; exit 2; }
    shift

    local base_ref=""
    local json_output=""
    local crates_csv=""
    local baseline_file="${CLIPPY_BASELINE_FILE:-docs/clippy-baseline.json}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base)
                base_ref="${2:-}"
                [[ -n "$base_ref" ]] || die "--base requires a ref"
                shift 2
                ;;
            --json)
                json_output="${2:-}"
                [[ -n "$json_output" ]] || die "--json requires a path"
                shift 2
                ;;
            --crates)
                crates_csv="${2:-}"
                [[ -n "$crates_csv" ]] || die "--crates requires a comma-separated list"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
    done

    case "$mode" in
        check-changed|check-workspace|snapshot|list-changed)
            ;;
        *)
            die "unknown mode: $mode"
            ;;
    esac

    require_tool cargo
    require_tool git
    require_tool jq
    require_tool realpath

    local ws_root metadata selected_file result_dir
    ws_root="$(find_workspace_root)" || die "could not find workspace root"
    baseline_file="$ws_root/$baseline_file"

    if [[ "$mode" != "snapshot" && "$mode" != "list-changed" && ! -f "$baseline_file" ]]; then
        die "baseline file not found: $baseline_file"
    fi

    tmpdir="$(mktemp -d)"
    # Use ${tmpdir:-} so trap does not fail when tmpdir is unset
    trap '[[ -n "${tmpdir:-}" ]] && rm -rf "$tmpdir"' EXIT
    metadata="$tmpdir/metadata.json"
    selected_file="$tmpdir/selected-crates.txt"
    result_dir="$tmpdir/results"
    mkdir -p "$result_dir"

    load_packages "$ws_root" "$metadata"

    case "$mode" in
        check-workspace)
            all_crates "$metadata" > "$selected_file"
            ;;
        check-changed|list-changed)
            changed_crates "$ws_root" "$metadata" "$base_ref" > "$selected_file"
            ;;
        snapshot)
            if [[ -n "$crates_csv" ]]; then
                crates_from_csv "$crates_csv" > "$selected_file"
            else
                all_crates "$metadata" > "$selected_file"
            fi
            ;;
    esac

    if [[ "$mode" == "list-changed" ]]; then
        cat "$selected_file"
        exit 0
    fi

    if [[ ! -s "$selected_file" ]]; then
        json_output="${json_output:-clippy-baseline-summary.json}"
        write_summary "$mode" "$base_ref" "$json_output" "$result_dir" "$selected_file" "$ws_root"
        exit 0
    fi

    local crate failures=0
    while IFS= read -r crate; do
        [[ -n "$crate" ]] || continue

        echo "clippy-baseline: running cargo clippy for $crate"

        local out_json err_log rc warnings baseline status stderr_excerpt diagnostic_excerpt
        out_json="$tmpdir/$crate.stdout.json"
        err_log="$tmpdir/$crate.stderr.log"

        if run_clippy_for_crate "$ws_root" "$crate" "$out_json" "$err_log"; then
            rc=0
        else
            rc=$?
        fi

        warnings="$(count_json_warnings "$out_json")"
        baseline="null"
        status="pass"

        if [[ "$mode" != "snapshot" ]]; then
            baseline="$(jq -r --arg crate "$crate" '.crates[$crate].warnings // empty' "$baseline_file")"
            if [[ -z "$baseline" ]]; then
                baseline="null"
                status="missing_baseline"
            elif [[ "$warnings" -gt "$baseline" ]]; then
                status="new_warnings"
            fi
        else
            baseline="$warnings"
        fi

        if [[ "$rc" -ne 0 ]]; then
            if [[ "$mode" != "snapshot" ]]; then
                local baseline_exit
                baseline_exit="$(jq -r --arg crate "$crate" '.crates[$crate].exit_code // 0' "$baseline_file")"
                if [[ "$baseline_exit" -eq 0 ]]; then
                    status="clippy_failed"
                fi
                # If baseline also had exit_code > 0, keep the warning-based status
            else
                status="clippy_failed"
            fi
        fi

        stderr_excerpt="$(tail -n "${CLIPPY_BASELINE_ERROR_LINES:-80}" "$err_log" 2>/dev/null || true)"
        diagnostic_excerpt="$(diagnostic_json_excerpt "$out_json")"
        result_object "$crate" "$status" "$warnings" "$baseline" "$rc" "$stderr_excerpt" "$diagnostic_excerpt" > "$result_dir/$crate.json"

        if [[ "$status" != "pass" ]]; then
            failures=$((failures + 1))
            echo "clippy-baseline: $crate status=$status warnings=$warnings baseline=$baseline"
        fi
    done < "$selected_file"

    json_output="${json_output:-clippy-baseline-summary.json}"
    write_summary "$mode" "$base_ref" "$json_output" "$result_dir" "$selected_file" "$ws_root"

    if [[ "$failures" -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
