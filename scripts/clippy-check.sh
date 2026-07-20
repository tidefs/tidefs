#!/usr/bin/env bash
# Run Clippy directly for changed workspace crates or the whole workspace.

set -euo pipefail

clippy_check_temporary_dir=""

cleanup_temporary_dir() {
    local directory="$clippy_check_temporary_dir"

    if [[ -n "$directory" && -d "$directory" ]]; then
        rm -rf -- "$directory"
    fi
}

die() {
    echo "clippy-check: $*" >&2
    exit 2
}

usage() {
    printf '%s\n' \
        'Usage:' \
        '  scripts/clippy-check.sh check-changed [--base <ref>]' \
        '  scripts/clippy-check.sh check-workspace' \
        '  scripts/clippy-check.sh list-changed [--base <ref>]'
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

find_workspace_root() {
    local dir
    dir="$(realpath "${1:-$PWD}")"

    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/Cargo.toml" ]] && grep -q '^\[workspace\]' "$dir/Cargo.toml"; then
            printf '%s\n' "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done

    return 1
}

load_workspace_packages() {
    local workspace_root="$1" metadata_file="$2"

    cargo metadata \
        --manifest-path "$workspace_root/Cargo.toml" \
        --locked \
        --format-version=1 \
        --no-deps > "$metadata_file"

    jq -e '.workspace_members | type == "array"' "$metadata_file" >/dev/null ||
        die "cargo metadata did not return workspace members"
}

workspace_package_rows() {
    local workspace_root="$1" metadata_file="$2"

    jq -r '
        .workspace_members[] as $member
        | .packages[]
        | select(.id == $member)
        | [.name, .manifest_path]
        | @tsv
    ' "$metadata_file" |
        while IFS=$'\t' read -r crate manifest; do
            local crate_dir relative_dir
            crate_dir="$(dirname "$manifest")"
            relative_dir="$(realpath --relative-to="$workspace_root" "$crate_dir")"
            printf '%s\t%s\n' "$crate" "$relative_dir"
        done |
        sort -k1,1
}

all_workspace_crates() {
    local package_rows_file="$1"

    cut -f1 "$package_rows_file" | sort -u
}

changed_workspace_crates() {
    local workspace_root="$1" package_rows_file="$2" base_ref="$3"
    local changed_files_file="$4" merge_base
    local changed_file crate relative_dir row
    local -a changed_files package_rows
    declare -A selected=()

    [[ "$base_ref" != -* ]] || die "base ref must not begin with '-'"
    merge_base="$(git -C "$workspace_root" merge-base "$base_ref" HEAD)" ||
        die "cannot find merge base for $base_ref and HEAD"
    git -C "$workspace_root" diff --no-renames --name-only -z "$merge_base" HEAD -- \
        > "$changed_files_file" || die "cannot diff from merge base $merge_base"
    mapfile -d '' -t changed_files < "$changed_files_file"

    if [[ "${#changed_files[@]}" -eq 0 ]]; then
        return 0
    fi

    for changed_file in "${changed_files[@]}"; do
        case "$changed_file" in
            .cargo/config.toml|Cargo.toml|Cargo.lock|rust-toolchain.toml)
                all_workspace_crates "$package_rows_file"
                return 0
                ;;
        esac
    done

    mapfile -t package_rows < "$package_rows_file"

    for changed_file in "${changed_files[@]}"; do
        for row in "${package_rows[@]}"; do
            IFS=$'\t' read -r crate relative_dir <<< "$row"
            if [[ "$changed_file" == "$relative_dir" ||
                  "$changed_file" == "$relative_dir/"* ]]; then
                selected["$crate"]=1
            fi
        done
    done

    if [[ "${#selected[@]}" -gt 0 ]]; then
        printf '%s\n' "${!selected[@]}" | sort
    fi
}

run_clippy() {
    local workspace_root="$1"
    shift
    local crate failures=0

    if [[ "$#" -eq 0 ]]; then
        echo "clippy-check: no changed workspace crates"
        return 0
    fi

    cd "$workspace_root"
    for crate in "$@"; do
        echo "clippy-check: running cargo clippy -p $crate --locked --all-targets"
        if ! cargo clippy -p "$crate" --locked --all-targets; then
            echo "clippy-check: failed: $crate" >&2
            failures=$((failures + 1))
        fi
    done

    if [[ "$failures" -ne 0 ]]; then
        echo "clippy-check: $failures crate(s) failed" >&2
        return 1
    fi

    echo "clippy-check: all $# selected crate(s) passed"
}

main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        return 0
    fi

    local mode="${1:-}" base_ref="origin/master"
    [[ -n "$mode" ]] || { usage >&2; exit 2; }
    shift

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --base)
                [[ "$mode" != "check-workspace" ]] ||
                    die "--base is not valid with check-workspace"
                base_ref="${2:-}"
                [[ -n "$base_ref" ]] || die "--base requires a ref"
                shift 2
                ;;
            -h|--help)
                usage
                return 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
    done

    case "$mode" in
        check-changed|check-workspace|list-changed)
            ;;
        *)
            die "unknown mode: $mode"
            ;;
    esac

    require_tool cargo
    require_tool git
    require_tool jq
    require_tool realpath

    local workspace_root metadata_file package_rows_file selected_file
    local -a crates
    workspace_root="$(find_workspace_root)" || die "could not find workspace root"
    clippy_check_temporary_dir="$(mktemp -d)"
    trap cleanup_temporary_dir EXIT
    metadata_file="$clippy_check_temporary_dir/metadata.json"
    package_rows_file="$clippy_check_temporary_dir/packages.tsv"
    selected_file="$clippy_check_temporary_dir/selected-crates"

    load_workspace_packages "$workspace_root" "$metadata_file"
    workspace_package_rows "$workspace_root" "$metadata_file" > "$package_rows_file"
    [[ -s "$package_rows_file" ]] || die "cargo metadata returned no workspace packages"

    case "$mode" in
        check-workspace)
            all_workspace_crates "$package_rows_file" > "$selected_file"
            ;;
        check-changed|list-changed)
            changed_workspace_crates \
                "$workspace_root" \
                "$package_rows_file" \
                "$base_ref" \
                "$clippy_check_temporary_dir/changed-files" > "$selected_file"
            ;;
    esac
    mapfile -t crates < "$selected_file"

    if [[ "$mode" == "list-changed" ]]; then
        if [[ "${#crates[@]}" -eq 0 ]]; then
            echo "clippy-check: no changed workspace crates" >&2
        else
            printf '%s\n' "${crates[@]}"
        fi
        return 0
    fi

    run_clippy "$workspace_root" "${crates[@]}"
}

main "$@"
