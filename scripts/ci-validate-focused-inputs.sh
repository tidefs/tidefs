#!/usr/bin/env bash
# ci-validate-focused-inputs.sh — validate Focused Rust workflow-dispatch inputs
#
# Called by .github/workflows/focused-rust.yml before test execution.
# Reads FOCUSED_CRATES and CARGO_TEST_ARGS from the environment.
# Exits 0 when inputs are valid; exits 1 with an ::error annotation on rejection.

set -euo pipefail

check_forbidden() {
    local value="$1" field="$2" pattern="$3" reason="$4"
    if printf '%s' "$value" | grep -Eq "$pattern"; then
        echo "::error title=Input validation failed::${field}: rejected: ${reason}"
        return 1
    fi
}

crates="${FOCUSED_CRATES:-}"
cargo_test_args="${CARGO_TEST_ARGS:-}"

# -- Empty check ----------------------------------------------------
if [[ -z "${crates//[[:space:]]/}" ]]; then
    echo "::error title=Input validation failed::crates: rejected: empty crate list"
    exit 1
fi

# -- Shell-safety: reject control chars and metacharacters ----------
check_forbidden "$crates" crates '[[:cntrl:]]' \
    'contains control characters' || exit 1
check_forbidden "$crates" crates '[;&|$`(){}<>]' \
    'contains shell metacharacters' || exit 1

# -- Parse, trim, and normalize entries -----------------------------
IFS=',' read -ra raw_entries <<< "$crates"
declare -A seen
normalized=()

for entry in "${raw_entries[@]}"; do
    name="$(printf '%s' "$entry" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -z "$name" ]]; then
        echo "::error title=Input validation failed::crates: rejected: empty entry after trimming"
        exit 1
    fi
    # Path-like entries
    if [[ "$name" =~ [/\\] ]] || [[ "$name" =~ \.rs$ ]]; then
        echo "::error title=Input validation failed::crates: rejected: path-like entry '${name}'"
        exit 1
    fi
    # Duplicate detection
    if [[ -n "${seen[$name]:-}" ]]; then
        echo "::error title=Input validation failed::crates: rejected: duplicate crate name '${name}'"
        exit 1
    fi
    seen[$name]=1
    normalized+=("$name")
done

if [[ "${#normalized[@]}" -eq 0 ]]; then
    echo "::error title=Input validation failed::crates: rejected: no valid crate entries"
    exit 1
fi

# -- Verify every entry is a workspace member -----------------------
ws_crates="$(cargo metadata --format-version=1 --no-deps 2>/dev/null | jq -r '.packages[].name')"
for name in "${normalized[@]}"; do
    if ! printf '%s\n' "$ws_crates" | grep -qxF "$name"; then
        echo "::error title=Input validation failed::crates: rejected: unknown crate '${name}'"
        exit 1
    fi
done

# -- Validate cargo_test_args (optional) ----------------------------
if [[ -n "$cargo_test_args" ]]; then
    check_forbidden "$cargo_test_args" cargo_test_args '[[:cntrl:]]' \
        'contains control characters' || exit 1
    check_forbidden "$cargo_test_args" cargo_test_args '[;&|$`(){}<>]' \
        'contains shell metacharacters' || exit 1
    check_forbidden "$cargo_test_args" cargo_test_args '\.\./' \
        'contains path traversal' || exit 1
fi

# -- Record normalized selection in step summary --------------------
{
    echo '## Validated Inputs'
    echo ''
    echo '**Crates ('"${#normalized[@]}"'):** '"${normalized[*]}"
    if [[ -n "$cargo_test_args" ]]; then
        echo '**Extra cargo test args:** `'"${cargo_test_args}"'`'
    else
        echo '**Extra cargo test args:** (none)'
    fi
    echo ''
} >> "$GITHUB_STEP_SUMMARY"

echo "::notice::Validated ${#normalized[@]} crate(s): ${normalized[*]}"
