#!/usr/bin/env bash
set -euo pipefail

write_normalized_validation_output_text_file() {
  local path="$1"
  local output="$2"
  awk '
    {
      sub(/[[:space:]]+$/, "")
      lines[++line_count] = $0
    }
    END {
      while (line_count > 0 && lines[line_count] == "") {
        line_count--
      }
      for (i = 1; i <= line_count; i++) {
        print lines[i]
      }
    }
  ' "$path" > "$output"
}

normalize_validation_output_text_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf 'validation output text file not found: %s\n' "$path" >&2
    return 1
  fi

  local tmp
  tmp="$(mktemp "${path}.normalize.XXXXXX")"
  write_normalized_validation_output_text_file "$path" "$tmp"
  mv "$tmp" "$path"
}

check_validation_output_text_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf 'validation output text file not found: %s\n' "$path" >&2
    return 1
  fi

  local tmp
  tmp="$(mktemp "${path}.check.XXXXXX")"
  write_normalized_validation_output_text_file "$path" "$tmp"
  if cmp -s "$path" "$tmp"; then
    rm -f "$tmp"
    return 0
  fi

  printf 'validation output text file needs normalization: %s\n' "$path" >&2
  if command -v diff >/dev/null 2>&1; then
    diff -u --label "$path (current)" --label "$path (normalized)" "$path" "$tmp" >&2 || true
  fi
  rm -f "$tmp"
  return 1
}

run_self_test() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/tidefs-output-normalize.XXXXXX")"
  local status=0
  (
    set -euo pipefail
    local sample="$tmp//root/ai/tmp/tidefs-validation/normalizer-selftest/sample.log"
    local expected="$tmp/expected.log"
    mkdir -p "$(dirname "$sample")"

    printf 'alpha   \n\n beta\t\n\n\n' > "$sample"
    printf 'alpha\n\n beta\n' > "$expected"
    normalize_validation_output_text_file "$sample"
    if ! cmp -s "$expected" "$sample"; then
      printf 'normalizer self-test content mismatch\n' >&2
      diff -u "$expected" "$sample" >&2 || true
      exit 1
    fi
    check_validation_output_text_file "$sample"

    local dirty="$tmp//root/ai/tmp/tidefs-validation/normalizer-selftest/dirty.log"
    local dirty_before="$tmp/dirty-before.log"
    printf 'gamma   \n\n\n' > "$dirty"
    cp "$dirty" "$dirty_before"
    if check_validation_output_text_file "$dirty" 2>"$tmp/check.err"; then
      printf 'normalizer self-test expected check mode rejection\n' >&2
      exit 1
    fi
    if ! grep -q 'needs normalization' "$tmp/check.err"; then
      printf 'normalizer self-test check mode did not explain rejection\n' >&2
      cat "$tmp/check.err" >&2
      exit 1
    fi
    if ! cmp -s "$dirty_before" "$dirty"; then
      printf 'normalizer self-test check mode modified input\n' >&2
      exit 1
    fi
  ) || status=$?
  rm -rf "$tmp"
  if [[ "$status" -eq 0 ]]; then
    printf 'validation output normalizer self-test ok\n'
  fi
  return "$status"
}

usage() {
  printf 'usage: %s [--self-test] [--check] FILE...\n' "$0" >&2
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  check_only=0
  paths=()
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --self-test)
        run_self_test
        exit $?
        ;;
      --check)
        check_only=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        while [[ "$#" -gt 0 ]]; do
          paths+=("$1")
          shift
        done
        ;;
      -*)
        printf 'unknown option: %s\n' "$1" >&2
        usage
        exit 2
        ;;
      *)
        paths+=("$1")
        shift
        ;;
    esac
  done

  if [[ "${#paths[@]}" -eq 0 ]]; then
    usage
    exit 2
  fi

  for path in "${paths[@]}"; do
    if [[ "$check_only" -eq 1 ]]; then
      check_validation_output_text_file "$path"
    else
      normalize_validation_output_text_file "$path"
    fi
  done
fi
