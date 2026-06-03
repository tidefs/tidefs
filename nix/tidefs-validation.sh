#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/nix/tidefs-output-normalize.sh"

run_id="${TIDEFS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-nix-validation}"
run_dir="${TIDEFS_RUN_DIR:-/root/ai/tmp/tidefs-validation/$run_id}"

env_step_timeout="${TIDEFS_STEP_TIMEOUT:-600s}"
repo_commit="unknown"
repo_branch="unknown"
repo_dirty="unknown"
if command -v git >/dev/null 2>&1 && git rev-parse --show-toplevel >/dev/null 2>&1; then
  repo_commit="$(git rev-parse HEAD)"
  repo_branch="$(git branch --show-current 2>/dev/null || git rev-parse --abbrev-ref HEAD)"
  if git diff --quiet --ignore-submodules -- \
    && git diff --cached --quiet --ignore-submodules -- \
    && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    repo_dirty="no"
  else
    repo_dirty="yes"
  fi
fi

mkdir -p "$run_dir"

summary="$run_dir/SUMMARY.md"
environment="$run_dir/environment.env"
: > "$summary"

write_env_kv() {
  local key="$1"
  local value="$2"
  printf '%s=%q\n' "$key" "$value" >> "$environment"
}

{
  printf '# Curated TideFS validation environment\n'
  printf '# This file intentionally records run-relevant metadata, not a full env dump.\n'
} > "$environment"
write_env_kv run_id "$run_id"
write_env_kv utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_env_kv repository "$repo_root"
write_env_kv repo_commit "$repo_commit"
write_env_kv repo_branch "$repo_branch"
write_env_kv repo_dirty "$repo_dirty"
write_env_kv validation_root "/root/ai/tmp/tidefs-validation"
write_env_kv run_dir "$run_dir"
write_env_kv validation_runner "nix/tidefs-validation.sh"
write_env_kv command_environment_policy "curated_no_secret_dump"
write_env_kv kernel "$(uname -srvmo)"
write_env_kv rustc "$(rustc --version 2>/dev/null || printf unavailable)"
write_env_kv cargo "$(cargo --version 2>/dev/null || printf unavailable)"
write_env_kv in_nix_shell "${IN_NIX_SHELL:-}"
write_env_kv nix_build_top "${NIX_BUILD_TOP:-}"

printf '# TideFS validation run\n\n' >> "$summary"
printf -- '- run id: `%s`\n' "$run_id" >> "$summary"
printf -- '- repository: `%s`\n' "$repo_root" >> "$summary"
printf -- '- repo commit: `%s`\n' "$repo_commit" >> "$summary"
printf -- '- repo dirty at start: `%s`\n' "$repo_dirty" >> "$summary"
printf -- '- environment: `%s`\n' "$environment" >> "$summary"
printf -- '- rustc: `%s`\n' "$(rustc --version 2>/dev/null || printf unavailable)" >> "$summary"
printf -- '- cargo: `%s`\n\n' "$(cargo --version 2>/dev/null || printf unavailable)" >> "$summary"

failed=0
step=0

step_pid=""

cleanup_interrupt() {
  if [[ -n "${step_pid:-}" ]] && kill -0 "$step_pid" 2>/dev/null; then
    printf '\n[validation] interrupt received; stopping current step (pid %s)\n' "$step_pid" >&2
    kill -TERM "$step_pid" 2>/dev/null || true
    wait "$step_pid" 2>/dev/null || true
  fi
  exit 130
}
trap cleanup_interrupt INT TERM

run_step() {
  step=$((step + 1))
  local name="$1"
  shift
  local log="$run_dir/$(printf '%02d' "$step")-$name.log"

  printf '==> %s\n' "$name"
  printf '## %s\n\n' "$name" >> "$summary"
  printf '```sh\n' >> "$summary"
  local command_line=""
  local arg quoted_arg
  for arg in "$@"; do
    printf -v quoted_arg '%q' "$arg"
    if [[ -n "$command_line" ]]; then
      command_line+=" "
    fi
    command_line+="$quoted_arg"
  done
  printf '%s\n```\n\n' "$command_line" >> "$summary"

  set +e
  timeout "$env_step_timeout" "$@" 2>&1 | tee "$log"
  local status=${PIPESTATUS[0]}
  set -e
  normalize_validation_output_text_file "$log"

  printf -- '- status: `%s`\n' "$status" >> "$summary"
  printf -- '- log: `%s`\n\n' "$log" >> "$summary"
  if [[ "$status" -ne 0 ]]; then
    failed=1
  fi
}

run_step cargo-fmt cargo fmt --check
run_step cargo-clippy cargo clippy --workspace --all-targets
run_step cargo-test cargo test --workspace --all-targets
run_step cargo-deny-licenses cargo deny check licenses
run_step store-demo cargo run -p tidefs-store-demo
run_step filesystem-demo cargo run -p tidefs-filesystem-demo
run_step block-volume-host-preflight cargo run -p tidefs-block-volume-adapter-daemon -- preflight-host
run_step block-volume-ublk-control-open cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-open
run_step block-volume-ublk-control-readonly-probe cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-readonly-probe
run_step block-volume-ublk-add-dev-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-add-dev
run_step block-volume-ublk-del-dev-cleanup-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-add-del-dev
run_step block-volume-ublk-set-params-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-set-params
run_step block-volume-ublk-start-dev-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-start-dev
run_step block-volume-ublk-fetch-req-readiness-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-fetch-req
run_step block-volume-ublk-data-queue-open-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-open
run_step block-volume-ublk-fetch-req-submit-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-fetch-req-submit
run_step block-volume-ublk-commit-fetch-boundary cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-commit-and-fetch
if [[ "$failed" -ne 0 ]]; then
  printf '\nvalidation result: failed\n' >> "$summary"
  normalize_validation_output_text_file "$summary"
  normalize_validation_output_text_file "$environment"
  printf 'validation result: failed\n'
  exit 1
fi

printf '\nvalidation result: passed\n' >> "$summary"
normalize_validation_output_text_file "$summary"
normalize_validation_output_text_file "$environment"
printf 'validation result: passed\n'
