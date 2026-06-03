#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: nix/tidefs-posix-scoreboard.sh [--run-id <id>] [--out <dir>]

Runs the live TideFS POSIX scoreboard and writes validation under the selected
output directory.

xfstests modes:
  TIDEFS_SCOREBOARD_XFSTESTS_CMD=<cmd>
      Pass an explicit command to the scoreboard. The command runs with
      TIDEFS_SCOREBOARD_MOUNT set to the live TideFS mount path.

  TIDEFS_XFSTESTS_DIR=<prepared-checkout>
      Generate an xfstests command from a prepared checkout. Optional knobs:
        TIDEFS_XFSTESTS_TESTS       tests to run, default: generic/001
        TIDEFS_XFSTESTS_EXCLUDE     path to exclude file (-E), default: unset
        TIDEFS_XFSTESTS_CHECK_ARGS  extra ./check arguments
        TIDEFS_XFSTESTS_FSTYP       FSTYP value, default: fuse
        TIDEFS_XFSTESTS_TEST_DEV    TEST_DEV value, default: live mount path
        TIDEFS_XFSTESTS_TEST_DIR    TEST_DIR value, default: <mount>/xfstests-test
        TIDEFS_XFSTESTS_SCRATCH_DEV SCRATCH_DEV value, default: live mount path
        TIDEFS_XFSTESTS_SCRATCH_MNT SCRATCH_MNT value, default: <mount>/xfstests-scratch

  TIDEFS_XFSTESTS_NIX_PACKAGE=1
      Run the repo-packaged xfstests-check wrapper against the live TideFS
      scoreboard mount. Optional knobs:
        TIDEFS_XFSTESTS_TESTS       tests to run, default: generic/001
        TIDEFS_XFSTESTS_EXCLUDE     path to exclude file (-E), default: unset
        TIDEFS_XFSTESTS_CHECK_ARGS  extra xfstests-check arguments

If neither mode is configured, the xfstests lane is recorded as an explicit
skip by the scoreboard. Skips are non-validation, not passes.

A canonical FUSE exclude list is maintained at
  scripts/tidefs-xfstests-exclude
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_id="${TIDEFS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-posix-scoreboard}"
scoreboard_dir="${TIDEFS_POSIX_SCOREBOARD_DIR:-/root/ai/tmp/tidefs-validation/$run_id/posix-scoreboard}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --run-id)
      if [ "$#" -lt 2 ]; then
        echo "--run-id requires a value" >&2
        exit 2
      fi
      run_id="$2"
      if [ -z "${TIDEFS_POSIX_SCOREBOARD_DIR:-}" ]; then
        scoreboard_dir="/root/ai/tmp/tidefs-validation/$run_id/posix-scoreboard"
      fi
      shift 2
      ;;
    --out)
      if [ "$#" -lt 2 ]; then
        echo "--out requires a value" >&2
        exit 2
      fi
      scoreboard_dir="$2"
      shift 2
      ;;
    *)
      echo "unknown tidefs-posix-scoreboard argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$scoreboard_dir"
scoreboard_dir="$(cd "$scoreboard_dir" && pwd -P)"

repo_commit="unknown"
if command -v git >/dev/null 2>&1 && git rev-parse --show-toplevel >/dev/null 2>&1; then
  repo_commit="$(git rev-parse HEAD)"
fi

configured_xfstests_modes=0
for value in "${TIDEFS_SCOREBOARD_XFSTESTS_CMD:-}" "${TIDEFS_XFSTESTS_DIR:-}" "${TIDEFS_XFSTESTS_NIX_PACKAGE:-}"; do
  if [ -n "$value" ]; then
    configured_xfstests_modes=$((configured_xfstests_modes + 1))
  fi
done

xfstests_mode="unconfigured"
if [ "$configured_xfstests_modes" -gt 1 ]; then
  echo "set only one xfstests mode: TIDEFS_SCOREBOARD_XFSTESTS_CMD, TIDEFS_XFSTESTS_DIR, or TIDEFS_XFSTESTS_NIX_PACKAGE" >&2
  exit 2
elif [ -n "${TIDEFS_SCOREBOARD_XFSTESTS_CMD:-}" ]; then
  xfstests_mode="explicit-command"
elif [ -n "${TIDEFS_XFSTESTS_NIX_PACKAGE:-}" ]; then
  if ! command -v xfstests-check >/dev/null 2>&1; then
    echo "TIDEFS_XFSTESTS_NIX_PACKAGE requires xfstests-check on PATH" >&2
    exit 2
  fi

  xfstests_mode="nix-package-live-mount"

  # Install mount.fuse helper so xfstests can mount tidefs via mount -t fuse.
  # xfstests calls mount -t fuse $TEST_DEV ... which looks for mount.fuse on PATH.
  mount_helper_dir="$scoreboard_dir/mount-helper"
  mkdir -p "$mount_helper_dir"
  ln -sf "$repo_root/scripts/tidefs-xfstests-mount" "$mount_helper_dir/mount.fuse"
  ln -sf "$repo_root/scripts/tidefs-xfstests-mount" "$mount_helper_dir/tidefs-preview"
  ln -sf "$repo_root/scripts/tidefs-mount-wrapper" "$mount_helper_dir/mount"
  ln -sf "$repo_root/scripts/tidefs-xfstests-check-wrapper" "$mount_helper_dir/tidefs-xfstests-check-wrapper"
  # Also make the wrapper findable as xfstests-check so the daemon's
  # from_scoreboard_env picks it up via which("xfstests-check").
  ln -sf "$repo_root/scripts/tidefs-xfstests-check-wrapper" "$mount_helper_dir/xfstests-check"
  export TIDEFS_XFSTESTS_MOUNT_HELPER_DIR="$mount_helper_dir"
  export TIDEFS_XFSTESTS_RESULTS_DIR="$scoreboard_dir/xfstests-results"
  export TIDEFS_XFSTESTS_TESTS="${TIDEFS_XFSTESTS_TESTS:-generic/001}"
  export TIDEFS_XFSTESTS_CHECK_ARGS="${TIDEFS_XFSTESTS_CHECK_ARGS:--fuse}"
  export TIDEFS_SCOREBOARD_XFSTESTS_PLAIN_FUSE=1
  export TIDEFS_XFSTESTS_EXCLUDE="${TIDEFS_XFSTESTS_EXCLUDE:-}"

  cat > "$scoreboard_dir/run-xfstests.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

mount="${TIDEFS_SCOREBOARD_MOUNT:?TIDEFS_SCOREBOARD_MOUNT is required}"
results="${TIDEFS_XFSTESTS_RESULTS_DIR:?TIDEFS_XFSTESTS_RESULTS_DIR is required}"
xfstests_work="$results/work"
mkdir -p "$results" "$xfstests_work"

# Prepend mount helper dir to PATH so mount -t fuse finds mount.fuse
if [ -n "${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR:-}" ] && [ -x "${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR}/mount.fuse" ]; then
  export PATH="${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR}:$PATH"
fi

export RESULT_BASE="$results"
export FSTYP="fuse"
export TEST_DEV="tidefs-preview"
export TEST_DIR="$mount"
if [ -n "${TIDEFS_XFSTESTS_SCRATCH_DEV:-}" ]; then
  export SCRATCH_DEV="$TIDEFS_XFSTESTS_SCRATCH_DEV"
fi
if [ -n "${TIDEFS_XFSTESTS_SCRATCH_MNT:-}" ]; then
  export SCRATCH_MNT="$TIDEFS_XFSTESTS_SCRATCH_MNT"
fi

{
  printf 'xfstests_check=%s\n' "$(command -v xfstests-check)"
  printf 'result_base=%s\n' "$RESULT_BASE"
  printf 'xfstests_work=%s\n' "$xfstests_work"
  printf 'fstyp=%s\n' "$FSTYP"
  printf 'test_dev=%s\n' "$TEST_DEV"
  printf 'test_dir=%s\n' "$TEST_DIR"
  printf 'scratch_dev=%s\n' "${SCRATCH_DEV:-}"
  printf 'scratch_mnt=%s\n' "${SCRATCH_MNT:-}"
  printf 'check_args=%s\n' "${TIDEFS_XFSTESTS_CHECK_ARGS:-}"
  printf 'tests=%s\n' "$TIDEFS_XFSTESTS_TESTS"
  printf 'exclude=%s\n' "${TIDEFS_XFSTESTS_EXCLUDE:-}"
} > "$results/tidefs-xfstests-env.txt"

check_args=()
if [ -n "${TIDEFS_XFSTESTS_CHECK_ARGS:-}" ]; then
  read -r -a check_args <<< "$TIDEFS_XFSTESTS_CHECK_ARGS"
fi

tests=()

if [ -n "${TIDEFS_XFSTESTS_EXCLUDE:-}" ] && [ -f "${TIDEFS_XFSTESTS_EXCLUDE}" ]; then
	check_args+=("-E" "${TIDEFS_XFSTESTS_EXCLUDE}")
fi

read -r -a tests <<< "$TIDEFS_XFSTESTS_TESTS"

cd "$xfstests_work"
exec xfstests-check "${check_args[@]}" "${tests[@]}"
EOF
  chmod +x "$scoreboard_dir/run-xfstests.sh"
  export TIDEFS_SCOREBOARD_XFSTESTS_CMD="$scoreboard_dir/run-xfstests.sh"
elif [ -n "${TIDEFS_XFSTESTS_DIR:-}" ]; then
  xfstests_mode="prepared-checkout"

  # Install mount.fuse helper so xfstests can mount tidefs via mount -t fuse.
  mount_helper_dir="$scoreboard_dir/mount-helper"
  mkdir -p "$mount_helper_dir"
  ln -sf "$repo_root/scripts/tidefs-xfstests-mount" "$mount_helper_dir/mount.fuse"
  ln -sf "$repo_root/scripts/tidefs-xfstests-mount" "$mount_helper_dir/tidefs-preview"
  ln -sf "$repo_root/scripts/tidefs-mount-wrapper" "$mount_helper_dir/mount"
  ln -sf "$repo_root/scripts/tidefs-xfstests-check-wrapper" "$mount_helper_dir/tidefs-xfstests-check-wrapper"
  # Also make the wrapper findable as xfstests-check so the daemon's
  # from_scoreboard_env picks it up via which("xfstests-check").
  ln -sf "$repo_root/scripts/tidefs-xfstests-check-wrapper" "$mount_helper_dir/xfstests-check"
  export TIDEFS_XFSTESTS_MOUNT_HELPER_DIR="$mount_helper_dir"

  xfstests_dir="$(cd "$TIDEFS_XFSTESTS_DIR" && pwd -P)"
  if [ -x "$xfstests_dir/check" ]; then
    xfstests_check="$xfstests_dir/check"
  elif [ -x "$xfstests_dir/bin/check" ]; then
    xfstests_check="$xfstests_dir/bin/check"
  else
    echo "TIDEFS_XFSTESTS_DIR must contain an executable check or bin/check: $TIDEFS_XFSTESTS_DIR" >&2
    exit 2
  fi

  export TIDEFS_XFSTESTS_DIR="$xfstests_dir"
  export TIDEFS_XFSTESTS_CHECK="$xfstests_check"
  export TIDEFS_XFSTESTS_RESULTS_DIR="$scoreboard_dir/xfstests-results"
  export TIDEFS_XFSTESTS_TESTS="${TIDEFS_XFSTESTS_TESTS:-generic/001}"
  export TIDEFS_XFSTESTS_CHECK_ARGS="${TIDEFS_XFSTESTS_CHECK_ARGS:-}"
  export TIDEFS_XFSTESTS_FSTYP="${TIDEFS_XFSTESTS_FSTYP:-fuse}"
  export TIDEFS_XFSTESTS_EXCLUDE="${TIDEFS_XFSTESTS_EXCLUDE:-}"

  cat > "$scoreboard_dir/run-xfstests.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

mount="${TIDEFS_SCOREBOARD_MOUNT:?TIDEFS_SCOREBOARD_MOUNT is required}"
results="${TIDEFS_XFSTESTS_RESULTS_DIR:?TIDEFS_XFSTESTS_RESULTS_DIR is required}"
mkdir -p "$results" "$mount/xfstests-test" "$mount/xfstests-scratch"

# Prepend mount helper dir to PATH so mount -t fuse finds mount.fuse
if [ -n "${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR:-}" ] && [ -x "${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR}/mount.fuse" ]; then
  export PATH="${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR}:$PATH"
fi

export RESULT_BASE="$results"
export FSTYP="${TIDEFS_XFSTESTS_FSTYP:-fuse}"
export TEST_DEV="${TIDEFS_XFSTESTS_TEST_DEV:-$mount}"
export TEST_DIR="${TIDEFS_XFSTESTS_TEST_DIR:-$mount/xfstests-test}"
export SCRATCH_DEV="${TIDEFS_XFSTESTS_SCRATCH_DEV:-$mount}"
export SCRATCH_MNT="${TIDEFS_XFSTESTS_SCRATCH_MNT:-$mount/xfstests-scratch}"

{
  printf 'xfstests_dir=%s\n' "$TIDEFS_XFSTESTS_DIR"
  printf 'xfstests_check=%s\n' "$TIDEFS_XFSTESTS_CHECK"
  printf 'result_base=%s\n' "$RESULT_BASE"
  printf 'fstyp=%s\n' "$FSTYP"
  printf 'test_dev=%s\n' "$TEST_DEV"
  printf 'test_dir=%s\n' "$TEST_DIR"
  printf 'scratch_dev=%s\n' "$SCRATCH_DEV"
  printf 'scratch_mnt=%s\n' "$SCRATCH_MNT"
  printf 'check_args=%s\n' "${TIDEFS_XFSTESTS_CHECK_ARGS:-}"
  printf 'tests=%s\n' "$TIDEFS_XFSTESTS_TESTS"
  printf 'exclude=%s\n' "${TIDEFS_XFSTESTS_EXCLUDE:-}"
} > "$results/tidefs-xfstests-env.txt"

check_args=()
if [ -n "${TIDEFS_XFSTESTS_CHECK_ARGS:-}" ]; then
  read -r -a check_args <<< "$TIDEFS_XFSTESTS_CHECK_ARGS"
fi

tests=()

if [ -n "${TIDEFS_XFSTESTS_EXCLUDE:-}" ] && [ -f "${TIDEFS_XFSTESTS_EXCLUDE}" ]; then
	check_args+=("-E" "${TIDEFS_XFSTESTS_EXCLUDE}")
fi

read -r -a tests <<< "$TIDEFS_XFSTESTS_TESTS"

cd "$TIDEFS_XFSTESTS_DIR"
exec "$TIDEFS_XFSTESTS_CHECK" "${check_args[@]}" "${tests[@]}"
EOF
  chmod +x "$scoreboard_dir/run-xfstests.sh"
  export TIDEFS_SCOREBOARD_XFSTESTS_CMD="$scoreboard_dir/run-xfstests.sh"
fi

{
  printf 'run_id=%s\n' "$run_id"
  printf 'utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'repo_root=%s\n' "$repo_root"
  printf 'repo_commit=%s\n' "$repo_commit"
  printf 'scoreboard_dir=%s\n' "$scoreboard_dir"
  printf 'xfstests_mode=%s\n' "$xfstests_mode"
  printf 'xfstests_command=%s\n' "${TIDEFS_SCOREBOARD_XFSTESTS_CMD:-}"
  printf 'xfstests_dir=%s\n' "${TIDEFS_XFSTESTS_DIR:-}"
  printf 'xfstests_tests=%s\n' "${TIDEFS_XFSTESTS_TESTS:-}"
  printf 'xfstests_check_args=%s\n' "${TIDEFS_XFSTESTS_CHECK_ARGS:-}"
  printf 'xfstests_exclude=%s\n' "${TIDEFS_XFSTESTS_EXCLUDE:-}"
  printf 'xfstests_per_test=%s
' "${TIDEFS_SCOREBOARD_PER_TEST:-}"
  printf 'kernel=%s\n' "$(uname -srvmo)"
} > "$scoreboard_dir/harness-env.txt"

  # Put mount helper dir on PATH so the daemon finds our xfstests-check wrapper.
  if [ -n "${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR:-}" ]; then
    export PATH="${TIDEFS_XFSTESTS_MOUNT_HELPER_DIR}:$PATH"
  fi
tidefs-posix-filesystem-adapter-daemon score-posix --out "$scoreboard_dir"

printf 'posix_scoreboard.summary=%s\n' "$scoreboard_dir/scoreboard.md"
