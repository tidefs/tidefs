# TideFS development targets
# Run `just --list` to see available targets.

# ---- workspace test runner ---------------------------------------------

# Run workspace-wide tests with JSON summary.
# Set CRATES to a comma-separated list to test only specific crates.
# Set EXCLUDE to a comma-separated list to skip specific crates.
# Example: CRATES=tidefs-auth,tidefs-btree just test-ci
# Example: EXCLUDE=tidefs-demo just test-ci
test-ci:
    @./scripts/ci-test-runner.sh \
        ${CRATES:+"--crates" "$CRATES"} \
        ${EXCLUDE:+"--exclude" "$EXCLUDE"} \
        --json ci-test-summary.json
    @echo
    @echo "Summary:"
    @jq -r '.[] | "  \(.crate): \(.status) (\(.tests.passed) passed, \(.tests.failed) failed, \(.duration_ms)ms)"' ci-test-summary.json

# Run workspace tests and write JSON summary to a custom path.
# Example: just test-ci-json /tmp/summary.json
test-ci-json PATH:
    @./scripts/ci-test-runner.sh --json {{ PATH }}

# Run workspace tests interactively (no JSON output, human-readable).
test-ci-interactive:
    @./scripts/ci-test-runner.sh

# ---- cargo helpers -----------------------------------------------------

# Check the entire workspace compiles.
check-workspace:
    cargo check --workspace

# Check the entire workspace compiles with --locked (requires current Cargo.lock).
# Use this for CI and pre-commit verification. If it fails, run:
#   cargo generate-lockfile   (minimal update) or   cargo update   (full refresh)
check-locked: check-cargo-lock-script
    cargo check --locked --workspace

# Check a single crate. Pass CRATE=name.
check CRATE:
    cargo check -p {{ CRATE }}

# Test a single crate. Pass CRATE=name.
test CRATE:
    cargo test -p {{ CRATE }}

# Format the entire workspace.
fmt:
    cargo fmt --all

# Run clippy across the workspace with warnings as errors.
clippy:
    cargo clippy --workspace -- -D warnings

# Run clippy on a single crate. Pass CRATE=name.
clippy-check CRATE:
    cargo clippy -p {{ CRATE }} -- -D warnings

# ---- full CI pipeline --------------------------------------------------

# Run the full CI pipeline: fmt, clippy, check, test.
ci: fmt clippy check-locked test-ci

# Run a fast CI check: fmt + clippy + check (no tests).
ci-fast: fmt clippy check-locked

# ---- lockfile guards ---------------------------------------------------

# Verify Cargo.lock is not older than workspace Cargo.toml manifests.
check-cargo-lock-script:
    @./scripts/check-cargo-lock.sh
