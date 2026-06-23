# Focused Rust Input Contract

This document defines the accepted workflow-dispatch input contract for the
`Focused Rust` GitHub Actions workflow (`.github/workflows/focused-rust.yml`).
The contract is enforced before test execution; invalid inputs are rejected
with a clear error message in the job summary.

## `crates` input

- Required, non-empty, comma-separated list of workspace crate names.
- Each entry is trimmed of surrounding whitespace before validation.
- Entries must be valid workspace member names as resolved by
  `cargo metadata --no-deps`.
- Rejected patterns:
  * Empty string or whitespace-only entry.
  * Control characters (U+0000-U+001F, U+007F).
  * Shell metacharacters: `` ; | & $ ` ( ) { } < > ``.
  * Path-like entries containing `/`, `\`, or `.rs`.
  * Duplicate names after case-sensitive normalization.
- Accepted example: `tidefs-xtask,tidefs-transport,tidefs-btree`
- Rejected example: `tidefs-xtask; rm -rf /` (shell injection attempt)
- Rejected example: `tidefs-xtask,tidefs-xtask` (duplicate)
- Rejected example: `tidefs-xtask,./crates/tidefs-btree` (path-like)

## `cargo_test_args` input

- Optional. When empty, no extra flags are passed to `cargo test`.
- Must be bounded to safe `cargo test` filter and flag arguments.
- Rejected patterns:
  * Control characters (U+0000-U+001F, U+007F).
  * Shell metacharacters: `` ; | & $ ` ( ) { } < > ``.
  * Path traversal sequences (`../`).
- Accepted example: `--test my_test -- --nocapture`
- Rejected example: `--locked; echo pwned` (shell injection attempt)

## Job summary

- The job `$GITHUB_STEP_SUMMARY` records the normalized crate list and any
  rejected-input reason before test execution.
- Rejected-input messages identify the offending input field and the
  rejection reason without printing untrusted text inline.
- Successful validation emits a notice with the count and names of
  validated crates.

## Non-goals (this slice)

- This contract does not change which tests `scripts/ci-test-runner.sh` runs
  for valid crate selections.
- It does not add clippy, rustfmt, or claims-gate enforcement.
- It does not touch `Cargo.lock`, runtime crates, validation claims, FUSE,
  kernel, storage paths, or release-candidate workflow logic.
