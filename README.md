# TideFS

TideFS is a Rust filesystem and storage stack aimed at OpenZFS/Ceph-class
reliability and scale. It is not there yet. The repo is a pre-alpha
implementation with serious architectural debt tracked in
`docs/REVIEW_TODO_REGISTER.md`.
TideFS does not currently fulfill the OpenZFS/Ceph-class narrative; that is
the target, not a present-tense capability claim.

This repository is the fresh TideFS tree on `master`; source paths, crates,
binaries, and docs should use TideFS names.

The primary remote is the public repository `tidefs/tidefs` on GitHub; the
operator approved making that main repository public on 2026-06-21. Public
visibility is a read boundary only, not a product release: outsider interaction
remains restricted by the documented public-read controls in `docs/GITHUB_CI.md`,
and TideFS infrastructure, runner credentials, deployment keys, API tokens, TLS
keys, and other secrets remain outside this repository. The companion
`tidefs/tidefs-infra-configuration` repository remains private.

## Current Policy

- License: `GPL-2.0-only WITH Linux-syscall-note`.
- Durable review debt belongs in `docs/REVIEW_TODO_REGISTER.md`; inline notes
  are only short pointers to register entries.
- Test changes must follow `docs/TEST_SIGNAL_POLICY.md`: prefer product and
  invariant signal over test-count growth, marker checks, and stale fixtures.
- Unreleased internal surfaces must follow
  `docs/UNRELEASED_AUTHORITY_POLICY.md`: choose current authority instead of
  preserving pre-release paths as legacy compatibility or migration debt.
- Mounted device-level compression and encryption are blocked behind
  `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`; lower object-store
  wrappers are not an end-to-end mounted filesystem claim.
- Publishing-facing capability wording must pass
  `cargo run -p tidefs-xtask -- check-claims-gate`.
- Commits should be clean, scoped, and bisectable in the same spirit as Linux
  kernel development.

## Layout

```text
apps/        runnable daemons, demos, and operator tools
crates/      storage core, adapters, kernel-facing crates, and shared types
docs/        design docs, review policy, and debt register
kmod/        Rust-for-Linux bridge substrate
xtask/       repo checks and developer commands
```

## Build

Keep Cargo output outside the repository:

```sh
export CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target
cargo check --workspace --locked
```

## Start Here

- `CONTRIBUTING.md`
- `docs/LICENSING.md`
- `docs/TEST_SIGNAL_POLICY.md`
- `docs/REVIEW_TODO_POLICY.md`
- `docs/REVIEW_TODO_REGISTER.md`
- `docs/INDEX.md`
