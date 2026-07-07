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

## Product Shape

The finished TideFS product shape is local-first storage with explicit local
and clustered modes for both mounted POSIX filesystem access and block-volume
export. Local modes are first-class single-node product modes, not temporary
cluster bring-up shortcuts.

A finished TideFS must make storage behavior durable and inspectable across
local pools/devices, mounted filesystem and block-export paths, crash recovery
to committed roots or explicit integrity/media failure, integrity checking,
scrub/rebuild/device lifecycle, snapshots and reclaim, capacity/reserve
accounting, page-cache/writeback/fsync/mmap durability, kernel-resident paths
where claimed, operator truth from current runtime state, and validation proof
packets tied to the claim registry.

That is the target shape, not current capability. Current status and blockers
belong in `docs/CLAIMS_GATE_POLICY.md`, generated `docs/CLAIM_REGISTRY.md`,
`docs/REVIEW_TODO_REGISTER.md`, and live GitHub issues and pull requests. Do
not maintain a separate requirements, roadmap, or status Markdown root for the
same product story.

## Current Policy

- License: `GPL-2.0-only WITH Linux-syscall-note`.
- Durable review debt belongs in `docs/REVIEW_TODO_REGISTER.md`; inline notes
  are only short pointers to register entries.
- Test changes must follow `docs/TEST_SIGNAL_POLICY.md`: prefer product and
  invariant signal over test-count growth, marker checks, and stale fixtures.
- Unreleased internal surfaces must follow
  `docs/UNRELEASED_AUTHORITY_POLICY.md`: choose current authority instead of
  preserving pre-release paths as legacy compatibility or migration debt.
- Control formats and JSON usage must follow
  `docs/CONTROL_FORMAT_AND_JSON_POLICY.md`: JSON is acceptable for explicit
  evidence, diagnostics, support, trace, and expert export surfaces, not as the
  default operator UX, hot-path protocol, or durable product format.
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

Use this repo-local reading order before changing behavior or documentation:

1. `README.md` - repository overview and current policy summary
2. `AGENTS.md` - agent and managed-worker contract
3. `docs/GITHUB_PR_DEVELOPMENT.md` - GitHub issue, branch, worktree, and PR flow
4. `docs/GITHUB_CI.md` - CI workflow, validation lanes, and secret boundary
5. `docs/CLAIMS_GATE_POLICY.md` - publishing-facing claim guardrails
6. `docs/REVIEW_TODO_POLICY.md` - durable review-debt policy
7. `docs/REVIEW_TODO_REGISTER.md` - current review-debt register
8. `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` - document authority and classification
9. `docs/INDEX.md` - documentation index and authority-family map

Read `docs/LICENSING.md`, `docs/TEST_SIGNAL_POLICY.md`,
`docs/UNRELEASED_AUTHORITY_POLICY.md`, and
`docs/CONTROL_FORMAT_AND_JSON_POLICY.md` when a change touches those surfaces.
