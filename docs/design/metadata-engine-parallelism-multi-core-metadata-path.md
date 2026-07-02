# Metadata Engine Parallelism Boundary

Status: historical pointer retained for the PR-owned ADR-0007 citation.

This file is no longer a design-spec library. Current workspace shape,
package roles, and source behavior live in source, `docs/ARCHITECTURE.md`,
`docs/workspace-package-classification.md`, and live GitHub issues/PRs.

## Current Pointers

- `docs/adr/0007-local-and-clustered-posix-block-modes.md` records the local
  versus clustered POSIX/block mode decision.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/lock_dispatch.rs`,
  `clustered_mount.rs`, and `clustered_lock_forwarder.rs` keep local in-process
  lock dispatch separate from clustered LOCK-service admission.
- `crates/tidefs-lock-service/src/lib.rs`,
  `crates/tidefs-lease-manager/src/lib.rs`, and
  `crates/tidefs-membership-epoch/src/lib.rs` are source-backed clustered
  coordination inputs.

## Boundary

Local metadata concurrency is a local filesystem, namespace, and adapter
implementation concern. Cluster-wide lock, lease, and membership integration is
a distinct clustered runtime mode. A local POSIX mount must not become a
clustered metadata engine merely because shared model types exist in the
workspace.

## Non-Claims

This pointer does not claim a multi-core metadata engine, distributed metadata
runtime, lock-sharding completeness, POSIX completeness, production readiness,
performance, or successor/comparator standing. Those remain behind source
implementation, validation evidence, `validation/claims.toml`, and
`docs/CLAIMS_GATE_POLICY.md`.
