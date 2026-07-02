# Clustered POSIX LOCK Forwarding Boundary

Status: current scoped pointer for GitHub issue #626.

This file remains because `docs/ARCHITECTURE.md` and the documentation
authority register cite it as the narrow clustered POSIX LOCK boundary. It is
not implementation evidence that clustered POSIX mounts are complete.

## Current Authority

- `docs/adr/0007-local-and-clustered-posix-block-modes.md` chooses distinct
  local and clustered POSIX/block modes.
- `docs/ARCHITECTURE.md` describes the local POSIX hot path and the clustered
  LOCK-service boundary at a high level.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/lock_dispatch.rs`,
  `clustered_mount.rs`, and `clustered_lock_forwarder.rs` are the source-backed
  local/clustered split for POSIX lock dispatch.
- `crates/tidefs-lock-service/src/lib.rs` and
  `crates/tidefs-membership-epoch/src/lib.rs` define the lock-service handle,
  transport, committed mount identity, epoch, term, and member vocabulary.

## Boundary

Local POSIX keeps using `LocalFileSystem`, `FuseVfsAdapter::new`, and
`DaemonLockDispatch`. The local path must not open cluster LOCK transport or
derive lock authority from membership services.

Clustered POSIX lock forwarding is admitted through
`ClusteredPosixMountRuntime::open_committed_mount(...)`. That boundary supplies
a committed `DatasetMountIdentity` plus a `ClusteredPosixAuthoritySnapshot`.
`ClusteredPosixLockForwarder::new(...)` owns the identity-bound
`LockServiceHandle` and `LockServiceTransport`.

`DatasetMountIdentity::ZERO`, local mount identity, command-line flags, and
single-node defaults are not valid clustered LOCK authority.

## Non-Claims

This document does not claim clustered POSIX mount readiness, distributed lock
runtime validation, failover behavior, POSIX completeness, production
readiness, kernel/no-daemon status, performance, or successor/comparator
standing. Those claims remain gated by source implementation, validation
evidence, `validation/claims.toml`, and `docs/CLAIMS_GATE_POLICY.md`.
