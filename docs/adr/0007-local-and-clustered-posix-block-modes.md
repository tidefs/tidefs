# ADR-0007: Local and clustered POSIX and block runtime modes

Date: 2026-06-20
Status: Accepted

## Context

TideFS exposes Linux-facing access through POSIX filesystem mounts and
block-volume exports. The repository already contains local storage and
adapter code, plus cluster membership, lease, transport, and lock-service
models. Issue #615 asked for an architecture decision before wiring more
cluster lock-service plumbing into mounted paths, because local deployments
must not accidentally inherit a cluster coordination bottleneck.

The review covered the required sources:

- `docs/00_user_requirements.md` requires source behavior, live issue state,
  current repo docs, and git history as review inputs.
- `docs/ARCHITECTURE.md` classifies the FUSE and ublk daemons as userspace
  harnesses above product layers, and lists lock, lease, membership, POSIX,
  and block-volume crates as distinct architectural pieces.
- `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` already distinguishes
  standalone pool import from cluster pool ownership, clears cluster
  membership on cross-system import, and requires export plus re-import for
  standalone/cluster migration.
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md` declares the
  FUSE daemon a bounded mirror rather than hidden production sovereignty.
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md` makes block
  export a first-class projection, defaults writable exports to a single
  writer authority, and treats multi-writer behavior as explicit and
  expensive.
- `docs/design/metadata-engine-parallelism-multi-core-metadata-path.md`
  defines local-node concurrency with in-process directory and extent locks,
  while cluster-wide lock integration is a later lease-aware wrapper.
- `docs/design/cluster-wide-distributed-lock-service-design.md`,
  `docs/MEMBERSHIP_SERVICE_DESIGN.md`, and
  `docs/design/coordination-pipeline-cluster-services-design-seal.md`
  establish cluster membership, lease, and LOCK services as clustered
  coordination services, not proof that every local mount operation should
  call a network-capable service.

Current source behavior also points to a mode split:

- `apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs` opens
  `LocalFileSystem` directly for FUSE VFS mounts.
- `crates/tidefs-local-filesystem/src/lib.rs` holds an in-process
  `LockTracker` and uses it for `getlk`, `setlk`, and blocking lock wait.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/lib.rs` describes POSIX
  and BSD flock state as in-memory daemon state that is not persisted across
  daemon restart.
- `crates/tidefs-lock-service/src/lib.rs` implements a cluster-facing LOCK
  protocol surface. Its `LockServiceHandle` still builds acquire and release
  frames with `DatasetMountId(0)`, which is why #574 was paused.
- `crates/tidefs-block-volume-adapter-core/src/lib.rs` is a deterministic
  local block-volume model for exact reads/writes, flush barriers, discard,
  and explicit refusals. The ublk daemon is a userspace adapter surface, not
  a clustered export authority by itself.

Issue and PR history confirms the same split:

- #444 and PR #456 scoped advisory lock lifecycle by dataset mount identity
  in the lock-service and worker-helper authority.
- #469 and PR #490 scoped lease lifecycle by committed dataset mount identity
  and membership epoch.
- #576 and PR #577 made the local filesystem compile by passing a
  `dataset_mount_id` through the local `LockTracker` API, but deliberately
  left the local field at `0` as a single-mount build fix.
- #574 was closed after operator clarification because it assumed mounted
  POSIX locks should be wired through the cluster `LockServiceHandle` before
  this mode decision existed.

## Decision

TideFS will expose explicit local and clustered runtime modes for both
POSIX filesystem access and block-volume export.

| Product surface | Mode | Decision |
|---|---|---|
| POSIX filesystem | local POSIX | Accepted as a first-class product mode. Local advisory locks, inode/dentry coordination, writeback, mmap, and cache coordination stay local or in-process for the mounted scope. |
| POSIX filesystem | clustered POSIX | Accepted as a distinct product mode. Cross-node POSIX coherence, cross-node advisory locks, failover fencing, and cluster cache decisions require MEMBERSHIP, lease, and LOCK services. |
| Block-volume export | local block export | Accepted as a first-class product mode. The default mutable export is one local writable authority with local queue, flush, capacity, and exactness accounting. |
| Block-volume export | clustered block export | Accepted as a distinct product mode. Cross-node export, failover, remote serving, and any multi-writer class require membership, lease/authority-domain fencing, reserve escrow, and placement/flush receipt continuity. |

The local modes are not bootstrap-only variants. They are the expected mode for
single-node deployments and must have a direct, local hot path. Cluster
membership, lease, and LOCK services may be present in the binary or share
types with local code, but they must not be required on the local POSIX or
local block hot path.

The clustered modes own the cluster services:

- Clustered POSIX may use the LOCK service for cross-node advisory locks,
  subtree/inode leases, F_SETLKW wait queues, cache break callbacks, and
  membership-epoch fencing. Per-node local locks remain the intra-node
  serialization primitive under granted leases.
- Clustered block export may use membership and lease authority to admit a
  writer, coordinate failover or handoff, guard reserve escrow, and bind flush
  or FUA success to durable receipts. Ambient cheap symmetric shared writable
  block export remains rejected.

Local-to-cluster conversion while mounted is rejected for now. The supported
boundary is explicit drain, unmount or export, cluster admission, re-import or
remount in clustered mode, and cache reconstruction. A future live upgrade can
be reconsidered only as a separate design and implementation issue.

## Alternatives Considered

### Local-only runtime

This keeps the local hot path simple and matches current source behavior, but
it fails the TideFS product ambition and existing distributed designs. It
would abandon membership, leases, placement epochs, storage-node work, and
cluster block export/failover requirements.

Rejected.

### Clustered-only runtime

This makes every mount and block export pass through the same membership,
lease, and lock-service authority. It appears simpler at the product matrix
level, but it would make local deployments depend on cluster services they do
not need. It would also risk adding network-shaped latency, leader/follower
failure modes, queueing, and service bootstrap requirements to operations
that current local source handles in-process.

Rejected.

### Explicit local/clustered mode split

This keeps local correctness and performance direct while preserving the
cluster architecture where it is semantically required. It matches current
docs that distinguish standalone and cluster pool ownership, current local
source behavior, the block charter's writer-local default, and the metadata
parallelism design's distinction between local locks and cluster leases.

Accepted.

### Live local-to-cluster upgrade while mounted

This would let an operator promote a live local mount or block export into a
clustered one without unmounting. It is attractive operationally but crosses
too many existing authority boundaries at once:

- POSIX inode and dentry caches would need cluster-epoch revalidation.
- Open file handles, flock/OFD/POSIX byte-range locks, and lock waiters would
  need remapping from local in-process state to epoch-fenced cluster state.
- Dirty page cache, mmap writeback, fsync state, and reply-commit ambiguity
  would need a global fence before another node can observe the dataset.
- Block queues, flush/FUA barrier cohorts, dirty ranges, write-zeroes/discard
  state, and capacity/reserve promises would need a new clustered authority
  domain without losing exactness.
- Membership admission changes failure and retry semantics for in-flight
  operations.

Rejected for now. The accepted upgrade boundary is an explicit remount or
migration workflow after quiesce/drain. This keeps the product semantics
explainable and avoids pretending that kernel and adapter caches can be
magically reclassified.

## Unified Path Evidence Requirement

A future implementation may try to share a unified local/cluster lock-service
or lease path only if it proves that local mode does not regress. The evidence
must include all of the following:

- A local-mode path that resolves without network transport, remote leader
  lookup, Raft replication, cluster membership heartbeat dependency, or
  unbounded background queues.
- Focused POSIX lock and metadata latency measurements against the previous
  in-process local path, including uncontended and contended advisory locks,
  create/unlink/rename, fsync, mmap/writeback, and mount/unmount.
- Focused block read/write/flush/FUA/discard measurements against the previous
  local export path, including queue-depth and tail-latency evidence.
- Failure injection showing that local mode has no new dependency on cluster
  leader availability, membership epoch progress, or remote lease expiry.
- Semantics tests showing that per-mount advisory locks, local cache
  invalidation, block flush barriers, and write exactness remain unchanged.

Without that evidence, local-mode coordination stays local and in-process.

## Consequences

The immediate implementation mapping is:

- #574 remains closed as an over-broad pre-decision implementation slice.
  Its lock-service handle plumbing belongs only to clustered POSIX, after the
  clustered mode issue states the required membership and lease prerequisites.
- #618 is the local POSIX follow-up to replace the local
  `dataset_mount_id = 0` placeholder with a committed mount/session identity
  for the in-process `LockTracker`, without routing local locks through the
  cluster LOCK service.
- #619 is the clustered POSIX follow-up to plumb committed mount identity
  into `LockServiceHandle` and clustered FUSE/VFS lock forwarding, explicitly
  scoped to clustered mode.
- #620 is the local block export follow-up to make local export admission
  and local single-writer authority explicit in the ublk/block adapter path,
  with no membership or distributed lease requirement.
- #621 is the clustered block export follow-up to add the membership,
  lease/authority-domain, reserve escrow, failover/handoff, and receipt
  continuity gates for cluster block exports.
