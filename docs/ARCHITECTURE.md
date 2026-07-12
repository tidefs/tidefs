# TideFS Architecture

> TFR-019 authority classification: Current spec (scoped). See
> `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is a compact map of current source ownership. Its source evidence
is the workspace member list in `Cargo.toml`, the package descriptions in
`apps/*/Cargo.toml` and `crates/*/Cargo.toml`, and the claim boundary in
`validation/claims.toml`.

This map is not a capability matrix. It does not claim that any layer is
complete, production-ready, kernel-resident, POSIX-complete, block-ready,
distributed, performance-validated, release-ready, or superior to an incumbent
filesystem. Product admission remains controlled by `docs/CLAIMS_GATE_POLICY.md`,
the generated `docs/CLAIM_REGISTRY.md`, `validation/claims.toml`, current
validation evidence, and live GitHub issues.

Still-real product gaps are tracked outside this file, including local
pool/device lifecycle (#1733), mounted POSIX runtime (#1734), integrity and
repair (#1735), capacity and reserve accounting (#1736), block-device boundary
(#1737), kernel residency (#1739), operator/release verdict (#1740), proof
packet admission (#1741), transaction and crash recovery (#1742), snapshot and
reclaim (#1743), page-cache/writeback/fsync (#1744), and distributed mode
(#1745).

## App Entrypoints

| Path | Source role |
|---|---|
| `apps/tidefs-posix-filesystem-adapter-daemon` | FUSE-facing POSIX adapter daemon and validation harness. |
| `apps/tidefs-block-volume-adapter-daemon` | ublk-facing block-volume adapter daemon and host/device boundary check. |
| `apps/tidefsctl` | Operator CLI and development harness command surface. |
| `apps/tidefs-scrub` | Object-store scrub and verification tool. |
| `apps/tidefs-storage-node` | Networked storage-node daemon that wires transport to replicated object-store code. |
| `apps/tidefs-filesystem-demo` | Local filesystem demonstration over the local object store. |
| `apps/tidefs-store-demo` | Local object-store write/read/replay demonstration. |

The app list describes binaries present in the workspace. It is not release or
operator-readiness evidence.

## Source Layer Map

| Layer | Representative source | Source role |
|---|---|---|
| POSIX/FUSE adapter | `crates/tidefs-fuser` (package `fuser`), `tidefs-posix-filesystem-adapter-reply`, `tidefs-posix-filesystem-adapter-workers-io`, `tidefs-posix-filesystem-adapter-workers-locks`, `tidefs-types-posix-filesystem-adapter-core` | FUSE protocol binding, reply construction, I/O dispatch, lock dispatch, and adapter types for the userspace mount path. |
| VFS and namespace | `tidefs-vfs-engine`, `tidefs-namespace`, `tidefs-inode-table`, `tidefs-local-filesystem`, `tidefs-dir-index`, `tidefs-extent-map`, `tidefs-object-io` | Local filesystem operation dispatch, path resolution, inode state, directory indexing, file extent mapping, and object offset bridging. |
| POSIX metadata and access checks | `tidefs-permission`, `tidefs-posix-acl`, `tidefs-xattr-storage`, `tidefs-posix-semantics`, `tidefs-inode-attributes`, `tidefs-lock-service` | Permission, ACL, extended-attribute, inode-attribute, semantic-definition, and advisory-lock code used by filesystem paths. |
| Local object and pool storage | `tidefs-local-object-store`, `tidefs-block-allocator`, `tidefs-space-accounting`, `tidefs-commit_group`, `tidefs-intent-log`, `tidefs-pool-import`, `tidefs-pool-scan`, `tidefs-pool-allocator`, `tidefs-spacemap-allocator`, `tidefs-reserve-ledger` | Local object persistence, allocation/accounting, transaction grouping, intent logging, pool scan/import, and reserve-ledger ownership. |
| Dataset and cleanup state | `tidefs-dataset-catalog`, `tidefs-dataset-lifecycle`, `tidefs-dataset-properties`, `tidefs-dataset-feature-flags`, `tidefs-cleanup-queue-core`, `tidefs-reclaim-queue-core`, `tidefs-reclaim`, `tidefs-segment-cleaner`, `tidefs-compaction`, `tidefs-dedup` | Dataset metadata, cleanup/reclaim queues, segment maintenance, compaction, and dedup model code. |
| Integrity and transforms | `tidefs-checksum-tree`, `tidefs-compression`, `tidefs-encryption`, `tidefs-scrub-core`, `tidefs-verification-engine`, `tidefs-erasure-coding`, `tidefs-erasure-coded-store`, `tidefs-anti-entropy-auditor`, `tidefs-btree`, `tidefs-frame` | Checksum, compression, encryption, scrub, verification, erasure-coding, anti-entropy, B-tree, and framed-I/O code. |
| Storage intent and scheduling | `tidefs-storage-intent-*`, `tidefs-background-scheduler`, `tidefs-data-cleaner`, `tidefs-flow-commit-coordinator`, `tidefs-incremental-job-core`, `tidefs-relocation-planner`, `tidefs-relocation-governor`, `tidefs-online-defrag` | Policy, media-capability, cost, prefetch, satisfaction, scheduling, background work, relocation, and defrag planning code. |
| Block-volume adapter | `tidefs-block-volume-adapter-core`, `tidefs-block-volume-adapter-ublk-control-runtime`, `tidefs-env-ublk-model`, `tidefs-ublk-abi`, `tidefs-block-kmod`, `tidefs-kernel-storage-io` | Shared block adapter contracts, ublk control probing, model surface, ublk ABI, block-kernel module, and kernel storage I/O code. |
| Kernel-facing POSIX and cutover | `tidefs-kmod-posix-vfs`, `tidefs-kernel-cutover-runtime`, `tidefs-kernel-storage-io` | Linux VFS adapter and userspace-to-kernel cutover code paths. Full no-daemon kernel admission remains gated outside this file. |
| Transport, placement, and replication | `tidefs-transport`, `tidefs-chunk-shipper`, `tidefs-vfs-rpc`, `tidefs-cluster`, `tidefs-membership-*`, `tidefs-lease`, `tidefs-lease-manager`, `tidefs-placement-planner`, `tidefs-placement-runtime`, `tidefs-replication`, `tidefs-replicated-object-store`, `tidefs-quorum-write*`, `tidefs-two-node-harness`, `tidefs-node-join`, `tidefs-node-drain` | Transport/session, RPC, cluster membership, lease, placement, replication, quorum-write, harness, join, and drain code. Distributed admission remains gated outside this file. |
| Rebuild and maintenance planning | `tidefs-rebuild-planner`, `tidefs-rebuild-runtime`, `tidefs-rebalance-planner`, `tidefs-recovery-loop`, `tidefs-replica-health`, `tidefs-device-removal`, `tidefs-relocation-planner` | Planning and runtime code for rebuild, rebalance, recovery, replica health, device removal, and relocation. |
| Models, validation, schemas, and shared types | `tidefs-model-core`, `tidefs-env-fuse-model`, `tidefs-env-ublk-model`, `tidefs-trace-oracle`, `tidefs-crash-oracle`, `tidefs-validation`, `tidefs-workload`, `tidefs-performance-contract`, `tidefs-schema-codec-*`, `tidefs-binary_schema-*`, `tidefs-types-*` | Model, oracle, validation, workload, performance-contract, schema-codec, binary-schema, and shared type crates. These crates are evidence or support surfaces only when a repo policy or workflow maps them to a specific claim. |

## Runtime Mode Boundary

ADR-0007 (`docs/adr/0007-local-and-clustered-posix-block-modes.md`) separates
local and clustered runtime modes for Linux-facing access surfaces. The boundary
is architectural scoping for source owners, not current product admission.

| Surface | Local source authority | Clustered source authority |
|---|---|---|
| POSIX filesystem | In-process mount/session state, local advisory locks, local commit-group and cache coordination. | Membership, lease, lock-service, VFS-RPC, and transport code around mounted clustered ownership. |
| Block-volume export | Local export admission, flush/exactness receipt code, and ublk adapter control/runtime code. | Membership, lease/authority-domain fencing, placement, reserve, and explicit failover or multi-writer admission code. |

The clustered POSIX LOCK boundary separates local in-process FUSE/VFS lock
dispatch from clustered forwarding admitted through committed clustered-mount
authority. Local POSIX uses `LocalFileSystem`, `FuseVfsAdapter::new`, and
`DaemonLockDispatch`; it must not open cluster LOCK transport or derive lock
authority from membership services. Clustered POSIX lock forwarding is admitted
through `ClusteredPosixMountRuntime::open_committed_mount(...)`, which supplies
a committed `DatasetMountIdentity` and `ClusteredPosixAuthoritySnapshot`.
`ClusteredPosixLockForwarder::new(...)` owns the identity-bound
`LockServiceHandle` and `LockServiceTransport`. `DatasetMountIdentity::ZERO`,
local mount identity, command-line flags, and single-node defaults are not
clustered LOCK authority. This boundary does not claim clustered POSIX mount
readiness, distributed lock runtime validation, failover behavior, POSIX
completeness, production readiness, kernel/no-daemon status, performance, or
successor/comparator standing.

## Representative Local Data Path

The local FUSE path currently runs through these source families:

1. The FUSE daemon receives a request and the vendored `fuser` member plus
   adapter workers parse and dispatch it.
2. `tidefs-vfs-engine` calls into namespace, inode, directory, extent, metadata,
   permission, and local filesystem code.
3. File data maps through `tidefs-extent-map` and `tidefs-object-io` to local
   object-store objects.
4. Object persistence, transaction grouping, intent logging, allocation,
   checksums, and configured transforms are owned by the local storage and
   integrity crates named above.
5. Replies return through the adapter reply and worker crates to the FUSE
   daemon.

This path summary is a wiring map. Crash-safety, fsync, page-cache, POSIX
semantics, performance, and recovery assertions remain claim-gated for their
exact scopes.

## Maintenance Rule

Update this file when app or crate ownership changes in the workspace. Keep it
short: route gaps to `validation/claims.toml`, generated claim output, durable
TFR rows, or live GitHub issues instead of preserving historical review tables
or incumbent-comparison prose here.
