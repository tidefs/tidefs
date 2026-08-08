# TideFS Architecture

> TFR-019 authority classification: Current spec (scoped). See
> `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the current source-ownership map and architecture verdict for
the selected local mounted-filesystem carrier. Its source evidence is the
workspace member list in `Cargo.toml`, package manifests, current runtime call
paths, `README.md`, and live issue #2388.

This map is not a capability claim. TideFS remains pre-alpha and does not claim
production readiness, POSIX completeness, kernel residency, complete block or
cluster modes, performance validation, or superiority to another filesystem.
Ordinary development comes from the product contract, this architecture,
current source, and live issues and pull requests. Claims and generated claim
output apply only when deciding what TideFS may publish; they do not select or
block ordinary implementation work.

## App Entrypoints

| Path | Source role |
|---|---|
| `apps/tidefs-posix-filesystem-adapter-daemon` | Selected local FUSE carrier library; binary-only validation commands must converge on the library carrier. |
| `apps/tidefsctl` | Selected local operator lifecycle and status carrier. |
| `apps/tidefs-scrub` | Scrub tool whose useful operator behavior is to consolidate into `tidefsctl`. |
| `apps/tidefs-block-volume-adapter-daemon` | Block-mode source retained outside the first local mounted carrier. |
| `apps/tidefs-storage-node` | Cluster-mode source retained outside the first local mounted carrier. |
| `apps/tidefs-filesystem-demo` | Harness signal to migrate into carrier tests before deleting the demo package. |
| `apps/tidefs-store-demo` | Harness signal to migrate into carrier tests before deleting the demo package. |

The app list describes binaries present in the workspace. It is not release or
operator-readiness evidence.

## Selected Local Mounted Architecture

The selected first architecture is one foreground owner process reached through
`tidefsctl`. The dependency direction is:

1. `tidefsctl` owns command parsing, lifecycle sequencing, and truthful status.
2. Pool scan/import owns device discovery, label agreement, import exclusion,
   activation, and export. It does not own filesystem transaction replay.
3. `tidefs-local-object-store::Pool` is the only durable object/device I/O
   authority below the filesystem.
4. One focused Pool-backed authority in `tidefs-local-filesystem` owns
   transaction publication, committed-root selection, replay, and reopen.
5. The dataset-scoped inode authority selected by
   `docs/INODE_NAMESPACE_AUTHORITY.md` owns durable dataset, root inode, inode,
   and directory identity. Namespace and inode-table crates may remain only as
   consumers or projections of that authority.
6. `VfsLocalFileSystem` is the mounted semantic authority. It translates VFS
   operations into the durable filesystem owner without another namespace or
   recovery decision.
7. `FuseVfsAdapter` is a thin kernel projection. It owns FUSE handles, lookup
   references, cache projection, replies, and unmount integration, but no
   durable inode, namespace, root, or transaction truth.
8. The live-owner endpoint projects status and bounded administration from the
   same VFS engine instance. It is not a second store opener.

The selected carrier path is:

`tidefsctl pool create` -> `tidefsctl pool mount --devices` -> pool label/import
admission -> `run_mount` -> `LocalFileSystem` -> `VfsLocalFileSystem` ->
`FuseVfsAdapter` -> mounted path.

Clean shutdown drains and commits the VFS engine, unmounts and joins the FUSE
session, exports the pool labels, and then removes the live-owner endpoint.
Crash recovery reopens the same devices and selects the newest complete
Pool-backed filesystem root before accepting mounted work.

## Current Runtime And Authority Map

| Stage | Current source | Current behavior | Verdict |
|---|---|---|---|
| Create | `apps/tidefsctl/src/commands/pool.rs`, `crates/tidefs-pool-import/src/create.rs` | Writes dual labels plus initial fixed-region VBCR/VRBT bootstrap state and leaves the pool exported. | Keep label/bootstrap creation; stop treating the fixed-region root as mounted filesystem state authority. |
| Import for mount | `apps/tidefsctl/src/commands/mount.rs`, `crates/tidefs-pool-import/src/lib.rs` | Validates labels, acquires the import lock, selects the fixed-region root, runs import-layer replay, mounts a catalog placeholder, and activates labels. | Contract to labels, lock, topology, activation, and export. Filesystem root selection/replay belongs below. |
| Carrier open | `apps/tidefs-posix-filesystem-adapter-daemon/src/lib.rs::run_mount` | Opens `LocalFileSystem` on the runtime metadata directory plus the devices, resolves the dataset, disables auto-commit, wraps VFS and FUSE, and publishes a live owner. | This is the only selected production local mount path. |
| Duplicate mount | `apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs::mount_vfs` | Separately opens recovery, namespace, commit-cycle, scrub, and signal/shutdown machinery and is invoked by validation and smoke commands. | Migrate useful tests to the carrier, then delete the duplicate runtime. Do not preserve two production architectures. |
| Object authority | `crates/tidefs-local-object-store/src/pool/mod.rs` | Opens the same labeled devices as a `Pool`, owns placement/device I/O, and persists object records and pool labels. | Keep as the only object/device I/O authority. |
| Filesystem root/recovery | `crates/tidefs-local-filesystem/src/{lib,recovery}.rs` | Selects Pool-backed root-slot records, validates content through Pool receipts, replays intent and commit-group state, and constructs live filesystem state. | Keep and focus as the single mounted transaction/root/recovery authority. |
| Dataset/inode/namespace | `FileSystemState`, `DatasetInodeAuthority`, `tidefs-namespace`, `tidefs-inode-table`, FUSE maps | Durable maps and allocator state exist in local-filesystem while namespace, inode-table, and FUSE maintain additional allocators, mirrors, and fallbacks. | Durable decisions stay in the dataset authority; all others become projections or are removed from the carrier. |
| VFS/FUSE | `vfs_engine_impl.rs`, `fuse_vfs_adapter.rs` | VFS calls local-filesystem, while the adapter also contains namespace-first fallbacks, inode/cache mirrors, and operation policy. | VFS owns semantics; FUSE owns only transport, handles, replies, and derived cache state. |
| Status/admin | `live_owner.rs`, `apps/tidefsctl/src/commands/live_owner.rs` | The owner socket delegates live work to the mounted engine and refuses reopening active devices behind it. | Keep and thin; status must describe the same engine and root selected for mounted I/O. |
| Shutdown/export | `run_mount`, `fuser::BackgroundSession::join`, adapter `destroy`, `pool_export`, live-owner `stop` | `join` drops the mount first; adapter destroy drains/syncs; labels export afterward; endpoint cleanup is last. | Preserve this order and make every failure explicit to the operator. |

## System-Level Shape

The repository is not short of implementations; it has too many overlapping
ones in the default graph:

- 166 root-workspace packages plus four excluded fuzz packages are present.
- The default normal dependency closure of `tidefsctl` plus the POSIX daemon is
  118 of 166 workspace packages: all 37 keep packages, 49 of 54 consolidation
  packages, and 32 of 73 extraction packages. Block, cluster, validation,
  workload, and performance-policy families are therefore still coupled to
  the local carrier; neither demo package is in the closure.
- Twenty-five of those 32 extraction packages are reachable through
  `tidefs-local-filesystem` itself. Gating only CLI commands or the daemon
  binary cannot contract the carrier; the core package must separate its local
  filesystem path from replication, send/receive, and policy subsystems.
- `fuse_vfs_adapter.rs` is 46,314 lines, `local-filesystem/src/lib.rs` is
  17,534, `vfs_engine_impl.rs` is 16,488, and the binary daemon `main.rs` is
  4,763 lines. The size is concentrated in four mixed-authority carriers.
- Pool import and local-filesystem both select roots and replay logs, but only
  the local-filesystem path loads the state served by mounted VFS operations.
- The library carrier and binary validation carrier construct different
  recovery, namespace, scheduler, and shutdown stacks.
- The adapter's direct normal dependencies include cluster, block, validation,
  workload, performance-contract, schema, namespace, and inode-table families.
  `tidefsctl` directly depends on block, cluster, transport, validation, and
  storage-policy families.

This is the governing diagnosis: TideFS's first product spine is obscured by a
large default dependency closure and duplicate authorities. Particular defects
must be repaired only after assigning them to the target owners above.

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
semantics, performance, and recovery wording must stay within observed source
and focused carrier tests. Publication claims remain a separate decision.

## Package-Root Disposition

This target disposition covers all 166 workspace members and all four excluded
fuzz package roots. `docs/workspace-package-classification.md` remains the
current-consumer inventory while this section decides the target dependency
shape.

These dispositions are not deletion proof. A removal change must first show
the exact current consumers, migrate or deliberately preserve useful signal,
and verify that the target contains no dirty, unpushed, unintegrated,
reviewable, rollback, recovery, evidence, or uncertain state. No package or
source is deleted by this architecture change.

### Keep: 37 Workspace Packages

Keep these as the selected carrier or a distinct durable/semantic boundary.
Their public surface and dependency lists still contract to the minimum used by
the local lifecycle.

```text
fuser
tidefs-auth
tidefs-background-scheduler
tidefs-block-allocator
tidefs-cache-core
tidefs-checksum-tree
tidefs-cleanup-engine
tidefs-commit_group
tidefs-dataset-catalog
tidefs-dataset-lifecycle
tidefs-dir-index
tidefs-durability-layout
tidefs-extent-map
tidefs-inode-attributes
tidefs-intent-log
tidefs-local-filesystem
tidefs-local-object-store
tidefs-object-io
tidefs-orphan-index
tidefs-permission
tidefs-pool-import
tidefs-pool-scan
tidefs-posix-acl
tidefs-posix-filesystem-adapter-daemon
tidefs-posix-semantics
tidefs-reclaim
tidefs-recovery-loop
tidefs-scrub-core
tidefs-segment-cleaner
tidefs-space-accounting
tidefs-spacemap-allocator
tidefs-types-pool-label-core
tidefs-types-vfs-core
tidefs-verification-engine
tidefs-vfs-engine
tidefs-xattr-storage
tidefsctl
```

### Consolidate: 54 Workspace Packages

The behavior may be useful to the selected carrier, but it is not an
independent durable authority. Absorb it into the nearest kept owner, make it a
private module, or feature-gate it out of the first carrier. Consolidation must
preserve the strongest existing carrier or invariant test.

```text
tidefs-binary_schema-checksum
tidefs-binary_schema-core
tidefs-binary_schema-framing
tidefs-btree
tidefs-cache-coherency
tidefs-claim-ledger
tidefs-cleanup-job-core
tidefs-cleanup-queue-core
tidefs-clock-timing
tidefs-compaction
tidefs-data-cleaner
tidefs-dataset-feature-flags
tidefs-dataset-properties
tidefs-dedup
tidefs-derived-catalog
tidefs-device-removal
tidefs-frame
tidefs-gc-pin-set
tidefs-geometry-convert
tidefs-incremental-job-core
tidefs-inode-table
tidefs-invalidation-feed
tidefs-locator-table
tidefs-lock-service
tidefs-namespace
tidefs-online-defrag
tidefs-pool-allocator
tidefs-posix-filesystem-adapter-reply
tidefs-posix-filesystem-adapter-workers-io
tidefs-posix-filesystem-adapter-workers-locks
tidefs-receive-stream
tidefs-reclaim-queue-core
tidefs-relocation-governor
tidefs-relocation-planner
tidefs-reserve-ledger
tidefs-schema-codec-posix-filesystem-adapter
tidefs-scrub
tidefs-storage-intent-core
tidefs-storage-intent-read-serving
tidefs-types-cache-lattice-core
tidefs-types-claim-ledger-core
tidefs-types-dataset-feature-flags-core
tidefs-types-dataset-lifecycle-core
tidefs-types-deferred-cleanup-core
tidefs-types-extent-map-core
tidefs-types-incremental-job-core
tidefs-types-orphan-index-core
tidefs-types-package-profile-catalog
tidefs-types-polymorphic-directory-index-core
tidefs-types-polymorphic-xattr-core
tidefs-types-posix-filesystem-adapter-core
tidefs-types-reclaim-queue-core
tidefs-types-space-accounting-core
tidefs-types-vfs-owned
```

### Extract From The Default Local Carrier: 73 Workspace Packages And Four Fuzz Roots

Preserve these sources for later block, kernel, clustered, transform,
replication, model, or development work, but do not compile them into the first
local mounted lifecycle by default. Extraction may use optional features,
separate workspace membership, or focused CI commands; it must not turn an
eventual product mode into a local-mount prerequisite.

```text
tidefs-anti-entropy-auditor
tidefs-block-kmod
tidefs-block-volume-adapter-core
tidefs-block-volume-adapter-daemon
tidefs-block-volume-adapter-ublk-control-runtime
tidefs-bulk-service
tidefs-chunk-shipper
tidefs-cluster
tidefs-compression
tidefs-coordination-strategy
tidefs-crash-oracle
tidefs-distributed-model-check
tidefs-encryption
tidefs-env-fuse-model
tidefs-env-ublk-model
tidefs-erasure-coded-store
tidefs-erasure-coding
tidefs-flow-commit-coordinator
tidefs-kernel-cutover-runtime
tidefs-kernel-storage-io
tidefs-kmod-bridge
tidefs-kmod-posix-vfs
tidefs-lease
tidefs-lease-manager
tidefs-membership-epoch
tidefs-membership-live
tidefs-membership-types
tidefs-model-core
tidefs-node-drain
tidefs-node-join
tidefs-offload-core
tidefs-partition-runtime
tidefs-performance-contract
tidefs-placement-planner
tidefs-placement-runtime
tidefs-posix-guarantee-verifier
tidefs-quorum-write
tidefs-quorum-write-runtime
tidefs-rebalance-planner
tidefs-rebuild-planner
tidefs-rebuild-runtime
tidefs-replica-health
tidefs-replicated-object-store
tidefs-replication
tidefs-replication-model
tidefs-schema-codec-vfs
tidefs-secret-key-policy-runtime
tidefs-send-stream
tidefs-shard-group
tidefs-snapshot-pruner
tidefs-storage-intent-cost
tidefs-storage-intent-local-media-capability
tidefs-storage-intent-media-capability-refresh
tidefs-storage-intent-policy
tidefs-storage-intent-prefetch-executor
tidefs-storage-intent-prefetch-feedback
tidefs-storage-intent-remote-media-capability
tidefs-storage-intent-satisfaction
tidefs-storage-intent-scheduler
tidefs-storage-intent-workload-signals
tidefs-storage-node
tidefs-tdma-scheduler
tidefs-trace-oracle
tidefs-transport
tidefs-two-node-harness
tidefs-types-secret-key-policy-core
tidefs-types-transport-session
tidefs-ublk-abi
tidefs-validation
tidefs-vfs-rpc
tidefs-witness-set
tidefs-workload
tidefs-xtask

fuzz (tidefs-fuzz)
crates/tidefs-binary_schema-core/fuzz (tidefs-binary_schema-core-fuzz)
crates/tidefs-local-filesystem/fuzz (tidefs-local-filesystem-fuzz)
crates/tidefs-local-object-store/fuzz (tidefs-local-object-store-fuzz)
```

The fuzz roots remain preserved and independently runnable. Extraction means
they stay outside the default carrier build, as they already do; it is not a
request to remove their corpora or findings.

### Delete After Signal Migration: Two Workspace Packages

```text
tidefs-filesystem-demo
tidefs-store-demo
```

These are not product carriers. They currently feed `nix/tidefs-validation.sh`,
packaged binary smoke checks, FUSE VM setup, and `tidefs-xtask` source checks.
Move the useful write/read/replay/snapshot/send-receive and object-store smoke
signal to focused tests through `tidefsctl` and `run_mount`, update those exact
consumers, and only then delete the demo packages in a reviewable removal PR.

The same rule applies below the package level to the daemon binary's
`mount-vfs`, `smoke-mount`, `score-posix`, and `xfstests-harness` product-like
paths: preserve focused test signal, move the test to the selected carrier,
then delete the duplicate runtime path rather than keeping two architectures.

## Contraction And Delivery Order

1. Land this source/target verdict and resolve the local-carrier documentation
   conflict. Do not change runtime behavior in the decision commit.
2. Remove manifest edges with no source consumer, then feature-gate or extract
   block, cluster, kernel, validation, workload, claims, schema, and performance
   families from normal local carrier dependencies. Recompute Cargo metadata
   after each coherent contraction.
3. Reduce pool import to label/topology/lock/activation/export ownership and
   route all mounted root selection and replay through the Pool-backed
   local-filesystem authority.
4. Make dataset inode authority the only durable namespace identity and remove
   namespace/inode-table/FUSE fallbacks that can decide durable truth.
5. Move validation from the binary `mount-vfs` stack to `tidefsctl` plus
   `run_mount`; then delete the duplicate mount and demo paths with their stale
   dependencies and policy checks.
6. Exercise create, mount, real I/O, `fsync`/`fdatasync`, rename, clean stop,
   crash, reopen, status, unmount/export, and reimport through the one carrier.
   Fix failures in the owner selected above rather than reintroducing another
   path.

The first three exact unused manifest edges already identified are
`tidefs-block-allocator` from the POSIX daemon, `tidefs-replication-model` from
`tidefsctl`, and `tidefs-dir-index` from `tidefs-local-filesystem`: their crate
identifiers have no non-test source reference in the declaring package. Each
removal still gets its own focused manifest/build check before landing.

## Maintenance Rule

Update this file when app or crate ownership changes in the workspace. Keep it
current: route implementation gaps to live GitHub issues and update the target
disposition when a real consumer changes. Use claims and generated claim output
only for publication decisions, not as an ordinary work queue or architecture
owner.
