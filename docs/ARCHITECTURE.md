# TideFS Architecture

> TFR-019 authority classification: Current spec (scoped). See
> `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the current source-ownership map and architecture verdict for
all four Product Contract modes. Its implemented source map is most complete
for the selected local mounted-filesystem carrier; the cross-mode sections
below select the target owners that later block and clustered carriers must
reuse rather than building parallel stores. Its source evidence is the
workspace member list in `Cargo.toml`, package manifests, current runtime call
paths, `README.md`, completed local-carrier issue #2388, and live architecture
issue #2432.

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
| `apps/tidefs-posix-filesystem-adapter-daemon` | Selected local FUSE carrier library; the binary retains only development test orchestration and has no local mount runtime. |
| `apps/tidefsctl` | Selected local operator lifecycle and status carrier. |
| `apps/tidefs-scrub` | Scrub tool whose useful operator behavior is to consolidate into `tidefsctl`. |
| `apps/tidefs-block-volume-adapter-daemon` | Retained ublk transport and development backends. It is not a second storage engine or operator lifecycle authority. |
| `apps/tidefs-storage-node` | Retained cluster transport and ownership substrate. It must consume the shared Pool-backed runtime; its current directory roots and side files are not a clustered storage format. |

The app list describes binaries present in the workspace. It is not release or
operator-readiness evidence.

## Selected Local Mounted Architecture

The selected first architecture is one foreground owner process reached through
`tidefsctl`. The dependency direction is:

1. `tidefsctl` owns command parsing, lifecycle sequencing, and truthful status.
2. Pool scan/import owns device discovery, highest-complete topology/lifecycle
   label agreement, import exclusion, activation, and export. Activation and
   export preserve the selected roster and lifecycle extensions; this layer
   does not own filesystem transaction replay.
3. `tidefs-local-object-store::Pool` is the only durable object/device I/O
   authority below the filesystem.
4. One focused Pool-backed authority in `tidefs-local-filesystem` owns
   transaction publication, committed-root selection, replay, and reopen.
5. The dataset-scoped inode authority selected by
   `docs/INODE_NAMESPACE_AUTHORITY.md` owns durable dataset, root inode, inode,
   and directory identity. The selected mounted carrier does not attach a
   `Namespace` or an inode-table durability projection; those crates may remain
   only for distinct consumers or derived reference projections.
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

## Four-Mode Product Architecture

The local mounted carrier is the first proven integration spine, not a license
to design the other modes around FUSE. All four final modes share one storage
composition:

```text
tidefsctl
  -> local import owner or committed cluster ownership
  -> one Pool-backed dataset runtime
       -> one pool catalog/root publication and replay frontier
       -> filesystem dataset engine -> VFS -> FUSE -> mounted path
       -> volume dataset engine -> ublk/block front end -> block path
  -> truthful runtime status from the same owner
```

The selected dependency and authority direction is:

1. `tidefs-pool-scan` and `tidefs-pool-import` discover devices and own label,
   topology, import-lock, activation, and export admission. They do not select
   dataset roots, replay dataset transactions, or serve data.
2. `tidefs-local-object-store::Pool` owns physical device/object I/O,
   placement, receipts, allocation, integrity, and durable sync. It remains
   unaware of filesystem paths, inodes, volume geometry, FUSE, ublk, or cluster
   membership semantics.
3. One shared Pool-backed dataset runtime owns the opened `Pool`, pool identity
   and properties, the canonical `DatasetCatalog`, the table of typed dataset
   roots, pool-wide capacity/reserve state, transaction publication, replay
   frontier, pin/drain state, and orderly close. This boundary is factored from
   the proven Pool-backed publication and recovery machinery currently
   concentrated in `tidefs-local-filesystem`; it is not a parallel engine.
4. A filesystem dataset engine owns inode, directory, extent, POSIX metadata,
   and filesystem snapshot semantics for one `DatasetId`. The existing
   `LocalFileSystem` and `VfsLocalFileSystem` are the implementation source to
   separate around this boundary. FUSE remains a projection.
5. A volume dataset engine owns exact logical capacity, logical and physical
   block geometry, sparse block extents, read/write, flush/FUA ordering,
   discard, resize, and volume snapshot semantics for one `DatasetId`. It uses
   the same Pool transaction/root authority as filesystem datasets. ublk and a
   future kernel block front end remain projections.
6. Local mode invokes the shared runtime directly and has no membership,
   remote lease, remote leader, or network dependency. Clustered mode wraps
   the same catalog and dataset engines with committed membership, ownership
   and fencing epochs, placement, replication, handoff, and recovery. It does
   not define a second catalog, dataset format, object store, or local hot path.

`Pool` is therefore too low to own the catalog, while `LocalFileSystem` is too
filesystem-specific to remain its owner. `tidefs-dataset-lifecycle` is an
in-memory lifecycle/model layer and is not the durable pool runtime. The
shared runtime belongs between raw `Pool` and the filesystem/volume engines;
its first implementation should extract existing authority rather than add a
new empty facade.

This composition fixes semantic and on-media authority, not one mandatory
execution domain. The current FUSE and ublk carriers use the userspace `Pool`
implementation while the no-daemon kernel target realizes the same pool root,
catalog, dataset-root, transaction, and replay contract in one
`KernelPoolCore`. Userspace and kernel front ends must never be concurrent
independent owners of one imported pool, and a residency transition must
quiesce and hand off that authority explicitly. Kernel residency therefore
does not introduce a second format or semantic engine, and it must not require
an always-running userspace runtime.

### Canonical Pool And Dataset Roots

The shared runtime publishes one pool root that binds all pool-wide truth
needed to reopen coherently:

- the canonical encoded `DatasetCatalog`;
- pool properties and capacity/reserve counters;
- a typed root record for each live `DatasetId`;
- the current transaction/replay generation; and
- pending reclaim, pin, and lifecycle obligations that must survive reopen.

Each typed dataset root then points to exactly one semantic engine root:

- filesystem: inode/directory/extent/snapshot state;
- volume: capacity/geometry/block-extent/snapshot state; or
- snapshot: one versioned, checksum-protected cross-mode object containing its
  snapshot generation and the exact immutable `DatasetRootRef` of a committed
  filesystem or volume root. A snapshot root cannot source another snapshot.

Publishing the catalog without its referenced typed roots, or publishing a
typed root without the catalog transition that makes it reachable, is
forbidden. A crash selects the newest complete pool root and either exposes the
entire transition or the prior state. Filesystem `fsync`/`syncfs` and block
flush/FUA converge on this publication machinery while retaining their
surface-specific dirty-range semantics.

Filesystem snapshot policy and lineage remain in `SnapshotRecord`, but that
record is not another snapshot format. For each data-retaining filesystem
snapshot or clone, its state record, `root@<name>` catalog entry, lifecycle pin,
typed Pool snapshot object, and exact captured filesystem root must agree.
Creation pins the captured graph before publishing the complete Pool
composition; deletion releases the pin inside the same mutation that removes
catalog and typed-root reachability. List, rollback, destroy, reopen, and root
retention fail closed on disagreement. Retention preserves the canonical Pool
root, every live typed dataset root, each snapshot object's exact immutable
source root, and the complete filesystem transaction/content or volume
map/chunk graph selected by those roots.

Pool objects owned by a dataset are addressed through a domain-separated
identity containing the stable `DatasetId`, object kind, logical identity, and
version or content identity. Volume block zero must therefore never resolve to
the same mutable object or written-block index in two volumes. Shared immutable
content may be deduplicated only through an explicit pool-owned reference and
reclaim authority; an unqualified key such as `b:<offset>` is not a product
namespace.

### Volume Object And Carrier Boundary

A catalog entry of `DatasetType::Volume` is incomplete unless its committed
typed root contains at least:

- exact capacity in bytes;
- logical block size and compatible physical/optimal I/O geometry;
- discard granularity and explicit discard support/refusal;
- stable `DatasetId` namespace and current root generation; and
- resize and snapshot generation state.

A writable local volume clone is another complete `DatasetType::Volume`, not
a catalog alias. `tidefsctl snapshot clone create <pool> <clone>
<volume@snapshot>` publishes a new stable `DatasetId`, `DatasetFlags::CLONE`,
an exact lineage edge to the canonical typed snapshot, and a target-namespaced
volume root initialized from the snapshot's immutable map. Reads may share
that captured immutable graph; every later map node and chunk created by clone
writes uses the clone's `DatasetId`, so block writes, discard, write zeroes,
and flush diverge without changing the source volume or snapshot. Snapshot
destroy refuses while an unpromoted clone retains that lineage. Promotion
atomically removes the lineage and clone flag while preserving the writable
volume; clone delete removes only the unpromoted clone's catalog/root
authority. Reopen validates the surviving lineage, typed roots, geometry, and
map graphs before publication.

Clone lifecycle mutations use the same Pool owner as block attach and are
refused while the affected source or clone volume is actively exported.
Filesystem `SnapshotRecord::Clone` entries remain shared-root snapshot-table
metadata, not independently mountable writable datasets. The product clone
command explicitly refuses filesystem snapshot sources until filesystem roots
have a dataset-scoped object namespace capable of supporting an independent
writable filesystem dataset.

The local operator path is:

```text
tidefsctl dataset create <pool>/<volume> --type volume --size <bytes>
  -> shared Pool-backed catalog plus volume root publication
tidefsctl block attach <pool>/<volume>
  -> local pool owner -> named volume engine -> owned ublk runtime
  -> /dev/ublkbN -> read/write/flush/FUA/discard
  -> detach or crash -> reopen the same Pool-backed volume root
```

The logical block size may have a documented default, but capacity is required
and exact; neither may be synthesized by the adapter. A pool may own mounted
filesystems and block exports concurrently, but all front ends attach to the
same neutral pool owner. The current mounted VFS live owner must be lifted to
that pool owner instead of teaching `VfsLocalFileSystem` to serve
`BlockAttach`. Conversely, a standalone local block export must be able to own
and import a pool without mounting a filesystem.

### Local And Clustered Composition

| Mode | Shared engine | Additional owner | Carrier |
|---|---|---|---|
| Local mounted filesystem | Pool runtime plus filesystem dataset engine | In-process import/session owner and local locks | `tidefsctl` -> FUSE mount |
| Local block-volume export | Pool runtime plus volume dataset engine | In-process export owner and local queue/barrier state | `tidefsctl` -> ublk/block path |
| Clustered mounted filesystem | The same pool and filesystem formats | Committed membership, dataset ownership/fencing, placement/replication, cross-node cache and lock authority | clustered owner -> FUSE or admitted kernel mount |
| Clustered block-volume export | The same pool and volume formats | Committed membership, writer fencing, placement/replication, failover/handoff, flush/FUA continuity | clustered owner -> block export path |

Local-to-cluster conversion retains ADR-0007's explicit drain, export/unmount,
cluster admission, and reopen boundary. It does not translate one format into
another. Cluster loss or ownership transfer must fence old front ends before a
new owner serves either dataset type.

The bounded clustered-block carrier reuses that same ownership boundary.
`tidefsctl block attach --cluster` authenticates to the provisioned Pool lease
authority before import, validates the committed clustered Pool and exact
owner grant, and opens the named `PoolVolumeBackend` under the
authority-reported remaining lifetime. The real ublk service loop periodically
renews that same owner, epoch, lease id, membership slot, and write fence,
including while clean shutdown drains requests. Renewal loss or expiry fences
read, write, discard/zero, flush, and canonical-root publication before ublk
STOP/DEL teardown. Clean shutdown drains and flushes first; both paths fence
and release the retained lease only after the ublk device can no longer issue
I/O. A successor must obtain a higher write fence and independently reopen the
named Pool volume. This does not yet establish a remote block protocol,
automated ublk failover, placement/replication, reserve escrow, or cross-node
flush/FUA continuity.

### Existing Source Disposition For This Architecture

- **Keep and factor:** Pool device/object I/O; the canonical
  `DatasetCatalog` encoding and stable IDs; Pool-backed root publication and
  recovery from `tidefs-local-filesystem`; filesystem inode/directory/extent
  semantics; low-level ublk control/data-queue code; and cluster membership,
  fencing, placement, replication, and transport code with demonstrated
  runtime consumers.
- **Consolidate:** catalog persistence and pool-wide properties out of
  `LocalFileSystem` into the shared runtime; `ClusterDatasetCatalog` into a
  committed ownership/proposal wrapper over the same durable catalog; mounted
  live-owner routing into a neutral pool owner; and capacity, pin, reclaim,
  transaction, and teardown decisions currently duplicated by front ends.
- **Remove from product paths when the shared consumer lands:** the retired
  directory-backed `tidefsctl block` route, hard-coded volume IDs and geometry,
  global `b:<offset>` keys and written-block index, storage-node
  `block-volume-data` side file, receiptless `fs_root` reopen paths, and
  adapter-local committed-root or recovery decisions.
- **Retain only as focused development backends when they provide distinct
  signal:** file-image, in-memory block, model, and ublk boundary probes. A
  model or its own tests do not justify a parallel product runtime. The large
  in-memory block admission/receipt structures and clustered catalog mirrors
  must either be consumed by the selected carrier or be consolidated/deleted
  after exact consumer review.

The first implementation slice after this decision is the smallest vertical
part of the named local block carrier that publishes one exact volume root in
the shared Pool authority and performs real namespaced read/write/flush through
that root. A catalog-only geometry record, parser-only attach command, ublk-only
device launch, or second directory/file backend does not satisfy the slice.

## Current Runtime And Authority Map

| Stage | Current source | Current behavior | Verdict |
|---|---|---|---|
| Create | `apps/tidefsctl/src/commands/pool.rs`, `crates/tidefs-pool-import/src/create.rs` | Writes dual labels plus initial fixed-region VBCR/VRBT bootstrap state and leaves the pool exported. | Keep label/bootstrap creation; stop treating the fixed-region root as mounted filesystem state authority. |
| Import for mount | `apps/tidefsctl/src/commands/mount.rs`, `crates/tidefs-pool-import/src/lib.rs` | Selects the highest complete redundant label family, validates exact topology-roster and lifecycle agreement plus feature, encryption, and pool-state agreement; acquires the exact import lock; opens devices at the selected copy offsets; activates writable ownership without dropping label extensions; reports removal state; and retains matching export/release. It does not select a fixed-region root, apply `min_epoch`, replay transactions, mount a placeholder namespace, or initialize VRBT. | Keep as mounted device admission only. Pool-backed filesystem root selection and replay belong below `run_mount`; full explicit `pool_import` retains its separate recovery behavior. |
| Carrier open | `apps/tidefs-posix-filesystem-adapter-daemon/src/lib.rs::run_mount` | Opens `LocalFileSystem` on the runtime metadata directory plus the devices, resolves the dataset, applies the selected sync, timestamp, capacity, writeback, maintenance, transform, and validation controls, wraps the one VFS/FUSE session, and publishes a live owner. | This is the only local mount runtime implementation. |
| Object authority | `crates/tidefs-local-object-store/src/pool/mod.rs` | Opens the same labeled devices as a `Pool`, owns placement/device I/O, and persists object records and pool labels. | Keep as the only object/device I/O authority. |
| Filesystem root/recovery | `crates/tidefs-local-filesystem/src/{lib,recovery}.rs` | Selects Pool-backed root-slot records, validates content through Pool receipts, replays intent and commit-group state, and constructs live filesystem state. | Keep and focus as the single mounted transaction/root/recovery authority. |
| Dataset/inode/namespace | `FileSystemState`, `DatasetInodeAuthority`, `tidefs-namespace`, `tidefs-inode-table`, FUSE maps | Local-filesystem owns durable dataset, root, inode, and directory state. `VfsLocalFileSystem` has no inode-table projection, and the selected adapter has neither a `Namespace` attachment nor an inode-table-backed normal dependency. FUSE lookup/forget references remain adapter-local maps. | Keep every durable decision in the dataset authority; keep non-carrier namespace users and kernel-reference projections outside mounted truth. |
| VFS/FUSE | `vfs_engine_impl.rs`, `fuse_vfs_adapter.rs` | VFS calls local-filesystem for lookup and mutation semantics. The adapter projects engine results, handles, lookup references, caches, replies, and FUSE lifecycle without another namespace owner, merged directory view, or mutation fallback. | Keep VFS as the semantic owner and FUSE as a derived kernel transport projection. |
| Status/admin | `live_owner.rs`, `apps/tidefsctl/src/commands/live_owner.rs` | The owner socket delegates live work to the mounted engine and refuses reopening active devices behind it. For bounded present-member removal/replacement, that one owner uses its neutral `PoolRuntime` to authenticate every active filesystem root, copy-on-write relocated content manifests for unmounted independent filesystems, durably queue predecessor manifests, and publish every successor typed root before topology publication. Versioned checksummed label lifecycle records, not runtime-directory side files, bind the Pool/member GUID authority needed to resume before receipt recovery. | Keep and thin; status must describe the same imported Pool and root selected for mounted I/O. The bounded Pool-wide lifecycle path is source to lift out of the VFS-specific owner, not authority for a second runtime. |
| Shutdown/export | `run_mount`, `fuser::BackgroundSession::join`, adapter `destroy`, `pool_export`, live-owner `stop` | `join` drops the mount first; adapter destroy drains/syncs; labels export afterward; endpoint cleanup is last. | Preserve this order and make every failure explicit to the operator. |

## System-Level Shape

The repository is not short of implementations; it has too many overlapping
ones in the default graph:

- 164 root-workspace packages plus four excluded fuzz packages are present.
- The default normal dependency closure of `tidefsctl` is 72 of 164 workspace
  packages (183 total); selecting its explicit `full` feature reaches 98
  workspace packages (220 total). Its manifest now has 16 required and 13
  optional normal dependencies. The default parser, help, source modules, and
  direct dependency edges therefore carry only the local pool, mount, device,
  dataset, snapshot, defrag, live-owner, and status families.
- The POSIX daemon now has 32 direct normal dependencies in its default local
  build and 38 with its explicit `full` feature. Its default has no direct
  normal edge to block-volume core, `bincode`, cluster, performance-contract,
  POSIX receipt schema/package-profile, workload, or clustered lock-service
  packages. The daemon has no performance-contract edge in any feature set.
  `cluster` owns clustered mount, LOCK forwarding, lock-service, and membership
  authority; `receipt-demo` and `workload-telemetry` each own one optional
  source/dependency family. `full` aggregates them with the retained data-policy
  and replication forwarding features for development packaging.
- The daemon's default normal tree reaches 71 of 164 workspace packages (169
  total packages including external crates), versus 88 workspace and 187 total
  with `full`. Its default carrier also excludes the distributed, claim,
  performance, storage-intent read-serving, and quorum-write families removed
  from the standalone `tidefs-local-filesystem`; its explicit features restore
  the adapter's retained cluster, replication, data-policy, receipt, and
  telemetry surfaces.
- `fuse_vfs_adapter.rs` is 43,303 lines, `local-filesystem/src/lib.rs` is
  18,698, `vfs_engine_impl.rs` is 15,835, the shared daemon `lib.rs` is 2,082,
  and the binary daemon `main.rs` is 771 lines. The remaining size is
  concentrated in the FUSE, local-filesystem, and VFS carriers plus focused
  validation orchestration.
- Mounted pool admission no longer selects fixed roots or replays filesystem
  transactions; Pool-backed local-filesystem recovery owns mounted state.
- The default `tidefs-local-filesystem` normal tree is 58 workspace packages
  (136 total) and excludes device-removal, replication-model, erasure-coding,
  claim-ledger, performance-contract, storage-intent read-serving, and
  quorum-write families. Its explicit `full` feature restores the retained
  optional subsystems and reaches 95 workspace packages (183 total).
- These normal-edge counts use `cargo tree --locked --offline
  --no-default-features -e normal -p <package>` and add `--all-features` only
  for the corresponding `full` census. Keeping `--no-default-features`
  explicit prevents unrelated workspace feature unification from inflating a
  carrier's reported default closure.
- Mounted validation now uses `tidefsctl pool create` plus `tidefsctl pool
  mount` or focused library tests. The daemon binary retains only
  development test orchestration and constructs no local mount, recovery,
  namespace, FUSE, or shutdown stack.
- The default daemon's public mount authority is standalone-only. Cluster lease
  decoding, cluster authority types, placement wrapping, and their tests compile
  only with `cluster`. Receipt-demo parsing/help/source compiles only with
  `receipt-demo`; workload observation/cache modules and their read/write/fsync
  logging hooks compile only with `workload-telemetry`. Production scrub
  scheduling remains local runtime behavior bounded to one record and one MiB
  per tick, without a second validation-artifact contract in the mount carrier.
- `tidefsctl` owns block-volume, cluster/transport, kernel/validation
  diagnostics, receive-merge, remote snapshot transport, and storage-intent
  policy command families behind explicit Cargo features. Its `cluster` feature
  selects the daemon cluster boundary, while full workspace Nix packaging
  selects both `tidefsctl/full` and daemon `full`. Focused default daemon
  packaging contains default `tidefsctl` plus the default daemon and supplies
  the pool-remount lifecycle row, so that outer carrier test has no optional
  daemon feature compiled in.

This is the governing diagnosis: TideFS's first product spine is obscured by a
large default dependency closure and duplicate authorities. Particular defects
must be repaired only after assigning them to the target owners above.

## Source Layer Map

| Layer | Representative source | Source role |
|---|---|---|
| POSIX/FUSE adapter | `crates/tidefs-fuser` (package `fuser`), `tidefs-posix-filesystem-adapter-reply`, `tidefs-posix-filesystem-adapter-workers-io`, `tidefs-posix-filesystem-adapter-workers-locks`, `tidefs-types-posix-filesystem-adapter-core` | FUSE protocol binding, reply construction, I/O dispatch, lock dispatch, and adapter types for the userspace mount path. |
| VFS and namespace | `tidefs-vfs-engine`, `tidefs-namespace`, `tidefs-inode-table`, `tidefs-local-filesystem`, `tidefs-dir-index`, `tidefs-extent-map`, `tidefs-object-io` | Local filesystem operation dispatch, path resolution, inode state, directory indexing, file extent mapping, and object offset bridging. |
| POSIX metadata and access checks | `tidefs-permission`, `tidefs-posix-acl`, `tidefs-xattr-storage`, `tidefs-posix-semantics`, `tidefs-inode-attributes`, `tidefs-types-vfs-core` | Permission, ACL, extended-attribute, inode-attribute, semantic-definition, and in-process `LockList` advisory-lock code used by the local filesystem path. |
| Local object and pool storage | `tidefs-local-object-store`, `tidefs-block-allocator`, `tidefs-space-accounting`, `tidefs-commit_group`, `tidefs-intent-log`, `tidefs-pool-import`, `tidefs-pool-scan`, `tidefs-pool-allocator`, `tidefs-spacemap-allocator`, `tidefs-reserve-ledger` | Local object persistence, allocation/accounting, transaction grouping, intent logging, pool scan/import, and reserve-ledger ownership. |
| Dataset and cleanup state | `tidefs-dataset-catalog`, `tidefs-dataset-lifecycle`, `tidefs-dataset-properties`, `tidefs-dataset-feature-flags`, `tidefs-cleanup-queue-core`, `tidefs-reclaim-queue-core`, `tidefs-reclaim`, `tidefs-segment-cleaner`, `tidefs-compaction`, `tidefs-dedup` | Dataset metadata, segment maintenance, compaction, and dedup model code. The mounted logical reclaim queue is a Pool-receipted filesystem system object persisted before root publication; object-store receipt-bound queues remain the separate physical-release authority. |
| Integrity and transforms | `tidefs-checksum-tree`, `tidefs-compression`, `tidefs-encryption`, `tidefs-scrub-core`, `tidefs-verification-engine`, `tidefs-erasure-coding`, `tidefs-erasure-coded-store`, `tidefs-anti-entropy-auditor`, `tidefs-btree`, `tidefs-frame` | Checksum, compression, encryption, scrub, verification, erasure-coding, anti-entropy, B-tree, and framed-I/O code. |
| Storage intent and scheduling | `tidefs-storage-intent-*`, `tidefs-background-scheduler`, `tidefs-data-cleaner`, `tidefs-flow-commit-coordinator`, `tidefs-incremental-job-core`, `tidefs-relocation-planner`, `tidefs-relocation-governor`, `tidefs-online-defrag` | Policy, media-capability, cost, prefetch, satisfaction, scheduling, background work, relocation, and defrag planning code. |
| Block-volume adapter | `tidefs-block-volume-adapter-core`, `tidefs-block-volume-adapter-ublk-control-runtime`, `tidefs-env-ublk-model`, `tidefs-ublk-abi`, `tidefs-block-kmod`, `tidefs-kernel-storage-io` | Shared block adapter contracts, ublk control probing, model surface, ublk ABI, block-kernel module, and kernel storage I/O code. |
| Kernel-facing POSIX and cutover | `tidefs-kmod-posix-vfs`, `tidefs-kernel-cutover-runtime`, `tidefs-kernel-storage-io` | Linux VFS adapter and userspace-to-kernel cutover code paths. Full no-daemon kernel admission remains gated outside this file. |
| Transport, placement, and replication | `tidefs-transport`, `tidefs-chunk-shipper`, `tidefs-vfs-rpc`, `tidefs-cluster`, `tidefs-membership-*`, `tidefs-lease`, `tidefs-lease-manager`, `tidefs-lock-service`, `tidefs-placement-planner`, `tidefs-placement-runtime`, `tidefs-replication`, `tidefs-replicated-object-store`, `tidefs-quorum-write*`, `tidefs-two-node-harness`, `tidefs-node-join`, `tidefs-node-drain` | Transport/session, RPC, cluster membership, lease and clustered lock authority, placement, replication, quorum-write, harness, join, and drain code. Distributed admission remains gated outside this file. |
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

This target disposition covers all 164 workspace members and all four excluded
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

The non-carrier `tidefs-filesystem-demo` and `tidefs-store-demo` packages were
deleted after their write/read/replay/snapshot/send-receive and object-store
signal was already owned by focused Pool/local-filesystem tests and the
selected `tidefsctl`/`run_mount` carrier. Their broad-validation, packaging,
and source-marker consumers were removed with them instead of preserving a
second demonstration path.

The daemon binary's duplicate local `mount-vfs` and `smoke-mount` paths were
deleted after their mounted signal moved to `tidefsctl pool create` plus
`tidefsctl pool mount` or focused direct tests. The retained `score-posix` and
`xfstests-harness` commands are development-only test orchestration; their
mounted work uses the selected carrier and they do not define another runtime
architecture.

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
5. Keep `run_mount` as the single library carrier under `tidefsctl pool mount`;
   keep validation consumers on `tidefsctl` or focused direct tests, with no
   duplicate daemon mount wrapper or smoke path.
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
