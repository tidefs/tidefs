# crates/

This directory contains reusable Rust library crates for TideFS.

> Review debt TFR-002/TFR-019: the package counts and tables below are stale
> review input, not current package authority. Cargo currently resolves 148
> workspace members and the root `members` list now matches that resolution,
> but older package inventories still disagree. Use `docs/WHOLE_REPO_REVIEW.md`
> and `docs/REVIEW_TODO_REGISTER.md` until this index is regenerated against
> current Cargo metadata.

Current audit note as of 2026-06-01:

- `cargo metadata --no-deps` reports 140 workspace crates under `crates/`.
- `find crates -name Cargo.toml` reports 144 crate manifests.
- 4 crate manifests under `crates/` are currently outside the workspace; all
  four are standalone crate-local fuzz harnesses.
- The abandoned POSIX adapter split-shard crate directories
  `tidefs-posix-filesystem-adapter-maintenance`,
  `tidefs-posix-filesystem-adapter-workers-meta`,
  `tidefs-posix-filesystem-adapter-workers-ns`, and
  `tidefs-posix-filesystem-adapter-workers-writeback` were deleted as
  consolidated #5725 residue.
- The excluded non-fuzz scaffold type crate roots
  `tidefs-types-archive-control-core`, `tidefs-types-observe-core`,
  `tidefs-types-policy-authority-core`, `tidefs-types-shadow-pilot`, and
  `tidefs-types-truth-view-core` were deleted after reverse-reference review
  found no live code consumers and their current record surfaces were already
  represented by `tidefs-types-vfs-core` or product-local code.
- This file is a source ownership index, not release proof. Capability claims
  must follow `docs/REVIEW_TODO_REGISTER.md`, `docs/CLAIMS_GATE_POLICY.md`, and
  `cargo run -p tidefs-xtask -- check-claims-gate`.

Authoritative companion docs:

- `docs/design/crate-dependency-graph-ownership-boundaries.md`
- `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`
- `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`

## Workspace Crates

| Crate | Area | Purpose |
| --- | --- | --- |
| `fuser` | POSIX/FUSE | Vendored FUSE userspace binding used by the POSIX adapter. |
| `tidefs-anti-entropy-auditor` | Distributed storage (not release proof) | Replica scan, compare, and audit bridge that identifies repair candidates. |
| `tidefs-auth` | Control and policy | Node identity, attestation, principal, grant, and audit primitives. |
| `tidefs-background-scheduler` | Maintenance | Tick-driven scheduler for incremental cleanup, scrub, and background jobs. |
| `tidefs-binary_schema-checksum` | Schema and codec | CRC32C and BLAKE3 checksum helpers for binary-schema records. |
| `tidefs-binary_schema-core` | Schema and codec | Endian, ID, feature-bit, and fingerprint primitives for binary schemas. |
| `tidefs-binary_schema-framing` | Schema and codec | Length-delimited envelope, section, and chunk framing. |
| `tidefs-block-allocator` | Storage core | Block bitmap allocator and write-admission space accounting. |
| `tidefs-block-kmod` | Kernel | Linux block-device module for TideFS block export. |
| `tidefs-block-volume-adapter-core` | Block adapter | Pure block-volume request and descriptor mapping core. |
| `tidefs-block-volume-adapter-ublk-control-runtime` | Block adapter | Linux ublk control-device runtime and queue boundary. |
| `tidefs-btree` | Storage core | Generic `no_std` B+tree used by indexes, queues, and maps. |
| `tidefs-cache-core` | Storage core | Cache-lattice registry, eviction, and coherency logic. |
| `tidefs-checksum-tree` | Maintenance | Incremental Merkle checksum tree for integrity checking and scrub. |
| `tidefs-chunk-shipper` | Distributed storage (not release proof) | Cross-node chunk staging, streaming, and receive orchestration. |
| `tidefs-claim-ledger` | Control and policy | Runtime claim ledger for capacity and resource admission. |
| `tidefs-cleanup-engine` | Maintenance | Deferred cleanup executor with checkpointing and intent-log safety. |
| `tidefs-cleanup-job-core` | Maintenance | `IncrementalJob` implementation for deferred cleanup work. |
| `tidefs-cleanup-queue-core` | Maintenance | B+tree-backed queue for deferred cleanup records. |
| `tidefs-clock-timing` | Control and policy | Hybrid logical clock, drift, timeout, and fence utilities. |
| `tidefs-cluster` | Distributed storage (not release proof) | Deterministic cluster lease and membership transition helpers. |
| `tidefs-commit_group` | Storage core | Transaction-group commit pipeline between mutations and stable storage. |
| `tidefs-compaction` | Maintenance | Background compaction job for derived and refcount catalog pages. |
| `tidefs-compression` | Maintenance | zstd and LZ4 object compression wrapper. |
| `tidefs-coordination-strategy` | Control and policy | Epoch-fenced coordination-strategy switch protocol. |
| `tidefs-data-cleaner` | Maintenance | Refcount-delta cleaner that frees zero-refcount segments. |
| `tidefs-dataset-catalog` | Storage core | Dataset path-to-id catalog with stable IDs across renames. |
| `tidefs-dataset-feature-flags` | Storage core | Runtime dataset feature compatibility and enablement gate. |
| `tidefs-dataset-lifecycle` | Storage core | Dataset `ACTIVE`, `DESTROYING`, and `TOMBSTONE` runtime transitions. |
| `tidefs-dataset-properties` | Storage core | Inherited dataset property framework and typed property checks. |
| `tidefs-dedup` | Maintenance | Post-process duplicate extent scanner and DDT planner. |
| `tidefs-derived-catalog` | Storage core | Cached derived directory and catalog views over authoritative indexes. |
| `tidefs-device-removal` | Storage core | Device decommission state machine and evacuation planner. |
| `tidefs-dir-index` | Storage core | Persistent directory index with inline and B+tree representations. |
| `tidefs-durability-layout` | Distributed storage (not release proof) | Mirror and erasure durability policy descriptors across failure domains. |
| `tidefs-encryption` | Maintenance | ChaCha20-Poly1305 object encryption wrapper. |
| `tidefs-erasure-coded-store` | Distributed storage (not release proof) | Local object store wrapper that stripes data with erasure coding. |
| `tidefs-erasure-coding` | Maintenance | Reed-Solomon erasure-coding engine. |
| `tidefs-extent-map` | Storage core | Per-file byte-range to physical extent map. |
| `tidefs-flow-commit-coordinator` | Distributed storage (not release proof) | Distributed flow commit receipt and state advancement layer. |
| `tidefs-frame` | Schema and codec | Compact per-object compression frame format. |
| `tidefs-gc-pin-set` | Maintenance | Pinned traversal roots that protect datasets during GC and destroy. |
| `tidefs-geometry-convert` | Storage core | Online durability-geometry conversion over locator entries. |
| `tidefs-incremental-job-core` | Maintenance | Shared `IncrementalJob` trait and checkpoint contract. |
| `tidefs-inode-attributes` | Storage core | Inode attributes, stat translation, xattrs, and link counts. |
| `tidefs-inode-table` | Storage core | Inode-number registry, allocator, lookup, and lifecycle table. |
| `tidefs-intent-log` | Storage core | Mutating filesystem intent records and framed append buffer. |
| `tidefs-kernel-cutover-runtime` | Kernel | Userspace cutover, fence, dry-run, and rollback executor for kernel transition. |
| `tidefs-kernel-storage-io` | Kernel | Kernel-portable block I/O traits and `KernelPoolCore` primitives. |
| `tidefs-kmod-posix-vfs` | Kernel | Linux POSIX VFS module delegating to the `VfsEngine` boundary. |
| `tidefs-lease` | Distributed storage (not release proof) | Quorum-backed distributed leases and fencing. |
| `tidefs-lease-manager` | Distributed storage (not release proof) | Lease grant, revoke, renew, and failure-revocation lifecycle. |
| `tidefs-local-filesystem` | Storage core | Userspace filesystem core: namespace, file data, txg, snapshots, and recovery. |
| `tidefs-local-object-store` | Storage core | Durable local object and segment store with pool-device backing. |
| `tidefs-locator-table` | Storage core | Logical-to-physical extent locator table. |
| `tidefs-lock-service` | Distributed storage (not release proof) | Sharded lock service protocol and phase-1 leader runtime. |
| `tidefs-membership-epoch` | Distributed storage (not release proof) | Deterministic membership epoch and placement model. |
| `tidefs-membership-live` | Distributed storage (not release proof) | Live SWIM-style membership, gossip, epoch, and transport session runtime. |
| `tidefs-membership-types` | Types | `no_std` membership service wire protocol types. |
| `tidefs-namespace` | Storage core | Namespace path resolution and create, lookup, unlink, and rename operations. |
| `tidefs-node-drain` | Distributed storage (not release proof) | Node drain, migration, fencing, and decommission flow. |
| `tidefs-node-join` | Distributed storage (not release proof) | Node admission, staged promotion, discovery, and state transfer. |
| `tidefs-object-io` | Storage core | Offset read/write bridge between extent maps and object store. |
| `tidefs-online-defrag` | Maintenance | Incremental extent-map defragmentation service. |
| `tidefs-orphan-index` | Storage core | Persistent index for nlink-zero and orphan recovery. |
| `tidefs-partition-runtime` | Distributed storage (not release proof) | Network partition detection, split-brain prevention, and healing. |
| `tidefs-permission` | POSIX/FUSE | Unix mode, ACL, and xattr namespace access decisions. |
| `tidefs-placement-planner` | Distributed storage (not release proof) | Replica target computation from policy and failure domains. |
| `tidefs-placement-runtime` | Distributed storage (not release proof) | Executes placement plans with budgets and conflict handling. |
| `tidefs-pool-allocator` | Storage core | Pool and metaslab allocator above segment free maps. |
| `tidefs-pool-import` | Storage core | Pool activation, superblock verification, and intent replay. |
| `tidefs-pool-scan` | Storage core | Device scan, label read, and topology report for pools. |
| `tidefs-posix-acl` | POSIX/FUSE | POSIX ACL binary xattr codec and evaluator. |
| `tidefs-posix-filesystem-adapter-reply` | POSIX/FUSE | FUSE reply construction and commit lanes. |
| `tidefs-posix-filesystem-adapter-workers-io` | POSIX/FUSE | FUSE read/writeback worker-pool support. |
| `tidefs-posix-filesystem-adapter-workers-locks` | POSIX/FUSE | FUSE lock-wait worker-pool support. |
| `tidefs-posix-guarantee-verifier` | Proof harness | Checks whether a coordination strategy satisfies POSIX operation guarantees. |
| `tidefs-posix-semantics` | POSIX/FUSE | Pure POSIX helpers for sticky, setgid, killpriv, and relatime behavior. |
| `tidefs-quorum-write` | Distributed storage (not release proof) | Deterministic prepare, transfer, commit, and witness write protocol. |
| `tidefs-quorum-write-runtime` | Distributed storage (not release proof) | Runtime quorum-write coordinator for `LocalFileSystem` writes. |
| `tidefs-rebalance-planner` | Distributed storage (not release proof) | Capacity rebalance planner with movement budgets and anti-affinity. |
| `tidefs-rebuild-planner` | Distributed storage (not release proof) | Loss and suspect rebuild flow planner. |
| `tidefs-rebuild-runtime` | Distributed storage (not release proof) | Async rebuild, backfill, and rebalance executor. |
| `tidefs-receive-stream` | Distributed storage (not release proof) | Receive-side VFSSEND and chunk reassembly verification. |
| `tidefs-reclaim` | Maintenance | Segment reclaim pipeline for the local object store. |
| `tidefs-reclaim-queue-core` | Maintenance | B+tree reclaim queue and dirty writeback engine. |
| `tidefs-recovery-loop` | Maintenance | Failure recovery loop from detection through verification. |
| `tidefs-relocation-planner` | Distributed storage (not release proof) | Relocation planner for tiering, drain, reclaim, and policy changes. |
| `tidefs-replica-health` | Distributed storage (not release proof) | Per-chunk replica health, lag, and flap suppression. |
| `tidefs-replicated-object-store` | Distributed storage (not release proof) | Multi-replica object-store wrapper with quorum write coordination. |
| `tidefs-replication` | Distributed storage (not release proof) | Replication fanout, quorum ACK, degraded read, and policy runtime. |
| `tidefs-replication-model` | Distributed storage (not release proof) | Deterministic replication topology and degraded read/write model. |
| `tidefs-reserve-ledger` | Control and policy | Reserve guarantees, pressure states, and budget-domain runtime. |
| `tidefs-schema-codec-posix-filesystem-adapter` | Schema and codec | Fixed-width codecs for POSIX adapter wake and receipt records. |
| `tidefs-schema-codec-vfs` | Schema and codec | VFS errno and operation codec hooks. |
| `tidefs-scrub-core` | Maintenance | Background checksum scrub and repair scheduling core. |
| `tidefs-secret-key-policy-runtime` | Control and policy | Secret-key seal, lease, rotate, revoke, activate, and recover runtime. |
| `tidefs-segment-cleaner` | Maintenance | Segment cleaner that compacts live records and frees dead segments. |
| `tidefs-send-stream` | Distributed storage (not release proof) | VFSSEND2 incremental dataset send stream writer. |
| `tidefs-shard-group` | Distributed storage (not release proof) | Shard group lifecycle and erasure-coded shard layout. |
| `tidefs-snapshot-pruner` | Maintenance | Snapshot auto-pruner with retention policy. |
| `tidefs-space-accounting` | Storage core | Logical and physical counters, statfs, ENOSPC, and capacity gates. |
| `tidefs-spacemap-allocator` | Storage core | Deterministic segment-level free-space allocator. |
| `tidefs-tdma-scheduler` | Distributed storage (not release proof) | Per-object TDMA slot scheduler for contending nodes. |
| `tidefs-trace-oracle` | Proof harness | Deterministic operation recording and replay oracle. |
| `tidefs-transport` | Distributed storage (not release proof) | TCP/RDMA transport, sessions, lanes, envelopes, and reconnection. |
| `tidefs-two-node-harness` | Proof harness | Deterministic two-node storage and transport scenario harness. |
| `tidefs-types-cache-lattice-core` | Types | Cache lattice value types. |
| `tidefs-types-claim-ledger-core` | Types | Claim, reserve, and witness value types. |
| `tidefs-types-control-plane-core` | Types | Control-plane scalar and newtype core. |
| `tidefs-types-dataset-feature-flags-core` | Types | Dataset feature-flag authority types. |
| `tidefs-types-dataset-lifecycle-core` | Types | Dataset lifecycle authority types. |
| `tidefs-types-deferred-cleanup-core` | Types | Deferred cleanup work-item records. |
| `tidefs-types-extent-map-core` | Types | Extent map authority records. |
| `tidefs-types-incremental-job-core` | Types | `IncrementalJob` budget, checkpoint, and progress records. |
| `tidefs-types-orphan-index-core` | Types | Orphan index key, cursor, and stat types. |
| `tidefs-types-package-profile-catalog` | Types | Build profile, package, and capability enums. |
| `tidefs-types-polymorphic-directory-index-core` | Types | Directory-index representation policy types. |
| `tidefs-types-polymorphic-xattr-core` | Types | xattr storage representation policy types. |
| `tidefs-types-pool-label-core` | Types | On-device pool label and device-class records. |
| `tidefs-types-posix-filesystem-adapter-core` | Types | POSIX adapter product-wake receipt types. |
| `tidefs-types-publication-pipeline-core` | Types | Publication ticket and lifecycle types. |
| `tidefs-types-reclaim-queue-core` | Types | Reclaim queue entry, stat, and error types. |
| `tidefs-types-response-registry-core` | Types | Response envelope, index, and recall types. |
| `tidefs-types-secret-key-policy-core` | Types | Secret-key policy record types. |
| `tidefs-types-space-accounting-core` | Types | Space counter, domain, and deadlist types. |
| `tidefs-types-transport-session` | Types | Transport session, cohort, and lane model types. |
| `tidefs-types-vfs-core` | Types | Portable VFS scalar and fixed record types. |
| `tidefs-types-vfs-owned` | Types | Alloc-backed owned mirrors for VFS boundary values. |
| `tidefs-ublk-abi` | Block adapter | Typed Linux ublk userspace ABI constants. |
| `tidefs-verification-engine` | Maintenance | Replicated chunk and segment verification engine. |
| `tidefs-vfs-engine` | VFS boundary | `VfsEngine` trait and canonical operation boundary. |
| `tidefs-vfs-rpc` | VFS boundary | `VfsEngine` RPC forwarding protocol over transport. |
| `tidefs-witness-set` | Distributed storage (not release proof) | Quorum witness selection and receipt tracking. |
| `tidefs-workload` | Proof harness | Workload signature and materialization classifier. |
| `tidefs-xattr-storage` | Storage core | Polymorphic xattr storage runtime. |

## Deletion / Archive Candidates

No deletion should happen from this README alone. Each candidate below needs an
issue-backed cleanup decision because deleted or archived subjects must not keep
living on the active authority path.

| Candidate | Basis | Disposition |
| --- | --- | --- |
| Remaining non-workspace crate-local fuzz harnesses | These have `Cargo.toml` files but are intentionally excluded from root workspace membership because cargo-fuzz targets are built separately. | Keep standalone-checkable while they cover parser or on-disk format inputs; delete when coverage is redundant. |
| Zero-reverse workspace review set: `tidefs-vfs-rpc`, `tidefs-workload`, `tidefs-secret-key-policy-runtime`, `tidefs-types-package-profile-catalog` | These are workspace members with zero in-workspace reverse dependencies. Some may be entrypoints, public surfaces, or issue-backed future work. | Review-only, not deletion by default. Require a concrete owner issue to classify each as live, planned, archived, or removable. The standalone `tidefs-posix-filesystem-adapter-runtime` crate was removed after review because the daemon owns the live runtime module. |
