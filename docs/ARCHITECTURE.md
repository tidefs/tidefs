# TideFS Architecture

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Layer Model

TideFS is organized as a stack of library crates. Each layer builds on the one
below. The FUSE and ublk daemons sit at the top as userspace harnesses; all
layers below them are kernel-bound.

```
Userspace (harness)
  apps/tidefs-posix-filesystem-adapter-daemon    FUSE mount daemon
  apps/tidefs-block-volume-adapter-daemon         ublk block daemon
  apps/tidefsctl                                  management CLI
  apps/tidefs-filesystem-demo                     Filesystem demo
  apps/tidefs-store-demo                          Object store demo

POSIX Adapter Layer (harness)
  tidefs-posix-filesystem-adapter-reply           FUSE reply construction
  tidefs-posix-filesystem-adapter-workers-io      I/O dispatch worker
  tidefs-posix-filesystem-adapter-workers-locks   Lock dispatch worker
  tidefs-fuser                                    Vendored FUSE protocol binding

Filesystem Layer (product)
  tidefs-vfs-engine                               VFS operation dispatch
  tidefs-namespace                                Path resolution, hard links, symlinks, rename
  tidefs-inode-table                              In-memory inode table
  tidefs-local-filesystem                         Inode records, directories, chunked files
  tidefs-dir-index                                Directory entries (micro-list, B-tree)
  tidefs-extent-map                               File extent mapping (hole/unwritten/data)
  tidefs-object-io                                Object read/write offset bridge

Storage Layer (product)
  tidefs-local-object-store                       Content-addressed BLAKE3-256 storage
  tidefs-block-allocator                          Free-space accounting
  tidefs-space-accounting                         Space counters, quotas
  tidefs-commit_group                             Transaction group commit
  tidefs-intent-log                               Intent log for crash recovery
  tidefs-pool-import                              Pool import, committed-root recovery
  tidefs-pool-allocator                           Pool-level allocation
  tidefs-segment-cleaner                          Segment cleaning (model surface; live physical reclaim requires receipt-bound dead-object drains)
  tidefs-compaction                               Live-data relocation, segment merge
  tidefs-reclaim-queue-core                       Freed-extent reclaim queue
  tidefs-cleanup-queue-core                       Persistent cleanup work queue
  tidefs-dataset-catalog                          Dataset lifecycle, create/list
  tidefs-dataset-lifecycle                        Dataset state machine
  tidefs-dataset-properties                       Property framework, inheritance
  tidefs-dataset-feature-flags                    Per-dataset feature gating
  tidefs-spacemap-allocator                       Persistent free-block spacemap
  tidefs-reserve-ledger                           Reserve ledger for critical writes
  tidefs-geometry-convert                         Pool geometry conversion (mirror<->EC)
  tidefs-dedup                                    Dedup model crate (not live write-path authority)

Integrity Layer (product)
  tidefs-checksum-tree                            BLAKE3-256 merkle tree verification
  tidefs-compression                              Zstd/LZ4 per-object compression
  tidefs-encryption                               ChaCha20-Poly1305 per-object encryption
  tidefs-reclaim                                  GC reclamation
  tidefs-scrub-core                               BLAKE3-verified background scrub
  tidefs-anti-entropy-auditor                     Merkle tree exchange, cross-node consistency
  tidefs-verification-engine                      Checksum verification dispatch
  tidefs-btree                                    B-tree primitives
  tidefs-frame                                    Framed I/O
  tidefs-erasure-coding                           Erasure coding encode/decode
  tidefs-erasure-coded-store                      Erasure-coded object storage

Permission Layer (product)
  tidefs-permission                               POSIX permission checking
  tidefs-posix-acl                                POSIX ACL encode/decode/evaluate
  tidefs-xattr-storage                            Extended attributes
  tidefs-posix-semantics                          POSIX behavior definitions
  tidefs-inode-attributes                         Inode attribute types
  tidefs-lock-service                             BSD flock, POSIX advisory locks

Transport Layer (product)
  tidefs-transport                                Session handshake, encrypted sessions
  tidefs-chunk-shipper                            Reliable chunk shipping, fragmentation
  tidefs-send-stream                              Segment framing, BLAKE3-authenticated send
  tidefs-replication-model                        Failure-domain topology, placement constraints
  tidefs-durability-layout                        Durability layout policy, replica distribution
  tidefs-replicated-object-store                  Replicated object read/write dispatch
  tidefs-replication                              Replication dispatch and tracking
  tidefs-replica-health                           IO-error-driven health tracker
  tidefs-placement-planner                        Deterministic object-to-node placement
  tidefs-placement-runtime                        Placement dispatch with session binding

Multi-Node Layer (product)
  tidefs-membership-epoch                         Epoch proposal, vote, commit protocol
  tidefs-membership-live                          Live membership, failure detection, fencing, transport session lifecycle, seed-peer bootstrap discovery
  tidefs-membership-types                         Membership type definitions
  tidefs-node-join                                Node-join protocol handshake
  tidefs-node-drain                               Node drain and evacuation
  tidefs-witness-set                              Quorum selection, persistence, verification
  tidefs-lease                                    Lease grant protocol
  tidefs-lease-manager                            Lease lifecycle management
  tidefs-tdma-scheduler                           TDMA slot allocator, clock sync
  tidefs-quorum-write                             Quorum write coordination
  tidefs-quorum-write-runtime                     Quorum write runtime dispatch
  tidefs-contention-detector                      Lock/lease contention detection
  tidefs-coordination-strategy                    Coordination strategy selection

Rebuild & Self-Healing Layer (product)
  tidefs-rebuild-runtime                          Async rebuild/backfill/rebalance engine
  tidefs-rebuild-planner                          Rebuild planning and prioritization
  tidefs-rebalance-planner                        Capacity rebalance planning
  tidefs-background-scheduler                     Background job scheduling
  tidefs-incremental-job-core                     Incremental job framework
  tidefs-relocation-planner                       Extent relocation planning
  tidefs-device-removal                           Device removal planning, evacuation
  tidefs-data-cleaner                             Data cleaning (model surface; not wired into mounted runtime)

Kernel Bridge Layer (product)
  tidefs-block-kmod                               Block-volume kernel module (K7-08)
  tidefs-kmod-posix-vfs                           POSIX VFS kernel module (K7-05)
  tidefs-kernel-cutover-runtime                   Userspace-to-kernel cutover runtime (K7-11)

```

## Runtime Mode Authority

ADR-0007 defines TideFS runtime modes for Linux-facing access surfaces. The
mode boundary is an architectural contract, not a current implementation claim:
local and clustered deployments are both intended product modes, and cluster
coordination must be scoped to the clustered modes that require it.

| Surface | Mode | Coordination authority |
|---|---|---|
| POSIX filesystem | local | In-process mount/session state, local advisory locks, local COMMIT_GROUP and cache coordination |
| POSIX filesystem | clustered | MEMBERSHIP, lease, and LOCK services plus per-node local locks under cluster leases |
| Block-volume export | local | Local export admission, local flush/exactness receipts, one admitted writable export authority by default |
| Block-volume export | clustered | MEMBERSHIP, lease/authority-domain fencing, placement receipts, reserve escrow, and explicit failover or multi-writer admission |

The cluster LOCK service is therefore not the default local POSIX or local
block hot-path authority. A future implementation may share code between
local and clustered paths only when the local path remains in-process and
validated as non-regressing for local latency, throughput, and POSIX/block
semantics.

The clustered POSIX LOCK forwarding boundary is specified in
`docs/design/clustered-posix-lock-forwarding-boundary.md`. It names the mounted
clustered owner that supplies committed dataset mount identity, membership
epoch, term, and LOCK transport while keeping the existing local FUSE/VFS lock
dispatch in-process.

## Data Flow

### Read Path

1. FUSE daemon receives READ request from kernel
2. Vendored `fuser` and adapter runtime parse the FUSE request
3. workers-io dispatches to VfsEngine::read()
4. VFS engine looks up inode, resolves file handle
5. Local filesystem maps offset to extents via extent-map
6. Extent map returns object keys for data blocks
7. Object store fetches content-addressed objects
8. Compression/encryption layers unwrap payload
9. Reply goes back through FUSE daemon to kernel

### Write Path

1. FUSE daemon receives WRITE request from kernel
2. Vendored `fuser`, adapter runtime, and workers-io dispatch
4. Local filesystem buffers write in intent log
5. On fsync or commit_group commit: dirty pages flushed
6. Content split into chunks, each BLAKE3-hashed
7. Compressed (zstd/LZ4), optionally encrypted
8. Stored in object store with content-addressed key
9. Extent map updated with new object key references
10. CommitGroup committed atomically

### Mount/Recovery

1. Pool opened from device(s), superblock read
2. Object store segment files scanned, index rebuilt
3. Authenticated committed root verified (BLAKE3-256 keyed)
4. Local filesystem replayed: inode table, directory tree
5. Intent log replayed for uncommitted writes
6. Namespace layer populated for path resolution
7. FUSE daemon ready to serve requests

## Key Design Decisions

### Content-Addressed Storage

Every data object is identified by its BLAKE3-256 hash. This means:
- Duplicate writes are idempotent (same content = same key)
- Integrity is inherent (hash mismatch = corruption detected)
- Snapshots are cheap (just pin object references)
- Send/receive is efficient (send only new object keys)

### Transaction Groups (CommitGroup)

All mutations are grouped into transaction groups. A commit_group commits atomically:
either all changes in the group are durable, or none are. This provides
crash consistency without fsck.

### Extent-Based File Layout

Files are not stored as contiguous byte ranges. Instead, each file is a
sequence of extents (offset + length + object key). This enables:
- Sparse files (holes consume no storage)
- Efficient random writes (only changed extents are rewritten)
- Snapshot sharing (extents can be shared across snapshots)
- Inline compression and encryption (per-extent payload)

### BLAKE3-256 Everywhere

A single hash function is used for all integrity:
- Object keys (content addressing)
- Checksum tree nodes (merkle verification)
- Root authentication (keyed hash for pool identity)
- Intent log records

This eliminates algorithm negotiation, simplifies the code, and provides
hardware-accelerated performance on modern CPUs.

## Crate Inventory

### Kernel-Bound Product Crates

Core product crates that implement the filesystem and storage stack.

| Crate | Lines | Purpose |
|---|---|---|
| tidefs-local-filesystem | 53,993 | Inode records, directories, chunked files, snapshots, send/recv |
| tidefs-local-object-store | 18,737 | Content-addressed storage, segment files, GC |
| tidefs-extent-map | 7,986 | File extent mapping (hole/unwritten/data tristate) |
| tidefs-dir-index | 6,274 | Directory entries (micro-list + B-tree) |
| tidefs-vfs-engine | 5,026 | VFS operation dispatch engine |
| tidefs-inode-table | 4,553 | In-memory inode table |
| tidefs-block-allocator | 3,543 | Free-space accounting, allocation |
| tidefs-namespace | 3,486 | Path resolution, hard links, symlinks, rename |
| tidefs-posix-acl | 3,451 | POSIX ACL encode/decode/evaluate |
| tidefs-permission | 2,558 | Permission checking |
| tidefs-space-accounting | 2,464 | Space counters, quotas |
| tidefs-xattr-storage | 2,165 | Extended attributes |
| tidefs-commit_group | 2,005 | Transaction group commit |
| tidefs-btree | 1,500 | B-tree primitives |
| tidefs-object-io | 1,547 | Object read/write offset bridge |
| tidefs-compression | 1,210 | Zstd/LZ4 per-object compression |
| tidefs-posix-semantics | 940 | POSIX behavior definitions |
| tidefs-reclaim | 822 | GC reclamation |
| tidefs-frame | 613 | Framed I/O |
| tidefs-intent-log | — | Intent log crash recovery |
| tidefs-pool-import | — | Pool import, committed-root recovery |
| tidefs-pool-allocator | — | Pool-level allocation |
| tidefs-segment-cleaner | — | Segment cleaning (model; live in LocalObjectStore) |
| tidefs-compaction | — | Live-data relocation |
| tidefs-reclaim-queue-core | — | Freed-extent reclaim queue |
| tidefs-cleanup-queue-core | — | Persistent cleanup work queue |
| tidefs-dataset-catalog | — | Dataset lifecycle |
| tidefs-dataset-lifecycle | — | Dataset state machine |
| tidefs-dataset-properties | — | Property framework |
| tidefs-dataset-feature-flags | — | Per-dataset feature gating |
| tidefs-spacemap-allocator | — | Persistent free-block spacemap |
| tidefs-reserve-ledger | — | Reserve ledger |
| tidefs-geometry-convert | — | Pool geometry conversion |
| tidefs-dedup | — | Dedup model crate (live authority in tidefs-local-filesystem) |
| tidefs-scrub-core | — | Background scrub engine |
| tidefs-anti-entropy-auditor | — | Merkle tree exchange |
| tidefs-erasure-coding | — | Erasure coding |
| tidefs-erasure-coded-store | — | Erasure-coded storage |

### POSIX Adapter Crates (harness, not kernel-bound)

| Crate | Purpose |
|---|---|
| tidefs-posix-filesystem-adapter-reply | FUSE reply construction |
| tidefs-posix-filesystem-adapter-workers-io | I/O dispatch |
| tidefs-posix-filesystem-adapter-workers-locks | Lock dispatch |
| tidefs-fuser | FUSE handler helpers (fsync, mkdir, rename, link, symlink, setattr) |
| tidefs-cache-core | Cache coherency core types |

### Types Crates (shared type definitions)

The `tidefs-types-*` crates provide shared record types, enums, and constants
used across the product and adapter layers. Current membership and kernel
compatibility status must come from Cargo metadata; older K7-03 inventories
included deleted scaffold roots and are no longer package authority.

### Transport & Multi-Node Crates (product)

| Crate | Purpose |
|---|---|
| tidefs-transport | Session handshake, encrypted sessions, close receipts |
| tidefs-chunk-shipper | Reliable chunk shipping, fragmentation, reassembly |
| tidefs-send-stream | Segment framing, BLAKE3-authenticated send |
| tidefs-replication-model | Failure-domain topology, placement constraints |
| tidefs-durability-layout | Durability layout policy |
| tidefs-replicated-object-store | Replicated object dispatch |
| tidefs-replication | Replication tracking |
| tidefs-replica-health | IO-error-driven health tracker |
| tidefs-placement-planner | Deterministic object-to-node placement |
| tidefs-placement-runtime | Placement dispatch with session binding |
| tidefs-membership-epoch | Epoch proposal/vote/commit protocol |
| tidefs-membership-live | Live membership, failure detection, transport session lifecycle |
| tidefs-node-join | Node-join protocol handshake |
| tidefs-node-drain | Node drain and evacuation |
| tidefs-witness-set | Quorum selection and persistence |
| tidefs-lease | Lease grant protocol |
| tidefs-lease-manager | Lease lifecycle management |
| tidefs-tdma-scheduler | TDMA slot allocator |


### Apps (userspace binaries)

| App | Purpose |
|---|---|
| tidefs-posix-filesystem-adapter-daemon | FUSE mount daemon |
| tidefs-block-volume-adapter-daemon | ublk block device daemon |
| tidefsctl | Management CLI |
| tidefs-filesystem-demo | Filesystem demo |
| tidefs-store-demo | Object store demo |
| tidefs-storage-node | Storage node daemon |
| tidefs-scrub | Scrub/repair CLI |

## Historical Workspace Authority Review

> Historical review input for TFR-002/TFR-019: this section is not current
> package authority. Use `docs/workspace-package-classification.md` for current
> workspace membership, package roles, and delete/archive classifications.

This section was previously written as the controlling workspace authority for
TideFS package families. It now remains review input only. The current package
authority is `docs/workspace-package-classification.md`; deleted scaffold type
roots and their old dependency chains are intentionally not repeated here.

### Historical Package Family Classification

The table below is a historical family taxonomy, not a current package list:

| Family | Historical classification | Historical workspace status |
|---|---|---|
| Product core (`tidefs-*` storage, filesystem, integrity, permission layers) | Product-critical | In workspace |
| Userspace harness (`tidefs-posix-filesystem-adapter-*`, `tidefs-block-volume-adapter-*`, daemons) | Product-critical | In workspace |
| Operator/query utility (`tidefsctl`, CLI surfaces) | Product-critical | In workspace |
| Bounded mirror (`apps/` demo, harness, and tool binaries) | Product-critical | In workspace |
| Kernel bridge (`tidefs-kmod-*`, `tidefs-block-kmod`, `tidefs-kernel-cutover-runtime`) | Product-critical | In workspace |
| Historical scaffold families | Deleted or stale review input | Not current package authority; see `docs/workspace-package-classification.md` |
| Kernel implementation (`kmod/`) | Product-critical (separate Kbuild tree) | In workspace as path member only; compiled via out-of-tree Kbuild |

### Scaffold Crate Disposition

The following lists are retained as historical review input. Current package
membership is not governed here; use `docs/workspace-package-classification.md`
and Cargo metadata. The deleted-root list and dependency evidence now live in
git history, the review register, and the package-classification table rather
than in this current architecture overview.

### Anti-Regression Rule

No new crate may be added to the workspace under a historical-scaffold family
prefix (`control-plane-*`, `policy-authority-*`, `observe-*`, `response-registry-*`,
`truth-view-*`, `shadow-pilot-*`) without an explicit issue-backed package
authority update in `docs/workspace-package-classification.md`. Historical
review notes in this document do not authorize scaffold recovery.

## Incumbent Comparison Boundary

The ZFS and CephFS comparison sections below are imported historical design
input, not current TideFS capability, performance, reliability, maturity,
feature-completeness, or successor claims. The "Where TideFS is ahead" rows
describe intended architectural differences, not validated product advantages.
The "gaps to close" rows describe work that remains deferred or unvalidated.
No statement in these comparison sections may be cited as current TideFS
product capability. Any future product-facing comparison must name a #875
claim id and carry the comparator evidence required by #928/#930.

## Comparison With ZFS

### Where TideFS is ahead

**Single hash function**: TideFS uses BLAKE3-256 for everything (object keys,
checksums, root auth, intent log). ZFS uses SHA-256 for checksums by default
with optional edonr/skein. Single-algorithm eliminates negotiation, simplifies
hardware acceleration, and reduces attack surface.

**Content-addressed object store**: TideFS identifies every data block by its
content hash. Duplicate writes are naturally coalesced. ZFS uses block pointers
with separate checksums; dedup requires a separate dedup table (DDT) with
significant memory cost.

**Extent-based layout with tristate**: TideFS extents track hole/unwritten/data
at the extent-map level. ZFS tracks holes implicitly through block pointer
absence and unwritten extents through a separate mechanism. The tristate model
gives cleaner fallocate, sparse file, and truncate semantics.

**No fsck by design**: TideFS commits in transaction groups with atomic
all-or-nothing semantics. ZFS also avoids fsck through copy-on-write, but
its on-disk format is more complex (root_records, multiple block pointer trees).

**Simpler on-disk format**: TideFS has three core on-disk structures (segment
files, extent maps, directory indexes). ZFS has root_records, block pointer
trees, space maps, DDT, and more. Simpler format means fewer bugs and faster
recovery.

### Where ZFS is ahead (gaps to close)

**Production maturity**: ZFS has 20 years of production deployment. TideFS is
in active development with no production deployment.

**Pool import/export**: ZFS has robust pool import/export. TideFS pool-import

**ARC memory management**: ZFS ARC is battle-tested with sophisticated
pressure response. TideFS has a basic ARC implementation.

**ZIL/LOG_DEVICE**: ZFS has a separate intent log device for synchronous writes.
TideFS intent log is implemented but not optimized for separate fast devices.

**Send/receive**: ZFS send/receive is mature. TideFS has local send/receive in
source, plus send-stream (segment framing) and the transport layer for network
data paths; incremental resume and compressed streams remain deferred.

**Administration tooling**: ZFS has `zpool` and `zfs` commands with
comprehensive management. TideFS has `tidefsctl` with basic pool create/list/
status/destroy and device add/remove/list/status.

## Comparison With CephFS

### Where TideFS is ahead

**Simpler architecture**: TideFS is userspace-first with deterministic
multi-node foundations sharing the same codebase. CephFS requires RADOS, MON,
MDS, and OSD daemons even for a basic deployment.

**Content-addressed integrity**: TideFS has inherent per-object integrity
through BLAKE3-256 content addressing. CephFS relies on replication and
scrub for integrity, with checksums as an optional feature.

**No external metadata service**: TideFS has no equivalent of Ceph MDS.
Metadata is stored in the local filesystem, eliminating a separate failure
domain.

**Deterministic snapshots**: TideFS snapshots are content-addressed and
deterministic by construction. CephFS snapshots require coordination
across MDS and OSD.

### Where CephFS is ahead (gaps to close)

**Scale-out**: CephFS scales horizontally across hundreds of nodes. TideFS
multi-node foundations exist (membership, placement, transport, leases,
quorum-write, two-node QEMU harness) but are not yet production-scale.

**Erasure coding**: Ceph has production erasure coding. TideFS has
erasure-coding and erasure-coded-store crates in source; production
certification remains deferred.

**CRUSH placement**: Ceph CRUSH provides deterministic placement across
heterogeneous clusters. TideFS placement-planner provides deterministic
object-to-node placement via BLAKE3 keyed hashing with health tracking;
full heterogeneous topology constraint evaluation remains deferred.

**Production tooling**: Ceph has `ceph` CLI, dashboard, Prometheus integration.
TideFS has basic tooling.

### Product Surface Scope

**No external object service**: TideFS does not expose an S3-compatible,
RADOS, or RGW-style object API. The supported product surfaces are filesystem
(POSIX/FUSE and kernel VFS) and block-volume (ublk/kernel block).
Any future product comparison would be limited to the filesystem (POSIX/FUSE and kernel VFS) and block-volume (ublk/kernel block) surfaces, not object-service compatibility. No successor or parity wording is current until a #875 claim id and #928/#930 comparator evidence exist for those surfaces.
