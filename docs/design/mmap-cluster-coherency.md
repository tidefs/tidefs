# mmap Cluster Coherency: Multi-Node Page-Level Consistency for Memory-Mapped Files, Remote Page Faulting, and RDMA-Based Cacheline Transfer — Design Specification

**Issue**: [#1771](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1771)
**Forgejo**: `codex:claimed`, `kind:design`, `lane:storage-core`, `source:coordinator`
**Prior Issues**: [#1661](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1661) (design), [#1259](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1259) → [#1612](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1612) (design), [#1580](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1580), [#1741](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1741) (tracking), [#1571](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1571) (implementation)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core (data path — Layer 10)
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8-11)
**Blocks**: multi-node mmap workloads, distributed shared buffer pools, cluster-wide shared memory semantics
**Related**: #1184 (coherency profiles), #1213 (VFS Engine/FUSE daemon), #1234 (VFS_RPC), #1211 (daemon memory budget), #1280 (kernel module OW-201)

---

## Revision History

| Date | Issue | Change |
|------|-------|--------|
| 2026-05-05 | #1771 | Canonical design issue; design doc confirmed as sealed authority. No spec changes; Rust implementation deferred to wire-up issues. |
| 2026-05-05 | #1845 | Canonical design issue; doc promoted to current mmap-cluster-coherency design-spec authority. No spec changes; design sealed as of #1259/#1661; Rust implementation deferred to wire-up issues. |
| 2026-05-05 | #1921 | Canonical design issue; doc promoted to current mmap-cluster-coherency design-spec authority. No spec changes; design sealed as of #1259/#1661; Rust implementation deferred to wire-up issues. |
| 2025-11-04 | #1661 | Initial design-spec: 13-section architecture, data structures, algorithms, tradeoffs, integration contracts. |
| 2025-06-02 | #1259 | Original design issue raised and sealed. |


## Abstract

This document defines the mmap cluster coherency model for TideFS: a lease-gated,
multi-node consistency protocol for memory-mapped file pages. It applies the
sharded lease hierarchy from #1248 (directory subtree → inode → byte range) to
kernel page-cache pages, providing correct multi-writer mmap semantics across
cluster nodes. It introduces remote page faulting via the BULK plane (#1229),
cacheline-granularity RDMA transfer for contended pages, sub-page false-sharing
mitigation through 256-byte sector tracking, and lease-revocation writeback
through the intent log (#1252). The integration surface spans FUSE
(#1208), coherency profiles (#1184), and the lock service (#1248).

ZFS has no cluster mmap. CephFS supports mmap but with weak coherency: writes on
one node may be invisible on another for seconds because kernel page-cache
with **correct, high-performance mmap coherency** at sub-10µs remote-fault
latency for RDMA-attached clusters — beating both ZFS and Ceph for distributed
databases, shared-memory applications, and latency-sensitive multi-node workloads.

---

## 1. Problem Statement

### 1.1 mmap in clustered filesystems

`mmap(2)` maps file pages directly into the application's virtual address space.
Loads and stores to the mapped region bypass the read/write syscall path
entirely, hitting the kernel page cache through hardware page faults. This is
the fastest userspace I/O path available, but it creates a coherency problem in
clustered filesystems:

- **Kernel page cache is local.** When node A writes to a mmap'd page, the
  modified data lives only in node A's kernel page cache.
- **No push on store.** A store instruction to a mmap'd address does not trigger
  any syscall, so there is no natural point to propagate the write to other
  nodes.
  on node B until the capability lease expires, making mmap unusable for
  latency-sensitive multi-node applications.

### 1.2 Why ZFS and Ceph fall short

| | ZFS | CephFS | TideFS (this design) |
|---|---|---|---|
| Multi-node writes | N/A (local only) | Weak, seconds of staleness | Correct, lease-gated |
| Remote page fault | N/A | >1ms (network round-trip) | <10µs (RDMA) |
| Cacheline transfer | N/A | Not supported | RDMA atomics |
| Lease-revocation writeback | N/A | Capability expiry flush | Intent-log fast path |
| Torn-write prevention | Bug-prone, commit_group/commit_group gap | Not guaranteed | commit_group-boundary-gated (§1.4) |

### 1.3 Target workloads

1. **Distributed databases** (e.g., shared buffer pool via mmap): multiple nodes
   reading and writing disjoint regions of the same file concurrently.
2. **Shared-memory applications**: two or more nodes cooperating on a common
   mmap'd region with low-latency visibility of writes.
3. **HPC checkpoint/restart**: burst writes to mmap'd files with strong
   consistency on `msync(MS_SYNC)` boundaries.
4. **Machine learning**: parameter-server-like access patterns where gradient
   updates must be visible to all readers within microseconds.

### 1.4 ZFS Anti-Pattern Hardening: mmap Torn-Write Prevention at commit_group Boundaries

ZFS mistake: mmap readers can observe torn (partially-written) data because
properly synchronized. A reader mmap'ing a file being written can see an
intermediate state that never existed at any commit_group commit point — a torn write
visible at the application level.

This is fundamentally a single-node problem, distinct from cluster mmap
coherency, and exists even without a second node. The root cause is that
ZFS's ZPL layer and page cache operations are not atomic with respect to
commit_group boundaries: a writeback can partially populate the page cache mid-commit_group,
exposing an inconsistent view to mmap'd readers.


mmap coherency MUST treat commit_group commit boundaries as the consistency point:

  boundaries.** When a commit_group commits that modified a file with active mmap
  atomically at the commit_group boundary. A reader with an mmap'd region sees either
  the pre-commit_group or post-commit_group state, never an intermediate mix.

  commit that modified the file. This provides the strongest consistency
  guarantee — every commit_group boundary is a visibility barrier. Suitable for
  distributed databases and shared-memory applications where correctness is
  paramount.

  multiple commit_group commits) but MUST still respect commit_group boundaries — the lazy
  preserves the invariant that mmap'd readers never observe a partial commit_group
  state.

- **`cluster` coherency profile:** Inherits `strict` semantics for commit_group
  advance their view of the file atomically at the same commit_group boundary.

- **`auto` coherency profile:** The daemon selects between `strict` and
  `perf` commit_group-boundary behaviour based on observed access patterns, write
  volume, and lease-contention metrics. The invariant that mmap readers
  never see a torn write is maintained regardless of the dynamic selection.

**Implementation sketch:**

The FUSE daemon registers a commit_group-commit callback with the intent log (#1252)
or the write-intent journal. On commit_group commit, for each inode with active mmap
mappings that was modified in the commit_group:

1. Identify the byte ranges modified in the committing commit_group.
2. For each page overlapping those ranges, check `PageCoherencyState`:
   - If status is `DirtyLocal` and the page was written in this commit_group: no
   - If status is `CleanShared` and the page overlaps modified ranges: mark
   application triggers a read fault (§5.1) which fetches the post-commit_group
   data from the writer node.

This mechanism ensures that no TideFS mmap reader ever observes a torn write,
even on a single node — a correctness property that ZFS cannot guarantee and
CephFS only approximates with capability timeouts.

---

## 2. Scope and Non-Scope

### In scope

- Lease-gated mmap coherency model: EXCLUSIVE writer, SHARED reader, no-lease
  states
- Remote page fault protocol: read faults and write-upgrade faults via BULK
  plane (#1229) and lock service (#1248)
- Cacheline-granularity transfer via RDMA atomic operations for contended pages
- Sub-page false-sharing mitigation: 256-byte sector tracking
- Lease revocation page writeback through intent log (#1252)
- FUSE integration: `read_folio`, `writepages`, `FUSE_NOTIFY_INVAL_PAGE`,
  custom `FUSE_NOTIFY` extension for cacheline coherence
- Page-level lease-epoch tagging for staleness detection (#1242)
  (#1208), lock service (#1248), and daemon memory budget (#1211)
- Mmap read-ahead policy under cluster leases

### Explicitly out of scope

- Kernel module (OW-201) implementation (this is a future optimisation; the
  design documents the FUSE path with kernel-module hooks noted)
- Block-volume (ublk) mmap surfaces (ublk uses its own generation-check path)
  transport/RDMA issue rules)
- Persistent memory (PMEM) DAX mmap coherency (distinct from page-cache mmap)
- `MAP_PRIVATE` copy-on-write semantics (standard kernel COW, no cluster
  interaction)
  `MAP_SHARED`)

---

## 3. Architecture Overview

### 3.1 Lease-gated mmap coherency tiers

TideFS applies the three-tier lease hierarchy from #1248 to mmap'd pages:

| Lease type | mmap behaviour |
|---|---|
| SHARED reader lease + SHARED inode lease | Node may cache clean pages; reads are served from local cache when lease-epoch matches. Writes must upgrade to EXCLUSIVE (§5.2) or forward to the writer. |

### 3.2 Component integration diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         TideFS Daemon (#1213)                             │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │          Mmap Coherency Engine (this design)                        │  │
│  │                                                                     │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────┐                   │  │
│  │  │ Page Fault   │  │ Sector       │  │ Lease   │                   │  │
│  │  │ State Machine│  │ Tracker      │  │ Write-  │                   │  │
│  │  │ (read/write) │  │ (256B false  │  │ back    │                   │  │
│  │  │              │  │  sharing)    │  │ Engine  │                   │  │
│  │  └──────┬───────┘  └──────┬───────┘  └────┬────┘                   │  │
│  │         │                 │               │                         │  │
│  │  ┌──────┴─────────────────┴───────────────┴────┐                    │  │
│  │  │         Page Lease-Epoch Tracker             │                    │  │
│  │  │  (per-page lease_epoch for staleness check)  │                    │  │
│  │  └──────────────────────┬──────────────────────┘                    │  │
│  └─────────────────────────┼───────────────────────────────────────────┘  │
│                            │                                              │
│  ┌─────────────┐  ┌────────┴────────┐  ┌─────────────────┐               │
│  │  Cache       │  │  BULK Plane    │  │  Intent Log     │               │
│  │  Hierarchy   │  │  Client (#1229)│  │  Client (#1252) │               │
│  │  (#1226)     │  │  - RDMA READ   │  │  - fast write-  │               │
│  │  - page cache│  │  - RDMA WRITE  │  │    back on      │               │
│  │  - ARC       │  │  - TCP stream  │  │    revocation   │               │
│  └─────────────┘  └─────────────────┘  └─────────────────┘               │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                      FUSE Daemon (#1213)                            │  │
│  │  - read_folio() handler → Page Fault State Machine                 │  │
│  │  - writepages() handler → Lease Writeback Engine                   │  │
│  │  - Custom FUSE_NOTIFY → Cacheline coherency notifications          │  │
│  │  - commit_group-commit callback → Torn-write prevention (§1.4)              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                    Linux Kernel (VFS / FUSE)                        │  │
│  │  - Page fault handler → FUSE read_folio / writepages               │  │
│  │  - Page cache (struct folio) → tagged with lease_epoch             │  │
│  │  - FUSE_NOTIFY_INVAL_PAGE → page eviction + TLB shootdown          │  │
│  │  - Future OW-201: direct kernel bypass                              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Coherency state machine (per-page)

```
                         ┌──────────────────┐
                         │ (no lease or      │
                         │  lease revoked)   │
                         └───────┬──────────┘
                                 │ read fault
                                 ▼
                         ┌──────────────────┐
            ┌────────────│   CLEAN_SHARED   │◄──────────┐
            │            │ (SHARED lease,   │           │
            │            │  remote fetch)   │           │
            │            └───────┬──────────┘           │
            │                    │ write fault           │
            │                    ▼                       │
            │            ┌──────────────────┐           │
            │            │  UPGRADE_PENDING  │           │
            │            │ (lease upgrade    │           │
            │            │  in flight)       │           │
            │            └───────┬──────────┘           │
            │                    │ upgrade granted       │
            │                    ▼                       │
            │            ┌──────────────────┐           │
            │            │   DIRTY_LOCAL    │           │
            │            │ (EXCLUSIVE lease,│           │
            │            │  writable)       │           │
            │            └───────┬──────────┘           │
            │                    │ lease revocation      │
            │                    │ (writeback + inval)   │
            └────────────────────┘                      │
                                 ........................
```

### 3.4 Cacheline-granularity coherency (extension)

For pages in **cacheline-coherent** mode (opt-in per inode via `fcntl` or
dataset feature flag), the coherency model operates at 64-byte cacheline
granularity rather than full-page granularity:

```
Node A writes 8 bytes at offset 128
  │
  ├── Local store hits page cache (page already writable under EXCLUSIVE)
  │
  └── If page is in cacheline-coherent mode:
        └── RDMA atomic write to Node B's registered memory region
              for offset 128..136 (cacheline-aligned 64B)
            Node B's daemon receives RDMA write completion
              └── Updates Node B's local page cache for that cacheline
                  (if page is mapped on Node B)
```

This means Node B, which holds a SHARED lease and has the page mapped read-only,
re-fetch cycle. This is how hardware cache coherency works — TideFS extends it
to distributed nodes for opted-in files.

---

## 4. Data Structures

### 4.1 `PageCoherencyState`

```rust
/// Per-page coherency state tracked in the daemon's mmap coherency engine.
///
/// One instance per page that is currently mmap'd (or recently mmap'd and
/// still tracked). Pages that are unmapped and clean are evicted from this
/// tracker; pages that are unmapped but dirty cannot be evicted until
/// writeback completes.
#[derive(Clone, Debug)]
pub struct PageCoherencyState {
    /// File and offset this page covers.
    pub inode_id: InodeId,
    pub page_index: u64,        // page-aligned offset / PAGE_SIZE

    /// Current coherency status.
    pub status: PageStatus,

    /// Compared against the current lease epoch on access; mismatch
    pub lease_epoch: EpochId,

    /// The lease grant that authorises the current status.
    /// For DIRTY_LOCAL pages, this is the EXCLUSIVE lease.
    /// For CLEAN_SHARED pages, this is the SHARED lease.
    pub authorising_lease_id: u64,

    /// Sub-page sector dirty bitmap (one bit per 256-byte sector).
    /// Only meaningful for DIRTY_LOCAL pages. Tracks which sectors
    /// of this page have been modified locally.
    pub sector_dirty: SectorBitmap,

    /// Timestamp of last state transition (for debugging/observability).
    pub last_transition_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageStatus {
    /// Page is not cached; any access triggers a fault.
    /// Page is cached clean under a SHARED lease; read-only.
    CleanShared,
    /// A lease upgrade is in flight to make this page writable.
    UpgradePending { request_id: u64 },
    /// Page is cached dirty under an EXCLUSIVE lease; writable.
    DirtyLocal,
    /// Lease is being revoked; dirty sectors are being written back.
    WritebackInProgress { request_id: u64 },
}
```

### 4.2 `SectorBitmap`

```rust
/// Tracks dirty state at sub-page granularity.
///
/// A 4KB page contains 16 sectors of 256 bytes each. The bitmap uses
/// one u16 to track which sectors are dirty.
///
/// This is the false-sharing mitigation: two nodes writing to different
/// sectors of the same page do NOT conflict. Only true byte-range overlaps
/// trigger lease revocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectorBitmap(u16);

impl SectorBitmap {
    /// Number of sectors per page (4KB / 256B).
    pub const SECTORS_PER_PAGE: usize = 16;

    /// Sector size in bytes.
    pub const SECTOR_SIZE: usize = 256;

    /// Mark a byte range as dirty.
    pub fn mark_dirty(&mut self, offset_in_page: u64, len: u64);

    /// Check if any sector in the given byte range is dirty.
    pub fn any_dirty_in_range(&self, offset_in_page: u64, len: u64) -> bool;

    /// Check if this bitmap overlaps with another (for conflict detection).
    pub fn overlaps(&self, other: &SectorBitmap) -> bool;

    /// Clear all dirty bits (after writeback completes).
    pub fn clear(&mut self);

    /// Return the set of dirty sector indices.
    pub fn dirty_sectors(&self) -> Vec<usize>;

    /// True if no sectors are dirty.
    pub fn is_clean(&self) -> bool;
}
```

### 4.3 `MmapCoherencyTracker`

```rust
/// The central tracker for all mmap'd pages on this node.
///
/// Backed by a page-indexed map (inode_id → page_index → PageCoherencyState).
/// Integrated with the daemon memory budget (#1211) — the tracker's memory
/// footprint is accounted against the `KernelPinnedDma` memory domain.
pub struct MmapCoherencyTracker {
    /// Per-inode page coherency state.
    pages: HashMap<InodeId, BTreeMap<u64, PageCoherencyState>>,

    /// In-flight lease upgrade requests.
    pending_upgrades: HashMap<u64, UpgradeRequest>,

    /// In-flight writeback operations.
    pending_writebacks: HashMap<u64, WritebackRequest>,

    /// Total number of tracked pages (for memory budget).
    tracked_page_count: usize,

    /// Memory budget for this tracker.
    max_tracked_pages: usize,

    /// Lock service client handle.
    lock_client: Arc<LockServiceClient>,

    /// BULK plane client handle.
    bulk_client: Arc<BulkPlaneClient>,

    /// Intent log client handle.
    intent_log: Arc<IntentLogClient>,

    /// Registered commit_group-commit callback for torn-write prevention (§1.4).
    commit_group_commit_callback: Option<CommitGroupCommitCallback>,
}
```

### 4.4 `CachelineCoherencyRegion` (extension)

```rust
/// Describes a memory region registered for cacheline-coherent access.
///
/// When a file is opened with cacheline-coherent mmap semantics, the daemon
/// registers the mapped pages with the RDMA NIC for direct remote access.
/// Remote nodes can then read or write individual cachelines via RDMA
/// atomics without involving the local CPU.
///
/// This is only meaningful for RDMA-attached clusters.
pub struct CachelineCoherencyRegion {
    /// The inode this region backs.
    pub inode_id: InodeId,

    /// Offset range in the file (page-aligned).
    pub file_offset_start: u64,
    pub file_offset_end: u64,

    /// RDMA memory region key (rkey) for remote access.
    pub rkey: u32,

    /// Virtual address of the registered memory (for local access).
    pub local_addr: u64,

    /// Length of the registered region in bytes.
    pub len_bytes: u64,

    /// Whether this region currently accepts remote writes.
    /// False when the local node holds EXCLUSIVE and is writing;
    /// True when the local node holds SHARED and wants to receive updates.
    pub accepting_remote_writes: bool,
}
```

---

## 5. Algorithms

### 5.1 Read page fault (node holds SHARED lease)

```
Application: load from mmap'd address → hardware page fault
  │
  ▼
Kernel: FUSE read_folio(inode, folio)
  │
  ▼
Daemon: MmapCoherencyEngine::handle_read_fault(inode_id, page_index)
  │
  ├─[1] Lookup PageCoherencyState for (inode_id, page_index)
  │      │
  │      ├─ Found + status == CLEAN_SHARED + lease_epoch matches current
  │      │    → Page is valid, populate folio from local cache, return
  │      │
  │      ├─ Found + lease_epoch mismatch
  │      │    → Page is stale, proceed to remote fetch
  │      │
  │           → Proceed to remote fetch
  │
  ├─[2] Determine source node:
  │      Query lock service: "who holds EXCLUSIVE for inode_id?"
  │
  ├─[3] Issue BULK READ from writer node:
  │      BULK plane OFFER(stream_id, total_len=PAGE_SIZE, mode=RDMA_READ, priority=HIGH)
  │      → ACCEPT → CREDIT → data transfer → DONE
  │      (If RDMA unavailable, falls back to TCP_STREAM)
  │
  ├─[4] Populate local page cache with received data
  │
  ├─[5] Create/update PageCoherencyState:
  │      status = CleanShared
  │      lease_epoch = current lease epoch
  │      authorising_lease_id = current SHARED lease id
  │
  └─[6] Return page to kernel → kernel maps into application address space
```

**Latency budget**: <10µs for RDMA (cacheline warm in remote memory), <100µs
for remote NVMe (cache miss on writer node, fetch from storage).

### 5.2 Write page fault (node holds SHARED lease, needs upgrade)

```
Application: store to mmap'd address → hardware page fault (write to read-only page)
  │
  ▼
Kernel: FUSE writepages or page_mkwrite (FUSE)
  │
  ▼
Daemon: MmapCoherencyEngine::handle_write_fault(inode_id, page_index, offset, len)
  │
  ├─[1] Check PageCoherencyState:
  │      │
  │      ├─ status == DIRTY_LOCAL (EXCLUSIVE held)
  │      │    → Page already writable, just update sector_dirty bitmap, return
  │      │
  │      └─ status == CLEAN_SHARED (SHARED held, need upgrade)
  │           → Proceed to lease upgrade
  │
  ├─[2] Request byte-range EXCLUSIVE lock from lock service:
  │      lock_service.acquire(
  │          domain = ByteRange(inode_id, page_start, page_end),
  │          class = EXCLUSIVE,
  │          blocking = true
  │      )
  │      Set status = UpgradePending { request_id }
  │
  ├─[3] Lock service revokes SHARED from all other nodes:
  │          nodes for this byte range
  │
  ├─[4] Other nodes process revocation (see §5.4)
  │
  ├─[5] Lock service grants EXCLUSIVE to this node
  │
  ├─[6] Update PageCoherencyState:
  │      status = DirtyLocal
  │      lease_epoch = new lease epoch
  │      authorising_lease_id = new EXCLUSIVE lease id
  │
  └─[7] Mark page writable in kernel → application store proceeds
```

**Latency budget**: <50µs for the two-hop lock upgrade (request + grant).

### 5.3 Cacheline-coherent write (no fault)

For files in cacheline-coherent mode, node A writes to a page it already
holds EXCLUSIVE on, and node B has the same page mapped read-only under
SHARED:

```
Node A (EXCLUSIVE writer):              Node B (SHARED reader):
  │                                       │
  store to offset 128                     │
  │                                       │
  ├─ Page already DIRTY_LOCAL             │
  │  → store hits local page cache        │
  │                                       │
  ├─ Check CachelineCoherencyRegion:      │
  │  "is node B accepting remote writes?" │
  │  → Yes (node B has region registered) │
  │                                       │
  ├─ RDMA atomic write:                   │
  │  rkey = B.region.rkey                 │
  │  addr = B.region.local_addr + 128     │
  │  data = 8 bytes written               │
  │                                       │
  │  ───────── RDMA write ──────────────→ │
  │                                       ├─ RDMA NIC writes cacheline
  │                                       │  directly into Node B's memory
  │                                       │
  │                                       ├─ Node B daemon receives
  │                                       │  completion notification
  │                                       │
  │                                       └─ Node B's page cache is now
  │                                          up-to-date at offset 128
  │
  └─ Done. Node B sees the write
     immediately, no page fault.
```

This bypasses the page fault entirely for the remote node. The data moves at
RDMA wire speed (typically <2µs for a cacheline on InfiniBand/ROCE).

### 5.4 Lease revocation + page writeback

When the lock service revokes an EXCLUSIVE lease (because another node
requested it):

```
Lock service → LEASE_REVOKE(inode_id, byte_range)
  │
  ▼
Daemon: MmapCoherencyEngine::handle_lease_revoke(inode_id, byte_range)
  │
  ├─[1] Find all PageCoherencyState entries in byte_range
  │
  ├─[2] For each dirty page:
  │     │
  │     ├─ Set status = WritebackInProgress { request_id }
  │     │
  │     ├─ Write dirty sectors to intent log (#1252):
  │     │   intent_log.append(
  │     │       inode_id, page_index,
  │     │       dirty_sectors, page_data
  │     │   )
  │     │   → intent_log.flush()
  │     │   → intent_log.ack()  // data is durable
  │     │
  │     ├─ Writeback is at 256-byte sector granularity:
  │     │   Only sectors marked dirty in sector_dirty are written.
  │     │   Clean sectors are not touched.
  │     │
  │
  ├─[3] Issue FUSE_NOTIFY_INVAL_PAGE for all affected pages:
  │     → Kernel evicts pages from page cache
  │     → TLB shootdown on all CPUs that mapped the page
  │
  ├─[4] Release lease back to lock service:
  │     lock_service.release(lease_id)
  │
  └─[5] If pages were in cacheline-coherent region:
        → Unregister RDMA region for remote writes
```

**Latency budget**: <500µs for typical dirty page count (tens of pages).

### 5.5 False sharing resolution: sub-page conflict detection

```
Node A: writes to offset 0..255   (sectors 0)
Node B: writes to offset 256..511 (sectors 1)
  │
  ├─ Both nodes request EXCLUSIVE byte-range locks for their respective ranges
  │
  ├─ Lock service checks overlap:
  │   Node A: EXCLUSIVE [0, 256)
  │   Node B: EXCLUSIVE [256, 512)
  │   → Ranges do NOT overlap → both grants succeed
  │
  ├─ Both nodes can write to the same page concurrently
  │   (different sectors)
  │
  └─ SectorBitmap tracks which sectors each node has dirtied
```

**Conflict only when**:
```
Node A: writes to offset 128..384 (sectors 0 and 1)
Node B: writes to offset 256..511 (sector 1)
  │
  → Ranges overlap at sector 1 → conflict detected
  → Lock service revokes one of the leases
```

### 5.6 Lease-epoch staleness detection

Every page in `PageCoherencyState` carries a `lease_epoch` field. The lease
epoch is incremented globally whenever a lease transition occurs for an inode
(grant, revoke, upgrade, downgrade).

```
On every page access:
  current_epoch = lock_service.get_epoch(inode_id)
  if page_state.lease_epoch != current_epoch:
      → Page is stale
```

This is integrated with the generation staleness discipline from #1242: the
`lease_epoch` is a monotonic counter within the lock service's Raft log, and

---

## 6. FUSE Integration

### 6.1 Kernel entry points

| Kernel operation | FUSE handler | Mmap coherency action |
|---|---|---|
| Read page fault | `read_folio(inode, folio)` | Read fault state machine (§5.1) |
| Write page fault | `writepages(inode, wbc)` or page_mkwrite | Write fault state machine (§5.2) |
| `msync(MS_SYNC)` | `fsync` / writepages flush | Flush dirty sectors to intent log; optional lease downgrade |
| `munmap` | `release` / writepages | Flush dirty sectors; release byte-range locks; unregister RDMA region |
| Cacheline notification | Custom `FUSE_NOTIFY` | Update specific cacheline without page eviction |

### 6.2 `FUSE_NOTIFY_INVAL_PAGE` mapping

daemon translates it to a `FUSE_NOTIFY_INVAL_PAGE` call:

```rust
    // 2. Issue FUSE_NOTIFY_INVAL_PAGE(inode, page_index * PAGE_SIZE, PAGE_SIZE)
    // 3. Kernel evicts page from page cache
    // 4. If page was mapped, kernel does TLB shootdown on all CPUs
}
```

### 6.3 Custom `FUSE_NOTIFY` for cacheline coherency

FUSE notification carries the cacheline offset and data:

```rust
/// Custom FUSE notification for cacheline-coherent updates.
///
/// Instead of evicting the entire page, the kernel updates only
/// the affected cacheline in place. Requires a kernel patch or
/// the OW-201 kernel module.
struct FuseNotifyCachelineUpdate {
    inode: u64,
    offset: u64,      // cacheline-aligned offset in file
    len: u16,         // 64 (one cacheline) or multiple
    data: [u8; 64],   // the new cacheline contents
}
```

For the FUSE-only path (no kernel module), the daemon uses a workaround:
temporarily mark the page not-present, let the next access fault, and serve
the updated data from the cacheline-coherency buffer. This adds ~2µs latency
vs. true in-place update but avoids kernel changes.

---

## 7. Integration Contracts

### 7.1 With Lock Service (#1248)

- Mmap coherency engine is a **consumer** of the lock service.
- Byte-range EXCLUSIVE locks are acquired for write faults (§5.2).
- The lease-epoch counter is read from the lock service's Raft state machine.

**Contract**: The lock service MUST deliver LEASE_REVOKE events before granting
a conflicting lease. The mmap engine MUST NOT release a revoked lease until
all dirty pages in the revoked range are written back (§5.4).


  with active mmap mappings.
  cache drop.


### 7.3 With BULK Plane (#1229)

- Read faults that miss local cache are served via BULK READ from the writer
  node (§5.1).
- Cacheline-coherent writes use RDMA WRITE to the reader node's registered
  memory region (§3.4, §5.3).
- Bulk transfer priority is HIGH for page faults (application is blocked).

**Contract**: The BULK plane MUST deliver page-fault data within the latency
budget (<10µs RDMA, <100µs NVMe). If RDMA is unavailable, the BULK plane
MUST fall back to TCP_STREAM.

### 7.4 With Intent Log (#1252)

- Dirty pages on lease revocation are written back to the intent log (§5.4).
  prevention (§1.4).

**Contract**: The intent log MUST acknowledge durability before the mmap engine
releases a revoked lease. Data written to the intent log MUST survive a node
crash and be readable by the next writer node.

### 7.5 With Coherency Profiles (#1184)

- The mmap coherency engine queries the active coherency profile for each
  inode.
  on every access.
  synchronization points only (msync, fsync).
- `auto`: dynamic selection based on observed access patterns.

### 7.6 With Daemon Memory Budget (#1211)

- The `MmapCoherencyTracker`'s memory footprint is accounted against the
  `KernelPinnedDma` memory domain.
- When the tracker hits `max_tracked_pages`, the least-recently-used clean
  pages are evicted (LRU eviction).
- Dirty pages cannot be evicted; if the tracker is full of dirty pages,
  writeback is triggered proactively.

---

## 8. Performance Targets

| Operation | Latency target | Notes |
|---|---|---|
| Read fault from remote RDMA | <10µs | Cacheline warm in remote node's memory |
| Read fault from remote NVMe | <100µs | Cache miss, fetch from storage via BULK plane |
| Write fault lease upgrade | <50µs | 2-hop: request + grant via lock service |
| Lease revocation + writeback | <500µs | Typical dirty page count (tens of pages) |
| Cacheline-coherent write (remote visibility) | <2µs | RDMA wire speed on InfiniBand/ROCE |
| Local read (CLEAN_SHARED, epoch match) | <1µs | No remote interaction |

### 8.1 Comparison

| | TideFS mmap (this design) | ZFS mmap | CephFS mmap |
|---|---|---|---|
| Multi-node writes | Correct, lease-gated | N/A (single node) | Weak, seconds of staleness |
| Remote page fault latency | <10µs (RDMA) | N/A | >1ms (network round-trip) |
| Cacheline transfer | RDMA atomics | N/A | Not supported |
| Torn-write prevention | commit_group-boundary-gated | Bug-prone | Not guaranteed |

---


## 9. Design Rationale and Key Tradeoffs

### 9.1 Why lease-gated mmap (not capability-timeout like CephFS)

CephFS uses capability-based caching with time-bound leases: a client holds a
capability for a fixed duration, and the MDS may revoke it asynchronously.
Between revocation and the client noticing, stale data may be served. This is
acceptable for read/write syscalls where the client explicitly checks
capabilities on each operation, but it fails for mmap because stores to mmap'd
pages generate no syscalls — the client never gets a chance to check.

TideFS instead uses **lease-gated coherency**:

- **Epoch-based staleness**: Every page carries a `lease_epoch`. On every
  access (read or write fault), the epoch is compared against the current
  lease epoch from the lock service. A mismatch means the page is stale,
  regardless of how much time has passed.
  `FUSE_NOTIFY_INVAL_PAGE` to the reading node's kernel, forcing eviction
  before the application can observe stale data.
- **Blocking lease acquisition**: Write faults block until the EXCLUSIVE
  lease is granted, guaranteeing that no stale data is ever written.

**Tradeoff**: This adds lock-service latency to the write-fault path (~50µs).
CephFS avoids this latency by making writes optimistic and resolving conflicts
later, but that model cannot guarantee correctness for mmap. TideFS chooses
**correctness over write-fault latency** in the default path, while providing
the `perf` coherency profile for workloads that accept eventual consistency.


Tracking dirty state at 256-byte granularity (16 sectors per 4KB page) incurs
a memory cost of 2 bytes per page (`SectorBitmap` as `u16`). The benefit is
that two nodes can write to different sectors of the same page concurrently
without triggering lease revocation — critical for database buffer pools and
any workload with false sharing.

**Tradeoff summary**:

| Approach | Memory/page | False sharing | Complexity |
|---|---|---|---|
| Full-page tracking (1 bit) | 1 bit | Full-page conflicts | Minimal |
| 256B sector tracking (this design) | 2 bytes | Sectors 0–15 tracked independently | Moderate |
| 64B cacheline tracking | 8 bytes | Per-cacheline | High (64 bits/bitmap) |
| Byte-granular tracking | 512 bytes | None | Prohibitive |

256-byte sectors are chosen as the sweet spot: they align with most filesystem
block sizes, capture the common patterns of structured data (database rows,
serialized structs), and keep the memory overhead at 2 bytes/page — a 0.05%
overhead on a 4KB page.

### 9.3 Cacheline-coherent RDMA vs. page-fault model

The cacheline-coherent extension (§3.4, §5.3) offers sub-2µs remote write
visibility via RDMA atomics, but it comes with significant constraints:

- **Hardware dependency**: Requires RDMA-capable NICs (InfiniBand, RoCE).
  Falls back to page-fault model over TCP.
- **Memory registration cost**: RDMA memory regions must be registered and
  pinned, consuming NIC resources and preventing page migration.
- **Security surface**: Registered memory is exposed to remote RDMA access;
  access control must be enforced at the NIC and lease-service level.
- **Kernel bypass complexity**: RDMA writes bypass the kernel page cache
  entirely, so the daemon must manage cache coherency between the RDMA
  region and the kernel's view of the same pages.

**Tradeoff**: The cacheline-coherent path is an opt-in extension for
latency-sensitive workloads on RDMA clusters. The default path uses the
page-fault model with FUSE integration, which works on any transport
(TCP or RDMA) and requires no kernel bypass.

### 9.4 Intent-log writeback vs. direct-to-storage writeback

On lease revocation, dirty pages must be written back before the lease can
be released. TideFS writes dirty sectors to the intent log (#1252) rather
than directly to the backing store:

- **Pro**: Intent-log writes are sequential and batched → low latency
  (<500µs for typical dirty page count).
- **Pro**: Data is durable after the intent-log `ack()`, so the lease can
  be released immediately.
- **Con**: The intent log must eventually be replayed to the backing store,
  adding a background I/O cost.
- **Con**: If the intent log is full (§10.3), writeback
  blocks until space is available.

**Alternative considered**: Write dirty pages directly to the backing store
(like NFS's `COMMIT`). Rejected because random 4KB writes to the backing
store are ~10× slower than sequential intent-log appends, and the lease
cannot be released until all writes are durable — blocking the requesting
node's write fault.

### 9.5 FUSE path vs. kernel module (OW-201)

The current design uses FUSE for all kernel interactions. This introduces
~2–5µs of context-switch overhead per page fault. The future OW-201 kernel
module would eliminate this by handling faults entirely in kernel space.

**Tradeoff**: FUSE is available today on every Linux system and requires no
kernel patches. The kernel module provides lower latency but requires a
loadable kernel module with its own maintenance, compatibility, and
distribution burden. The design explicitly targets FUSE for the initial
implementation, with OW-201 as an optimisation path.

### 9.6 Sub-page tracking overhead at scale

The `MmapCoherencyTracker` stores per-page state for every mmap'd page.
At scale (e.g., 1TB mmap'd dataset = 256M pages), the tracker would consume:

| Field | Size | 256M pages |
|---|---|---|
| `PageCoherencyState` | ~48 bytes | ~12.3 GB |
| `BTreeMap` node overhead | ~32 bytes | ~8.2 GB |
| `HashMap` bucket overhead | ~16 bytes | ~4.1 GB |
| **Total** | | **~24.6 GB** |

This is ~2.4% of the mapped dataset size — acceptable for server-class
hardware but significant. Mitigations:

1. **LRU eviction** (§7.6): Clean pages can be evicted, dropping tracker
   entries.
2. **Sparse tracking**: Only track pages that have been faulted; untouched
   pages consume no tracker memory.
3. **Huge-page compression**: 2MB huge pages reduce the per-page overhead
   by 512× (one entry per 2MB vs. one per 4KB).
4. **Memory budget enforcement** (#1211): The tracker's memory is capped;
   when the cap is exceeded, pages are evicted aggressively.

---
## 10. Edge Cases and Error Handling

### 10.1 Writer node crashes during page fault

If the writer node (EXCLUSIVE lease holder) crashes while a reader node has
an in-flight BULK READ for a page fault:

1. BULK plane detects connection loss → returns error to mmap engine.
2. Mmap engine queries lock service for new writer node.
3. Lock service Raft leader detects crashed node → revokes its leases.
4. New writer node is elected (or the lock service promotes the requesting
   reader if it held the lease before the crash).
5. Page fault is retried to the new writer.

### 10.2 Lease upgrade timeout

If a write-fault lease upgrade request times out (lock service unreachable):

1. Mmap engine returns `EIO` to the kernel for the page fault.
2. Kernel delivers `SIGBUS` to the application (standard mmap error
   semantics for inaccessible pages).
3. Mmap engine logs the timeout and updates metrics.
4. Application may retry or abort.

### 10.3 Intent log full during revocation writeback

If the intent log is at capacity during lease revocation writeback:

1. Mmap engine blocks until space is available.
2. Intent log applies backpressure to the caller (standard flow control
   from #1252).
3. Lease release is delayed; the requesting node's lease upgrade is
   also delayed.
4. If the intent log is persistently full (>100ms), the mmap engine
   escalates to the operator alerting system.

### 10.4 `MADV_DONTNEED` and `MADV_FREE`

- `MADV_DONTNEED`: The kernel may discard the page immediately. The mmap
  discarded.
- `MADV_FREE`: The kernel may discard the page lazily. The mmap engine treats
  this as a hint only; dirty pages are not written back until the kernel
  actually reclaims the page (detected via the next writepages call).

### 10.5 `msync(MS_ASYNC)` vs. `msync(MS_SYNC)`

- `MS_ASYNC`: Dirty sectors are queued for writeback but the call returns
  immediately. No lease downgrade. Appropriate for performance-sensitive
  paths where eventual consistency is sufficient.
- `MS_SYNC`: Dirty sectors are flushed to the intent log and the call blocks
  until durable. The node may optionally downgrade from EXCLUSIVE to SHARED
  after the flush (if no other dirty pages remain).

---

## 11. Security Considerations

### 11.1 RDMA memory registration

Cacheline-coherent regions require registering process memory with the RDMA
NIC. This exposes the registered pages to remote RDMA reads and writes:

- **Access control**: Only nodes with a valid cluster identity (#1228) and
  an active SHARED lease for the inode may issue RDMA reads.
- **Write authority**: Only the node holding the EXCLUSIVE byte-range lock
  may issue RDMA writes to a cacheline-coherent region.
- **Memory safety**: RDMA regions are registered with remote-read-only or
  remote-write permissions matching the lease state. When a lease is
  downgraded from EXCLUSIVE to SHARED, the RDMA region's permissions are
  updated atomically.

### 11.2 Intent-log confidentiality

Dirty page data in the intent log carries the same encryption policy as the
parent dataset (#1256). No additional per-page encryption is applied.

---

## 12. Observability

### 12.1 Metrics

| Metric | Type | Description |
|---|---|---|
| `mmap.page_fault.read.total` | Counter | Total read page faults |
| `mmap.page_fault.read.remote` | Counter | Read faults served from remote node |
| `mmap.page_fault.read.local` | Counter | Read faults served from local cache |
| `mmap.page_fault.write.upgrade` | Counter | Write faults that triggered lease upgrade |
| `mmap.page_fault.write.local` | Counter | Write faults on already-writable pages |
| `mmap.lease.upgrade.latency_us` | Histogram | Lease upgrade latency distribution |
| `mmap.revocation.writeback.pages` | Histogram | Pages written back per revocation |
| `mmap.revocation.writeback.latency_us` | Histogram | Writeback latency per revocation |
| `mmap.cacheline.transfers` | Counter | Cacheline-coherent transfers |
| `mmap.cacheline.conflicts` | Counter | False-sharing conflicts detected |
| `mmap.tracker.pages` | Gauge | Total pages in mmap coherency tracker |
| `mmap.tracker.memory_bytes` | Gauge | Memory consumed by tracker structures |
| `mmap.commit_group.torn_write_prevented` | Counter | Torn writes prevented by commit_group-boundary gating |

### 12.2 Trace points

- `mmap:fault_read`: inode_id, page_index, source_node, latency_us
- `mmap:fault_write`: inode_id, page_index, upgrade_latency_us
- `mmap:revoke_begin`: inode_id, page_count, dirty_page_count
- `mmap:revoke_end`: inode_id, pages_written, latency_us
- `mmap:cacheline_xfer`: inode_id, offset, len, target_node

---

## 13. Future Work

### 13.1 Kernel module (OW-201)

The FUSE path introduces ~2–5µs of overhead per fault (context switch to
userspace daemon). A kernel module (OW-201) would:

- Handle page faults entirely in kernel space (no context switch).
- Integrate the lease-epoch check directly into the kernel's PTE fault handler.
- Provide native `FUSE_NOTIFY_CACHELINE_UPDATE` for in-place cacheline updates.
- Eliminate the FUSE daemon from the hot path entirely.

### 13.2 Huge-page coherency

2MB and 1GB huge pages are tracked as arrays of 256-byte sectors (8192 sectors
for 2MB, 524288 for 1GB). The `SectorBitmap` is extended to `[u64; N]` for
huge pages. The coherency model is identical but the tracker's memory overhead
is proportionally larger.

### 13.3 Persistent mmap regions

For datasets that are exclusively mmap'd (no read/write syscalls), the daemon
could register the entire dataset as a persistent RDMA region, eliminating
per-fault setup overhead. This would match the performance profile of DAX
(direct access) filesystems while retaining cluster coherency.

### 13.4 Multi-tier RDMA networks

For clusters with mixed RDMA and TCP fabrics, the BULK plane could route
cacheline transfers over RDMA while using TCP for full-page transfers. This
optimises for the common case (small, frequent updates) without requiring
RDMA for every node pair.

---

## 14. References

- [#1248] Cluster-Wide Distributed Lock Service — Sharded Leases
- [#1226] Inode/Page Cache Hierarchy (cache-lattice views)
- [#1229] Cluster BULK Plane Protocol
- [#1252] Intent Log and LOG_DEVICE Device
- [#1242] Generation Staleness Discipline
- [#1184] Named Coherency Profiles for FUSE Daemon Caching
- [#1211] Daemon Memory Budget
- [#1213] VFS Engine (FUSE daemon)
- [#1234] VFS_RPC
- OW-201: Kernel-space mmap coherency module (future)
