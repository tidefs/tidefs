# page-cache / writeback / mmap integration (P5-03) (v0.316)

This document is the production-depth source-of-truth for the posix_filesystem_adapter page-cache, writeback, and mmap contract on Linux 7.0.

For cluster mmap coherency across nodes, see Forgejo #1259 (`[DESIGN] mmap cluster coherency`).

It answers the question:


See also:
- `docs/FUSE_REQUEST_WORKER_QUEUE_MODEL_P5-02.md`
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md`
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md`
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `docs/CLUSTER_TRANSPORT_BOUNDEDNESS_DESIGN.md` (cluster BULK-plane foundation for #1259 remote page faulting)

## OW-204 implemented-source binding

Forgejo issue `#28` / `OW-204` binds this law into source through
`PAGE_CACHE_WRITEBACK_MMAP_SPEC`,
`PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES`, and
`page_cache_writeback_mmap_acceptance_cases()` in
`crates/tidefs-local-filesystem/src/lib.rs`.

The implementation-tracked non-release cases cover:

- buffered writeback dirty epochs and writeback batches;
- shared writable mmap and synchronous `msync` durability;
- private mmap copy-on-write non-publication behavior;
- direct-I/O reconciliation against cached windows;
- `fsync`/`fdatasync`/`O_SYNC` durability beyond clean page-cache state.

This is an implemented-source specification gate. It does not claim live mmap
support, direct-I/O support, production Linux kernel integration, or POSIX
completion.

## Metrics snapshot

| Metric | Count |
|---|---:|
| Named coherency classes | 6 |
| Canonical state machines | 4 |
| Userspace-kernel split points | 8 |
| New runtime schema families introduced here | 10 |
| New algorithm families introduced here | 10 |

## 1. Non-negotiable rules

1. **Page cache is never authoritative truth.**
   Authoritative truth still lives in published revisions, projection roots, receipts, claims/reserves, and fences. Page-cache state only accelerates charter-serving visibility.

2. **Every cached page window is anchor-bound.**
   Buffered or mmap-visible bytes must carry enough anchor / projection-root / freshness-fence context to prove what truth epoch they reflect.

3. **Dirtying is explicit and receipt-linked.**
   Buffered writes, shared mmap dirties, and writeback batches must move through named dirty epochs and writeback batches. No implicit "kernel will sort it out later" law is allowed.

4. **Userspace posix_filesystem_adapter and future kernel posix_filesystem_adapter share one logical state machine.**

5. **Direct I/O is a coherency class, not a flag accident.**
   `O_DIRECT` and other direct-uncached paths must explicitly reconcile with buffered and mmap-visible state. Bypassing cache does not permit hidden stale data.

6. **Shared mmap is first-class correctness, not a later optimization.**

7. **Durability is stronger than writeback completion.**
   A page becoming clean or a writeback batch completing is not enough to claim durable visibility when the charter requires publication and storage-commit receipts.


9. **No duplicate whole-file userspace cache is permitted in posix_filesystem_adapter.**
   In userspace FUSE mode, Linux kernel page cache is the primary byte-residency plane. Userspace keeps mirrors, dirty-epoch state, and staging buffers only.

10. **Pinned page / DMA / zero-copy bytes remain obligations.**
    Exact mechanics are completed later in `P4-04`, but this pass makes the interaction points and invariants explicit now.

## 2. Shared logical model

### 2.1 Logical page and window units

The canonical logical byte unit for posix_filesystem_adapter cache coordination is the **4 KiB page index**.

Pages are grouped into **page windows** for runtime efficiency:
- default read populate window: **64 KiB**
- sequential-read growth ceiling: **1 MiB**
- dirty-epoch seal target: **1 MiB or 32 ms**, whichever comes first
- writeback batch ceiling: **8 MiB** or an earlier fence / fsync / msync / pressure boundary

These values are policy defaults under `control_plane`, not hidden daemon constants.

### 2.2 Coherency classes

Every open handle, mapping region, and active page window is classified into one of these classes:

| Class | Meaning | Typical sources |
|---|---|---|
| `cache_coherency_0.buffered_cached` | normal buffered page-cache visibility | buffered read/write, cached metadata-driven I/O |
| `cache_coherency_1.shared_mmap_writeback` | writable shared mapping with writeback discipline | `MAP_SHARED` writable mappings |
| `cache_coherency_2.private_mmap_cow` | private mapping with copy-on-write isolation | `MAP_PRIVATE` writable mappings |
| `cache_coherency_3.direct_uncached` | direct path bypassing cached windows | `O_DIRECT`, explicit uncached bulk operations |
| `cache_coherency_4.exec_readonly` | executable / readonly cache visibility | text mappings, readonly shared mappings |

### 2.3 Visibility classes

Page-cache-visible bytes carry one of these visibility states:
- `vis.clean_visible`
- `vis.dirty_private`
- `vis.dirty_shared`
- `vis.writeback_pending`
- `vis.poisoned`

The response envelope and charter rendering decide what Linux may observe. The cache class never decides truth on its own.

## 3. Canonical runtime/schema families

The shared runtime model introduces these canonical families.

| Record | Purpose | Authority class |
|---|---|---|
| `PosixFilesystemAdapterPageObjectRecord` | object-scoped cache root for one visible file object under one projection root | runtime mirror |
| `PosixFilesystemAdapterPageResidencyRecord` | page-index range residency state, current anchor vector, current visibility class | runtime mirror |
| `PosixFilesystemAdapterPageWindowRecord` | contiguous admitted page window with class, owner refs, size, and counters | runtime mirror |
| `PosixFilesystemAdapterMmapRegionMirrorRecord` | mirror of one mmap region and its mapping class, permissions, and drain state | runtime mirror |
| `PosixFilesystemAdapterDirtyEpochRecord` | grouping of dirty windows that must flush/publish together | runtime mirror / dirty state |
| `PosixFilesystemAdapterWritebackBatchRecord` | sealed writeback batch with batch scope, durability class, and fence requirements | runtime mirror / receipt-linked |
| `PosixFilesystemAdapterPageLoanRecord` | loan or pinned ownership token for a page payload crossing runtime boundaries | runtime mirror / reserve-linked |
| `PosixFilesystemAdapterCacheCoherencyClassRecord` | object/handle/mapping coherence declaration and current direct/buffered conflict state | authoritative declaration / runtime state |

## 4. Canonical state machines

### 4.1 Page-residency state machine

States:
- `absent`
- `clean_read`
- `mapped_clean`
- `dirty_open`
- `dirty_sealed`
- `writeback_inflight`
- `poisoned`

Allowed core transitions:
- `absent -> clean_read`
- `clean_read -> mapped_clean`
- `clean_read -> dirty_open`
- `mapped_clean -> dirty_open`
- `dirty_open -> dirty_sealed`
- `dirty_sealed -> writeback_inflight`
- `writeback_inflight -> clean_read`
- `* -> poisoned`

### 4.2 Mmap-region state machine

States:
- `closed`
- `mapped_ro`
- `mapped_shared_clean`
- `mapped_shared_dirty`
- `mapped_private_cow`
- `revoke_wait`
- `drained`

Rules:
- private mappings may dirty private pages without creating publication-visible dirty epochs
- shared writable mappings transition through `mapped_shared_dirty` and must join dirty epochs / writeback batches
- truncate / collapse / insert / cutover may move a region to `revoke_wait`

### 4.3 Dirty-epoch / writeback-batch state machine

States:
- `collecting`
- `sealed`
- `storage_write_inflight`
- `publication_wait`
- `visible_clean`
- `durable_clean`
- `error_poisoned`

Rules:
- `collecting` may aggregate buffered writes and shared-mmap dirties for one object scope
- `sealed` means page ownership and byte ranges are frozen for one writeback attempt
- `publication_wait` means storage copy is complete but charter-visible durability is not yet satisfied
- `durable_clean` is required before claiming `fsync`, `fdatasync`, `msync(MS_SYNC)`, or `O_SYNC` durability


States:
- `issued`
- `reader_fault_blocked`
- `drop_wait`
- `fence_wait`
- `complete`

Rules:
- `reader_fault_blocked` allows new faults to wait rather than repopulate stale bytes

## 5. Userspace FUSE law on Linux 7.0

### 5.1 Residency ownership

In userspace posix_filesystem_adapter mode:
- Linux kernel owns actual page-cache folios/pages and mmap-visible residency
- posix_filesystem_adapter userspace owns only:
  - request-context mirrors
  - page-window mirrors
  - dirty epochs / writeback batches
  - page-loan records

The daemon may never keep an independent whole-file byte cache that outranks kernel residency.

### 5.2 Buffered reads

Buffered read miss flow:
1. kernel faults or read path discovers missing page-cache bytes
2. posix_filesystem_adapter emits `PosixFilesystemAdapterFaultContextMirrorRecord`
3. `cache_coherency_0.buffered_cached` window is chosen or extended
4. bytes are populated from authoritative object revision or lawful product
5. kernel page cache becomes resident under the resulting anchor vector

### 5.3 Buffered writes

Buffered write flow:
1. incoming write joins or opens a `PosixFilesystemAdapterDirtyEpochRecord`
2. affected page windows move to `dirty_open`
3. epoch seals on size/time/flush/fence boundary
4. a `PosixFilesystemAdapterWritebackBatchRecord` is emitted
5. storage write + publication + durability fences determine when windows return clean

### 5.4 Shared writable mmap

Shared writable mmap is treated as **cache_coherency_1.shared_mmap_writeback**.

Rules:
- first shared write on a clean mapped region opens or joins a dirty epoch
- shared dirty windows obey the same seal and writeback-batch law as buffered writes
- `msync(MS_ASYNC)` schedules sealing/writeback
- `msync(MS_SYNC)` waits for the relevant batch to become at least `visible_clean`
- if the charter demands durable visibility, `MS_SYNC` waits for `durable_clean`

### 5.5 Private writable mmap

Private writable mmap is **cache_coherency_2.private_mmap_cow**.

Rules:
- private faults and dirtying do not create publication-visible dirty epochs
- they may share clean populate windows with other classes until first private dirtying
- they never satisfy shared durability claims by themselves

### 5.6 Truncate / hole punch / collapse / insert


Rules:
- block or defer overlapping new faults during transition
- drain or split affected dirty epochs
- seal required writeback batches before truth shift if charter law requires
- drop or remap overlapping windows and mapping mirrors
- only then allow new population against the new anchor set / size map

### 5.7 Direct I/O and uncached paths

Direct I/O is **cache_coherency_3.direct_uncached**.

Rules:
- overlapping dirty cached windows must be sealed and drained before direct write proceeds
- direct reads may bypass cache only if no overlapping dirty epoch exists; otherwise they wait or force reconciliation

## 6. Future kernel posix_filesystem_adapter kmod law — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)

The future kernel variant uses the same logical records and state machines, but with native kernel residency and writeback mechanics.

### Kernel-owned mechanisms
- folios/pages in address_space
- readahead hooks
- page fault and `page_mkwrite` integration
- writepages/writepage state

### Same logical law, different mechanics
The kernel path still must emit or mirror:
- dirty epochs
- writeback batches
- page loans / pins
- coherence class declarations

What changes is only the implementation substrate:
- kernel workqueues instead of userspace worker lanes for page/writeback internals
- folio references and pins instead of userspace frame loans
- direct access to address_space state instead of FUSE request mirrors

## 7. Rust seam families and core types

This pass is detailed enough to name the implementation seams that both userspace and future kernel variants must obey.

### Core Rust trait families
- `PosixFilesystemAdapterPageCacheBridge`
- `PosixFilesystemAdapterFaultResolver`
- `PosixFilesystemAdapterDirtyEpochManager`
- `PosixFilesystemAdapterWritebackBatcher`
- `PosixFilesystemAdapterMmapLeaseManager`
- `PosixFilesystemAdapterDirectIoCoherency`
- `PosixFilesystemAdapterPageLoanBroker`
- `PosixFilesystemAdapterWritebackDurabilityFence`
- `PosixFilesystemAdapterCachePressureHook`

### Canonical type families
- `PageIndex`
- `PageWindowKey`
- `CoherencyClass`
- `VisibilityClass`
- `DirtyEpochId`
- `WritebackBatchId`
- `PageLoanId`
- `MmapRegionId`
- `FaultEpoch`

### Module split (userspace first, kernel-ready)
- `posix_filesystem_adapter_cache::context`
- `posix_filesystem_adapter_cache::window`
- `posix_filesystem_adapter_cache::mmap`
- `posix_filesystem_adapter_cache::dirty`
- `posix_filesystem_adapter_cache::writeback`
- `posix_filesystem_adapter_cache::direct`
- `posix_filesystem_adapter_cache::loan`
- `posix_filesystem_adapter_cache::pressure`

## 8. Reserve, pressure, and pin interaction

This pass now makes the connection points explicit:
- page-cache windows live primarily in `memory_domain_3.adapter_serving_hot`
- dirty epochs / writeback batches live in `memory_domain_2.staging_dirty`
- page loans / future pinned zero-copy state must account against `memory_domain_7.kernel_pinned_dma`
- pressure law from `P4-03` may:
  - throttle new shared dirtying
  - force dirty-epoch sealing
  - compact read windows
  - deny new large populate windows


The live system must surface at least these counters and receipts:
- dirty epochs open / sealed / inflight
- writeback batch bytes and age
- shared-mmap dirty bytes
- direct-I/O/cache conflict count
- page-loan bytes and age
- writeback/publication mismatch findings
- cache-poison findings

Every severe mismatch between:
- visible clean state,
- publication receipts,
- and durability receipts


## 10. Intentional cuts and deferred detail

Settled here:
- logical page/window law
- coherency classes
- shared mmap / buffered writeback discipline
- direct-I/O reconciliation law
- userspace vs kernel mechanical split
- required seam families and core types

Still completed later, but now on explicit rails:
- exact zero-copy / DMA / pin broker mechanics (`P4-04`)
- exact block queue / ublk interaction details (`P6-01`, `P6-02`)
- kernel locking / RCU / workqueue law (`P7-03`)
- cluster mmap coherency design settled in #1259; runtime implementation deferred to (`P6-03`, `P6-04`)

## 11. Production consequences

With this pass settled:
- posix_filesystem_adapter worker topology (`P5-02`) now has a lawful byte-residency and dirty/writeback partner model
- cache and pressure law (`P4-02`, `P4-03`) now connect directly to page-cache and mmap behavior
- the next biggest unresolved production risk is no longer "how do buffered I/O and mmap fit into the runtime?"
- it is now the exact **zero-copy / pinning / page-loan law** (`P4-04`) and the **block_volume_adapter queue topology / flush semantics** (`P6-01`, `P6-02`)
- the cluster mmap coherency extension (#1259) now has a settled design; multi-node page-level lease-gated consistency, remote page faulting via BULK plane, cacheline-granularity RDMA transfer, and false-sharing mitigation are on explicit rails for implementation
