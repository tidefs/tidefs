# Cache Page Authority Model

This document is the narrow repo-tracked authority table for TideFS cache
classification vocabulary and cache-layer ownership. It names which cache
layers are authoritative, derived, optional, or experimental so source comments
can share one boundary for page cache, ARC, L2ARC, dirty tracking, writeback,
inode metadata cache, directory listing cache,
path-lookup cache, and future kernel page-cache roles.

This table describes current implementation ownership. It is not an end-to-end
page-cache, writeback, mmap, or durability test; mounted and kernel behavior
must be established through the corresponding runtime boundary.

## Authority Classes

| Class | Meaning |
|---|---|
| **Authoritative** | This layer decides the named in-flight ownership, placement, dirty-state, or metadata-cache fact for its declared scope. It does not imply durability or publication authority outside that scope. |
| **Derived** | This layer is a mirror or acceleration structure backed by an authoritative source.  It never decides publication success, recovery root selection, or durability.  Losing every entry cannot change visible committed truth. |
| **Optional** | This layer is available for performance but not required for correctness.  The system must function correctly with the layer disabled or absent. |
| **Experimental** | This layer is a target or transitional integration surface whose behavior must stay claim-gated until runtime validation covers the exact declared mode. |

## Authority Table

| Cache Layer | Location | Data Scope | Dirty Ownership | Classification | Kernel Role |
|---|---|---|---|---|---|
| **PageCache** | `tidefs-cache-core` | Page-granularity cache (4 KiB pages) with LRU eviction, dirty tracking, and writeback coordination | Authoritative only for a consumer that explicitly attaches it; never mounted-read authority | **Authoritative** (for an attached dirty-page scope) | Not attached to the current FUSE carrier and not the Linux kernel writeback cache |
| **WeightedArc** | `tidefs-cache-core` | Generic ARC eviction policy (T1/T2/B1/B2) with byte-weight tracking for metadata entries | None (metadata-only, no dirty data) | **Authoritative** (for metadata placement) | ARC policy may inform kernel LRU |
| **L2ARC** | `tidefs-cache-core` | Persistent second-level read cache on fast NVMe/SSD devices | None -- every entry has an authoritative copy on main pool devices | **Derived** | Kernel page cache is the final L1; L2ARC is a userspace flash tier |
| **Prefetch** | `tidefs-cache-core` | Sequential-read detection and readahead planning | None (populates PageCache) | **Derived** | Kernel readahead is authoritative in kernel mode |
| **HotReadCache** | `tidefs-local-filesystem` | Whole-file read cache for `read_file`/`read_symlink` with ARC eviction | None -- a hit is usable only after current strict receipt authority is re-read | **Derived** | Not applicable in kernel mode |
| **InodeCache** | `tidefs-local-filesystem` | ARC cache for inode metadata with lazy on-demand loading | None (metadata-only) | **Authoritative** (for inode metadata caching) | Future kernel inode cache |
| **local-fs PageCache** | `tidefs-local-filesystem/src/page_cache/` | Page cache mirroring object-store content with its own DirtyPageTracker and reclaim | Derived from object store; never authoritative for durability | **Derived** (delegates to cache-core PageCache for page-level authority) | Merged into kernel page cache in kernel mode |
| **DirtyPageTracker (range)** | `tidefs-local-filesystem/src/dirty_page_tracker.rs` | Per-inode dirty range tracking with coalescing for writeback flush path | Authoritative for dirty byte ranges awaiting flush | **Authoritative** | Replaced by kernel dirty-folio tracking in kernel mode |
| **DirtySet** | `tidefs-local-filesystem/src/writeback.rs` | Writeback dirty accounting: data bytes, metadata ops, dirty inodes, catalog dirty flag | Authoritative for dirty-state classification and commit-group triggers | **Authoritative** | Replaced by kernel writeback in kernel mode |
| **WritebackDaemon** | `tidefs-local-filesystem/src/writeback_daemon.rs` | Periodic dirty-page flush scheduling loop | Delegates to DirtyPageTracker and FlushTarget | **Derived** | Replaced by kernel bdflush/kworker in kernel mode |
| **Readahead** | `tidefs-local-filesystem/src/readahead.rs` | Sequential-read detection and prefetch window planning | None (populates caches) | **Derived** (supplements cache-core Prefetch) | Kernel readahead is authoritative in kernel mode |
| **FUSE `dirty_state` ranges** | `tidefs-posix-filesystem-adapter-daemon` | Per-inode ranges for registered-handle release/prune coordination | Derived from successful engine writes and cleared only after engine durability or exact authoritative-range replacement; never byte or durability authority | **Derived** | The sole adapter dirty projection; distinct from unavailable kernel writeback-cache negotiation |
| **FUSE writeback cache** | `tidefs-posix-filesystem-adapter-daemon` | Kernel writeback-cache negotiation | No product dirty ownership: requests are refused pending receipt-aware coherency | **Unavailable** | Product mounts do not negotiate it |
| **Kernel page cache** | Linux VFS | Native kernel folio/page cache | No regular-file read authority in the current FUSE adapter contract | **Bypassed by readable-open reply policy** | The adapter returns `FOPEN_DIRECT_IO`; the real mounted receipt-authority test verifies the same-open-file-descriptor behavior |

## Invariants

1. No two cache layers may hold overlapping dirty-data authority for the same
   byte range. `tidefs-cache-core::PageCache` owns dirty pages only for an
   explicitly attached consumer. In the current mounted carrier, engine/local
   filesystem state owns bytes and writeback; adapter `dirty_state` is only a
   derived range projection.

2. The `HotReadCache` in local-filesystem is classified as **Derived**. A hit
   may be returned only after the current Pool placement receipt is re-read and
   validated; cached bytes never substitute for placement authority.

3. The FUSE daemon has no file-data read cache or alternate block-volume read
   plane. Its open-reply policy adds `FOPEN_DIRECT_IO` to every readable open
   and masks `FOPEN_KEEP_CACHE`; the mounted acceptance test must verify that a
   same-file-descriptor read reaches the VFS engine and current Pool
   placement-receipt authority.

4. The local-filesystem `page_cache/` module is classified as **Derived**. It
   mirrors object-store content for read acceleration and must never be cited
   as the authoritative source for durability or recovery. Authority lives in
   the object store and the committed root-slot chain. Its `DirtyPageTracker`
   (BTreeSet-based) is a shadow of the authoritative `DirtyPageTracker` (range
   coalescing) in `dirty_page_tracker.rs`.

5. `L2ARC` is explicitly **non-authoritative**: device failure is survivable.
   Every L2ARC entry has an authoritative copy on main pool devices.  BLAKE3
   checksums are used for on-device integrity verification only, not as a
   generic proof marker.

6. The current FUSE adapter configures the Linux kernel page cache out of the
   regular-file read plane. Kernel writeback caching is unavailable until it
   can preserve receipt-aware coherency. The adapter has no byte mirror or
   writeback scheduler; its one `dirty_state` range map coordinates release
   and pruning without negotiating kernel writeback.

7. In full-kernel mode (kmod-posix-vfs), the kernel page cache is the single
   authoritative byte-residency plane.  All userspace cache layers are absent
   or disabled.  Dirty tracking and writeback are kernel-native.

## Eviction And Flush Boundaries

| Layer | Trigger | Authority update |
|---|---|---|
| L2ARC | Ghost-hit filter eviction, index capacity pressure, device trim | L2ArcIndex entry removal, circular-log overwrite |
| local-fs PageCache | Dirty page flush completion, memory pressure reclaim | `DirtyPageTracker::mark_clean`, `reclaim::evict_clean_pages` |
| DirtyPageTracker (range) | Writeback flush completion | `flush_inode` removal |
| FUSE `dirty_state` ranges | Successful flush, `fsync`/`fdatasync`, `syncfs`, release flush, or exact authoritative-range replacement | Derived range removal; engine/local-filesystem bytes remain authoritative |

## Reclaim and Memory Pressure

- **cache-core PageCache**: LRU eviction of clean, unpinned pages.  Dirty
  pages are skipped during automatic eviction and must be written back first.
- **local-fs PageCache**: High/low watermark reclaim
  (`DEFAULT_PAGE_CACHE_HIGH_WATERMARK_BYTES` /
  `DEFAULT_PAGE_CACHE_LOW_WATERMARK_BYTES`).  Clean pages may be evicted under
  memory pressure after dirty ownership has been cleared.
- **WeightedArc**: Byte-weight capacity enforcement with ghost-list adaptive
  sizing.  Eviction from T1/T2 into B1/B2 ghost lists, with ghost cap
  enforcement (`2 * max_bytes`, `2 * max_entries`).
- **L2ARC**: Circular log-structured device with implicit overwrite eviction.
  Index capacity enforcement via random entry removal.
- **HotReadCache**: LRU eviction with byte-weight and entry-count caps.
- **InodeCache**: LRU eviction with byte-weight caps via ARC p-adaptation.

## Future Kernel Page-Cache Targets

| Milestone | Cache Layer | Target role |
|---|---|---|
| kmod-posix-vfs baseline | Kernel page cache | Primary byte-residency plane for FUSE and kmod mounts |
| VFS writeback expansion | Kernel dirty-folio tracking | Authoritative dirty tracking; replaces userspace DirtySet/WritebackDaemon |
| Block kmod | Kernel block I/O page cache | Block-device page cache for ublk direct and ext4 mounts |
| Full-kernel no-daemon | Kernel page cache (unified) | Single authoritative cache plane; all userspace caches disabled |

## Validation Boundary

This document provides the cache/page-cache authority vocabulary and the
receipt-aware cache classification used by current source comments. It keeps
`HotReadCache` and local-fs `page_cache/` derived or scoped rather than
durability or placement authority, and records that the duplicate FUSE read
cache has been removed.

It does not establish kernel writeback-cache correctness, mmap durability,
full-kernel integration, performance, or production readiness.

| Check | Boundary |
|---|---|
| `cargo test -p tidefs-cache-core` | Exercises page cache, weighted ARC, L2ARC, directory listing cache, path lookup cache, and prefetch units; non-closing by itself. |
| `cargo test -p tidefs-local-filesystem` | Exercises hot read cache, inode cache, local page cache, dirty page tracker, and writeback units; non-closing by itself. |
| Kbuild / kmod-posix-vfs cache integration | Deferred to kernel work; not established by this document. |
| Full-kernel no-daemon | Deferred to the full-kernel milestone; not established by this document. |

## Related Documents

- `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` and
  `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` -- current
  page-cache/writeback/mmap and invalidation authority
- `docs/REVIEW_TODO_REGISTER.md` -- current review debt and unresolved TFR-008 cache/writeback/recovery boundary
