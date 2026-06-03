# Cache Page Authority Model (v0.420)

Canonical cache authority declaration for the TideFS userspace stack.  This
document is the single repo-tracked authority table that names which cache is
authoritative, derived, optional, or experimental.  It closes the split-cache
A16 risk by assigning clear ownership for FUSE read cache, page cache, ARC,
L2ARC, dirty tracking, writeback, inode metadata cache, directory listing
cache, path-lookup cache, and future kernel page-cache roles.

## Authority Classes

| Class | Meaning |
|---|---|
| **Derived** | This layer is a mirror or acceleration structure backed by an authoritative source.  It never decides publication success, recovery root selection, or durability.  Losing every entry cannot change visible committed truth. |
| **Optional** | This layer is available for performance but not required for correctness.  The system must function correctly with the layer disabled or absent. |

## Authority Table

| Cache Layer | Location | Data Scope | Dirty Ownership | Classification | Kernel Role |
|---|---|---|---|---|---|
| **PageCache** | `tidefs-cache-core` | Page-granularity read cache (4 KiB pages) with LRU eviction, dirty tracking, and writeback coordination | Authoritative for dirty pages in flight; writeback lifecycle gates durability | **Authoritative** | Mirrors kernel page cache in FUSE mode |
| **WeightedArc** | `tidefs-cache-core` | Generic ARC eviction policy (T1/T2/B1/B2) with byte-weight tracking for metadata entries | None (metadata-only, no dirty data) | **Authoritative** (for metadata placement) | ARC policy may inform kernel LRU |
| **L2ARC** | `tidefs-cache-core` | Persistent second-level read cache on fast NVMe/SSD devices | None -- every entry has an authoritative copy on main pool devices | **Derived** | Kernel page cache is the final L1; L2ARC is a userspace flash tier |
| **Prefetch** | `tidefs-cache-core` | Sequential-read detection and readahead planning | None (populates PageCache) | **Derived** | Kernel readahead is authoritative in kernel mode |
| **HotReadCache** | `tidefs-local-filesystem` | Whole-file read cache for `read_file`/`read_symlink` with ARC eviction | None -- already documented as "not authority" in PC-003 | **Derived** (superseded by cache-core PageCache) | Not applicable in kernel mode |
| **InodeCache** | `tidefs-local-filesystem` | ARC cache for inode metadata with lazy on-demand loading | None (metadata-only) | **Authoritative** (for inode metadata caching) | Future kernel inode cache |
| **local-fs PageCache** | `tidefs-local-filesystem/src/page_cache/` | Page cache mirroring object-store content with its own DirtyPageTracker and reclaim | Derived from object store; never authoritative for durability | **Derived** (delegates to cache-core PageCache for page-level authority) | Merged into kernel page cache in kernel mode |
| **DirtyPageTracker (range)** | `tidefs-local-filesystem/src/dirty_page_tracker.rs` | Per-inode dirty range tracking with coalescing for writeback flush path | Authoritative for dirty byte ranges awaiting flush | **Authoritative** | Replaced by kernel dirty-folio tracking in kernel mode |
| **DirtySet** | `tidefs-local-filesystem/src/writeback.rs` | Writeback dirty accounting: data bytes, metadata ops, dirty inodes, catalog dirty flag | Authoritative for dirty-state classification and commit-group triggers | **Authoritative** | Replaced by kernel writeback in kernel mode |
| **WritebackDaemon** | `tidefs-local-filesystem/src/writeback_daemon.rs` | Periodic dirty-page flush scheduling loop | Delegates to DirtyPageTracker and FlushTarget | **Derived** | Replaced by kernel bdflush/kworker in kernel mode |
| **Readahead** | `tidefs-local-filesystem/src/readahead.rs` | Sequential-read detection and prefetch window planning | None (populates caches) | **Derived** (supplements cache-core Prefetch) | Kernel readahead is authoritative in kernel mode |
| **FUSE ReadCache** | `tidefs-posix-filesystem-adapter-daemon` | Whole-file LRU read cache keyed by inode (64 MiB default byte limit) | None (non-authoritative by design) | **Derived** (superseded by cache-core PageCache; duplicate of HotReadCache) | Not applicable in kernel mode |
| **FUSE WritebackInodeCache** | `tidefs-posix-filesystem-adapter-daemon` | Buffered-write inode cache for FUSE writeback-cache path | Delegated to local-filesystem writeback path | **Derived** | Not applicable in kernel mode |
| **FUSE writeback cache** | `tidefs-posix-filesystem-adapter-daemon` | Optional buffered-write cache in the FUSE daemon hot path | Delegated to local-filesystem writeback path; gated behind `--writeback-cache` flag | **Optional** (off by default per A11/A16 red gate) | Not applicable in kernel mode |
| **Kernel page cache** | Linux 7.0 VFS | Native kernel folio/page cache for FUSE and kmod mounts | Authoritative in kernel mode; mirrors userspace authorities in FUSE mode | **Authoritative** (kernel mode) / **Experimental** (FUSE mode: kernel decides eviction) | Definitive |

## Invariants

1. No two cache layers may hold overlapping dirty-data authority for the same
   byte range.  The authoritative dirty owner for in-flight page data is
   `tidefs-cache-core::PageCache`.  The authoritative dirty owner for
   writeback accounting is `tidefs-local-filesystem::DirtySet`.

2. The `HotReadCache` in local-filesystem is classified as **Derived** and
\
3. The FUSE daemon `ReadCache` (in `read_cache.rs`) is classified as

   **Derived** and **superseded** by `tidefs-cache-core::PageCache`.  It is a

   functional duplicate of the local-filesystem `HotReadCache` — both are

   whole-file LRU/ARC read caches that mirror authoritative content.  The

   canonical read-cache authority in the userspace stack is

   `tidefs-cache-core::PageCache`.  Both the daemon `ReadCache` and the

   local-fs `HotReadCache` must be removed in favor of cache-core delegation.

   **superseded** by `tidefs-cache-core::PageCache`.  It must not grow new
   conflict with cache-core.  Future work will remove it entirely in favor
   of cache-core delegation.

3. The local-filesystem `page_cache/` module is classified as **Derived**.  It
   mirrors object-store content for read acceleration and must never be cited
   as the authoritative source for durability or recovery.  Authority lives in
   the object store and the committed root-slot chain.  Its `DirtyPageTracker`
   (BTreeSet-based) is a shadow of the authoritative `DirtyPageTracker` (range
   coalescing) in `dirty_page_tracker.rs`.

4. `L2ARC` is explicitly **non-authoritative**: device failure is survivable.
   Every L2ARC entry has an authoritative copy on main pool devices.  BLAKE3
   checksums are used for on-device integrity verification only, not as a
   generic proof marker.

5. In FUSE userspace mode, the Linux kernel page cache is the primary
   byte-residency plane.  Userspace keeps mirrors, dirty-epoch state, and
   staging buffers only.  The `tidefs-cache-core::PageCache` mirrors the
   kernel page cache for read acceleration.

6. In full-kernel mode (kmod-posix-vfs), the kernel page cache is the single
   authoritative byte-residency plane.  All userspace cache layers are absent
   or disabled.  Dirty tracking and writeback are kernel-native.


|---|---|---|
| L2ARC | Ghost-hit filter eviction, index capacity pressure, device trim | L2ArcIndex entry removal, circular-log overwrite |
| local-fs PageCache | Dirty page flush completion, memory pressure reclaim | `DirtyPageTracker::mark_clean`, `reclaim::evict_clean_pages` |
| DirtyPageTracker (range) | Writeback flush completion | `flush_inode` removal |
| FUSE writeback cache | `fsync`/`fdatasync`/`O_SYNC`/commit barrier | Writeback daemon flush + commit-group sync |

## Reclaim and Memory Pressure

- **cache-core PageCache**: LRU eviction of clean, unpinned pages.  Dirty
  pages are skipped during automatic eviction and must be written back first.
- **local-fs PageCache**: High/low watermark reclaim
  (`DEFAULT_PAGE_CACHE_HIGH_WATERMARK_BYTES` /
  `DEFAULT_PAGE_CACHE_LOW_WATERMARK_BYTES`).  Clean pages evicted under
- **WeightedArc**: Byte-weight capacity enforcement with ghost-list adaptive
  sizing.  Eviction from T1/T2 into B1/B2 ghost lists, with ghost cap
  enforcement (`2 * max_bytes`, `2 * max_entries`).
- **L2ARC**: Circular log-structured device with implicit overwrite eviction.
  Index capacity enforcement via random entry removal.
- **HotReadCache**: LRU eviction with byte-weight and entry-count caps.
- **InodeCache**: LRU eviction with byte-weight caps via ARC p-adaptation.

## Future Kernel Page-Cache Roles

| Milestone | Cache Layer | Role |
|---|---|---|
| kmod-posix-vfs baseline | Kernel page cache | Primary byte-residency plane for FUSE and kmod mounts |
| VFS writeback expansion | Kernel dirty-folio tracking | Authoritative dirty tracking; replaces userspace DirtySet/WritebackDaemon |
| Block kmod | Kernel block I/O page cache | Block-device page cache for ublk direct and ext4 mounts |
| Full-kernel no-daemon | Kernel page cache (unified) | Single authoritative cache plane; all userspace caches disabled |

## A-Register Resolution

This document addresses **A16** (Performance, Scale, mmap, And Page-Cache
Claims Are Mostly Design-Level) from
`/root/ai/docs/projects/tidefs/state/full-review-attention-register.md`:

- **Closes**: the "Decide one cache/page-cache authority model" needed item.
  This document is the canonical authority model.
- **Advances**: the "Remove or disable duplicate whole-file caching if it
  contradicts P5-03" needed item.  `HotReadCache` is reclassified as Derived
  and superseded; local-fs `page_cache/` is reclassified as Derived.
- **Does not close**: the writeback-cache correctness gate (A11), performance


|---|---|
| unit check | `cargo test -p tidefs-cache-core` (page_cache, weighted_arc, l2arc, directory_listing_cache, path_lookup_cache, prefetch tests), non-closing by itself. |
| unit check | `cargo test -p tidefs-local-filesystem` (hot_read_cache, inode_cache, page_cache, dirty_page_tracker, writeback tests), non-closing by itself. |
| Kbuild | kmod-posix-vfs cache integration (deferred to kernel work) |
| full-kernel no-daemon | Kernel page cache as sole authority (deferred to full-kernel milestone) |

## Related Documents

- `docs/HOT_READ_CACHE_PC003.md` -- original hot read cache design (not authority)
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md` -- cache taxonomy and invariants
- `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md` -- page-cache/writeback/mmap law
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md` -- memory pressure and reclaim
- `/root/ai/docs/projects/tidefs/state/full-review-attention-register.md` -- A16 finding
