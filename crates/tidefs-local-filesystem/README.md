# tidefs-local-filesystem

Durable local filesystem model built on the TideFS Local Object Store.

## Overview

`tidefs-local-filesystem` is the primary filesystem implementation crate in
TideFS. It publishes namespace changes through immutable transaction objects
and root-slot commits on top of [`tidefs_local_object_store`]. On reopen,
the implementation selects the newest Pool-authorized committed root and,
when recovery policy permits, replays newer durable intents before retiring
the log records they made redundant. This is not an automatic-repair or
release-readiness claim.
Product recovery and writeback claims remain gated by
`docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`, `validation/claims.toml`,
`docs/CLAIM_REGISTRY.md`, the registry-listed validation artifacts, and live
GitHub issues.

The crate sits between the FUSE daemon
(`tidefs_posix_filesystem_adapter_daemon`) above and
[`LocalObjectStore`] below. The FUSE daemon translates kernel VFS requests
into calls on the `VfsEngine` trait, implemented by
`VfsEngineImpl`([vfs_engine_impl]), which delegates to [`LocalFileSystem`]
methods. The filesystem in turn reads and writes content through the object
store's key-value interface, managing inode metadata, directory entries,
extent maps, and content objects as distinct object-key families.

## Architecture

```
FUSE daemon (tidefs-posix-filesystem-adapter-daemon)
         │
         ▼
  VfsEngineImpl (crate::vfs_engine_impl)
         │
         ▼
  LocalFileSystem
    ├── FileSystemState          (inode table, dirs, extent maps, quota)
    ├── CommitGroupStateMachine  (Open → Quiesce → Sync)
    ├── WriteBuffer              (small-write coalescing)
    ├── DirtySet                 (data, metadata, catalog dirty tracking)
    ├── IntentLog                (durable mutation records and replay payloads)
    ├── PageCache                (cached read pages + dirty-page tracking)
    └── BackgroundScheduler      (orphan reclaim, defrag, optional scrub)
         │
         ▼
  LocalObjectStore (tidefs-local-object-store)
```

## Key Types

| Type | Purpose |
|------|---------|
| [`LocalFileSystem`] | Top-level filesystem handle: open, close, read, write, fsync |
| [`FileSystemError`] | Unified error covering I/O, integrity, and semantic errors |
| [`FileSystemStats`] | Space usage, inode counts, and health counters |
| [`RootAuthenticationKey`] | Cryptographic key for committed-root authentication |
| `FileSystemState` | Authoritative metadata snapshot: inode table, directories, extent maps, quota, space accounting |
| [`DedupIndex`] | In-memory `BTreeMap`-backed dedup index mapping `ContentFingerprint` to canonical `ObjectKey` |
| [`FsckReport`] | Block-level and metadata integrity scan output with severity classification |
| [`RecoveryProbeReport`] | Committed-root selection summary after reopen |
| [`RecoveryAuditReport`] | Deterministic replay-audit of committed-root chain |
| [`OnlineVerifierReport`] | Live integrity scan of pool object state |
| [`CommitGroupConfig`] | Transaction-group config: sync thresholds, auto-commit policy |
| [`IntentLog`] | Durable mutation log containing metadata records and replay payloads |
| [`PageCache`] | In-memory page cache for read acceleration and dirty-page tracking |

## Transaction Model

Writes are grouped into transaction groups managed by
[`CommitGroupStateMachine`]. Each commit group proceeds through
`Open → Quiesce → Sync`; durable state is published through authenticated
transaction objects and a root slot.

## Recovery Model

On open, [`recovery`] selects the newest Pool-authorized committed root and
replays newer durable intent-log entries when the selected recovery policy
allows mutation. The [`crash_recovery`] module contains crash-matrix validation
fixtures rather than the mounted recovery implementation. [`repair`] applies
corruption resolution strategies (truncate, mark-corrupt, reconstruct), and
[`scrub`] runs a full block-level checksum pipeline with outcome
classification.

These mechanics describe current source behavior and focused tests. Broader
recovery, write/fsync/writeback, mmap, and automatic repair admission remains
non-claim authority tracked by `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`,
TFR-008, `validation/claims.toml`, and the claim-registry product gates.

## Background Services

A writable mounted open starts the shared scheduler with
`BackgroundOrphanReclamation`, online extent-map defragmentation, and an
optional `BackgroundScrubber` when its interval is nonzero. `BackgroundReclaim`
is a model/test surface. Mounted production open does not start
`WritebackDaemon`; the foreground write-buffer byte threshold and explicit
durability operations drive content flushes.

## Reclaim Authority

Mounted `LocalFileSystem` does not currently free physical segments through the
receipt-bound dead-object drain. The lower queue records Pool receipt
generations, but it does not persist exact obsolete-placement tokens bound to
an authenticated filesystem root. A filesystem generation and a global Pool
receipt-allocation frontier are different domains and cannot authorize one
another. Physical entries therefore remain queued fail-closed until that
root-bound identity exists.

`LocalObjectStore::drain_dead_segments` also leaves the older object-store
reclaim queue allocated without committed clearance. `BackgroundReclaim` and
`ProcessedDelta` in `background_reclaim.rs` are model/test surfaces
quarantined behind `#[cfg(test)]` and are not product reclaim evidence.

Current implementation reclaim path (non-claim):

1. `record_reclaim_delta()` — records refcount deltas into the local
   `BPlusTreeReclaimQueue` during unlink, truncate, and rename-overwrite.
2. `tick_background_services()` Duty 2 — drains the local queue and calls
   `Pool::delete()` for each entry.
3. `Pool::delete()` — removes the current placement/index entries and
   enqueues lower reclaim work.
4. The mounted path stops after that logical handoff. Receipt-bound physical
   entries are conservatively retained; it does not infer root stability from
   receipt allocation order.

This sequence records current source behavior and focused tests. Product
physical reclaim requires exact per-placement identity, durable root binding,
and retained-root/snapshot clearance. Product reclaim, source-retirement, and
lifecycle wording remains blocked by
`docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`, TFR-010,
`validation/claims.toml`, `docs/CLAIM_REGISTRY.md`, and the open follow-ups
named there.

## Dedup

## Block-Level Extent Deallocation (discard / UNMAP)



`LocalFileSystem::free_extent_range()` is the block-device discard path. It

frees logical extents in the extent allocator for a given inode without path

resolution or namespace mutation, then updates the spacemap and reclaim

ledger.



```

pub fn free_extent_range(

    &mut self,

    inode_id: InodeId,

    byte_offset: u64,

    byte_len: u64,

) -> Result<u64>

```



- If `byte_len` is zero, returns `Ok(0)` immediately.

- Delegates to `ExtentAllocator::free_extent()`. When the range has no

  allocated extents, the `ExtentNotFound` error is treated as success with

  0 bytes freed.

- On success, the freed byte count is fed to `SpaceAccounting` via

  `accumulate_delta(SpaceDelta::new_free(...))` and `track_physical_free(...)`,

  and a reclaim-queue entry is recorded so background compaction eventually

  reclaims the physical space.

The internal [`DedupIndex`] (`src/dedup.rs`) is a lightweight in-memory
deduplication map backed by `BTreeMap<ContentFingerprint, (ObjectKey, u64)>`.
It maps content fingerprints to canonical object keys and tracks reference
counts so entries are removed when no consumer remains. This is separate
from the `tidefs-dedup` crate, which provides a post-process scanner
(`DedupScanner`) operating on extent maps under the background scheduler.

## Error Handling

All public fallible methods return `crate::Result<T>` which is
`std::result::Result<T, FileSystemError>`. [`FileSystemError`] covers
three categories:

- **I/O errors** — wrapped [`StoreError`] from the object-store layer.
- **Integrity errors** — missing/invalid root keys, corrupt committed-root
  summaries, corrupt inode/directory records, intent-log replay failures.
- **Semantic errors** — `NotFound`, `AlreadyExists`, `DirectoryNotEmpty`,
  `QuotaExceeded`, `IsDirectory`, `NotFile`, `PermissionDenied`,
  `NoSpace`, `CorruptContent`, `Unsupported`.

## Module Map

| Module | Purpose |
|--------|---------|
| `lib.rs` | [`LocalFileSystem`], public entry points, module declarations |
| `error.rs` | [`FileSystemError`] enum and `Result<T>` type alias |
| `types.rs` | Supporting types: `FileSystemState`, `RootAuthenticationKey`, `ContentFingerprint`, etc. |
| `vfs_engine_impl.rs` | `VfsEngine` trait implementation bridging the FUSE adapter |
| `commit_group.rs` | `CommitGroupStateMachine`, `CommitGroupConfig`, commit phases and ordering |
| `intent_log.rs` | `IntentLog` and intent-log buffer for crash-safe mutations |
| `crash_recovery.rs` | Crash-matrix validation fixtures |
| `recovery.rs` | Mounted committed-root selection and durable-intent replay |
| `repair.rs` | Corruption resolution: truncate, mark-corrupt, reconstruct |
| `scrub.rs` | Block-level checksum pipeline with outcome classification |
| `fsck.rs` | `FsckReport`, `FsckCategory`, `FsckSeverity` |
| `dedup.rs` | `DedupIndex`: in-memory BTreeMap-backed content dedup |
| `page_cache/` | `PageCache`, `DirtyPageTracker`, LRU reclaim |
| `write_buffer.rs` | Small-write coalescing before object-store dispatch |
| `writeback.rs` | `DirtySet` tracking and writeback orchestration |
| `writeback_daemon.rs` | Background writeback timer service |
| `namespace/` | Link, unlink, rename, symlink operations |
| `snapshot.rs` | Snapshot create, list, delete, rollback |
| `send_receive.rs` | `VFSSEND1` changed-record export/import |
| `posix_acl.rs` | POSIX ACL integration |
| `xattr_dispatch.rs` | Extended attribute get/set/list/remove dispatch |
| `quota.rs` | Quota enforcement and space-accounting bridge |
| `device_removal.rs` | Device removal lifecycle and drain coordination |
| `statfs.rs` | Filesystem statistics (`statfs`/`statvfs`) |
| `allocation.rs` | Space allocation policy and extent allocator integration |
| `open_dispatch.rs` | File open/release dispatch with handle lifecycle |
| `release_dispatch.rs` | File release and resource cleanup |
| `crash_hooks.rs` | Deterministic crash-injection points for testing |
| `checksum.rs` | Block-level checksum computation and verification |
| `background_compaction.rs` | `BackgroundCompaction`: B+tree compaction service |
| `background_reclaim.rs` | `BackgroundReclaim`: model/test reclaim-queue entry processing (quarantined behind `#[cfg(test)]`) |
| `background_orphan_reclamation.rs` | `BackgroundOrphanReclamation`: orphan cleanup service |
| `space_pressure.rs` | `SpacePressure`: auto-compaction trigger logic |
| `fuse_fsync.rs` | FUSE `fsync`/`fsyncdir` dispatch |
| `fuse_getattr.rs` | FUSE `getattr`/`statx` attribute resolution |
| `fuse_setattr.rs` | FUSE `setattr` (chmod, chown, truncate, utimes) |
| `fuse_statfs.rs` | FUSE `statfs` capacity reporting |
| `parity_raid.rs` | Erasure-coded parity-RAID layout |
| `inode_cache.rs` | In-memory inode attribute cache (Authoritative) |
| `object_keys.rs` | Object-key family constructors |
| `orphan_cleanup.rs` | Orphan inode and block reclamation |
| `journal_cleaner.rs` | Intent-log journal pruning |
| `pool_label.rs` | Pool label management |
| `persistence.rs` | Object-store persistence helpers |
| `transaction.rs` | Transaction object management |
| `records.rs` | On-disk record serialization |
| `encoding.rs` | Binary encoding/decoding helpers |
| `helpers.rs` | Internal helper functions |
| `constants.rs` | Crate-wide constants |
| `content.rs` | Content object read/write operations |

## Cache Authority

Cache authority for this crate follows the canonical model at
`docs/cache-authority-model.md`.  Every cache layer in this crate carries an
authority classification (Authoritative, Derived, Optional, or Experimental)
in its module-level documentation.

| Module | Authority | Delegates To |
|---|---|---|
| `inode_cache.rs` | **Authoritative** | — |
| `page_cache/` | **Derived** | `tidefs-cache-core::PageCache` |
| `dirty_page_tracker.rs` | **Authoritative** (range tracking) | — |
| `writeback.rs` | **Authoritative** (dirty accounting) | — |
| `writeback_daemon.rs` | **Derived** | `dirty_page_tracker` + `writeback` |

There is no local whole-file content cache. Dirty overlay reads use buffered
bytes, and committed content reads retain current Pool placement authority.
The local-fs `PageCache` remains Derived and must not grow dirty-data or
durability authority that conflicts with cache-core.


## Revision Note

Last reconciled against codebase: 2026-07-23.
