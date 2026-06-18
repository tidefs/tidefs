# tidefs-local-filesystem

Durable local filesystem model built on the TideFS Local Object Store.

## Overview

`tidefs-local-filesystem` is the primary filesystem implementation crate in
TideFS. It publishes namespace changes through immutable transaction objects
and root-slot commits on top of [`tidefs_local_object_store`]. On reopen,
incomplete commits are ignored and the newest valid committed root is
selected automatically — production recovery never requires an operator
repair pass.

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
    ├── CommitGroupStateMachine  (Open → Syncing → Committed)
    ├── WriteBuffer              (small-write coalescing)
    ├── DirtySet                 (data, metadata, catalog dirty tracking)
    ├── IntentLog                (crash-safe mutation records)
    ├── PageCache                (cached read pages + dirty-page tracking)
    └── Background Services
         ├── BackgroundCompaction
         ├── BackgroundOrphanReclamation
         └── WritebackDaemon
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
| [`CrashRecoveryReport`] | Intent-log replay and root-selection summary after crash |
| [`RecoveryAuditReport`] | Deterministic replay-audit of committed-root chain |
| [`OnlineVerifierReport`] | Live integrity scan of pool object state |
| [`CommitGroupConfig`] | Transaction-group config: sync thresholds, auto-commit policy |
| [`IntentLog`] | Metadata-level intent-log buffer for crash-safe namespace operations |
| [`PageCache`] | In-memory page cache for read acceleration and dirty-page tracking |
| [`TxgReplayEngine`] | Replays committed txgs during mount, bridging committed-root discovery to commit_group journal records |

## Transaction Model

Writes are grouped into transaction groups managed by
[`CommitGroupStateMachine`]. Each commit group proceeds through
`Open → Syncing → Committed` phases. A `CommitClass` tags each commit
group as `Sync`, `DataSync`, or `AutoCommit` to control durability
semantics. The state machine ensures exactly-once replay of committed
groups after a crash.

## Recovery Model

On open, [`crash_recovery`] replays the intent log and selects the
newest valid committed root. The [`recovery`] module handles torn-tail
repair without operator intervention. [`repair`] applies corruption
resolution strategies (truncate, mark-corrupt, reconstruct), and
[`scrub`] runs a full block-level checksum pipeline with outcome
classification.

### Txg Commit Replay

[`TxgReplayEngine`] replays committed transaction groups during mount
recovery, bridging the gap between committed-root discovery (root-slot
ring scan) and commit_group journal records.

The mount sequence runs: root-slot recovery → intent-log replay →
commit_group journal recovery → **txg commit replay** → mount.

Chain digests are computed via `compute_chain_digest` from
`tidefs-commit_group` using domain-separated BLAKE3 key derivation.
After each txg is replayed, a completion marker is written under the
deterministic key `txg-replay-marker-{txg_id}`, allowing interrupted
replays to resume from the last fully-applied group.

## Background Services

Four background services are wired via [`tidefs_background_scheduler`]:

- **`BackgroundCompaction`** — compacts the reclaim queue's B+tree
  when fill ratios drop below the configured threshold, using
  [`BPlusTreeReclaimQueue`] from [`tidefs_reclaim_queue_core`].
- **`BackgroundReclaim`** — model/test surface only (quarantined behind
  `#[cfg(test)]`); live mounted-pool physical reclaim requires the
  receipt-bound dead-object drain in `LocalObjectStore` (see Reclaim
  Authority below).
- **`BackgroundOrphanReclamation`** — cleans up orphaned inodes and
  blocks that lost their last reference path.
- **`WritebackDaemon`** — flushes dirty data from the page cache to
  the object store on a timer, gated by the dirty-set tracker.

## Reclaim Authority

The mounted-pool segment-freeing authority is the receipt-bound dead-object
drain in `tidefs-local-object-store`. `LocalObjectStore::drain_dead_segments`
now inspects the older object-store reclaim queue and fails closed without
committed receipt evidence. `BackgroundReclaim` and `ProcessedDelta` in
`background_reclaim.rs` are model/test surfaces quarantined behind
`#[cfg(test)]` and are not release reclaim validation.

Production reclaim chain:

1. `record_reclaim_delta()` — records refcount deltas into the local
   `BPlusTreeReclaimQueue` during unlink, truncate, and rename-overwrite.
2. `tick_background_services()` Duty 2 — drains the local queue and calls
   `LocalObjectStore::delete()` for each entry.
3. `LocalObjectStore::delete()` — removes the object from the in-memory
   index and enqueues a legacy object-store reclaim entry.
4. Receipt-bound dead-object drain — frees physical segments only after
   committed deadlist and snapshot-pin clearance evidence authorizes the
   dead object ids.

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
| `commit_group.rs` | `CommitGroupStateMachine`, `CommitGroupConfig`, `CommitClass` |
| `txg_replay.rs` | [`TxgReplayEngine`]: committed-txg roll-forward with BLAKE3 chain verification |
| `intent_log.rs` | `IntentLog` and intent-log buffer for crash-safe mutations |
| `crash_recovery.rs` | Mount-time intent-log replay and root selection |
| `recovery.rs` | Torn-tail repair, committed-root chain traversal |
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
| `hot_read_cache.rs` | Small-read cache for frequently accessed blocks (Derived, superseded by cache-core) |
| `inode_cache.rs` | In-memory inode attribute cache (Authoritative) |
| `object_keys.rs` | Object-key family constructors |
| `orphan_cleanup.rs` | Orphan inode and block reclamation |
| `readahead.rs` | Sequential read prefetch (Derived) |
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
| `hot_read_cache.rs` | **Derived** (superseded) | `tidefs-cache-core::PageCache` |
| `inode_cache.rs` | **Authoritative** | — |
| `page_cache/` | **Derived** | `tidefs-cache-core::PageCache` |
| `dirty_page_tracker.rs` | **Authoritative** (range tracking) | — |
| `writeback.rs` | **Authoritative** (dirty accounting) | — |
| `writeback_daemon.rs` | **Derived** | `dirty_page_tracker` + `writeback` |
| `readahead.rs` | **Derived** | `tidefs-cache-core::Prefetch` |

The `HotReadCache` and local-fs `PageCache` are classified as Derived and
must not grow new authority claims or dirty-data ownership that conflicts
with `tidefs-cache-core`.  Future work will remove the `HotReadCache` in
favor of cache-core delegation and merge the local-fs `PageCache` into
cache-core.


## Revision Note

Last reconciled against codebase: 2026-05-17.
