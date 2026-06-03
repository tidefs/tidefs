# Local Storage Allocator (OW-102 / PC-006)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document records the historical tracker item 102 allocator/free-space
accounting slice and the publishing-checklist `PC-006` space-management/ENOSPC
slice for review.

## Implemented State

The Local Filesystem now has a finite allocator policy:

- `LocalStorageAllocatorPolicy::content_capacity_bytes`
- `LocalStorageAllocatorPolicy::inode_capacity`
- `LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES`

The allocator is enforced before publishing a new root. A mutation that would exceed the content or inode capacity returns `FileSystemError::NoSpace`; the FUSE preview maps that error to `ENOSPC`.

Content accounting is chunk-graph based. The allocator counts unique chunk/content objects referenced by the proposed current namespace plus content still protected by committed fallback roots. The protected committed roots set is therefore part of allocator admission. This means rewriting a chunk can require temporary capacity for both the old protected chunk and the new chunk until later reclamation can prove the old chunk is no longer protected.

## PC-006 Scope

`PC-006` is covered for the current local preview by implementation-tracked non-release design and
tests for:

- finite content-grain and inode capacity accounting before publication;
- allocator admission that rejects oversized content or inode growth without
  mutating namespace state;
- protected committed-root chunk accounting before reuse;
- `statfs` reporting the same allocator truth used by admission;
- FUSE preview `ENOSPC` mapping for allocator exhaustion;
- fallocate mode `0` allocation through the same allocator path.

This is not a production block-volume, ublk, sparse reservation, or broad
external durability claim. Those remain deferred production gates.

## Statfs

`LocalFileSystem::statfs()` renders the same allocator report used for admission:

- total/free blocks come from `content_capacity_bytes`, `allocator_reserved_bytes`, and `reusable_free_bytes`;
- block size and fragment size are `LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES`;
- file count and free file count come from `inode_capacity` and the live inode table.

The userspace FUSE preview returns these values through `ReplyStatfs` instead of returning `EIO`.

## Fallocate

`LocalFileSystem::fallocate_file()` supports allocator-admitted mode-zero allocation by zero-extending the chunked file layout to `offset + length` when needed.

The FUSE preview supports `fallocate` with mode `0`. Other fallocate mode flags remain `EOPNOTSUPP` until sparse extent identity, hole punching, and keep-size reservation records exist.


Source and tests:

- `allocator_counts_protected_chunk_refs_before_reuse`
- `allocator_rejects_inode_exhaustion_without_mutation`
- `fallocate_extends_through_allocator_and_reports_statfs`
- `preview_fuse_model_reports_statfs_and_fallocate_mode_zero`
- `LocalStorageAllocatorReport`
- `protected_committed_content_entries`
- `ensure_content_capacity_with_planned_inode`


```sh
cargo run -p tidefs-xtask -- check-local-storage-allocator
tidefs-xtask check-local-storage-allocator
```

This check binds the source markers, documentation, FUSE preview
historical tracker item 102 and publishing-checklist item `PC-006`. Live
work-state tracking is in Forgejo; tracking issue: #1872.



## Remaining Work

This slice does not implement mutating compaction or garbage collection. It
deliberately treats protected committed-root content as unavailable for reuse.
Later `OW-103` work must prove root-retention safety before reclaiming old
and sparse reservation modes remain out of scope for `PC-006`.
