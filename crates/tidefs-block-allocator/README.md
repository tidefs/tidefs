# tidefs-block-allocator

Userspace block allocator: the pacing component that gates all write-path work
in TideFS. Answers "where can I put this data?" and "how much space is left?",
sitting between the extent map and the object store.

## Position in the stack

```
FUSE handler / ublk target
        |
  VfsEngine / extent map    -- "I need N blocks for this file"
        |
  BlockAllocator            -- "here are N free blocks" or ENOSPC
        |
  object store / bitmap persistence
```

Every file-extent write, block-device I/O, and object-store allocation flows
through this crate. It is the single authority on free-block tracking,
admission control, and per-inode quota enforcement for the entire storage pool.

## Architecture

`BlockAllocator` is the single public entry-point, wrapping all mutable state
behind `Arc<RwLock<AllocatorInner>>`. It is `Clone` (cheap `Arc` clone) and
safe to share across threads.

Internal components:

- [`FreeBlockBitmap`](src/bitmap.rs) — persistent bit-level free/used tracking
  (1 = used, 0 = free). Bit `i` corresponds to block `i`. Supports first-fit,
  best-fit, and scattered allocation, plus `FreeExtentIter` for
  fragmentation-aware compaction.
- [`QuotaTable`](src/quota.rs) — per-inode reserve → commit → release lifecycle
  with hard-limit enforcement. Entries lazily created on first access and
  pruned when both reserved and committed counts reach zero.
- `AllocatorTopology` / `DeviceTopology` — sector-alignment contracts and
  per-device physical geometry (logical/physical sector size, min I/O size,
  alignment offset). The allocator resolves the correct topology at allocation
  time and rejects cross-device requests.
- [`Statfs`](src/statfs.rs) — Linux `statfs`/`statvfs` block counters; inode
  fields zeroed for namespace-layer merge.
- `TrimSink` — optional TRIM/UNMAP dispatch (file-backed `fallocate` or
  block-device `BLKDISCARD`). Coalesces adjacent freed ranges and enforces a
  configurable `min_discard_bytes` threshold.
- Device registry — maps `DeviceId` to `DeviceTopology` for per-device fencing
  and topology-aware allocation via `alloc_bytes_at` and
  `alloc_any_skip_devices`.

## Allocation strategy

Three-tier strategy, called through `BlockAllocator::alloc`:

1. **First-fit** via `FreeBlockBitmap::alloc_contiguous` — scans forward from
   the last allocation hint for the first run of consecutive free bits. Good
   average-case performance, no full-scan overhead.
2. **Best-fit** via `FreeBlockBitmap::alloc_contiguous_best_fit` — scans the
   entire bitmap, selects the smallest free run that satisfies the request.
   Reduces long-term fragmentation at the cost of a full scan.
3. **Scattered fallback** via `FreeBlockBitmap::alloc_any` — picks any free
   blocks (non-contiguous) when the bitmap is too fragmented for a contiguous
   run.

Higher-level entry points enrich the result:

- `allocate(n)` — returns `AllocResult` with `NoSpace { largest_free_extent }`
  diagnostic; contiguous-only (no scattered fallback).
- `allocate_aligned(bytes)` — rounds byte count up to the configured sector
  boundary before delegating to `allocate`.
- `alloc_bytes(bytes)` — byte-oriented with physical-sector alignment
  awareness; prefers physically-aligned runs from the spacemap size-class
  cache, falling back to scattered allocation.
- `alloc_bytes_at(bytes, pool_offset)` — allocates at a target pool offset
  with per-device topology resolution and inward-rounding alignment.

## Allocation lifecycle

Every write goes through three phases:

1. **Reserve** (`BlockAllocator::reserve`) — claim blocks against the inode's
   quota. Fails with `AllocError::QuotaExceeded` if the hard limit would be
   breached. No bitmap mutation.
2. **Allocate** (`alloc` / `allocate` / `alloc_bytes`) — obtain concrete block
   addresses from the free-block bitmap. On success, blocks are marked used and
   the spacemap is updated.
3. **Commit** (`BlockAllocator::commit`) — move reserved quota to committed
   (counted against the inode's hard limit). Marks the bitmap dirty for the
   next flush.

Rollback: `release()` aborts a reservation; `free()` + `uncommit()` undo an
already-committed allocation.

## Concurrency contract

A single `Arc<RwLock<AllocatorInner>>` guards all mutable state. The write
path (`alloc`/`free`/`flush`/`reserve`/`commit`/`release`/`uncommit`) takes a
write lock; read-only operations (`statfs`, `free_count`, `block_count`,
`topology_for`, `quota_counts`) take a read lock. Contention is expected to be
low because the lock is held only for bitmap/table mutation, not for I/O.

## Error surface

`AllocError` ([src/error.rs](src/error.rs)) has 10 variants covering the full
failure space:

| Variant | Condition |
|---|---|
| `NoSpace` | Pool exhausted (ENOSPC) |
| `QuotaExceeded` | Per-inode hard limit breach |
| `AlignmentViolation` | Request violates sector / min-I/O alignment |
| `MisalignedOffset` | Start offset not sector-aligned |
| `MixedDeviceTopology` | Range spans devices with different topologies |
| `DeviceNotRegistered` | No topology registered for the offset |
| `DeviceAlreadyRegistered` | Duplicate `DeviceId` in registry |
| `Io` | I/O error during bitmap flush |
| `AlignmentImpossible` | Sector rounding consumed >50% of request |
| `InvalidDeviceTopology` | Supplied topology fails validation |

## Invariant guarantees

- `free_count + sum(len(all outstanding allocations)) == block_count` at every
  observable point. Verified by `FreeBlockBitmap::check_invariants()`.
- Guard bits beyond `block_count` are permanently marked used; they are never
  returned by any allocation method.
- The quota table enforces `committed + reserved + pending <= limit` per inode
  atomically within the write lock.
- Sector-alignment rounding is applied before bitmap allocation; the allocator
  rejects requests where alignment consumes more than `MAX_ALIGNMENT_SLACK`
  (50%) of the requested range.
- Cross-device allocation requests are rejected with `MixedDeviceTopology`.

## On-disk format

The free-block bitmap is the allocator's persistent state. Format notes:

- **Bit-level encoding**: bit `i` = 1 means block `i` is used, 0 means free.
  Stored as a flat array of little-endian `u64` words.
- **Region**: the bitmap occupies a reserved byte range (`Region { offset,
  length }`) at a well-known position in the backing storage image. Region size
  is `ceil(block_count / 64) × 8` bytes.
- **Guard bits**: if `block_count` is not a multiple of 64, unused bits in the
  last word are permanently set to 1 (used) and are never allocated or freed.
- **No version header, magic, or checksum**: the bitmap is a raw bit array.
  Versioning, checksums, and integrity verification are the responsibility of
  the object-store layer that persists the region.
- **Pre-release**: TideFS has not shipped a public release. The bitmap format
  has no backward-compatibility obligations. Future releases may change the
  encoding (add a header, compress, or split into per-device shards) without
  migration support.
- **Flush**: `BlockAllocator::flush_to()` writes only dirty words through a
  `BitmapFlushSink`. After a successful write, the bitmap is marked clean.
  Callers managing their own I/O can use `flush_words()` / `mark_clean()`.
- **Mount**: `BlockAllocator::from_persisted()` reconstructs the bitmap and
  spacemap from previously flushed words. Missing words are treated as fully
  used (safe default).

## Integration map

| Consumer crate | Interface bridge | Role |
|---|---|---|
| `tidefs-local-filesystem` | `BlockAllocator` (direct dep) | File-extent allocation in the FUSE write path: `reserve` / `alloc` / `commit` / `free` |
| `tidefs-block-volume-adapter-core` | `BlockAllocator` (direct dep) | Block-device write-path admission and space reservation for ublk targets |
| `tidefs-local-object-store` | `BlockAllocator` (direct dep) | Object-storage block provisioning; bitmap flush through `BitmapFlushSink` |
| `tidefs-device-removal` | `BlockAllocator` (direct dep) | Device fencing and deallocation; uses `alloc_any_skip_devices` and `free_blocks` |
| `tidefs-validation` | `BlockAllocator` (direct dep) | Deterministic allocation replay in test harnesses; exercises `from_persisted` and `flush_to` |

## Module map

| Module | Responsibility |
|---|---|
| [`bitmap`](src/bitmap.rs) | `FreeBlockBitmap` with bit-level alloc/free, first-fit/best-fit/scattered strategies, `FreeExtentIter`, invariant checks, and fenced-device allocation variants |
| [`quota`](src/quota.rs) | `QuotaTable` — per-inode reserve/commit/release/uncommit lifecycle with hard-limit enforcement |
| [`statfs`](src/statfs.rs) | `Statfs` struct mirroring Linux `statfs`/`statvfs` block fields; inode fields zeroed for namespace-layer merge |
| [`error`](src/error.rs) | `AllocError` enum: 10 variants covering ENOSPC, quota, alignment, device topology, and I/O failures |
| [`lib`](src/lib.rs) | `BlockAllocator` public entry-point, `AllocatorTopology`, `DeviceTopology`, `DeviceId`, `Region`, `BitmapFlushSink`, `TrimSink`, `TrimRequest`, `TrimStats`, and device registry |

## Testing

11 test files under `tests/` exercise allocation, deallocation, fragmentation,
concurrency, persistence round-trip, space accounting, edge cases, and
property-based allocation via `proptest`. The inline `#[cfg(test)] mod tests`
in `bitmap.rs`, `quota.rs`, and `statfs.rs` cover unit-level invariants.
