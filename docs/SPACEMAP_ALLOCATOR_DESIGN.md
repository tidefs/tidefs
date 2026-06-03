# Spacemap, Allocator, and Free-Space Tracking Design (G1 Foundation, P1 hard-gate)

Maturity: **design-spec** for the persistent spacemap format, run-based free-segment
allocator (SegmentFreeMap), metaslab-partitioned bitmap encoding (SpaceMapBitmap),
segment generation counters, ENOSPC semantics, and incremental spacemap checkpointing
integrated with the commit_group commit pipeline.

This document closes Forgejo issue #1189.

## 1. Motivation

Space management is the #1 missing foundation in the tidefs design book's "What is
missing" section (G1). Without a persistent spacemap and deterministic allocator, the
system cannot:

- Correctly report ENOSPC — writes must be rejected before the pool is physically full,
  and the allocator is the authority on whether space exists.
- Implement space pressure handling (#1181) — GC and reclamation depend on the allocator
  to both report exhaustion and receive freed segments back.
- Support pool expansion or shrink — adding new devices requires merging new free space
  into the allocator's free set.
- Do efficient segment allocation at scale — metaslab partitioning enables parallel
  allocation and locality-aware placement.

The existing codebase has allocation type sketches
(`tidefs-local-filesystem/src/allocation.rs`) and pool-level segment management
(`tidefs-local-object-store/src/pool.rs`) but no runtime allocator, no persistent
spacemap, and no ENOSPC path.

ZFS's approach (metaslab allocator with spacemap logs) is battle-tested but complex:
each metaslab has an in-core AVL tree of free segments plus an on-disk log of
allocations/frees that must be replayed on import. This design simplifies the model by
using a deterministic run-based free map with incremental bitmap checkpoints — no
log replay required.

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1267 (COMMIT_GROUP state machine) | Commit pipeline | Spacemap checkpoint is written during each commit_group commit. Dirty metaslabs are flushed to the pool-map journal as part of the commit record. |
| #1254 (pool import/export) | Pool bootstrap | On pool import, the spacemap checkpoint is read from the pool-map journal to reconstruct the in-memory free map. |
| #1181 (space pressure) | ENOSPC trigger | The allocator reports `FreeMapError::NoFreeSegments` when the pool is full; this triggers the space pressure path which invokes GC. |
| #1180 (refcount delta cleanup) | Segment free path | When GC reclaims a segment, `add_free(seg)` returns it to the allocator's free set. |
| #1223 (dataset feature flags) | Pool organization | Datasets live in a pool; the allocator is pool-scoped, not per-dataset. |
| #1215 (space accounting) | Physical vs logical space | The allocator tracks physical segment allocation; the space accounting model tracks logical usage within segments. |
| #1219 (dataset lifecycle) | Destroy reclamation | When a dataset is destroyed, its segments are freed back to the allocator. |

## 3. Architecture Overview

```
                    ┌─────────────────────────┐
                    │     SegmentFreeMap       │
                    │  (in-memory, per-pool)   │
                    │                          │
                    │  free_runs: BTreeSet of  │
                    │  [start, end) intervals  │
                    │                          │
                    │  dirty_metaslabs: Bitmap │
                    │  generation counters     │
                    └──────┬──────────────────┘
                           │
              alloc_after  │  add_free
              remove_free  │  is_free
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Segment     │  │  SegmentStore │  │  GC / Reclaim│
│  Allocator   │  │  (append)     │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
                           │
                           │ on commit_group commit
                           ▼
                  ┌─────────────────┐
                  │ SpaceMapCheckpoint│
                  │ (on-media, per   │
                  │  pool-map journal │
                  │  commit record)   │
                  │                  │
                  │ metaslabs: [u8]  │
                  │ per metaslab     │
                  │ 1=free, 0=used   │
                  └─────────────────┘
```

The design separates three concerns:
1. **SegmentFreeMap** — in-memory free segment tracker with run-based representation
2. **SpaceMapBitmap** — on-media bitmap encoding with metaslab partitioning
3. **Checkpointing** — incremental flush of dirty metaslabs to the pool-map journal

## 4. SegmentFreeMap: Deterministic Free-Segment Allocator

### 4.1 Core data structure

```
SegmentFreeMap {
    segment_count: u64,
    free_runs: BTreeSet<(u64, u64)>,  // Sorted, disjoint half-open [start, end) intervals
    generation: u64,                    // Monotonic generation counter for segment lifecycle
    dirty_metaslabs: Bitmap,            // Which metaslabs need checkpointing
}
```

The `free_runs` set is always maintained as a set of sorted, disjoint, non-adjacent
intervals. Adjacent runs are merged on insert; overlapping runs are rejected. This
guarantees O(log N) lookup for `is_free()` and O(log N) insertion/removal.

### 4.2 Operations

**`new(segment_count: u64, initial_free: Vec<(u64, u64)>) -> SegmentFreeMap`**

Construct from an initial set of free runs. Runs are sorted, merged if adjacent,

**`alloc_after(cursor: u64) -> Result<u64, FreeMapError>`**

Allocate one free segment at or after `cursor`. Algorithm:
1. Find the first free run where `run.start >= cursor` or `run.end > cursor`.
2. If no run found after `cursor`, wrap to `segment 0` and search again.
3. If still no free segment, return `FreeMapError::NoFreeSegments`.
4. Remove the allocated segment from `free_runs`:
   - If the segment was the only one in the run and the run had length 1, delete the run.
   - If the segment is at `run.start`, increment `run.start` by 1.
   - If the segment is at `run.end - 1`, decrement `run.end` by 1.
   - Otherwise, split the run into `[start, seg)` and `[seg+1, end)`.
5. Mark the segment's metaslab as dirty.
6. Return the allocated segment index.

This cursor-based allocation provides natural wear leveling: the cursor advances
monotonically through the segment space, wrapping to zero when exhausted. Unlike
random allocation, this avoids hot spots while remaining deterministic.

**`add_free(seg: u64) -> Result<(), FreeMapError>`**

Return a segment to the free set. Idempotent: if the segment is already free,
returns `Ok(())` without error. Algorithm:
1. If `seg` is already free (covered by a run), return `Ok(())`.
2. Find the insertion point in `free_runs`.
3. Insert `(seg, seg+1)` and merge with adjacent runs if they touch.
4. Mark the segment's metaslab as dirty.

**`remove_free(seg: u64) -> Result<(), FreeMapError>`**

Mark a segment as used. This is the non-GC path — used when the SegmentStore
allocates a segment. Errors if the segment is already used (not in free set).
Delegates to the same run-removal logic as `alloc_after`.

**`is_free(seg: u64) -> bool`**

Test membership in the free set. O(log N) binary search over runs.

**`runs() -> Vec<(u64, u64)>`**

Return the current free runs for checkpoint serialization.

**`stats() -> SegmentFreeMapStats`**

```
SegmentFreeMapStats {
    segment_count: u64,
    free_segments: u64,
    used_segments: u64,
    free_runs: u64,
    fragmentation_pct: f64,  // (free_runs / free_segments) * 100
}
```

### 4.3 Cursor wrapping semantics

The cursor wraps from the highest segment index back to 0. This requires special
handling to avoid the ABA problem: a segment freed at index N while the cursor is
past N should still be allocatable. The implementation handles this by:

1. First pass: search from `cursor` to `segment_count`.
2. Second pass (if first fails): search from 0 to `cursor`.
3. If both fail: ENOSPC.

The cursor is advanced past the allocated segment on each successful allocation.
It is NOT reset to the allocated position — it continues advancing even if the
allocation came from the wrap-around pass. This ensures that recently freed
segments are not immediately reallocated, giving GC time to stabilize.

## 5. SpaceMapBitmap: Metaslab-Partitioned Bitmap Encoding

### 5.1 Partitioning strategy

The segment space is divided into fixed-size metaslabs. Each metaslab is
independently encoded as a bitmap where bit=1 means free and bit=0 means used.

Default metaslab size: 4096 segments (configurable via pool property
`metaslab_segments`). This is chosen to make each metaslab bitmap exactly
512 bytes (4096 bits / 8 bits per byte), which aligns with common block sizes.

Metaslab count: `ceil(segment_count / metaslab_segments)`

Last metaslab padding: if `segment_count` is not a multiple of `metaslab_segments`,
the trailing bits in the last metaslab's bitmap are cleared to 0 on encode and
ignored on decode.

### 5.2 Bit ordering

Within each byte: little-endian bit ordering (bit 0 = LSB). This matches the
v0.262 Python reference implementation and is the conventional choice for bitmap
storage in little-endian architectures.

```
Byte 0: [seg0] [seg1] [seg2] [seg3] [seg4] [seg5] [seg6] [seg7]
         LSB                                                     MSB
```

### 5.3 Encode

```
encode_bitmaps(free_runs: &[(u64, u64)], segment_count: u64, metaslab_segments: u64)
    -> Vec<Vec<u8>>
```

1. Compute metaslab layout: `metaslab_count = ceil(segment_count / metaslab_segments)`.
2. For each metaslab `m`:
   a. Create a zeroed bitmap of `metaslab_segments / 8` bytes.
   b. For each free run, compute overlap with metaslab `m`:
      - `run_start_in_ms = max(run.start, m * metaslab_segments) - m * metaslab_segments`
      - `run_end_in_ms = min(run.end, (m+1) * metaslab_segments) - m * metaslab_segments`
      - Set bits `run_start_in_ms` through `run_end_in_ms - 1` to 1.
   c. Clear padding bits beyond `segment_count` in the last metaslab.
3. Return vector of per-metaslab bitmap blobs.

### 5.4 Decode

```
decode_bitmaps(bitmaps: &[Vec<u8>], segment_count: u64, metaslab_segments: u64)
    -> Vec<(u64, u64)>
```

1. For each metaslab `m`:
   a. Scan the bitmap blob byte-by-byte, bit-by-bit.
   b. Collect runs of consecutive 1-bits.
   c. Convert bit positions to global segment indices: `global_seg = m * metaslab_segments + bit_pos`.
   d. Skip bits beyond `segment_count` in the last metaslab.
2. Merge adjacent runs across metaslab boundaries.
3. Return merged run list.

### 5.5 SpaceMapCheckpointV1 record

Persisted in the pool-map journal as part of each commit_group commit.

```
SpaceMapCheckpointV1 {
    magic: [u8; 4],                // "SPMP"
    version: u32,                  // 1
    segment_count: u64,            // Total segments in pool
    metaslab_segments: u64,        // Segments per metaslab
    metaslab_count: u32,           // Number of metaslabs in this checkpoint
    dirty_metaslab_count: u32,     // Number of dirty metaslabs included (incremental)
    generation: u64,               // Monotonic generation counter for segment lifecycle
    entries: [MetaslabBitmapEntry; dirty_metaslab_count],
}

MetaslabBitmapEntry {
    metaslab_index: u32,           // Which metaslab this bitmap is for
    bitmap_len: u32,               // Length of bitmap_data in bytes
    bitmap_data: [u8; bitmap_len], // Bitmap blob (1=free, 0=used)
}
```

Full checkpoints write all metaslabs. Incremental checkpoints write only dirty
metaslabs (those whose free/used state changed since the last commit).

## 6. Segment Generation Counters

### 6.1 Problem

When a segment is freed and later reallocated, stale pointers from old data may
still reference the segment. Without generation counters, a stale read might
interpret new data as the old format — a silent corruption vector.

### 6.2 Solution

Each segment carries a `generation: u64` counter that increments on every free
cycle. The counter is stored alongside the segment's on-media state and is
verified on every read:

```
SegmentHeaderV1 {
    // ... existing fields ...
    generation: u64,  // Incremented each time the segment is freed and reallocated
}
```

When reading a block, the pointer carries the expected generation. If the
segment's current generation doesn't match, the read is rejected with a
`StaleGeneration` error. This is a defense-in-depth measure that complements
the existing checksum-based integrity verification (#1287).

### 6.3 Integration with SegmentFreeMap

The `SegmentFreeMap.generation` field is NOT the per-segment generation — it
is a pool-wide counter used to assign generation numbers to newly allocated
segments. On `alloc_after()`:

1. Allocate segment `s`.
2. Read the segment's previous generation `g_old` from the segment header.
3. Set the segment's new generation to `pool_free_map.generation`.
4. Increment `pool_free_map.generation`.

This guarantees that every allocation cycle produces a unique generation,
even across pool restarts (the pool-wide generation is persisted in the
spacemap checkpoint).

## 7. Integration with SegmentStore and COMMIT_GROUP Commit

### 7.1 Pool open / import flow

On pool open (after pool import per #1254):

1. Read the latest `SpaceMapCheckpointV1` from the pool-map journal.
2. Decode all metaslab bitmaps into a free run list via `decode_bitmaps()`.
3. Construct the in-memory `SegmentFreeMap` from the run list.

### 7.2 Segment allocation flow

When the SegmentStore needs a new segment:

1. Call `free_map.alloc_after(cursor)`.
2. On success: update the segment header's `generation` field, mark segment
   as active in the segment index.
3. On `NoFreeSegments`: trigger space pressure path (#1181) — initiate GC,
   wait for reclamation, retry allocation.

### 7.3 Segment free flow (GC / reclaim)

When GC or dataset destroy frees a segment:

1. Verify the segment is currently used (not already free).
2. Increment the segment's generation counter (stored in a pending-free record
   until the segment is reallocated).
3. Call `free_map.add_free(seg)` — this marks the segment as free in the
   in-memory map and marks its metaslab as dirty.

### 7.4 COMMIT_GROUP commit integration

During each commit_group commit:

1. Check `free_map.dirty_metaslabs` for any modified metaslabs.
2. If dirty metaslabs exist:
   a. Encode only dirty metaslabs via `encode_bitmaps()`.
   b. Write `SpaceMapCheckpointV1` with only dirty entries to the pool-map journal.
   c. The checkpoint is committed atomically with the rest of the commit_group — if the
      commit_group fails, the spacemap state is not persisted and the in-memory free map
      remains unchanged.
3. Clear `free_map.dirty_metaslabs` after successful commit.

### 7.5 Crash recovery

The spacemap checkpoint is always a consistent snapshot of the free/used state
at the last committed commit_group. If the system crashes:

- The in-memory free map is reconstructed from the checkpoint on next import.
- Any segments allocated after the last checkpoint but before the crash are
  treated as used (they are referenced by the intent log or other committed
  data structures that survived the crash through journal replay).
- The allocator's free set may temporarily undercount free segments until the
  next GC pass discovers and frees orphaned segments. This is safe: undercounting
  free space is conservative (may report ENOSPC slightly early), but never
  overcounting (which would lead to double-allocation).

## 8. ENOSPC Semantics

### 8.1 Allocation error hierarchy

```
FreeMapError {
    NoFreeSegments,          // Pool is full; GC must run
    SegmentOutOfRange(u64),  // Segment index exceeds segment_count
    AlreadyUsed(u64),        // remove_free called on an already-used segment
    AlreadyFree(u64),        // remove_free called on an already-free segment
}
```

### 8.2 Reservation model (deferred)

Full reservation support (per-dataset quotas, admin reserve, etc.) is deferred to
the space accounting design (#1215). The V1 allocator provides only the fundamental
mechanism: a free/used segment bitmap. Higher-level reservation policies are built
on top of this.

### 8.3 Space pressure threshold

Before the pool is completely full, a configurable threshold triggers space
pressure notifications. Default: 95% capacity. When `used_segments / segment_count
> 0.95`, the allocator emits a `SpacePressureWarning` event that the space pressure
handler (#1181) uses to schedule proactive GC.

## 9. Metaslab Partitioning Strategy

### 9.1 Design rationale

Metaslab partitioning provides three benefits:

- **Parallel allocation**: With one allocator lock per metaslab, multiple threads
  can allocate segments concurrently without contention. The V1 implementation
  uses a single free map (single-threaded allocation), but the metaslab
  partitioning in the on-disk format enables future parallelism without format
  changes.

- **Locality-aware placement**: Related data (e.g., all extents of one file) can
  be placed in the same metaslab, improving read locality. The allocator can
  prefer metaslabs based on dataset or file identity.

- **Incremental checkpointing**: Only dirty metaslabs need to be written on each
  commit, reducing journal write amplification.

### 9.2 Default sizing

Default: 4096 segments per metaslab. This gives 512-byte bitmaps per metaslab.
For a 1 TB pool with 64 MB segments, that's 16,384 segments → 4 metaslabs.
For a 100 TB pool, 1,638,400 segments → 400 metaslabs.

The size is configurable via the pool property `metaslab_segments`. Tuning
guidance:
- Smaller metaslabs → more parallelism potential, larger checkpoint overhead.
- Larger metaslabs → fewer metaslabs to manage, coarser dirty granularity.
- The default of 4096 is a balanced choice for typical NVMe-backed pools.

## 10. ZFS Comparison

| Dimension | ZFS | tidefs (this design) |
|---|---|---|
| Free space tracking | Per-metaslab AVL tree of free segments + spacemap log (ZFS spacemap) | Single BTreeSet of runs per pool; metaslab bitmap for persistence |
| On-disk format | Spacemap log: append-only log of alloc/free operations; replay required on import | Incremental bitmap checkpoints; no log replay — decode bitmap directly |
| Allocation strategy | First-fit or best-fit within a metaslab; per-metaslab allocator with separate lock | Cursor-based allocation with wrap-around; natural wear leveling without randomness |
| Metaslab size | Dynamic: starts at 1/4096 of pool, grows up to 8 GB of space | Fixed: 4096 segments (configurable); each metaslab = 512 bytes on disk |
| Generation counters | Not present in ZFS; relies on block pointer birth commit_group for staleness detection | Per-segment generation counter; stale pointer detection at read time |
| ENOSPC | Returns ENOSPC when spacemap reports no free space; slop space reserve prevents full exhaustion | Returns `FreeMapError::NoFreeSegments`; 95% threshold triggers proactive GC |
| Incremental checkpoint | Spacemap log flushed on commit_group commit; full replay on import | Only dirty metaslabs written; no replay needed |
| Crash recovery | Replay spacemap log from last root_record | Reconstruct from last committed SpaceMapCheckpointV1; no replay |

Key tidefs advantages:
- **No log replay** on import: the bitmap checkpoint is always a consistent snapshot
  of the last committed commit_group. ZFS spacemap log replay can be slow for large pools
  with long-running commit_group groups.
- **Simpler on-disk format**: a single bitmap per metaslab vs ZFS's two-stage
  spacemap (in-core AVL + on-disk log). This eliminates the class of bugs where
  the log and the AVL tree diverge.
- **Deterministic wear leveling**: cursor-based allocation with wrap-around is
  simpler than ZFS's metaslab selection heuristics and produces predictable
  allocation patterns that are easier to reason about.

## 11. Implementation Plan

### Phase 1: SegmentFreeMap core
- Implement `SegmentFreeMap` struct with `BTreeSet<(u64, u64)>` backing.
- Implement `new()`, `alloc_after()`, `add_free()`, `remove_free()`, `is_free()`.
- Implement run merge/split logic.
- Implement `stats()`.
- Unit tests: allocation, free, double-free idempotency, wrap-around, ENOSPC,
  run merge on adjacent free, run split on partial allocation, fragmentation stats.

### Phase 2: SpaceMapBitmap encode/decode
- Implement `bitmap_layout()` with metaslab partitioning math.
- Implement `encode_bitmaps()` and `decode_bitmaps()`.
- Implement `SpaceMapCheckpointV1` record type.
- Unit tests: encode/decode round-trip, partial last metaslab, edge cases
  (1 segment, all free, all used, single free run across metaslab boundary).

### Phase 3: Segment generation counters
- Add `generation: u64` to segment header.
- Implement `alloc_after()` generation assignment.
- Unit tests: generation monotonicity, stale generation detection.

### Phase 4: Pool open/import integration
- Implement `SegmentFreeMap::from_checkpoint()` reconstructor.
- Wire into pool open path (after pool-map journal read).
- Integration test: create pool → allocate segments → export → import → verify
  free map matches.

### Phase 5: COMMIT_GROUP commit integration
- Implement `dirty_metaslabs` tracking in `SegmentFreeMap`.
- Implement `SpaceMapCheckpointV1` write during commit_group commit.
- Implement dirty metaslab clearing after successful commit.
- Integration test: allocate, commit, crash (simulated), recovery, verify free map.

### Phase 6: ENOSPC and space pressure
- Implement 95% threshold `SpacePressureWarning` event emission.
- Implement `FreeMapError::NoFreeSegments` integration with SegmentStore.
- Integration test: fill pool to 100% → verify ENOSPC → free segment → verify
  allocation resumes.

### Phase 7: Per-metaslab allocator (future)
- Split single `SegmentFreeMap` into per-metaslab instances with per-metaslab locks.
- Implement metaslab selection policy (round-robin, locality-aware).
- This phase is deferred until multi-threaded allocation is needed.

- `tidefs-xtask check-spacemap-allocator`: runs the full test suite for phases 1-6.
- QEMU smoke test: create pool, allocate segments until ENOSPC, free segments,
  export/import, verify free map consistency.

## 12. Open Questions

1. **Metaslab size default**: Is 4096 segments (512-byte bitmaps) the right
   for incremental checkpoint flushes.
2. **Cursor persistence**: Should the allocation cursor be persisted across
   restarts, or reset to 0 on each import? Persisting provides better wear
   leveling continuity; resetting simplifies the design.
3. **Per-kind allocation**: Should metadata and data segments use separate
   free maps with separate cursors? The v0.262 Python design suggests per-kind
   cursors but a single free map. Separate free maps would prevent data
   allocation from starving metadata.
4. **Slop space reserve**: ZFS reserves 1/64 of pool space as "slop" to prevent
   complete exhaustion. Should tidefs implement a similar reserve?

Answers deferred to implementation review.
