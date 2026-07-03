# tidefs-pool-allocator

Lower-layer segment allocator for caller-provided free-segment maps. It tracks
free segments, picks segment_groups, reports allocator-local pressure
transitions, and serialises its own free-map checkpoints.

This crate answers "which free segment can this caller use next?" at segment
granularity. It is a placement input below mounted capacity accounting,
reclaim policy, and pool/device lifecycle authority. Product-facing capacity,
quota, `statfs`, reclaim, and pool/device lifecycle truth lives in
`docs/CAPACITY_ACCOUNTING_AUTHORITY.md`,
`docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`, and
`validation/claims.toml`.

## Position in the stack

```
mounted capacity / pool-device lifecycle authority
        |
  pool-import / pool-scan   -- provide device and free-segment inputs
        |
  PoolAllocator             -- allocator-local next-segment choice or ENOSPC
        |
  object store / reclaim    -- callers consume/free/checkpoint segments
        |
  BlockAllocator            -- "here are N free blocks within this segment"
```

## Architecture

Two allocator levels, one crate:

- **`PoolAllocator`** — single-device allocator wrapping a `SegmentFreeMap`
  with per-segment_group cursors, least-free-first segment_group selection,
  round-robin tiebreaking, and pressure-transition detection.
- **`MultiDevicePoolAllocator`** — coordinates multiple per-device
  `PoolAllocator` instances behind a unified allocate/free surface with
  device-class routing and cross-device checkpoint coordination.

Both levels are `Clone`-safe and hold no I/O handles; persistence is the
caller's responsibility via `PoolAllocator::to_checkpoint` /
`PoolAllocator::from_checkpoint`.

## Allocation strategy

### Single-device (`PoolAllocator::allocate`)

1. **Segment_group selection** — compute per-segment_group free counts from
   the free runs, then pick the non-empty segment_group with the fewest free
   segments (least-free-first packing for spatial locality). Ties are broken
   with a round-robin counter that advances past the selected segment_group.
2. **Cursor-based allocation** — use the selected segment_group's monotonic
   cursor to find a free segment via `alloc_after()`. The cursor wraps within
   the segment_group boundary, never crossing into another segment_group.

Callers that need a specific segment (e.g., store open with an existing
cursor) can bypass the selection policy via `PoolAllocator::alloc_after`.

### Multi-device (`MultiDevicePoolAllocator::allocate`)

3. **Device selection** — iterate per-device allocators in registration order;
   the first device that successfully allocates a segment wins. No
   cross-device balancing policy is applied (least-free-first operates within
   each device independently).

## Allocation lifecycle

```
allocate() --> use segment --> add_free(segment) --> back in free pool
                 |
                 v
           check_pressure_transition()
                 |
                 v
           to_checkpoint() --> persist free-map state
```

## Design invariants

1. Per-segment_group cursors advance monotonically within each segment_group,
   wrapping within the segment_group boundary — they never cross
   segment_groups.
2. Segment_group selection is deterministic given the same free-map state:
   pick the non-empty segment_group with the fewest free segments; break ties
   with a round-robin counter.
3. Pressure events fire on threshold crossing (rising edge: >= 95% used;
   falling edge: < 95% used), never on repeated queries while already under
   pressure. Hysteresis prevents repeated event flooding.
4. All errors forward the underlying `FreeMapError` faithfully — no
   information is swallowed.
5. Multi-device allocators maintain per-device `PoolAllocator` instances; the
   aggregate `any_device_under_pressure` flag is true when at least one device
   crosses the pressure threshold.

## Public API

### Core types

| Type | Role |
|---|---|
| `PoolAllocator` | Single-device segment allocator |
| `MultiDevicePoolAllocator` | Multi-device coordinator |
| `PoolAllocatorError` | Error enum (wraps `FreeMapError`) |
| `SpacePressureEvent` | Pressure transition (enter/exit) |
| `PoolAllocatorStats` | Snapshot of allocator-visible free-segment state |
| `SegmentGroupAllocStats` | Per-segment_group allocation counters |
| `AllocDeviceClass` | Device class for multi-device routing |
| `MultiDeviceAllocError` | Multi-device error enum |

### Delegation methods

`PoolAllocator` exposes passthrough methods to the underlying `SegmentFreeMap`:
`add_free`, `remove_free`, `is_free`, `runs`, `free_count`,
`dirty_segment_groups`, `clear_dirty_segment_groups`.

### Checkpoint coordination

- `PoolAllocator::to_checkpoint(dirty_only)` — serialises free-map state to
  `SpaceMapCheckpointV1`. Incremental (dirty_only=true) or full.
- `PoolAllocator::from_checkpoint(checkpoint)` — reconstructs a `PoolAllocator`
  from a persistent checkpoint, decoding per-segment_group bitmaps.

### Pressure tracking

- `PoolAllocator::is_under_pressure()` — query current pressure state (>= 95%
  used).
- `PoolAllocator::check_pressure_transition()` — detect crossing events
  (enter/exit) with hysteresis; returns `None` when pressure state is stable.
- `PoolAllocator::reset_pressure_tracking()` — force-reset hysteresis after
  pool import.

## Error surface

### `PoolAllocatorError`

| Variant | Condition |
|---|---|
| `NoFreeSegments` | Pool exhausted (ENOSPC) |
| `SegmentOutOfRange(seg)` | Segment index exceeds `segment_count` |
| `AlreadyUsed(seg)` | Segment is already in the target state |
| `InvalidRun(start, end)` | Run bounds are invalid |
| `CorruptCheckpoint` | Spacemap checkpoint is unreadable |

### `MultiDeviceAllocError`

| Variant | Condition |
|---|---|
| `NoFreeSegments` | No free segments across any device |
| `NoDeviceForClass(class)` | No device registered for the requested class |

## Integration map

| Consumer crate | Interface bridge | Role |
|---|---|---|
| `tidefs-local-object-store` | `PoolAllocator` (direct dep) | Free-segment tracking for object-store writes; checkpoint serialization via `to_checkpoint`/`from_checkpoint`; pressure-signal monitoring |
| `tidefs-reclaim` | `SegmentFreer` impl for `PoolAllocator` | Drains dead object segments back to the free pool via `add_free` |
| `tidefs-pool-import` | `PoolAllocator::from_checkpoint` | Bootstrap pool allocator state from on-disk checkpoint during mount |
| `tidefs-pool-scan` | `PoolAllocator::stats` | Pool health and capacity reporting via allocation statistics |
| `tidefs-dataset-lifecycle` | `SpacePressureEvent` | Capacity planning triggers background reclamation or dataset resize when pressure transitions fire |
| `tidefs-block-allocator` | Segments allocated here | BlockAllocator operates within segments; pool allocator decides *which* segment, block allocator decides *which blocks* within it |

## Module map

| Module | Responsibility |
|---|---|
| [`lib`](src/lib.rs) | `PoolAllocator`, `MultiDevicePoolAllocator`, `PoolAllocatorError`, `MultiDeviceAllocError`, `SpacePressureEvent`, `PoolAllocatorStats`, `SegmentGroupAllocStats`, `AllocDeviceClass`, and all inline tests |

All source lives in `src/lib.rs`; there are no submodules.

## On-disk format

`PoolAllocator` does not own its own on-disk format. It delegates to
`SegmentFreeMap` for free-segment tracking and to `SpaceMapCheckpointV1` for
persistent checkpoint serialization. Format notes:

- **SegmentFreeMap** uses per-segment_group bitmaps backed by free runs; runs
  are encoded as `(start, end)` pairs.
- **SpaceMapCheckpointV1** serialises the free map into a checkpoint structure
  with per-segment_group bitmaps and a generation counter. The checkpoint is
  the unit of persistence.
- **Incremental checkpoint** (`dirty_only=true`) includes only segment_groups
  modified since the last checkpoint; full checkpoint includes all
  segment_groups.
- **Pre-release**: TideFS has not shipped a public release. The checkpoint
  format has no backward-compatibility obligations.
- **No magic, no checksum**: versioning and integrity verification are the
  responsibility of the object-store layer that persists the checkpoint.

## Testing

All tests live inline in `src/lib.rs` under `#[cfg(test)] mod tests` and a
second `#[cfg(test)]` block for `MultiDevicePoolAllocator`. They cover:

- Basic allocation/exhaustion
- `add_free`/`remove_free` idempotency
- Pressure transitions (enter/exit/stable)
- Per-segment_group cursor tracking and wrapping
- Round-robin tiebreaking
- Selection policy (least-free-first)
- `alloc_after` bypass
- Error conversion from `FreeMapError`
- Full lifecycle round-trips (allocate, exhaust, free, re-allocate)
- Checkpoint serialization (full and dirty-only)
- Dirty segment_group tracking and clearing
- Multi-device coordination, device-class routing, and cross-device
  checkpoint
- Integration-chain propagation (allocate → pressure → exhaustion → free →
  exit pressure → re-allocate)

## Build and test

```sh
# Check compilation
cargo check -p tidefs-pool-allocator

# Generate documentation
cargo doc --no-deps -p tidefs-pool-allocator --open

# Run tests
cargo test -p tidefs-pool-allocator
```
