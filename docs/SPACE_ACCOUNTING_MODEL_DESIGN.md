# Space Accounting Model Design (P1 hard-gate)

Maturity: **design-spec** for logical vs physical space accounting, space domains
for clone families, the reservation model (fallocate guarantees), cleaner scheduling
with watermarks, snapshot deadlist accounting, obligation ledger integration, and the
statfs() contract.

This document closes Forgejo issue #1215.

## 1. Motivation

Space accounting is the bridge between what users see (logical space — "how much
disk space do I have left?") and what the allocator manages (physical space — "which
segments are free?"). Collapsing these into a single number creates two failure modes:

- **Over-reporting**: If `statfs` reports physical free segments, users see space
  that may be consumed by snapshots, reservations, or clone deduplication. They
  write data, then get ENOSPC when the physical pool is full.
- **Under-reporting**: If `statfs` reports only logical free space without accounting
  for reclaimable dead bytes, users see "disk full" when GB of space could be freed
  by the cleaner.

The space accounting model separates these concerns with explicit coupling rules:
logical space controls *whether* an operation is allowed (ENOSPC), physical space
controls *when* it completes (may block/throttle).

ZFS's accounting is functional but has well-known pain points: `zfs list` shows
`USED` / `AVAIL` but the relationship between these numbers and the underlying
metaslab allocator is opaque, and snapshot space accounting with `usedbysnapshots`
requires periodic scans that produce stale results under heavy write load. This
design provides O(1) snapshot deadlist accounting and clear coupling between the
accounting model and the allocator from #1189.

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1189 (spacemap/allocator) | Physical space reporting | The accounting model queries `SegmentFreeMap::stats()` for `phys_free_segments` and integrates with the allocator's ENOSPC path. |
| #1223 (dataset feature flags) | Per-dataset quotas | Quota enforcement is gated by feature flags; ACL/xattr space consumption is accounted within `logical_used_bytes`. |
| #1219 (dataset lifecycle) | Destroy reclamation | When a dataset enters DESTROYING, its logical space counters are zeroed and its physical extents are freed through the allocator. |
| #1267 (COMMIT_GROUP state machine) | Atomic counter updates | Space counter adjustments (alloc, free, reservation) are committed atomically within a commit_group. |
| #1181 (space pressure) | Cleaner scheduling | When `phys_free_segments < target_free_segments`, the accounting model signals the space pressure handler to invoke the cleaner. |
| #1207 (orphan index) | Orphan space accounting | Orphaned inodes (nlink==0 but still open) consume space tracked separately from `logical_used_bytes` until reclaimed. |
| #818 (obligation ledger) | Pre-allocator scarcity gate | The obligation ledger gates writes before the allocator; space accounting provides the post-allocator ENOSPC check. Both commit deltas in the same commit_group. |

## 3. Logical Space Counters

### 3.1 DatasetSpaceCountersV1

Every dataset carries logical space counters in its dataset record's TLV extension
area. These are updated atomically within each commit_group.

```
DatasetSpaceCountersV1 {
    logical_used_bytes: u64,      // Unique live bytes reachable from any live root
    pinned_snapshot_bytes: u64,   // Subset pinned by snapshot deadlists (O(1) tracked)
    reserved_bytes: u64,          // Space reserved via fallocate (UNWRITTEN extents)
    orphan_bytes: u64,            // Space held by nlink==0 inodes still open
    quota_bytes: u64,             // Hard quota for this dataset (0 = no quota)
    slop_bytes: u64,              // Non-user-allocatable safety headroom
}
```

### 3.2 Derived values

```
logical_alloc_bytes = logical_used_bytes + reserved_bytes + orphan_bytes
logical_avail_bytes = max(0, quota_bytes - logical_alloc_bytes - slop_bytes)
```

When `quota_bytes == 0` (no quota), `logical_avail_bytes` is derived from the
pool's physical capacity: `max(0, phys_capacity - logical_alloc_bytes - slop)`.

`logical_avail_bytes` is what matters for ENOSPC decisions: if a mutating operation
would push `logical_alloc_bytes` beyond the quota/slop ceiling, it is refused
with ENOSPC.

### 3.3 SpaceDelta accumulator

Each mutating operation produces a `SpaceDelta` that is accumulated during the
commit_group and committed atomically.

```
SpaceDelta {
    logical_used_delta: i64,      // + for new writes, - for truncate/free
    reserved_delta: i64,          // + for fallocate, - for write-into-unwritten or punch
    orphan_delta: i64,            // + for unlink-while-open, - for final close
    pinned_snapshot_delta: i64,   // + for snapshot create, - for snapshot destroy
}
```

- No counter underflow: `counter + delta >= 0` for all counters.
- Quota ceiling: if `quota_bytes > 0`, then `logical_alloc_bytes + sum(deltas) <= quota_bytes - slop_bytes`.
- Domain consistency: sum of deltas across all datasets in a domain must not create
  negative aggregate logical_used (safety assertion).

## 4. Physical Space Counters

### 4.1 PoolPhysicalCountersV1

Physical space is pool-scoped, not per-dataset. These counters are derived from
the allocator (#1189) and the cleaner.

```
PoolPhysicalCountersV1 {
    phys_free_segments: u64,          // Segments in SegmentFreeMap (immediately allocatable)
    phys_free_bytes: u64,             // phys_free_segments * SEG_BYTES
    phys_reclaimable_bytes: u64,      // Dead bytes in older segments awaiting cleaning
    phys_tail_reserved_segments: u64, // Reserve for cleaner + metadata forward progress
    phys_total_segments: u64,         // Total pool capacity in segments
    phys_total_bytes: u64,            // phys_total_segments * SEG_BYTES
}
```

### 4.2 Coupling rule

```
ENOSPC decision: logical_avail_bytes <= 0  →  refuse operation with ENOSPC
Blocking decision: phys_free_segments <= min_free_segments  →  block/throttle until cleaner runs
```

This separation ensures:
- A dataset with quota exhausted correctly reports ENOSPC even when physical space
  is abundant (quota enforcement).
- A pool nearing physical exhaustion blocks writes even when logical quota remains
  (physical safety).
- The cleaner has a dedicated reserve (`phys_tail_reserved_segments`) so it can
  always make forward progress — without this, a full pool could deadlock because
  the cleaner itself needs segments to write relocated data.

### 4.3 refresh_physical_counters

```
fn refresh_physical_counters(pool: &Pool) -> PoolPhysicalCountersV1 {
    let free_stats = pool.segment_free_map.stats();
    PoolPhysicalCountersV1 {
        phys_free_segments: free_stats.free_segments,
        phys_free_bytes: free_stats.free_segments * SEG_BYTES,
        phys_reclaimable_bytes: pool.cleaner.estimate_reclaimable(),
        phys_tail_reserved_segments: pool.config.tail_reserve_segments,
        phys_total_segments: pool.segment_count,
        phys_total_bytes: pool.segment_count * SEG_BYTES,
    }
}
```

## 5. Space Domains for Clone Families

### 5.1 Concept

When a dataset is cloned, the clone and its origin share physical blocks. Reporting
`logical_used_bytes` per dataset would double-count shared blocks. Instead, datasets
are grouped into **space domains**: all clones of the same origin (and the origin
itself) belong to the same domain.

```
SpaceDomainId: u64  // Unique identifier for a clone family
```

A byte counts as logically used if it is reachable from *any* live dataset head
in the domain. statfs() and quota enforcement operate at the domain level.

### 5.2 Domain lifecycle

- **Create**: A new dataset with no clone origin creates a new `SpaceDomainId`.
  The domain's counters are initialized from the dataset's extents.
- **Clone**: The clone inherits the origin's `space_domain_id`. No counter change —
  the clone shares existing blocks.
- **Snapshot**: Snapshots belong to the same domain as their parent dataset.
  Snapshot creation does not change domain counters.
- **Destroy last member**: When the last dataset in a domain is destroyed, the domain
  is reclaimed and its `SpaceDomainId` may be reused.
- **Promote** (future): Detaching a clone from its origin creates a new domain
  for the promoted dataset. Shared blocks are accounted to the new domain; the
  origin's domain loses those blocks from its counters.

### 5.3 statfs integration

For a mounted dataset, `statfs` reports the domain's counters, not the individual
dataset's counters. This is the correct behavior: a clone consuming 10 GB of shared
space in a 100 GB domain should see 90 GB available, not 100 GB.

The domain counter lookup is O(1) via a `HashMap<SpaceDomainId, DomainCounters>`
in the pool's in-memory state.

## 6. Reservation Model

### 6.1 UNWRITTEN extents as persistent reservations

`fallocate(FALLOC_FL_KEEP_SIZE)` creates UNWRITTEN extents (#1225 tristate model).
These are persistent, on-disk reservations: the space is allocated (the extent
occupies logical bytes), but no data is written. When the application writes into
the reserved region:

1. The UNWRITTEN extent is converted to DATA.
2. `logical_used_bytes` does NOT change (the bytes were already counted as
   `reserved_bytes`).
3. `reserved_bytes` decreases by the converted byte count.

This guarantees that a successful `fallocate` followed by writes within the
reserved region never fails with ENOSPC — the space was already accounted.

### 6.2 Admission control

Each mutating operation computes a worst-case byte delta:

```
fn admission_check(op: &MutationOp, counters: &DatasetSpaceCountersV1) -> Result<()> {
    let needed = op.worst_case_byte_delta();
    if counters.logical_avail_bytes() < needed {
        return Err(ENOSPC);
    }
    if op.is_reservation() && counters.quota_bytes > 0 {
        if counters.logical_alloc_bytes() + needed > counters.quota_bytes - counters.slop_bytes {
            return Err(ENOSPC);
        }
    }
    Ok(())
}
```

Worst-case byte deltas:
- `write(offset, len)`: `len` bytes (worst: all new data, no overwrite).
- `fallocate(offset, len)`: `len` bytes (full reservation).
- `truncate(new_size)`: `-(old_size - new_size)` bytes (frees space).
- `unlink()`: `-(file_size)` bytes (frees space, deferred for nlink>1 via orphans).
- `clone()`: 0 bytes (shared blocks already accounted in domain).

### 6.3 Punch hole

`fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` releases reservations:
- DATA extents in the punched range are freed → `logical_used_bytes` decreases.
- UNWRITTEN extents in the punched range are dropped → `reserved_bytes` decreases.
- If the range falls entirely within UNWRITTEN extents, `logical_used_bytes` does
  not change (the reservation bytes become unreserved directly).

## 7. Snapshot Deadlist Accounting

### 7.1 The O(n) problem

Without deadlist accounting, computing `pinned_snapshot_bytes` requires scanning
all snapshots and summing the bytes of blocks they uniquely reference. For a dataset
with thousands of snapshots, this would be O(total blocks) — impossibly slow for
online operation. ZFS works around this with periodic `zfs list -t snapshot` scans,
but the result is often stale by minutes or hours.

### 7.2 O(1) deadlist model

Each snapshot carries per-snapshot deadlist metadata:

```
SnapshotSpaceRecord {
    snap_commit_group: u64,               // CommitGroup at which the snapshot was created
    deadlist_root_ptr: BlockPointer, // B+tree of pinned extent IDs
    deadlist_bytes: u64,         // Total bytes pinned by this snapshot's deadlist
    state: SnapshotState,        // ACTIVE or DESTROYING
}
```

**Snapshot creation:**
1. Create the snapshot dataset record with state ACTIVE.
2. `deadlist_bytes = 0` (initially no exclusive blocks — all shared with parent).
3. Parent dataset's `pinned_snapshot_bytes` does NOT change.

**Block free (refcount drops 1->0):**
1. Check if any live snapshots (birth_commit_group) reference this block.
2. If yes: move the block's extent ID into the oldest applicable snapshot's
   deadlist B+tree. Increment that snapshot's `deadlist_bytes` by the block size.
   Increment the dataset's `pinned_snapshot_bytes` by the block size.
3. If no: the block is truly free. Decrement `logical_used_bytes`.

**Snapshot destroy:**
1. Walk the snapshot's deadlist B+tree.
2. For each pinned block: decrement the block's refcount.
   - If refcount reaches 0: block freed -> decrement `logical_used_bytes`.
   - If refcount stays > 0: block still referenced by another snapshot or clone.
3. Decrement parent dataset's `pinned_snapshot_bytes` by `deadlist_bytes`.
4. Delete the snapshot dataset record.

Complexity: O(m) where m = number of exclusively pinned blocks in the destroyed
snapshot, not O(n) where n = total blocks in the dataset. For snapshots that pin
few blocks (common for frequent small-change snapshots), destroy is near-instant.

### 7.3 statfs interaction

`pinned_snapshot_bytes` does NOT reduce `statfs`'s `f_bfree` or `f_bavail`.
Snapshots do not consume the user's quota — they pin physical space, which is
tracked separately through physical counters and the cleaner's watermarks.

## 8. Cleaner Scheduling with Watermarks

### 8.1 Watermark hierarchy

```
min_free_segments: u64       // Hard floor; writes block when below this
target_free_segments: u64    // Soft target; background cleaner runs when below this
high_free_segments: u64      // Ceiling; cleaner stops when above this
```

Defaults (configurable per pool):
- `target_free_segments = 5% of phys_total_segments`
- `min_free_segments = 2% of phys_total_segments`
- `high_free_segments = 8% of phys_total_segments`

### 8.2 Trigger algorithm

```
fn cleaner_scheduler(pool: &Pool) -> CleanerAction {
    let phys_free = pool.segment_free_map.stats().free_segments;
    if phys_free < pool.config.min_free_segments {
        CleanerAction::BlockWriters  // Writers blocked until cleaner makes progress
    } else if phys_free < pool.config.target_free_segments {
        CleanerAction::StartBackground  // Background cleaner activated
    } else if phys_free > pool.config.high_free_segments {
        CleanerAction::Stop  // Cleaner can rest
    } else {
        CleanerAction::NoChange
    }
}
```

### 8.3 Victim selection

The cleaner ranks segments by utilization (lowest first) to maximize gain:

```
gain_bytes(seg) = SEG_BYTES - live_bytes_in_segment(seg)
```

Segments are processed in `gain_bytes` descending order, bounded by `max_clean_work`
(default: 10 segments per cleaner cycle). Live bytes in victim segments are
relocated to fresh segments before the victim is freed.

### 8.4 Net-free guarantee

The cleaner must eventually make forward progress. If all segments are full
(no reclaimable dead bytes), the pool is genuinely full. The logical gate converges
to ENOSPC, and writes are refused. This is correct behavior — the system is not
promising space it cannot deliver.

### 8.5 Forward-progress reserve

`phys_tail_reserved_segments` (default: 0.5% of pool capacity, minimum 4 segments)
is NEVER allocated by the general allocator. Only the cleaner and metadata
operations (journal writes, pool-map updates) can allocate from this reserve. This
guarantees that the cleaner can always write relocated data and complete its cycle,
even when the pool appears 100% full.

## 9. Obligation Ledger Integration

The obligation ledger (#818) provides a complementary scarcity gate that operates
before the allocator check. The two systems operate at different granularities:

- **Obligation ledger**: Design rule Rule 3 — every content write runs through
  `ensure_obligation_capacity` before the allocator check. Claims are registered
  against `staging_dirty` and released on overwrite/truncation.
- **Space accounting model**: Tracks logical counters per dataset/domain; gates
  operations at the ENOSPC boundary using `admission_check()`.

Consistency contract: a write that passes the obligation ledger's scarcity gate
must also pass the space accounting model's ENOSPC check. Both systems commit
deltas within the same commit_group, ensuring atomicity.

A write that passes obligation but fails space accounting is a correctness
violation (the accounting model should never be stricter than the obligation
ledger for the same budget domain). The obligation ledger is the authority on
whether capacity exists; space accounting refines that into user-visible counters.

## 10. ZFS Comparison

| Dimension | ZFS | tidefs (this design) |
|---|---|---|
| Logical space | `USED`/`AVAIL` in `zfs list`; `usedbysnapshots` via periodic scan (often stale) | O(1) counters per dataset; `logical_used_bytes`, `pinned_snapshot_bytes` via deadlists |
| Physical space | Metaslab allocator free space; opaque to users and tools | `phys_free_segments` and `phys_reclaimable_bytes` exposed; explicit coupling rules |
| Quota | `quota`/`refquota` properties enforced at DMU level | `quota_bytes` per dataset; ENOSPC at `logical_avail_bytes <= 0` |
| Reservation | `reservation` property guarantees space; `refreservation` for snapshots | UNWRITTEN extents as persistent reservations; fallocate admission control |
| Clone accounting | `usedbychildren` property with no space domain abstraction | `SpaceDomainId` groups clones + origin; shared blocks counted once for statfs |
| Snapshot deadlist | Deadlist internal to ZFS; no O(1) exposed accounting | `deadlist_bytes` per snapshot with O(1) counter updates; O(m) destroy |
| Cleaner | N/A — ZFS CoW inherently reclaims; no separate cleaner needed | Watermark-based cleaner with min/target/high thresholds; forward-progress reserve |
| statfs | Reflects `refquota` or pool capacity; block size may vary by dataset | Reflects logical quota + avail at domain level; stable 4096 block size |

Key tidefs advantages:
- **O(1) snapshot deadlist**: unlike ZFS's `usedbysnapshots` (periodic scan -> stale
  results), tidefs maintains `deadlist_bytes` per snapshot with O(1) updates and
  O(m) destroy where m = exclusively pinned blocks.
- **Explicit logical/physical coupling**: two-layer ENOSPC (logical for users,
  physical for backpressure) is more predictable than ZFS's opaque DMU<->SPA
  interaction.
- **Space domains**: grouping clones and origins prevents double-counting shared
  blocks in statfs — ZFS has no equivalent abstraction.

## 11. Implementation Plan

### Phase 1: DatasetSpaceCountersV1 and SpaceDelta
- Define `DatasetSpaceCountersV1` struct and derived methods.
- Unit tests: counter arithmetic, delta accumulation, overflow/underflow refusal.

### Phase 2: SpaceDomainId and domain-scoped accounting
- Define `SpaceDomainId` type and domain lifecycle (create, inherit, reclaim).
- Implement `HashMap<SpaceDomainId, DomainCounters>` in pool state.
- Wire `statfs` to domain-level counter aggregation.
- Unit tests: clone shares domain, destroy last member reclaims, statfs correctness.

### Phase 3: Reservation model with admission control
- Implement `admission_check()` with operation-type worst-case byte deltas.
- Wire UNWRITTEN<->DATA conversion through extent map (#1225) with counter transitions.
- Implement punch hole counter adjustments.
- Unit tests: fallocate guarantee, write-into-reserved, ENOSPC on quota exhaustion.

### Phase 4: Snapshot deadlist accounting
- Define `SnapshotSpaceRecord` with `deadlist_bytes`.
- Implement refcount-1->0 deadlist movement when live snapshots exist.
- Implement snapshot destroy with deadlist walk and counter reclamation.
- Unit tests: O(1) deadlist tracking, snapshot destroy O(m), counter consistency.

### Phase 5: Physical counters and cleaner watermarks
- Define `PoolPhysicalCountersV1` with `refresh_physical_counters()`.
- Implement coupling rule and watermark-based cleaner trigger.
- Implement forward-progress reserve enforcement.
- Unit tests: threshold transitions, reserve allocation, cleaner cycle integration.

### Phase 6: statfs implementation
- Implement full statfs contract: logical quota, avail, stable 4096 block size.
- Wire domain-scoped counters into per-mount statfs responses.
- Integration test: create domain -> write -> snapshot -> verify statfs -> destroy.

### Phase 7: Obligation ledger consistency
- Verify write-path consistency: obligation ledger and space counters commit in same commit_group.
- Verify free-path consistency: truncate/unlink updates both systems atomically.
- Integration test: write under contention -> verify both systems agree on available space.

- `tidefs-xtask check-space-accounting`: runs the full test suite for all 7 phases.
- QEMU smoke test: create dataset -> set quota -> write to ENOSPC -> snapshot -> verify
  deadlist bytes -> destroy snapshot -> verify space reclaimed -> export/import -> verify.

## 12. Open Questions

1. **Slop default**: What fraction of quota should be reserved as slop? ZFS uses
   1/64 of pool capacity. tidefs should start with 1/64 as default and allow
   per-dataset override via `slop_bytes` property.
2. **Domain migration on promote**: When a clone is promoted, should blocks move
   to a new domain or stay in the old domain with refcounting? Moving simplifies
   statfs; staying preserves deduplication. V1: stay until `tidefsctl dataset
   migrate-domain` provides explicit control.
3. **Cross-pool domains**: Should space domains span pools? V1: no. Domains are
   pool-local. Cross-pool clone families require send/receive (#1251).
4. **Reservation overcommit**: Should reservations be allowed to temporarily exceed
   quota? Current design: no. Reservation is a hard guarantee, and overcommit would
   violate the fallocate guarantee.

Answers deferred to implementation review.
