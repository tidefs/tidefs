# Online Defrag of Base Shards: Block Pointer Rewrite Design

**Issue**: [#1265](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1265)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1222 (rebake), #1232 (snapshot deadlist), #1189 (spacemap), #1241 (BACKGROUND lane), #1229 (BULK plane)
**Merged from**: #1262 (duplicate)

## Incumbent Comparison Boundary

This imported design document uses ZFS and Ceph defragmentation behavior as
historical design input. Its comparison text is not current TideFS online
defrag capability, performance, availability, cost, or successor evidence.
Any future product-facing comparison must name a #875 claim id and carry the
comparator evidence required by #928/#930.

## Abstract

This document defines the online defragmentation design for tidefs. Defrag rewrites
existing base shards to improve physical layout — reducing shard count, healing
fragmentation, and compacting space — without taking datasets offline. The
architecture reuses the rebake machinery (#1222) and leverages extent_id indirection
to make block pointer rewrite (BPR) safe, transactional, and snapshot-aware.

## 1. Motivation

ZFS's most notorious missing feature is online defrag: no BPR means physical layout is
permanent post-write. The only defrag option is `zfs send | zfs recv`, requiring free
space ≥ dataset size and downtime. Ceph avoids this with object storage but still
fragments within OSDs.

After extended tidefs operation:
- Partially overwritten files leave holes in base shards
- CoW snapshots create chains of fragmented extent pointers
- Hot files that are frequently appended/truncated develop sparse extent maps
- Spacemap fragmentation reduces large-allocation efficiency

Without online defrag, performance degrades monotonically.

## 2. Core Design: Defrag = Rebake++

Defrag reuses the same machinery as rebake (#1222):

| Aspect | Rebake (#1222) | Defrag (#1265) |
|---|---|---|
| Domain | Ingest → Base | Base → Base |
| Locator swap protocol | Same | Same |
| Durability policy ladder | Same | Same |
| Budgeted BACKGROUND scheduling | Same | Same |
| Crash-resumption via cursor | Same | Same |

The difference: rebake converts newly written ingest extents to base shards;
defrag rewrites existing base shards to improve physical layout.

## 3. Block Pointer Rewrite (BPR) Domain

### 3.1 Target Block-Pointer Rewrite Model Relative To ZFS

ZFS cannot rewrite block pointers because its block pointer tree (root_record → objset
→ object_node → indirect blocks → data blocks) ties physical addresses directly to the
logical namespace. Rewriting a block would cascade updates up the entire tree.

tidefs avoids this via **extent_id indirection**:

```
File extent map                Locator table
┌─────────────────┐          ┌───────────────────────┐
│ logical_offset  │          │ extent_id → shard[]   │
│ ├─ extent_id(N) │──────────│  shard[0]: (dev, LBA) │
│ ├─ extent_id(M) │    │     │  shard[1]: (dev, LBA) │
│ └─ extent_id(P) │    │     └───────────────────────┘
└─────────────────┘    │
                       │     ┌───────────────────────┐
                       │     │ extent_id → shard[]   │
                       └─────│  shard[0]: (dev, LBA) │
                             └───────────────────────┘
```

The extent_id is a stable logical address. The locator (extent_id → physical shard
list) is the indirection layer. Defrag updates the locator, NOT the extent map.
File extent maps are NOT dirtied by defrag.

### 3.2 Key Insight

Extent_id indirection makes BPR a single-level update: only the locator entry for
the defragged extent_id changes. No cascading updates to upper layers. This is
impossible in ZFS's indirect-block architecture.

## 4. Fragmentation Scoring

### 4.1 Score Function

```
frag_score(extent_id) =
    w1 * (logical_bytes / physical_bytes)
  + w2 * (shard_count / ideal_shard_count)
  + w3 * (seeks_per_read_byte)
  + w4 * (snapshot_dead_bytes / total_bytes)
```

| Component | Meaning | Default Weight |
|---|---|---|
| `logical_bytes / physical_bytes` | Space efficiency (<1 means fragmentation waste) | w1 = 10.0 |
| `shard_count / ideal_shard_count` | Shard fragmentation (ideal = 1 per extent) | w2 = 5.0 |
| `seeks_per_read_byte` | IO pattern cost (estimated seeks per byte read) | w3 = 2.0 |
| `snapshot_dead_bytes / total_bytes` | Dead space behind snapshots | w4 = 3.0 |

Only extents with `frag_score > threshold` (default: 2.0) are defrag candidates.

### 4.2 Candidate Selection

1. Score all base extents in the dataset
2. Sort by descending frag_score
3. Process candidates in order, budgeted per tick (default: 16 extents/tick)
4. Skip candidates that were defragged in the last N commit_groups (anti-thrash)
5. Skip candidates currently locked by demand IO

## 5. Defrag Algorithm

```
defrag_extent(extent_id):
    1. Read all live shards for extent_id from the locator table
    2. Reassemble the logical extent from shards
    3. Re-encode with current dataset durability policy:
       a. Compression (if enabled per dataset policy)
       b. Erasure coding (if enabled per dataset policy)
       c. Placement (optimal device selection)
    4. Write new base shards to fresh segments via the BULK allocation plane
    5. In a single commit_group:
       a. Update locator: atomically swap old base pointers → new base pointers
       b. Decrement refcount on old base shards (mark as dead)
       c. Update spacemap: free old space (subject to deadlist)
    6. Old shard segments become eligible for GC via normal journal cleaning
    7. Advance the persistent position cursor for crash resumption
```

## 6. Safety Invariants

| # | Invariant | Rationale |
|---|---|---|
| 1 | Old shards remain readable until locator update commit_group commits | Crash before commit: data intact |
| 2 | Crash before commit_group commit: new shards unreachable, old shards valid | Normal GC reclaims orphaned new shards |
| 3 | Crash after commit_group commit: old shards dead (refcount==0), new shards live | Atomic locator swap guarantees consistency |
| 4 | No window where data is unreachable | Locator swap is atomic within the commit_group |
| 5 | Defrag never violates durability policy | New shards must meet current policy (e.g., ≥ min replication) |

### 6.1 Locator Swap Atomicity

The locator update is a single commit_group operation:
1. Old locator entry: `extent_id → [shard_A, shard_B, shard_C]`
2. New locator entry: `extent_id → [shard_X, shard_Y]`
3. The swap from old→new is committed atomically in one commit_group
4. If the commit_group fails (crash before commit), old entry remains → old shards valid
5. If the commit_group succeeds, new entry is live → new shards accessible

## 7. Snapshot Integration

Defrag must cooperate with the snapshot deadlist (#1232):

- **Extents pinned by snapshots can still be defragged**: the logical extent_id
  is the same, so snapshots reference the same extent_id, not physical shards.
- **New shards get the same `birth_commit_group` as the original**: preserves snapshot
  time bounds for space accounting.
- **Old shards are freed only after the holding snapshot is destroyed**: the
  deadlist tracks the old shards and delays GC until all referencing snapshots
  are gone.
- **No snapshot space amplification**: defrag does not increase the space
  consumed by snapshots because old shards are tracked by the deadlist, not
  immediately freed.

## 8. Budgeting and Scheduling

### 8.1 Per-Tick Budget

| Parameter | Default | Description |
|---|---|---|
| `max_extents_per_tick` | 16 | Maximum extents defragged per BACKGROUND tick |
| `max_bytes_per_tick` | 256 MiB | Maximum bytes rewritten per tick |
| `max_io_ops_per_tick` | 128 | Maximum IO operations per tick |
| `throttle_if_demand_latency` | 5 ms | Pause defrag if demand IO latency exceeds threshold |

### 8.2 Anti-Thrash

- Extents defragged in the last `N` commit_groups are skipped (default: N=1000)
- If an extent's frag_score drops below threshold after defrag, it won't be
  reconsidered until score rises again
- Rapid defrag→re-fragment cycles are prevented by the anti-thrash window

## 9. Observability

| Metric | Type | Description |
|---|---|---|
| `defrag_extents_processed` | Counter | Total extents defragged |
| `defrag_bytes_rewritten` | Counter | Total bytes rewritten by defrag |
| `defrag_space_recovered` | Counter | Bytes freed after GC of old shards |
| `defrag_frag_score_distribution` | Histogram | Distribution of frag_score across all base extents |
| `defrag_tick_duration_us` | Histogram | Per-tick processing time |
| `defrag_candidates_skipped` | Counter | Candidates skipped due to budget/throttle |

## 10. Edge Cases

### 10.1 Empty Extent

An extent with no live shards (all dead/GC'd) is skipped.

### 10.2 Extent Being Written

If an extent is currently in the ingest pipeline (being written or rebaked),
defrag skips it. Coordination via extent-level lock in the locator table.

### 10.3 Dataset Destroy

If a dataset is being destroyed, defrag is cancelled and progress cursor is

### 10.4 Out-of-Space

If the BULK plane cannot allocate space for new shards, defrag pauses and
surfaces a soft error. No data loss — existing shards remain valid.

## 11. Test Plan

| Test ID | Scenario | Expected Result |
|---|---|---|
| DF-01 | Single extent, 8 shards → defrag | Reduces to ≤4 shards (better layout) |
| DF-02 | Fragmented extent with 50% dead space | New shards exclude dead space, frag_score decreases |
| DF-03 | Crash during commit_group commit (between write and locator swap) | Old shards valid, new shards GC'd, no data loss |
| DF-04 | Crash after commit_group commit | New shards live, old shards dead, data consistent |
| DF-05 | Extent behind 3 snapshots → defrag | Extent defragged, old shards held by deadlist |
| DF-06 | Defrag with budget=2 extents/tick | Only 2 extents processed per tick |
| DF-07 | Demand IO spike → defrag throttles | Defrag pauses, demand IO unaffected |
| DF-08 | Repeated defrag of same extent | Anti-thrash prevents re-processing within window |
| DF-09 | Dataset destroy during defrag | Defrag cancelled, no partial state |
| DF-10 | Out-of-space during defrag write | Defrag pauses, existing data intact |

## 12. ZFS and Ceph Design Lessons (Non-Claim)

| Aspect | ZFS | Ceph (Bluestore) | TideFS target design |
|---|---|---|---|
| Online defrag | None (send/recv only) | Internal (opaque, not extent-aligned) | Extent-aligned BPR via locator swap |
| BPR mechanism | Impossible (cascading indirect updates) | N/A (object storage) | Extent_id indirection makes BPR single-level |
| Snapshot-aware | N/A | N/A | Yes — deadlist tracks old shards |
| Budget control | N/A | Tunable priority | Per-tick budget with demand throttle |
| Observability | N/A | Internal counters | frag_score histogram, per-extent metrics |

## 13. References

- #1222 — Rebake architecture (ingest → base conversion)
- #1232 — Snapshot deadlist design
- #1189 — Spacemap allocator
- #1241 — BACKGROUND lane scheduler
- #1229 — BULK plane for data movement
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md` — rebake design
- Issue #1262 — merged duplicate with extended rationale
