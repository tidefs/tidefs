# Snapshot Deadlist Pinning Algorithm Design (P1 spec-draft)

Maturity: **spec-draft** for the snapshot deadlist pinning algorithm that
replaces the naive "bump-all-refcounts-at-snapshot-create" model with an
O(log n) birth_commit_group/death_commit_group interval-based approach.

This document closes Forgejo issue #1232.

## 1. Motivation

Issue #1215 defines the high-level space accounting model (logical vs physical)
and mentions snapshot-pinned space, but does not specify the algorithm for:

- How snapshot create pins extents without O(N) namespace scans.
- How to determine which snapshot pins a freed extent.
- How snapshot destroy releases pinned space incrementally.

The v0.262 Python PoC used a naive "bump all refcounts at snapshot create"
model that iterated every extent in the dataset at snapshot time, which
does not scale past trivial file counts. The Rust implementation needs
a production-grade algorithm with the following properties:

- **Snapshot create is O(log n):** no namespace scan to bump refcounts.
  Only per-snapshot metadata is written.
- **Pinning is lazy and correct:** when an extent's refcount transitions
  1→0, the system determines which snapshot (if any) still references it
  via O(log n) commit_group-interval lookup.
- **Snapshot destroy is incremental:** large deadlists are processed in
  bounded chunks, cursor-driven and resumable after restart.
- **Space observability is transactional:** `pinned_snapshot_bytes` is
  reported separately from `logical_used_bytes` and is consistent across
  crashes.

### 1.1 ZFS anti-patterns avoided

| ZFS issue | TideFS design response |
|---|---|
| Single AVL-tree deadlist per snapshot; destroy must scan entire deadlist synchronously | Per-snapshot B-tree with cursor-driven, resumable processing |
| Snapshot destroy stalls for seconds with hundreds of snapshots | Bounded by `(max_ids, max_bytes, max_ms)` per commit_group; only one destroy job RUNNING per dataset |
| No sub-file or sub-directory snapshot scope | Dataset-level snapshots only (V1); sub-file snapshots deferred to a future ro_compat feature flag |
| Deadlist grows unboundedly with snapshot count | move-or-free progression naturally drains deadlists toward the newest snapshot |

## 2. Core Data Structures

### 2.1 Per-extent lifetime metadata

Every DATA extent ID and UNWRITTEN reservation ID in the
`ExtentLocatorValueV1` payload carries two commit_group fields:

```
birth_commit_group: u64   // commit_group when the ID was allocated (created)
death_commit_group: u64   // commit_group when refcount became 0 for the active dataset
                 // 0 = still referenced by active dataset
```

These fields already exist in `ExtentLocatorValueV1` as defined in #1285
(`docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md` section 5.1). The snapshot pinning
algorithm interprets them as the pinning interval `[birth_commit_group, death_commit_group)`.

### 2.2 Per-snapshot metadata

```
SnapshotMeta {
    snapshot_name: Vec<u8>,       // user-visible name bytes
    snap_commit_group: u64,                // commit_group at which the snapshot root was captured
    deadlist_root_ptr: LocatorId, // root of persistent B-tree of deadlist entries
    deadlist_count: u64,          // number of IDs in deadlist (O(1) observability)
    deadlist_bytes: u64,          // sum of bytes pinned (O(1) for df)
    state: u8,                    // 0 = ACTIVE, 1 = DESTROYING
    destroy_commit_group: u64,             // commit_group at which destroy started (0 if ACTIVE)
    clone_count: u32,             // number of live clones of this snapshot
    flags: u8,                    // reserved
}
// Total: ~64 + name bytes
```

### 2.3 Snapshot commit_group index

Two persistent B+trees enable efficient snapshot lookup by both name and commit_group:

```
snap_name_index: BTree<snapshot_name_bytes, SnapshotMeta>
snap_commit_group_index:  BTree<(snap_commit_group: u64, snapshot_name_bytes), SnapshotMetaRef>
```

The `snap_commit_group_index` supports `lower_bound(commit_group)` queries — "find the first
snapshot whose `snap_commit_group >= commit_group`" — in O(log n) time. This is the essential
primitive for the pinning algorithm.

### 2.4 Snapshot deadlist entry

```
DeadlistEntry {
    locator_id: LocatorId,   // 16 bytes -- points into ExtentLocatorTable
    byte_length: u64,        //  8 bytes -- for O(1) deadlist_bytes accounting
    birth_commit_group: u64,          //  8 bytes -- snapshot of extent birth_commit_group at entry time
    death_commit_group: u64,          //  8 bytes -- snapshot of extent death_commit_group at entry time
}
// Total: 40 bytes per entry
```

The `birth_commit_group` and `death_commit_group` are snapshotted at insertion time so the
deadlist entry remains self-describing even if the locator value is later
reclaimed.

## 3. Pinning Rule

When a refcount transitions 1→0 for a DATA extent or UNWRITTEN reservation
identified by `locator_id`:

### 3.1 Step-by-step

1. **Record death:** Set `death_commit_group = current_commit_group` in the
   `ExtentLocatorValueV1` for `locator_id`.

2. **Find interval:** Read `birth_commit_group` from the same locator value.
   The pinning interval is `[birth_commit_group, death_commit_group)`.

3. **Query snap_commit_group_index:** `S_first = snap_commit_group_index.lower_bound(birth_commit_group)`.
   Returns the first (oldest) snapshot with `snap_commit_group >= birth_commit_group`.

4. **Candidate check:**

   - If `S_first` does not exist: no snapshot can reference this extent.
     Go to step 5a.
   - If `S_first.snap_commit_group >= death_commit_group`: the snapshot was created after
     the extent became dead. Go to step 5a.
   - If `S_first.state == DESTROYING` and `S_first.destroy_commit_group <= death_commit_group`:
     the snapshot is being destroyed and the destroy freeze point precedes
     the extent's death. Skip `S_first` and check
     `S_next = snap_commit_group_index.next(S_first)`. Repeat candidate check.
     If no eligible snapshot remains, go to step 5a.
   - Otherwise: `S_first` pins this extent. Go to step 5b.

5. **Action:**

   a. **No snapshot pins this extent:**
      - Decrement `logical_used_bytes` by `extent.byte_length`.
      - Enqueue `locator_id` for immediate reclamation via the refcount
        cleanup queues (issue #1180).

   b. **Snapshot S_first pins this extent:**
      - Insert `DeadlistEntry { locator_id, extent.byte_length, birth_commit_group, death_commit_group }`
        into `S_first.deadlist` (persistent B-tree).
      - Increment `S_first.deadlist_count` by 1.
      - Increment `S_first.deadlist_bytes` by `extent.byte_length`.
      - Keep `logical_used_bytes` unchanged (bytes remain logically used,
        now pinned by snapshot).

### 3.2 Correctness argument

- Snapshots with `snap_commit_group < birth_commit_group` cannot reference the extent because
  it did not exist when the snapshot was captured.
- Snapshots with `snap_commit_group >= death_commit_group` cannot reference the extent because
  it was already freed (death_commit_group marks the commit_group when the active dataset
  dropped its reference).
- Therefore, only snapshots with `snap_commit_group` in `[birth_commit_group, death_commit_group)` can
  possibly reference the extent.
- The pinning rule conservatively assigns the extent to the _oldest_ such
  snapshot. This is correct because the oldest snapshot's namespace root
  includes all bytes that existed at `snap_commit_group`: if the extent was alive
  then, the snapshot references it.
- DESTROYING snapshots where `destroy_commit_group <= death_commit_group` are skipped because
  the destroy freeze point guarantees no new IDs should enter that deadlist.
  The extent instead moves to the next newer snapshot (or is reclaimed if
  none remains).

### 3.3 Edge case: snapshot create while extents are dying

If a snapshot is created at `snap_commit_group = T` while an extent's refcount
is transitioning 1→0 in the same commit_group, ordering within the commit_group matters:

- Snapshot root capture MUST commit before refcount transitions commit
  within the same commit_group. This ensures `snap_commit_group < death_commit_group` for any extent
  dying in commit_group `T` after the snapshot root was captured in `T`.
- The commit_group commit ordering design (#1267) already specifies a seven-step
  pipeline where metadata (including snapshot roots) commits before the
  commit record. The pinning rule is compatible: `death_commit_group = current_commit_group`
  is set during the same commit_group but the snapshot root's `snap_commit_group = T` is
  visible before the extent's `death_commit_group = T` is durable, so the interval
  `[birth_commit_group, T)` correctly includes the new snapshot.

## 4. Snapshot Destroy: Two-Phase Move-or-Free

### 4.1 Phase 1: Freeze

1. Mark snapshot state as `DESTROYING`.
2. Set `destroy_commit_group = current_commit_group`.
3. Commit this commit_group.
4. After this commit, no new IDs enter this snapshot's deadlist (the pinning
   rule skips DESTROYING snapshots where `destroy_commit_group <= death_commit_group`).

### 4.2 Phase 2: Process deadlist incrementally

The destroy job is cursor-driven, resumable, and bounded:

```
SnapshotDestroyJob {
    snapshot_id: SnapshotId,
    cursor: Option<LocatorId>,   // last processed deadlist entry; None = start
    ids_processed: u64,
    bytes_processed: u64,
    state: DestroyJobState,      // RUNNING, PAUSED, COMPLETE
    started_commit_group: u64,
    last_progress_commit_group: u64,
}
```

For each deadlist entry, in cursor order:

1. Read the entry's `locator_id` and `byte_length`.
2. Look up the `ExtentLocatorValueV1` for `locator_id` to get current
   `birth_commit_group` and `death_commit_group`.
3. Query `snap_commit_group_index` for the next newer snapshot after the destroyed
   snapshot (by `snap_commit_group`):
   a. If a newer snapshot `S_next` exists and `S_next.snap_commit_group < death_commit_group`:
      move the entry to `S_next.deadlist`, update counters on both snapshots
      (`deadlist_count`, `deadlist_bytes`).
   b. Otherwise: the entry is no longer pinned by any snapshot. Enqueue
      `locator_id` for reclamation, decrement `logical_used_bytes`.
4. Advance cursor.
5. If `ids_processed >= max_ids` OR `bytes_processed >= max_bytes` OR
   `elapsed >= max_ms`: pause the job and schedule continuation in the
   next commit_group.

Boundedness properties:

- Per-commit_group work bounded by `(max_ids, max_bytes, max_ms)`.
- Only one destroy job RUNNING per dataset at a time.
- After all entries are processed (cursor reaches end), the snapshot
  metadata is removed and the deadlist B-tree is freed.

### 4.3 Crash safety during destroy

- Deadlist entry moves are transactional within a commit_group: both the remove from
  `S_old.deadlist` and the insert into `S_next.deadlist` (with counter updates)
  happen atomically.
- If a crash occurs mid-destroy, the cursor position is durable: on next mount
  the destroy job resumes from the last committed cursor.
- If a crash occurs between freeze and any processing, the snapshot is
  `DESTROYING` with `cursor = None`, so processing starts from the beginning.
- Counter consistency: `deadlist_count` and `deadlist_bytes` are recomputed
  the B-tree's actual contents.

## 5. Clone Interaction (V1 policy)

### 5.1 Destroy prevention

A snapshot with `clone_count > 0` is not destroyable. The freeze step (Phase 1)
rejects with `EBUSY` if any live clone references the snapshot.

### 5.2 Clone space domain

Clones created from a snapshot root share the same space domain as the parent
dataset (issue #1215). Extents pinned by a snapshot that has clones remain
pinned until the clone is destroyed and the snapshot is subsequently destroyed
via the two-phase move-or-free algorithm.

### 5.3 Pruner pin-evidence gate

Retention pruning is fail-closed. Before a retention candidate enters the
delete set, the pruner must read current-version per-snapshot pin evidence that
matches the candidate's catalog root and contains explicit clone-origin and
deadlist-pin fields. A missing evidence index, missing candidate entry, missing
clone-origin field, missing deadlist-pin field, stale root evidence, corrupt
pin-evidence payload, clone-origin evidence that disagrees with the current
clone/origin indices, live clone/origin pin, or deadlist pin blocks the
candidate and leaves it out of the delete set. The prune result reports these
states separately from retention-policy keeps and snapshot checksum integrity
failures.

### 5.4 Future: org.tidefs:clone_promote

A future ro_compat feature flag `org.tidefs:clone_promote` will allow promoting
a clone to an independent dataset, at which point the clone's reference to
the parent snapshot is severed (`clone_count--` on the parent) and the clone
receives its own copy of the snapshot's deadlist. Not in scope for this design.

## 6. Space Observability

### 6.1 Dataset-level counters

```
DatasetSpaceView {
    logical_used_bytes: u64,       // total bytes logically in use (active + pinned)
    physical_used_bytes: u64,      // total bytes physically allocated (after CoW, compression)
    pinned_snapshot_bytes: u64,    // sum of all snapshot deadlist_bytes
    snapshot_count: u32,
    reclaimable_bytes: u64,        // bytes in DESTROYING deadlists being drained
}
```

### 6.2 Per-snapshot counters

```
SnapshotSpaceView {
    snap_commit_group: u64,
    deadlist_count: u64,
    deadlist_bytes: u64,
    state: SnapshotState,          // ACTIVE or DESTROYING
}
```

### 6.3 Transactional consistency

All counters are part of the committed state within a commit_group. After a crash,
mount by the recovery path.

## 7. Relationship to Existing Issues

| Issue | Relationship |
|---|---|
| #1215 (space accounting) | Specifies the snapshot-specific pinning and release mechanics that feed the logical/physical accounting model |
| #1219 (dataset lifecycle) | Adds DESTROYING state for snapshots; destroy jobs are lifecycle-managed |
| #1223 (dataset feature flags) | Snapshots enabled via feature flag; ro_compat flags for clone_promote (future) |
| #1180 (refcount delta cleanup) | The "enqueue to reclaim" path feeds the refcount cleanup queues |
| #1285 (extent maps and locator tables) | `birth_commit_group`/`death_commit_group` fields defined in `ExtentLocatorValueV1`; locator table is the source of truth for extent lifetime |
| #1267 (commit_group commit ordering) | Snapshot root capture ordering relative to refcount transitions within a commit_group; crash-safety ordering contract |
| #1217 (B-tree infrastructure) | Deadlist and snapshot indexes are B-trees; cursor iteration for incremental destroy |

## 8. Implementation Plan

This is a **spec-draft**. Implementation is deferred to a continuation issue.

### 8.1 Implementation phases (future)

1. **Phase A — Locator payload extension:** Extend `ExtentLocatorValueV1` with
   `birth_commit_group`/`death_commit_group` fields per #1285 section 5.1. Current design already
   reserves these fields; implementation fills them.
2. **Phase B — Snapshot metadata and indexes:** Implement `SnapshotMeta` record,
   `snap_name_index` and `snap_commit_group_index` B+trees, snapshot create wiring.
3. **Phase C — Pinning rule:** Implement the 1→0 refcount transition handler
   with `snap_commit_group_index.lower_bound()` lookup, deadlist insertion, and
   reclamation enqueue.
4. **Phase D — Snapshot destroy:** Implement two-phase freeze + incremental
   move-or-free with cursor-driven resumption.
5. **Phase E — Space observability:** Wire `pinned_snapshot_bytes` into
   `statfs`/`DatasetSpaceView` reports.
6. **Phase F — Crash tests:** Add deadlist consistency and destroy-job
   resumption tests to the crash harness (#1230).

### 8.2 Dependencies

- #1285 must be implemented first (locator table with `birth_commit_group`/`death_commit_group`).
- #1267 commit_group commit ordering must be implemented (snapshot root ordering within commit_group).
- #1217 B-tree infrastructure must be implemented (deadlist and index storage).


| Gate | Description |
|---|---|
| `snapshot-create-is-ologn` | Snapshot create touches only snapshot metadata, not extent maps |
| `pinning-rule-routes-correctly` | Extent freed → routed to correct snapshot deadlist |
| `pinning-rule-no-snapshot-reclaims` | Extent freed with no matching snapshot → immediate reclamation |
| `destroy-is-incremental` | Snapshot destroy with 100k deadlist entries processes in bounded commit_groups |
| `destroy-resumes-after-crash` | Kill mid-destroy, verify resume from cursor |
| `snapshot-create-ordering` | Snapshot root commit-before-refcount-transition within same commit_group |

## 10. Design Decisions and Rationale

### 10.1 Why oldest snapshot pins, not newest

When multiple snapshots could pin an extent (all have `snap_commit_group` in the
interval), the oldest snapshot is chosen because:

- The oldest snapshot has the earliest `snap_commit_group`, so it is the first
  consumer that blocks reclamation.
- On destroy of the oldest snapshot, the entry naturally moves to the
  next newer snapshot via the incremental move-or-free algorithm.
- This minimizes bookkeeping: only one snapshot's deadlist contains the
  entry at any time.

### 10.2 Why birth_commit_group/death_commit_group on every extent, not a separate table

Embedding `birth_commit_group` and `death_commit_group` in `ExtentLocatorValueV1` avoids a
join on every refcount transition. The locator table is already the source
of truth for extent existence; adding two 8-byte fields is cheaper than
maintaining a separate mapping with consistency guarantees.

### 10.3 Why cursor-driven, not batch-committed

Batch-committing the entire deadlist on destroy would block the commit_group for
unbounded time (ZFS anti-pattern). Cursor-driven processing with per-commit_group
bounds ensures forward progress without stalling the system.

### 10.4 Why skip DESTROYING snapshots in pinning rule

Once a snapshot enters DESTROYING state, its deadlist is being drained.
Adding new entries after the freeze point would create an infinite drain
loop. The `destroy_commit_group` check ensures a clean cut: extents freed after
the freeze go to the next newer snapshot.

## 11. References

- v0.262 Python reference: `tidefs_v0.262/docs/notes/2026-02-06-fuse-userspace-api-and-mmap.15c-space-accounting-and-cleaning.md` section 15.8.7
- Extent maps and locator tables design: `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md` (#1285)
- CommitGroup commit ordering design: `docs/design/canonical-commit-ordering-commit_group-state-machine.md` (#1267)
- Dataset lifecycle states: Forgejo issue #1219
- Dataset feature flags: Forgejo issue #1223
- Refcount delta cleanup: Forgejo issue #1180
- Crash harness: Forgejo issue #1230
