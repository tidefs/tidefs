# ADR-0002: Persistent Orphan Index

Date: 2026-05-05
Status: Accepted

Current authority note: this ADR records the accepted historical design
direction. It does not prove current persistent-orphan-index, reclaim,
crash-recovery, space-accounting, release, production, or incumbent-comparison
behavior. Product-facing comparison or successor wording still requires #875
claim ids plus #928/#930 comparator evidence.

## Context

TideFS is an authoritative graph of stable identities and immutable revisions.
When a dataset, snapshot, or extent reference is deleted, the system must track
which blocks become unreferenced (orphaned) so they can be reclaimed. Without a
persistent index, orphan detection requires a full dataset scan — expensive and
unbounded in time.

ZFS spacemap traversal and Ceph per-object reference tracking are historical
design inputs for the orphan/reclaim problem space. This ADR does not claim
that TideFS is currently more correct, faster, or more reliable than either
incumbent; it records the design requirement for a crash-safe, incremental
orphan index integrated with the transaction-group (COMMIT_GROUP) commit model.

## Decision

Implement a **persistent orphan index** as a first-class on-media structure:

1. **Separate index from spacemaps**: the orphan index tracks *which* objects
   are orphaned; spacemaps track *where* free space is. The two are independent
   but reconciled during reclaim.

2. **COMMIT_GROUP-atomic updates**: orphan index mutations are committed atomically with
   the transaction group that produces them. A COMMIT_GROUP commit includes both the
   deletion that orphans blocks and the index entries that record them.

3. **Three-state lifecycle**: each orphan index entry transitions through
   `Pending` (detected, not yet safe to reclaim), `Reclaimable` (safe to free),
   and `Reclaimed` (space freed, entry tombstoned).

4. **Crash recovery**: after a crash, the orphan index is replayed against the
   spacemap. Any `Reclaimable` entries whose reclaim didn't complete are
   re-queued. The index is append-only with tombstones; replay is deterministic.

5. **Crate structure**: `tidefs-orphan-index` for the core data structures and
   algorithms; `tidefs-types-orphan-index-core` for shared type definitions.

6. **Deferred cleanup integration**: the orphan index feeds the deferred cleanup
   background service (`tidefs-cleanup-queue-core`), which processes entries in
   priority order according to space pressure.

## Consequences

- Crash-safe orphan tracking without full dataset scans.
- Incremental: only newly-orphaned blocks require index updates per COMMIT_GROUP.
- Memory overhead: in-memory index size proportional to orphan count, not
  dataset size.
- Reclaim ordering honors space-pressure signals via the deferred cleanup
  scheduler.
- Coordination required with spacemap allocator to ensure freed blocks aren't
  double-allocated during crash recovery replay.

Historical design input: deleted by GitHub issue #1675; this ADR remains only
target-history background, not current product evidence.
Issues: [#2063](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2063),
[#2083](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2083)
