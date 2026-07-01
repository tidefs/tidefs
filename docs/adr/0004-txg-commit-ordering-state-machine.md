# ADR-0004: COMMIT_GROUP Commit Ordering State Machine

Date: 2026-05-05
Status: Accepted

Current authority note: this ADR records the accepted historical design
direction. It does not prove current TXG/commit-group ordering behavior,
crash consistency, release readiness, production readiness, or storage claim
closure. Use live source, current authority docs, and `validation/claims.toml`
for current behavior.

## Context

Transaction groups (COMMIT_GROUPs) are the fundamental unit of atomic commitment in
TideFS. Every metadata mutation, data write, space allocation, and checksum
update must be committed atomically within a COMMIT_GROUP. Multiple subsystems
(dataset lifecycle, space accounting, extent maps, orphan index, checksum
verification) must coordinate their per-COMMIT_GROUP work with a defined ordering.

Without a formal state machine, subsystems make ad-hoc assumptions about when
their callbacks fire relative to other subsystems, leading to bugs where one
subsystem reads stale state committed by another within the same COMMIT_GROUP.

## Decision

Implement a **COMMIT_GROUP commit ordering state machine** (`pool/commit_group.rs`) with these
design choices:

1. **MetadataRoots staging**: each COMMIT_GROUP maintains a staging area
   (`MetadataRoots`) where subsystems register their per-COMMIT_GROUP mutations. The
   staging area is isolated from committed state until the COMMIT_GROUP closes.

2. **Commit classes**: mutations are classified into ordering tiers:
   - `PreCommit`: space reservations, extent allocations
   - `Commit`: metadata mutations, extent map updates, orphan index entries
   - `PostCommit`: checksum finalization, observability events
   This ensures space is reserved before metadata is written, and checksums
   cover the final committed state.

3. **CommitGroupManager**: central coordinator with `stage_roots()` and `staged_roots()`
   accessors, an `AtomicU64`-based COMMIT_GROUP counter, and a manual `Debug` impl for
   observability.

4. **Export surface**: all COMMIT_GROUP types are re-exported from `pool/mod.rs` through
   `crates/tidefs-pool-allocator/src/lib.rs`, making the state machine available
   to all pool-layer consumers.

5. **Deterministic ordering**: within each commit class, subsystem callbacks
   are invoked in a fixed, documented order (space accounting → extent maps →
   orphan index → checksums → observability).

## Consequences

- Eliminates cross-subsystem ordering bugs within a single COMMIT_GROUP.
- `MetadataRoots` staging provides isolation: no subsystem sees partially-
  committed COMMIT_GROUP state.
- Commit classes prevent circular dependencies (e.g., checksums covering
  not-yet-allocated space).
- Fixed callback ordering is documented and testable.
- The `AtomicU64` COMMIT_GROUP counter (vs. `AtomicF64` in earlier iterations) ensures
  monotonic COMMIT_GROUP IDs on all platforms.
- Future subsystems plug into the state machine by registering in the
  appropriate commit class.

Historical design input: `docs/TXG_STATE_MACHINE_DESIGN.md`
Issues: [#1654](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1654),
[#1743](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1743)
