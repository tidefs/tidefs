# tidefs-scrub-core

Background scrub primitives for segment-level and object-level checksum
verification in TideFS.

This README describes the crate APIs and local invariants. Product repair,
cross-replica comparison, recovery orchestration, and release-admission
authority lives in the repo-level docs and issues listed in
[Scope Boundaries](#scope-boundaries).

## Architecture

The crate provides three service tiers:

1. **ScrubService** — a `BackgroundService` that walks segment files, verifies
   every record's BLAKE3-256 integrity trailer, and records mismatches to the
   `SuspectLog`. Supports cursor-resumable walks and chain-of-trust validation.

2. **ScrubWorker** — a full-traversal object scrubber that enumerates all
   objects in the store, verifies each payload against its BLAKE3 checksum tree
   root, and collects `ScrubOutcome` records.

3. **ScrubRepairEngine** — a caller-driven API for checksummed repair attempts.
   The caller supplies a `BlockReconstructor` and, for writeback admission, a
   `CrossReplicaComparisonRecord`. The engine verifies candidate bytes against
   the expected BLAKE3 hash and records the attempt in an in-memory ledger.

## Repair API Boundary

The `scrub_repair` module provides typed repair-attempt helpers:

```text
Scrub traversal ──► checksum mismatch detected
                         │
                         ▼
                ScrubRepairEngine
                   │
           BlockReconstructor
           (caller supplied)
                   │
             verify candidate
                   │
          comparison-gated writeback
                   │
            ScrubRepairLedger
            (attempt record)
```

### Detection

During block traversal, the caller identifies a block whose BLAKE3 hash does
not match the expected checksum from the checksum tree.

### Reconstruction

`ScrubRepairEngine` calls `BlockReconstructor::reconstruct()` to obtain
candidate bytes and source identifiers. The trait is intentionally abstract:
backend-specific source selection, I/O, and retry policy belong to the caller
or to the recovery crates that own that behavior.

### Writeback Admission

`repair_one_with_comparison()` requires a `CrossReplicaComparisonRecord`.
Missing, stale, contradictory, or unreconciled comparison evidence returns a
typed refusal such as `MissingComparisonRecord`, `StaleComparisonRecord`,
`CrossReplicaDisagreement`, or `UnreconciledComparison`.

### Ledger

Each attempt is recorded in a `ScrubRepairLedger` with domain-separated BLAKE3
hashing (domain: `tidefs-scrub-repair-v1`). The ledger is an in-memory
crate-local record for the lifecycle of the pass.

## Configuration Boundary

The crate does not define operator UAPI, persistence policy, backend source
selection, or repair scheduling. Callers provide those policies around the core
types:

- **Concurrency**: controlled by the caller or by the supplied
  `BlockReconstructor`.
- **Retry policy**: controlled by the caller.
- **Retention**: `ScrubRepairLedger` keeps events in memory for the pass; any
  durable record format belongs outside this crate.

## Ledger Counters

`ScrubRepairLedger` exposes crate-local counters and event accessors:

| Field or method | Description |
|---|---|
| `repair_count` | Count of attempts whose candidate bytes verified and whose writeback call succeeded |
| `repair_failure_count` | Count of attempts that failed reconstruction, verification, or writeback |
| `event_count()` | Total recorded events |
| `validation_digest()` | Domain-separated BLAKE3 digest over the in-memory event list |

## Modules

| Module | Description |
|---|---|
| `scrub_repair` | Caller-driven repair-attempt API with BLAKE3-checked candidates and comparison-gated writeback |
| `repair_scheduling` | Bridge between scrub findings and prioritized repair dispatch |
| `object_scanner` | Abstract object traversal for scrub workers |
| `integrity_verifier` | Per-object BLAKE3 integrity verification |
| `rate_limiter` | I/O rate limiting for background scrub |
| `scheduler` | Scrub scheduling policy |
| `detector` | Segment-level corruption detection |
| `scrub_ledger` | Record-level scrub outcome logging |

## Scope Boundaries

Use these existing authorities for broader behavior:

- `../../docs/SCRUB_IDENTITY_AUTHORITY.md` for scrub identity and the boundary
  that scrub identity alone does not authorize repair scheduling or writeback.
- `../../docs/CROSS_REPLICA_SCRUB_COMPARISON_DESIGN.md` for comparison evidence
  semantics and the current design boundary.
- `../../docs/ERASURE_CODED_STORE_AUTHORITY.md` for erasure-coded store scope.
- GitHub issues #18, #1735, #1745, #1792, #1860, and #1861 for remaining
  placement, recovery, scrub, and product-admission work.
