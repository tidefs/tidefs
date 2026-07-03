# tidefs-segment-cleaner

Segment-level garbage collection for the TideFS log-structured local object store.

Identifies underutilized segments, ranks them by local cleaning yield, plans
movement of live objects out of fragmented segments, and routes fully-dead
segment freeing through receipt-bound reclaim interfaces.

## Architecture

| Module | Purpose |
|--------|---------|
| `lib.rs` | Core types: `SegmentCleanerService` (IncrementalJob), `SegmentCleanerDriver`, `DeadObjectTracker`, `BackgroundVictimSelector`, `BlockStore` traits, `CompactExecutor` |
| `cleaner.rs` | `SegmentCleaner` decision engine: liveness queue management, `CleaningCandidate` schedule planning with age/dead-ratio filters |
| `scanner.rs` | `SegmentLivenessScanner`: stateful candidate iterator ranking segments by compaction efficiency |
| `victim.rs` | `VictimSelector`: liveness-ratio victim selection from the reclaim queue |
| `candidate_selector.rs` | `CandidateSelector`: pin-set-aware candidate selection filtering out segments reachable from pinned traversal roots |
| `policy.rs` | `CleaningPolicy` (Auto/Deferred/Urgent) with space-pressure selection, `CleanerBackpressure` for write-path throttling, `SegmentScorer` for cost-benefit ranking |
| `ledger.rs` | `CleanerLedger` with BLAKE3-verified `CleanerLedgerRecord` (magic VCLD, version 1, 80-byte encoded record) for local cleaner progress state |
| `physical_reclaim.rs` | Receipt-bound physical reclaim bridge: consumes `DeadObjectReclaimQueue`, returns `ReclaimReceipt`, and frees through `SegmentFreer` without creating a capacity authority |

## Cleaning Policy

The `CleaningPolicy` selects aggressiveness based on pool free-space fraction:

- **Deferred** (free >= 15%): skip cleaning unless segment is fully dead
- **Auto** (free 5-15%): normal cost-benefit threshold
- **Urgent** (free < 5%): clean all eligible segments, bypass age guard

`CleanerBackpressure` is derived from policy + dead fraction and signals the
write path: Normal, Throttle, RejectNonCritical, or RejectAll.

## Persistence

The `CleanerLedger` tracks cleaned/freed segments, bytes migrated, and a
resumption cursor in an 80-byte BLAKE3-verified record (magic `VCLD`, version 1).
This crate encodes and decodes that record for cleaner-local progress state.
Filesystem recovery, allocator publication, and mounted capacity authority are
owned by the broader TideFS authority documents and validation claims.

## Integration Points

- `tidefs-reclaim-queue-core`: `SegmentLivenessQueue` for dead/live byte accounting
- `tidefs-reclaim`: `ReclaimReceipt`, `SegmentFreer`, and receipt-bound dead-object drain inputs
- `tidefs-gc-pin-set`: `GcPinSet` for pin-aware candidate filtering
- `tidefs-incremental-job-core`: `IncrementalJob` trait for background scheduling
- The `BlockStore` trait abstracts the local object store for block enumeration,
  reading, and writing during compaction

This crate is not the compaction, snapshot/deadlist, allocator, mounted
capacity, or release-readiness authority. Keep product-level reclaim and
capacity conclusions in the authority documents, validation claims, and live
issues that own those boundaries.

## Validation

```
cargo test -p tidefs-segment-cleaner
```
