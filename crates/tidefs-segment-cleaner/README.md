# tidefs-segment-cleaner

Segment-level garbage collection for the TideFS log-structured local object store.

Identifies underutilized segments, ranks them by reclaimable yield, compacts
live objects out of fragmented segments, frees fully-dead segments, and
persists cleaning progress through a BLAKE3-verified ledger for crash-safe
resumption.

## Architecture

| Module | Purpose |
|--------|---------|
| `lib.rs` | Core types: `SegmentCleanerService` (IncrementalJob), `SegmentCleanerDriver`, `DeadObjectTracker`, `BackgroundVictimSelector`, `BlockStore` traits, `CompactExecutor` |
| `cleaner.rs` | `SegmentCleaner` decision engine: liveness queue management, `CleaningCandidate` schedule planning with age/dead-ratio filters |
| `scanner.rs` | `SegmentLivenessScanner`: stateful candidate iterator ranking segments by compaction efficiency |
| `victim.rs` | `VictimSelector`: liveness-ratio victim selection from the reclaim queue |
| `candidate_selector.rs` | `CandidateSelector`: pin-set-aware candidate selection filtering out segments reachable from pinned traversal roots |
| `policy.rs` | `CleaningPolicy` (Auto/Deferred/Urgent) with space-pressure selection, `CleanerBackpressure` for write-path throttling, `SegmentScorer` for cost-benefit ranking |
| `ledger.rs` | `CleanerLedger` with BLAKE3-verified `CleanerLedgerRecord` (magic VCLD, version 1, 80-byte on-disk format) for crash-safe cleaning resumption |

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
On crash, the ledger is decoded from the pool root to avoid double-releasing
segments and to resume from the last cleaned segment.

## Integration Points

- `tidefs-reclaim-queue-core`: `SegmentLivenessQueue` for dead/live byte accounting
- `tidefs-gc-pin-set`: `GcPinSet` for pin-aware candidate filtering
- `tidefs-incremental-job-core`: `IncrementalJob` trait for background scheduling
- The `BlockStore` trait abstracts the local object store for block enumeration,
  reading, and writing during compaction

## Validation

```
cargo test -p tidefs-segment-cleaner  # 220 tests
```
