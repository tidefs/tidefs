# tidefs-scrub-core

Background scrub service for periodic segment-level checksum verification in TideFS.

## Architecture

The crate provides three service tiers:

1. **ScrubService** — a `BackgroundService` that walks segment files, verifies
   every record's BLAKE3-256 integrity trailer, and records mismatches to the
   `SuspectLog`. Supports cursor-resumable walks and chain-of-trust validation.

2. **ScrubWorker** — a full-traversal object scrubber that enumerates all
   objects in the store, verifies each payload against its BLAKE3 checksum tree
   root, and collects `ScrubOutcome` records.

3. **ScrubRepairEngine** — an automatic checksum scrub repair pipeline that
   detects corrupt blocks, reconstructs them from redundant storage (erasure-coded
   shards or replication), verifies the rebuilt BLAKE3 hash, and records each
   repair event in a domain-separated BLAKE3-256 validation ledger.

## Scrub-Repair Pipeline

The `scrub_repair` module closes the detect-to-repair loop:

```text
Scrub traversal ──► checksum mismatch detected
                         │
                         ▼
                ScrubRepairEngine
                   │          │
           BlockReconstructor  ScrubRepairLedger
           (rebuild-runtime    (BLAKE3-verified
            or replica read)    validation log)
                   │
             verify rebuilt
             write back
```

### Detection

During block traversal, the engine compares each block's BLAKE3 hash against
the expected checksum from the checksum tree. A mismatch indicates silent
data corruption.

### Rebuild Dispatch

On mismatch, the engine calls into `BlockReconstructor::reconstruct()` to
rebuild the block from available redundant shards:
- **Erasure-coded**: reconstructs from surviving data shards and parity
- **Replicated**: reads a healthy replica copy

### Validation Ledger

Each repair event is recorded in a `ScrubRepairLedger` with domain-separated
BLAKE3-256 validation (domain: `tidefs-scrub-repair-v1`). The validation digest
covers: block address, expected hash, corrupted hash, rebuilt hash, shard
sources used, and timestamp. Two identical corruption+repair sequences produce
the same deterministic validation digest, enabling cross-node verification.

## Configuration

- **Repair concurrency limit**: controlled by the `BlockReconstructor`
  implementation (e.g., `TransferWindow` in `tidefs-rebuild-runtime`)
- **Retry policy**: `ScrubRepairEngine` records each attempt; the caller
  (e.g., `repair_cycle` in `tidefs-local-filesystem`) controls retry loops
- **Validation retention**: `ScrubRepairLedger` accumulates events in memory
  for the lifecycle of a scrub-repair pass; validation digests can be persisted
  alongside committed roots for audit trails

## Operator-Visible Metrics

| Metric | Description |
|---|---|
| `repair_count` | Number of blocks successfully repaired (rebuilt + verified + written back) |
| `repair_failure_count` | Number of blocks where repair was attempted but failed (unrepairable, write-back error) |
| `event_count` | Total repair events (success + failure) |
| `validation_digest` | BLAKE3-256 domain-separated digest over the full repair history |

Access via `ScrubRepairLedger` or through `LocalFileSystem::scrub_repair_pass()`.

## Modules

| Module | Description |
|---|---|
| `scrub_repair` | Automatic checksum scrub repair pipeline with BLAKE3-verified validation |
| `repair_scheduling` | Bridge between scrub findings and prioritized repair dispatch |
| `object_scanner` | Abstract object traversal for scrub workers |
| `integrity_verifier` | Per-object BLAKE3 integrity verification |
| `rate_limiter` | I/O rate limiting for background scrub |
| `scheduler` | Scrub scheduling policy |
| `detector` | Segment-level corruption detection |
| `scrub_ledger` | Record-level scrub outcome logging |
