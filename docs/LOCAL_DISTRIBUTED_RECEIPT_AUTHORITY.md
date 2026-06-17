# Local/Distributed Placement Receipt Authority

Maturity: live implementation note tracking issue #18 receipt-authority
progress.
This document is not a closure claim for the full
local-filesystem, distributed transport, rebake, rebuild, and runtime
validation surface.

## Authority Model

TideFS records physical placement with a `PlacementReceipt`. The receipt is
the durable locator authority for a logical object or stripe: it binds the
object key, placement epoch, receipt generation, redundancy policy, payload
digest, and selected physical targets.

Local and distributed layers should consume projections of this same authority
instead of inventing a second placement truth. In this slice, the local
object-store exposes receipt-returning write and repair entry points so callers
can carry durable placement identity forward without doing a second lookup.

## Implemented Local APIs

| Surface | Current behavior |
|---------|------------------|
| `Pool::put` | Writes receipt-publishing I/O classes through pool-wide placement and persists a `PlacementReceipt` |
| `Pool::put_with_receipt` | Performs the same receipt-publishing write and returns the persisted receipt |
| `PoolStoreMut::put_with_receipt` | Data-class convenience wrapper for callers holding a mutable pool store |
| `Pool::get` | Prefers persisted receipt lookup and falls back to device scans only when no receipt exists |
| `Pool::placement_receipts` | Scans persisted receipts and returns the latest logical receipt per object key |
| `PlacementReceipt::shared_receipt_ref` | Projects local receipts into the shared `PlacementReceiptRef` model |
| `Pool::repair_with_receipt` | Rewrites reconstructed bytes through placement and returns the replacement receipt |
| receipt-bound drains | Hold obsolete physical objects until replacement receipt generation is stable |

`IntentLog` writes keep receiptless write-ahead-log semantics. Callers that
need receipt authority must use a receipt-publishing I/O class such as `Data`,
`Metadata`, or `ReadCache`.

## Receipt Format

### `PlacementReceipt`

```rust
pub struct PlacementReceipt {
    pub object_key: ObjectKey,
    pub epoch: u64,
    pub generation: u64,
    pub policy: PoolRedundancyPolicy,
    pub failure_domain_level: FailureDomainLevel,
    pub payload_len: u64,
    pub shard_len: u32,
    pub payload_digest: [u8; 32],
    pub targets: Vec<PlacementReceiptTarget>,
    pub planner_replay_receipt: Option<PlacementReplayReceipt>,
}
```

### `PlacementReceiptTarget`

```rust
pub struct PlacementReceiptTarget {
    pub device_index: u32,
    pub device_guid: [u8; 16],
    pub shard_index: u16,
    pub role: PlacementTargetRole,
    pub stored_digest: [u8; 32],
}
```

### `PlacementReceiptRef`

The shared reference carries the receipt identity needed by rebuild, backfill,
and transport models without copying the entire local receipt payload:

```rust
pub struct PlacementReceiptRef {
    pub object_id: u64,
    pub object_key: [u8; 32],
    pub receipt_epoch: EpochId,
    pub receipt_generation: u64,
    pub redundancy_policy: ReceiptRedundancyPolicy,
    pub payload_len: u64,
    pub payload_digest: [u8; 32],
    pub target_count: u16,
}
```

## Write And Repair Flow

1. A caller writes through `Pool::put_with_receipt` or
   `PoolStoreMut::put_with_receipt`.
2. The pool uses pool-wide placement to select target devices for the active
   redundancy policy.
3. The write persists the physical object or shards and then persists a
   `PlacementReceipt`.
4. The caller receives the `StoredObject` plus the authoritative
   `PlacementReceipt`.
5. If a previous receipt existed, obsolete physical locations are enqueued for
   receipt-bound reclaim using the replacement receipt as evidence.

`Pool::repair_with_receipt` uses the same write path for reconstructed bytes.
The replacement receipt has a higher generation and becomes the current
authority for subsequent reads.

## Read And Reclaim Flow

`Pool::get` first loads the current receipt for the object key. Replicated
receipts try recorded targets and verify the logical payload digest. Erasure
receipts read recorded shards, verify stored shard digests, and reconstruct
when enough shards remain available. If no receipt is present, pre-receipt
device scanning remains the local fallback for older in-tree harness data.

Receipt-bound dead-object drains only free obsolete physical objects after the
replacement receipt generation is stable. This keeps reclaim from racing the
durable publication of the replacement placement authority.

## Validation In This Slice

The local object-store tests cover:

- receipt-returning writes through `put_with_receipt`;
- rejection of receiptless `IntentLog` writes through `put_with_receipt`;
- repair rewrites that publish a newer receipt generation;
- receipt persistence across pool close/reopen cycles (local replay);
- receipt-bound reclaim that holds dead objects until the replacement receipt
  generation is stable and durable;
- rebake-gated dead-object enqueue via `QueueFamily::Rebake` with generation
  stability enforcement.

The replicated object-store tests cover:

- `put_named_with_receipt` quorum-write integration with receipt validation;
- receipt-validated degraded reads with replica fallback;
- two-node receipt transfer and receipt-read tests via
  `SegmentFetchRequest`/`SegmentFetchResponse`;
- receipt-repair task execution with verified completion tracking;
- placement map versioning and receipt-ref propagation.

The rebuild planner tests cover:

- receipt-backed object placement validation;
- reconstruction planning with receipt-ref authority;
- malformed-policy receipt rejection;
- erasure and replicated layout planning;
- deterministic plan sealing and integrity verification.

The local-filesystem tests cover:

- receipt generation during content writes through `put_with_receipt`;
- receipt durability gating in rewrite-path extent trimming;
- receipt rotation through the content rewrite path;
- reclaim drain gating on durable receipt evidence;
- re-enqueue when replacement receipt is not yet durable.

The scrub-core multi-node fanout protocol carries `PlacementReceiptRef` so
peers validate placement authority during distributed verification.

### Transport Protocol Receipt Carriage

The replication transport carries receipts in key protocol messages:

- `SyncResponse { entries: Vec<SyncEntry> }` where each `SyncEntry` carries
  an optional `placement_receipt_ref`;
- `ReadPlanResponse { placement_receipt_ref: Option<PlacementReceiptRef> }`;
- `RepairObject { placement_receipt_ref, authoritative_payload }` and
  `RepairObjectAck { repaired_placement_receipt_ref }`.

The segment-fetch protocol (`SegmentFetchRequest`/`SegmentFetchResponse`) carries
receipt authority for cross-node byte-range reads over transport sessions:

- `SegmentFetchRequest { object_id, placement_receipt_ref, segment_offset, segment_length }` —
  a node requests a byte range from a remote object. Real movement paths send a
  non-synthetic `PlacementReceiptRef`; absent or synthetic refs are legacy
  fallback only.
- `SegmentFetchResponse { object_id, segment_offset, segment_length, payload }` —
  the serving node reads the exact object key from the pool-backed receipt lookup
  and returns the segment bytes with per-message integrity.

The `TransportReplicatedStore::fetch_remote_segment_by_receipt` and
`handle_segment_fetch_request` entry points wire this protocol end-to-end,
validating that synthetic receipt refs are rejected and that pool-backed
receipt lookups drive the segment read.

### Completed

Completed issue #18 split work merged so far:

- #343 (merged): pool exposes receipt-returning placement writes;
- #344 (merged via PR #358): local-filesystem extent writes persist and replay
  receipt references through extent IO;
- #345 (merged via PR #350): distributed storage-node and transport paths move
  receipt-addressed extents between nodes via `PutWithReceipt` protocol;
- #346 (merged via PR #357): rebake/reclaim receipt publishing, generation-stability
  gating, `DeadObjectReplacementReceipt::erasure_coded` constructor, and
  `authorizes_reclaim_for_with_stable_generation` enforcement;
- #352 (merged via PR #362): local-filesystem routes content writes through
  `PoolStoreMut::put_with_receipt` for receipt generation;
- #354 (merged via PR #375): local-filesystem preserves durable receipt evidence
  during rewrites, deletion, and reclaim;
- #355 (merged via PR #355): erasure receipt coverage and
  rebuild-after-replacement tests;
- #356 (merged via PR #366): replicated-object-store receipt-validated
  degraded reads and two-node receipt-read tests;
- #360 (merged via PR #360): receipt generation consumed during recovery and
  replay paths;
- #363 (merged via PR #372): local-filesystem read-path extent lookup via
  receipt generation;
- #364 (merged via 5aaf309): local-filesystem tests for receipt generation
  validation in content inspection;
- #369 (merged via PR #369): scrub-core receipt authority in multi-node fanout
  protocol and rebuild-after-replacement integration test;
- #370 / #371 (merged via e0915b6, 8c59fb4): distributed model-check
  integration with settled receipt types and durable-rebuild gating;
- #376 (merged via PR #379): local-filesystem receipt rotation wired into
  the content rewrite path;
- #377 (merged via PR #388): receipt durability wired into rewrite-path
  extent trimming, with rollback state preservation;
- #378 (merged via PR #378): docs updated to reflect current merged state;
- #380 (merged via PR #380): `put_named_with_receipt` added to
  `TransportReplicatedStore` with quorum-write and receipt-validation
  integration;
- rebuild completion receives receipt-verified task tracking with
  `record_receipt_verified_task_completion` that validates erasure and
  replicated policy correctness, including erasure malformed-policy rejection.

### Remaining

The merged split issues above do not close the full issue #18 acceptance
criteria. Remaining implementation and validation work includes:

- Wire primary distributed writes so the storage-node and pool-backed write
  paths record durable receipts before transport fan-out;
- Finish read, degraded-read, scrub, repair, and rebuild paths that still need
  to consume receipt authority outside the focused split APIs above;
- Finish rebake/reclaim runtime paths that must trim only after durable
  replacement receipt evidence is available;
- Complete distributed state-transfer paths that move receipt-addressed extents
  and preserve read availability during node/device loss within the configured
  redundancy policy;
- Add two-node/distributed storage-node integration tests plus runtime rows for
  two-node receipt transfer, degraded-read availability, rebuild after
  replacement, and reclaim under sustained write pressure.

Runtime rows remain milestone-gate validation, not first-edit implementation.
RDMA and broad release-candidate runs are further milestone gates (see issue
#18 validation tier).

## References

- Issue #18: local/distributed receipt authority
- Issue #344: local-filesystem receipt-ref extent IO
- Issue #345: distributed receipt-addressed extent transfer
- Issue #346: receipt-driven rebake/reclaim durability gating
- Issue #17: pool-wide redundancy placement
- Issue #16: media substrate
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`
