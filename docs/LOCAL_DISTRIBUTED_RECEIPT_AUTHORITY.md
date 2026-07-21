# Local/Distributed Placement Receipt Authority

Authority note: live implementation note for receipt-authority progress.
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
| `Pool::get` | Selects the current receipt across every attached device and reads only its recorded targets; receiptless raw reads are limited to `IntentLog` |
| `Pool::placement_receipts` | Scans every attached device and returns the latest logical receipt per object key |
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

`ReceiptRedundancyPolicy::target_count_satisfies` is the shared policy-width
gate. It requires the policy to be well-formed and the recorded `target_count`
to equal the policy width: replicated receipts must record exactly `copies`
targets, and erasure receipts must record exactly `data_shards + parity_shards`
targets. `PlacementReceiptRef::is_policy_satisfying` applies that gate to a
receipt reference, and `PlacementReceiptRef::is_committed_authority` additionally
requires the reference to be non-synthetic. Consumers must reject synthetic,
under-width, over-width, and malformed-policy receipt references as placement
authority.

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

`Pool::get` first selects the current receipt for the object key across every
attached device, regardless of the requested I/O class. Replicated receipts try
only recorded targets and verify the logical payload digest. Erasure receipts
read recorded shards, verify stored shard digests, and reconstruct only when
enough verified shards remain available. A selected receipt whose payload is
unavailable, corrupt, or insufficient returns an error rather than ordinary
absence.

Receiptless raw reads are limited to `IntentLog`, whose write-ahead-log
semantics intentionally do not publish placement receipts. For `Data`,
`Metadata`, and `ReadCache`, raw bytes without a receipt are an authority error.
A never-present or fully deleted non-IntentLog key returns ordinary absence only
after every attached device confirms that neither a receipt nor raw bytes for
the key exist.

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

The storage-node client frame path now treats durable placement receipts as the
primary write authority for clustered writes. Pool-backed `Frame::Put` writes
through `Pool::put_with_receipt` and returns a `PutWithReceiptResponse` with
the recorded `PlacementReceiptRef`. Transport-backed primaries refuse
receiptless `Frame::Put` instead of acknowledging a write that cannot prove
pool placement authority; callers must use `PutWithReceipt` or a pool-backed
receipt-producing boundary. Client-facing `PutWithReceipt` frames validate the
supplied receipt against the object name, payload length, payload digest,
target width, policy shape, and synthetic-generation marker before any backend
write is accepted.

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
criteria. Remaining implementation and validation work is split into
non-overlapping GitHub issues:

- #674 owns distributed primary write and transport fan-out paths:
  `apps/tidefs-storage-node`, `crates/tidefs-replicated-object-store`, and
  `crates/tidefs-transport`;
- #675 owns local read, degraded-read, scrub, repair, and rebuild consumers:
  `crates/tidefs-local-filesystem`, `crates/tidefs-scrub-core`,
  `apps/tidefs-scrub`, and `crates/tidefs-rebuild-planner`;
- #676 owns rebake/reclaim trim gating and replay:
  `crates/tidefs-local-object-store`, `crates/tidefs-reclaim`, and
  `crates/tidefs-reclaim-queue-core`.

Runtime rows remain milestone-gate validation, not first-edit implementation.
RDMA and broad release-candidate runs are further milestone gates (see issue
#18 validation tier).

## References

- Issue #18: local/distributed receipt authority
- Issue #344: local-filesystem receipt-ref extent IO
- Issue #345: distributed receipt-addressed extent transfer
- Issue #346: receipt-driven rebake/reclaim durability gating
- Issue #674: distributed primary receipt fan-out
- Issue #675: local read/scrub/repair/rebuild receipt consumers
- Issue #676: rebake/reclaim policy-satisfying receipt gate
- Issue #17: pool-wide redundancy placement
- Issue #16: media substrate
- Deleted shard/rebake historical lineage
- source-owned replication, rebuild, and relocation model crates
- `docs/STORAGE_INTENT_RESULT_REFUSAL_EVIDENCE_DESIGN.md`
