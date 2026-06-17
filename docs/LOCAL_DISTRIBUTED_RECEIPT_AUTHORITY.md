# Local/Distributed Placement Receipt Authority

Maturity: scoped implementation note for the local object-store receipt APIs
that feed issue #18. This document is not a closure claim for the full
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
- repair rewrites that publish a newer replacement receipt;
- latest-receipt scans after rewrites and stale receipt injection;
- projection from local receipts into `PlacementReceiptRef`;
- receipt-bound reclaim gating for replicated and erasure rewrites.

## Remaining Issue #18 Acceptance Work

The following work remains under issue #18 and the focused split issues:

- #344: local-filesystem extent writes must persist and replay receipt
  references;
- #345: distributed storage-node and transport paths must move
  receipt-addressed extents between nodes;
- degraded read, rebuild, and backfill runtimes must consume durable receipt
  authority instead of synthesizing placement from current topology alone;
- #346: rebake and reclaim flows must prove ingest/base trimming is gated on
  durable replacement receipts. The `DeadObjectReclaimQueue` now supports
  `publish_replacement_receipt` for rebake to attach replacement evidence,
  and `dequeue_receipt_bound_batch_with_stable_generation` to gate reclaim
  drains on generation-stable receipt authority;
- `DeadObjectReplacementReceipt` carries an `erasure_coded` constructor and
  `authorizes_reclaim_for_with_stable_generation` to enforce both policy
  correctness and generation stability;
- two-node transfer, degraded-read, rebuild-after-replacement, and runtime
  reclaim validation rows must run in GitHub Actions.

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
