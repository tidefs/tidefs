# Local/Distributed Placement Receipt Authority

Maturity: **implementation** for the unified receipt framework driving
placement, rebuild, rebake, and reclaim (issue #18).

## 1. Receipt Authority Model

TideFS uses one placement receipt per logical object/stripe. The receipt is
the durable source of truth for physical extent location. Local and
distributed code consult the same receipt format; no second object-store
authority is bolted onto the side.

| Layer | Receipt Role |
|-------|-------------|
| `Pool::put_with_receipt` | Produces a `PlacementReceipt` on every pool-wide write |
| `Pool::get` | Prefers receipt-driven lookup before directory scanning |
| `Pool::repair_with_receipt` | Records a replacement receipt after scrub/read repair |
| `ReplicatedObjectStore` | Projects receipts into `PlacementReceiptRef` for distributed I/O |
| `RebuildRuntime` | Consumes receipt refs for backfill and rebuild movement |
| `ReclaimConsumer` | Gates dead-object trimming on durable replacement receipts |

## 2. Receipt Format

### PlacementReceipt (local authority)

```rust
pub struct PlacementReceipt {
    pub object_key: ObjectKey,          // 32-byte logical object key
    pub epoch: u64,                      // topology/membership epoch
    pub generation: u64,                 // monotonic receipt write generation
    pub policy: PoolRedundancyPolicy,    // Replicated{copies} or Erasure{k,m}
    pub failure_domain_level: FailureDomainLevel,
    pub payload_len: u64,                // logical payload length
    pub shard_len: u32,                  // erasure shard length (0 for replicated)
    pub payload_digest: [u8; 32],        // BLAKE3 of logical payload
    pub targets: Vec<PlacementReceiptTarget>,
    pub planner_replay_receipt: Option<PlacementReplayReceipt>,
}
```

### PlacementReceiptTarget (per-device record)

```rust
pub struct PlacementReceiptTarget {
    pub device_index: u32,      // device index at receipt epoch
    pub device_guid: [u8; 16],  // persistent device GUID
    pub shard_index: u16,       // replica/shard index within stripe
    pub role: PlacementTargetRole,  // Data or Parity
    pub stored_digest: [u8; 32],    // BLAKE3 of stored bytes
}
```

### PlacementReceiptRef (distributed projection)

The shared `PlacementReceiptRef` carries receipt identity fields needed
by distributed rebuild, backfill, and transport code:

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

## 3. Write Path

1. Caller invokes `Pool::put_with_receipt(class, key, payload)`
2. Pool runs `plan_pool_wide_placement` through the hash-ring placement
   planner to select target devices from all eligible pool devices
3. Data is written to every target (replicated fanout or erasure stripe)
4. Stored digests are recorded in each `PlacementReceiptTarget`
5. The receipt is persisted on target devices via `write_placement_receipt`
6. If an old receipt existed for this key, it is enqueued for dead-object
   reclaim with the new receipt as replacement evidence

## 4. Read Path

1. `Pool::get` first attempts `load_placement_receipt` for the key
2. If a receipt exists, `get_with_receipt` reads from recorded targets:
   - Replicated: tries each target; verifies `payload_digest`
   - Erasure: reads available shards; reconstructs if needed
3. If no receipt exists, falls back to device directory scanning
4. On checksum mismatch, the read-self-heal path records a
   `ReadRepairEvent` and repairs from healthy replicas

## 5. Rebuild Path

1. `Pool::placement_receipts` scans all persisted receipts
2. Receipts are projected into `PlacementReceiptRef` via `shared_receipt_ref`
3. `RebuildRuntime` consumes receipt refs for backfill/rebuild tasks
4. Data movement is verified against the receipt's `payload_digest`
5. Completed movements are anchored via receipt-based completion records

## 6. Reclaim Path

1. When a write replaces an old receipt, `enqueue_obsolete_placement_after_replacement`
   enqueues a `DeadObjectEntry` with `DeadObjectReplacementReceipt`
2. The reclaim queue's `dequeue_receipt_bound_batch` filters for entries
   whose replacement receipt authorizes reclaim (non-synthetic, correct
   key, well-formed policy, sufficient target count)
3. Only after the replacement receipt is durable and policy-satisfying
   are dead segments freed

## 7. Repair Path

1. Scrub detects corruption via checksum verification
2. `resolve_violation` selects a repair strategy (reconstruct, truncate,
   mark-corrupt)
3. `Pool::repair_with_receipt` rewrites data through placement planner,
   producing a fresh receipt that supersedes the original
4. The original receipt is automatically enqueued for reclaim

## 8. Tests

- `put_with_receipt_returns_placement_receipt`: local pool write produces
  retrievable receipt
- `repair_with_receipt_supersedes_original`: repair produces receipt with
  higher generation
- `receipt_bound_dead_object_drain_*`: reclaim gating on replacement receipts
- Two-node receipt transfer (distributed transport)
- Degraded read with receipt authority
- Rebuild after device replacement (receipt-driven)

## 9. References

- Issue #18 (this authority)
- Issue #16 (media substrate)
- Issue #17 (pool-wide redundancy placement)
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`
