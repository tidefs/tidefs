# Pool-Wide Redundancy and Placement Contract

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

Maturity: **implemented** with pool-level property tests.

This document is the source of truth for how TideFS pools place objects across
devices, replacing the earlier fixed device-group model. Every object or logical
stripe allocation selects its physical targets from all eligible pool devices
according to the configured redundancy policy, failure-domain rules, health,
capacity, and epoch.

## 1. Motivation

Before this contract, a pool administrator would preconfigure a device as
`DeviceKind::Mirror` or `DeviceKind::ParityRaidN`, and that fixed topology
dictated where data landed. This stranded capacity: adding a device required
reconfiguring an explicit group, and the pool could not freely spread work
across all hardware.

The pool-wide model (GitHub issue [#17]) makes the pool the unit of placement
authority:

- There is one set of byte-addressable pool devices.
- Each allocation consults the pool redundancy policy.
- Placement is deterministic and receipt-backed.
- Device add/remove changes the eligible set for new allocations without
  breaking reads of old data.

## 2. Redundancy Policy

The pool exposes a single `PoolRedundancyPolicy`, specified in
`crates/tidefs-local-object-store/src/pool/mod.rs`:

```rust
pub enum PoolRedundancyPolicy {
    Replicated { copies: u8 },
    Erasure { data_shards: u8, parity_shards: u8 },
}
```

- **Replicated**: stores `copies` full replicas on distinct eligible devices.
- **Erasure**: stores one erasure-coded stripe with `data_shards + parity_shards`
  physical shard targets across distinct eligible devices.

The redundancy policy is part of `PoolProperties` and is persisted in the pool
label so that every open/re-import restores the same policy.

## 3. Placement Planner

Placement uses a deterministic keyed hash-ring planner
(`HashRingPlacementPlanner` in `crates/tidefs-placement-planner`) that:

1. Collects all eligible (healthy, online, matching I/O class) pool devices.
2. Computes a BLAKE3-derived score per device for each shard/replica slot,
   keyed by object identity and placement key.
3. Selects the required number of distinct devices respecting failure-domain
   anti-affinity constraints.
4. Produces a `PlacementDecision` that includes the list of device targets
   and a `PlacementReplayReceipt` for tamper-proof replay verification.

The planner is deterministic: same (object_id, policy, device set, epoch)
always produces the same targets. It uses virtual-node hash-ring mapping
(16 vnodes per GiB of capacity), weighted by device health and available
capacity.

## 4. Placement Receipts

Each write through the pool-wide path persists a `PlacementReceipt`
(`crates/tidefs-local-object-store/src/pool/mod.rs`) containing:

- The object key.
- The epoch in which the allocation was made.
- The redundancy policy and failure domain level.
- The ordered list of physical `PlacementReceiptTarget` entries, each keyed by
  persistent device GUID.
- The BLAKE3 digest of the logical payload.
- A sealed planner replay receipt for offline verification.

Receipts are the durable locator authority. A read consults the receipt to
find the device targets rather than recomputing placement against a possibly
changed topology.

## 5. Read Path (Receipt Authority)

The `Pool::get` method follows a strict authority chain:

1. Attempt to load the persisted placement receipt for the key.
2. If a valid receipt exists and its replay authority matches (the sealed
   planner receipt matches the stored locator), route the read to the
   device GUIDs listed in the receipt.
3. For replicated placement: try each target in order until a payload whose
   digest matches the receipt's `payload_digest` is found.
4. For erasure placement: collect sufficient data shards from receipt
   targets and decode.
5. If no receipt exists (pre-receipt data), fall back to a sequential scan
   of eligible devices.

This guarantees that reads honour the placement decision recorded at write
time, even after the pool topology has changed (devices added/removed, epoch
bumped).

## 6. Epoch and Device Lifecycle

Each pool tracks a monotonic `placement_epoch`. The epoch increments when:

- A device is added (`add_device`).
- A device is removed (`remove_device` / `safe_remove_device`).
- A device is replaced (`replace_device`).

Old receipts carry the epoch of their original allocation. The read path
resolves receipt targets by device GUID, so receipts remain readable across
epochs as long as the target device is still present. New allocations use
the current epoch and the current full eligible device set.

This decouples durability (old receipts stay valid) from new placement
(new allocations use the expanded/reduced device set).

## 7. Guarantees and Tests

The following properties are verified by pool-level tests in
`crates/tidefs-local-object-store/src/pool/mod.rs`:

| Property | Test |
|---|---|
| All eligible devices receive allocations over many writes | `pool_wide_placement_uses_all_eligible_devices_over_many_allocations` |
| Erasure placement uses all eligible devices | `pool_wide_placement_erasure_uses_all_eligible_devices` |
| No fixed device subset owns all stripes | `pool_wide_placement_no_fixed_device_subset_owns_all_stripes` |
| Redundancy policy determines target width | `redundancy_policy_determines_placement_target_width` |
| Old receipts readable after device add | `placement_epoch_add_device_leaves_old_receipt_readable_and_new_allocations_expand` |
| Receipt-backed reads survive topology change | `corrupt_replay_receipt_blocks_topology_fallback_read` |
| Receipt generation monotonic across rewrites | `receipt_generation_prefers_newer_same_epoch_rewrite` |
| Safe device removal evacuates receipt-backed objects | `safe_remove_device_evacuates_objects` |

The placement planner crate (`tidefs-placement-planner`) independently verifies:

- Keyed placement uses all eligible devices over many allocations.
- Target width follows the redundancy policy (Mirror/N, Erasure k+m).
- Deterministic seeds produce deterministic placements.
- Different seeds produce different placements.

## 8. Cross-Cutting Contracts

- **Distributed rebuild/backfill**: `PlacementReceipt::shared_receipt_ref()`
  projects a local receipt into a `PlacementReceiptRef` for distributed
  rebuild planning (`tidefs-rebuild-planner`).
- **Transport**: `PutWithReceipt` protocol carries placement receipts
  across nodes for distributed receipt transfer
  (`tidefs-flow-commit-coordinator`).
- **Reclaim**: Obsolete receipts are enqueued as dead-object entries with
  replacement receipt evidence for asynchronous space reclamation.
- **Pool import/export**: Device GUIDs survive export/re-import cycles,
  making receipt targets durable across pool lifecycle events.
- **Failure domains**: Placement respects the failure domain hierarchy
  (Device/Node/Rack/Datacenter) specified in the pool label, ensuring
  anti-affinity at the configured separation level.

## 9. What Was Replaced

Before this contract, the pool accepted per-device topology shapes
(`DeviceKind::Mirror`, `DeviceKind::ParityRaid1/2/3`) that decided data
placement at device-configuration time. Those variants still exist for
physical device-level mirroring/parity within a single `Device`, but the
pool no longer uses them as placement policy. The pool redundancy policy
(`PoolRedundancyPolicy`) is the single source of truth for object/stripe
placement decisions.
