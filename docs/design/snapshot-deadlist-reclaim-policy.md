# Snapshot Deadlist Reclaim Policy

> Decision record for reclaim drain cadence, admission limits, queue-size
> reporting, and capacity/accounting integration.
>
> Parent design: #1248 (deadlist integration).
> Depends on #1263 (derivation API), #1264 (queue integration), and #1265
> (snapshot-delete wiring) for implementation evidence.
> Reclaim constants are provisional until validation evidence exists.

## 1. Context

`docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` §4 defines the deadlist
integration model: when a snapshot or clone is deleted and its lifecycle pin
released, objects reachable only through that released root are derived as
receipt-bound dead-object candidates, enqueued into the
`DeadObjectReclaimQueue`, and physically freed only after a durable receipt
and a `SnapshotExtentPinSet` clearance gate confirm the object is truly
unreferenced.

The derivation API (#1263), queue persistence (#1264), and snapshot-delete
enqueue wiring (#1265) define _what_ enters the queue and _how_ the
receipt-bound drain processes entries. This document decides the policy
layer _above_ that machinery: when the drain runs, how large batches may be,
how operators observe deferred space, and how the capacity authority
distinguishes deadlist debt from physically freed space.

## 2. Evidence Reviewed

- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` §4 (deadlist integration decision,
  §4.8 follow-up issue map).
- `crates/tidefs-reclaim-queue-core/src/dead_object_queue.rs` —
  `DeadObjectReclaimQueue`, `DeadObjectEntry`, `dequeue_batch_with_orphan_watermark`,
  commit_group-anchored eligibility, orphan-watermark gating.
- `crates/tidefs-local-object-store/src/reclaim_queue.rs` — persistent
  named-object storage for the dead-object queue, reclaim receipts, and
  snapshot extent pins.
- `crates/tidefs-reclaim/src/lib.rs` — `ReclaimConsumerConfig`,
  `ReceiptBoundDeadObjectDrain`, `ReclaimGate`, `SegmentFreer`.
- `crates/tidefs-segment-cleaner/src/physical_reclaim.rs` —
  `PhysicalReclaimConfig`, receipt-bound drain bridge, `drain_receipt_bound_physical_reclaim`.
- `crates/tidefs-local-filesystem/src/capacity_authority.rs` —
  `CapacityAuthority`, `used_bytes`/`reserved_bytes`/`pending_bytes` counters,
  `derive_statfs` for FUSE/POSIX statfs reporting.
- `crates/tidefs-local-filesystem/src/space_pressure.rs` —
  `SpacePressureLevel` (Healthy/Warning/Sync/Critical), `SpacePressureConfig`.
- `crates/tidefs-local-filesystem/src/statfs.rs` — `Statvfs` derivation
  from `CapacityAuthority`.

## 3. Architecture

The deadlist reclaim policy sits between the queue machinery and the
operator-visible capacity surface:

```text
Snapshot delete (#1265)
  │
  ▼
Derivation API (#1263) ──► DeadObjectReclaimQueue (#1264)
                                   │
                    ┌──────────────┘
                    ▼
 Reclaim Drain Policy (this document)
  ├── drain cadence (background bounded, space-pressure stepped)
  ├── admission limits (per-drain batch cap, orphan-watermark gating)
  ├── queue-size reporting (deadlist_debt_bytes counter)
  └── capacity integration (CapacityAuthority extension)
                    │
                    ▼
 Receipt-bound physical drain ──► SegmentFreer ──► CapacityAuthority.record_free()
```

## 4. Drain Cadence

### 4.1 Decision: Background bounded drain with space-pressure escalation

The drain runs on two triggers:

1. **Background periodic drain** (primary). A background-service tick fires
   every `deadlist_drain_interval_secs` (default: 30 s). Each tick dequeues
   at most `deadlist_drain_batch_max` entries (default: 1024), processes
   them through the receipt-bound drain, and commits freed segments back to
   the allocator.

2. **Space-pressure escalation** (secondary). When `SpacePressureLevel` reaches
   `Sync` or `Critical`, a synchronous drain runs immediately on the
   allocating thread before returning ENOSPC. This synchronous drain uses a
   smaller batch cap (`deadlist_drain_sync_batch_max`, default: 256) to
   bound allocation-path latency while still reclaiming urgent space.

The background drain never runs on the allocation hot path. The synchronous
escalation drain is the only path that blocks a writer.

### 4.2 Rejected Alternative: Synchronous delete-time drain

A synchronous drain that tries to free every deadlisted object at
snapshot-delete time was rejected:

- Snapshot deletion already mutates the state map, catalog, and lifecycle
  pins inside a transaction boundary. Adding root walking, receipt
  publication, and segment freeing to that transaction would couple
  authority mutations (which must be fast and atomic) with physical
  allocation work (which can be slow and may fail).
- Clone shared-root semantics mean that a "delete" may only decrement a
  pin count without releasing any objects; attempting a synchronous drain
  for every deletion would waste work.
- The existing receipt-bound drain path already provides the resumable,
  fail-closed state that synchronous delete-time drain would need to
  reinvent (see `DeadObjectReclaimQueue`'s `death_commit_group` and
  orphan-watermark gating).

### 4.3 Rejected Alternative: Direct allocator consultation

The allocator consults the deadlist directly before allocating new extents.
Rejected in `SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` §4.6; reaffirmed here
because it would bypass committed receipt evidence, stable-generation
checks, and the `SnapshotExtentPinSet` guard.

## 5. Admission Limits

### 5.1 Per-drain batch cap

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `deadlist_drain_batch_max` | 1024 entries | Aligned with `ReclaimConsumerConfig::max_entries_per_drain`; one receipt-bound drain call fits within a single background tick without starving other services. |
| `deadlist_drain_sync_batch_max` | 256 entries | One quarter of the background cap; bounds allocation-path stall under space pressure while still freeing meaningful space. |
| `max_free_batch` | 64 segments | Inherited from `ReclaimConsumerConfig::max_free_batch`; caps the spacemap checkpoint work per drain before the allocator must absorb freed segments. |

### 5.2 Concurrent drain serialization

Only one drain (background or synchronous) may be active at a time. An
`AtomicBool` guard (or equivalent) prevents concurrent queue mutation. If
a synchronous escalation arrives while a background drain is active, the
synchronous caller either waits for the background drain to finish or
returns a partial-free result immediately (the caller then re-checks ENOSPC
and retries if needed).

### 5.3 Orphan-watermark gating

Entries blocked by the orphan replay watermark are counted in
`orphan_watermark_blocked_count` and reported via the queue-size surface
(§6). They are never silently dropped; they remain in the queue until the
watermark advances or the inode mapping becomes available.

### 5.4 Deadlist drain interval

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `deadlist_drain_interval_secs` | 30 s | Frequent enough that normal snapshot-delete throughput reclaims space within operator-observable windows; infrequent enough that the background tick does not contend with foreground I/O on every commit. |

All defaults in §5 are configurable and conservative. Production tuning
requires validation evidence from the #1263–#1265 implementation artifacts.

## 6. Queue-Size Reporting

### 6.1 Decision: `deadlist_debt_bytes` counter

`CapacityAuthority` gains one new atomic counter:

- `deadlist_debt_bytes: AtomicU64` — the sum of `DeadObjectEntry::allocated_bytes`
  for all entries currently in the `DeadObjectReclaimQueue`.

This counter is updated at enqueue time (add) and at receipt-bound drain
acknowledgement time (subtract). It is not a per-allocation hot-path write;
only the derivation enqueue (#1265) and the drain acknowledgement touch it.

The counter feeds two operator surfaces:

1. **statfs reporting**: `bfree` and `bavail` are adjusted so that
   `deadlist_debt_bytes` is excluded from free space (it is not yet
   physically free) but reported separately so operators can distinguish
   "truly free" from "reclaimable debt."

2. **Operator UAPI** (future): a `tidefs pool stats` or equivalent
   operator command surfaces `deadlist_debt_bytes` alongside
   `used_bytes` and `free_bytes`.

### 6.2 statfs projection

`CapacityAuthority::derive_statfs` extends its block-counter derivation:

```text
physically_free_bytes = total_bytes - used_bytes - reserved_bytes
debt_blocks           = deadlist_debt_bytes / block_size
statfs_free_blocks    = max(0, physically_free_bytes / block_size)
statfs_avail_blocks   = max(0, (physically_free_bytes - root_reserve_bytes) / block_size)
```

The `deadlist_debt_bytes` is _not_ subtracted from `bfree` or `bavail`
because it is already part of `used_bytes` (deadlisted objects are still
physically allocated). The authority's existing `used_bytes` counter
already accounts for them; the debt counter is additive observability, not
a double-count.

If a future operator surface needs a "physically free plus reclaimable"
number, the operator tooling combines `free_bytes + deadlist_debt_bytes`
at query time rather than baking that sum into `CapacityAuthority`.

### 6.3 Queue-depth operator signal

In addition to the byte counter, the dead-object queue exposes:

- `queue_length`: total entry count.
- `eligible_count`: entries whose `death_commit_group` is ≤ the current
  stable committed transaction group.
- `blocked_by_orphan_watermark`: entries that are eligible by commit_group
  but blocked by the orphan replay watermark.
- `blocked_by_receipt`: entries whose replacement receipt generation is
  below the stable committed generation.
- `receipt_bound_count`: entries that carry a `replacement_receipt` and
  will require receipt authorization before physical free.

These signals are exposed through the operator UAPI (future) and the
background-service telemetry path. They are not wired into statfs because
POSIX statfs has no field for per-reason queue breakdowns.

## 7. Capacity/Accounting Integration

### 7.1 Deadlist debt vs. physical free

The capacity authority already tracks `used_bytes` as the sum of committed
extent allocations. Deadlisted objects are still allocated extents (their
segments have not been freed), so they remain in `used_bytes`. This is
correct: the capacity authority must not claim space is free until the
segment freer has physically released it.

The new `deadlist_debt_bytes` counter is subordinate to `used_bytes`:
`deadlist_debt_bytes ≤ used_bytes` always. Capacity tools may display both
to show how much `used_bytes` is reclaimable.

### 7.2 Interaction with space pressure

`SpacePressureLevel` derivation continues to use `used_bytes / total_bytes`
as its primary signal. Deadlist debt is not subtracted because:

- Deadlisted objects still consume physical space and contribute to
  allocator fragmentation.
- The space-pressure escalation path (§4.1) already triggers synchronous
  drain under `Sync`/`Critical` pressure, which reduces deadlist debt.
- Subtracting debt prematurely could hide real space exhaustion behind a
  large deadlist that the drain has not yet processed.

### 7.3 ENOSPC gating

`CapacityAuthority::check_enospc` (the gate used by write/create/truncate
paths) is unchanged. It gates on `available_bytes() ≤ 0`, where
`available_bytes = total_bytes - used_bytes - reserved_bytes - root_reserve_bytes`.

Deadlist debt does not relax the ENOSPC gate. The synchronous escalation
drain (§4.1) may free enough segments to reopen the gate, but the gate
itself does not treat deadlisted space as available.

### 7.4 Quota interaction

Dataset quota enforcement (`quota_table.check_delta`) queries
`capacity_authority.free_bytes()` for the pool-level free byte floor.
Deadlist debt is invisible to quota checks for the same reason it is
invisible to ENOSPC: deadlisted space is not free until the segment freer
releases it.

## 8. Scope Boundaries

### 8.1 In scope (this document)

- Drain cadence policy (background bounded + space-pressure escalation).
- Per-drain admission limits and batch caps.
- Queue-size reporting (deadlist_debt_bytes counter, statfs projection,
  operator telemetry signals).
- Capacity/accounting integration (relationship between deadlist_debt_bytes
  and existing `used_bytes`/`free_bytes`/ENOSPC/space-pressure surfaces).

### 8.2 Out of scope

- Deadlist derivation algorithm (#1263).
- Queue persistence format (#1264).
- Snapshot-delete enqueue wiring (#1265).
- Receive-side trigger wiring (#1259).
- Deadlist scrub or segment compaction policy.
- Production-tuned constants (requires validation evidence from
  #1263–#1265).
- Distributed or cross-node deadlist reclaim.
- Online deadlist defragmentation or priority-ordered drain.

## 9. Follow-Up Issues

When #1263, #1264, and #1265 have landed implementation evidence, the
following source issues should be split from this policy:

1. **deadlist-background-drain**: Wire the background periodic drain tick
   into the background-service framework. Expected write set:
   `crates/tidefs-local-filesystem/src/background_reclaim.rs` (new or
   extended). Validation: focused unit tests for tick scheduling, batch
   cap enforcement, and drain serialization.

2. **deadlist-sync-escalation**: Wire the synchronous space-pressure drain
   into the allocation path. Expected write set:
   `crates/tidefs-local-filesystem/src/capacity_authority.rs` and/or
   `allocation.rs`. Validation: unit tests for ENOSPC escalation, sync
   batch cap enforcement, and concurrent drain exclusion.

3. **deadlist-debt-capacity**: Add `deadlist_debt_bytes` to
   `CapacityAuthority`, wire the enqueue/drain counter updates, and extend
   `derive_statfs`. Expected write set:
   `crates/tidefs-local-filesystem/src/capacity_authority.rs`,
   `crates/tidefs-local-filesystem/src/statfs.rs`. Validation: unit tests
   for counter consistency, statfs projection, and crash-recovery
   re-derivation of the counter from the persisted queue.

4. **deadlist-operator-uapi**: Expose queue-depth and debt-byte telemetry
   through the operator API surface. Expected write set: operator command
   or admin-service extension. Validation: focused smoke test.
