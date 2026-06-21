# Erasure-Coded Store Authority

Maturity: current authority document for GitHub issue #748.

Authority claim path: `local.storage.erasure_coded_store_authority.v1`.

This document decides the placement, read-path, rebuild, and write-path
authority boundaries for `crates/tidefs-erasure-coded-store` relative to the
object-store pool, placement planner, receipt system, and recovery
orchestrator. It is a design-decision document, not a runtime implementation
claim. The claim path above is a named authority path, not a validated product
claim, and must remain blocked until the implementation and validation evidence
named below exist.

## Scope

This authority covers:

- whether the EC store owns shard placement or consumes placement-planner and
  receipt authority like replicated paths do;
- who selects the healthy shard subset on read and invokes reconstruction;
- whether missing-shard rebuild is an EC-store-local operation or consumes
  repair/receipt dispatch;
- whether write ingestion produces EC-encoded extents inline or via an async
  encode queue;
- mapping follow-up implementation issues with non-overlapping expected write
  sets.

This authority does not cover EC encode/decode mathematics, the GF(2^8)
Reed-Solomon engine in `tidefs-erasure-coding`, the XOR single-parity model in
`tidefs-replication-model`, or the TideCRUSH placement algorithm specified in
`docs/ERASURE_CODING_PLACEMENT_DESIGN.md`. Those are upstream contracts that
the EC store consumes; this document only decides the store-level authority
boundaries.

## Evidence Reviewed

- `docs/ERASURE_CODED_LAYOUT_OW306.md` — current single-parity XOR model spec
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` — TideCRUSH placement, erasure
  family catalog, recovery loop orchestration, and integration contracts
- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` — placement receipt model,
  write/repair/read/reclaim flows, receipt format with erasure policy support
- `crates/tidefs-erasure-coded-store/` — current local EC store runtime:
  inline encode, per-store read with reconstruction, `flush_repairs()`,
  `repair_store()`, `compute_shard_to_store()` consuming `PlacementPlan`
- `crates/tidefs-erasure-coding/` — GF(2^8) RS engine used by the store
- `crates/tidefs-replication-model/` — `ErasureCodingProfile`, `RedundancyPolicy::ErasureCoded`,
  `DurabilityLevel::for_erasure_coded`, and `ErasureLayoutPolicy` for the
  OW-306 XOR model
- `docs/workspace-package-classification.md` — classifies
  `tidefs-erasure-coded-store` as planned authority surface requiring a
  follow-up issue
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` — TFR-019 classification
  framework for doc authority states

## Current State Summary

The EC store (`crates/tidefs-erasure-coded-store`) is an implementation-tracked
local runtime. It:

- splits objects into stripes and encodes each stripe with GF(2^8) Reed-Solomon
  across `k + m` local `LocalObjectStore` instances;
- reads from all shards, reconstructs from any k survivors, and queues missing
  shards for repair via `flush_repairs()`;
- already imports `PlacementPlan` and `DeviceCandidate` from
  `tidefs-placement-planner` and can compute a shard-to-store mapping from
  placement input (`compute_shard_to_store()`);
- provides `repair_store()` to rebuild all objects on a single failed store
  from survivors.

The pool crate (`tidefs-pool`) has no erasure-code integration. The
`PlacementReceipt` format in `tidefs-object-store` already supports erasure
policies: `ReceiptRedundancyPolicy` gates require `target_count ==
data_shards + parity_shards`, and the receipt read path already describes
erasure reads with shard-digest verification and reconstruction.

What is missing: a decision on whether the EC store evolves into a
pool-level authority surface that consumes placement and receipt authority
the same way replicated paths do, or whether it remains a standalone local
store with its own placement model.

## Decisions

### 1. Placement Model: Consume Pool Placement And Receipt Authority

The EC store does not own its own extent placement. It consumes the same
placement-planner and receipt authority that replicated paths use.

Rationale:

- The existing placement design (`ERASURE_CODING_PLACEMENT_DESIGN.md`)
  specifies TideCRUSH as the deterministic placement function for all
  redundancy policies, including erasure coding. Having the EC store own a
  parallel placement truth would fork the placement authority.
- The `PlacementReceipt` format already encodes erasure policy targets
  (`data_shards + parity_shards`), and the receipt read path already describes
  erasure reads with shard-digest verification and reconstruction. This is
  the same receipt authority that replicated paths use.
- The EC store already imports `PlacementPlan` and `DeviceCandidate` from
  `tidefs-placement-planner`. The `compute_shard_to_store()` function is a
  local precursor to full receipt consumption.
- A single placement truth (pool-wide placement → receipt) avoids the split
  brain that would arise from an EC-store-local placement table that diverges
  from the pool's topology view.

Concrete contract:

- The pool's write path (`Pool::put_with_receipt`) selects targets through
  pool-wide placement, persists a `PlacementReceipt` with erasure policy
  targets, and returns the receipt.
- The EC store receives the placement targets from the receipt (or from the
  placement plan that produced the receipt) and writes each shard to the
  assigned device/store.
- The EC store does not select devices; it consumes an ordered device list
  from the placement authority.

### 2. Read-Path Boundary: EC Store Owns Shard Selection And Reconstruction

When a consumer requests an EC-encoded extent, the EC store owns the full
read path: selecting the healthy shard subset, verifying per-shard digests,
invoking Reed-Solomon reconstruction when shards are missing, and queuing
repair for degraded shards.

Rationale:

- The EC store already implements this exact boundary: `get_named()` reads
  all shards, attempts reconstruction from survivors, and enqueues
  `PendingEcRepair` entries for missing or corrupt shards.
- The pool's `get` already describes erasure reads as "read recorded shards,
  verify stored shard digests, and reconstruct when enough shards remain
  available" (`LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`).
- Keeping the shard-level decode logic inside the EC store avoids leaking
  erasure-coding internals (k, m, GF(2^8) matrix inversion, stripe boundaries)
  into the pool and other consumers.

Concrete contract:

- Pool calls `ErasureCodedStore::get_named()` (or an async equivalent) and
  receives reconstructed bytes or an error when fewer than k shards survive.
- The EC store internally: selects the k healthiest shards, verifies embedded
  digests, reconstructs, queues repairs, and returns the payload.
- The pool does not need to know the shard topology; it only knows the
  logical object identity and the receipt that records where shards live.

### 3. Rebuild Model: Local Repair Is EC-Store-Local; Orchestrated Repair Consumes Dispatch

Missing-shard rebuild has two tiers with different ownership:

| Tier | Trigger | Owner | Scope |
|------|---------|-------|-------|
| Local per-stripe repair | Degraded read, `flush_repairs()` | EC store | Reconstruct one shard from k survivors and write it back to its assigned store |
| Orchestrated repair | Member failure, background scrub | Recovery loop orchestrator (future) | Enumerate affected stripes, re-place via TideCRUSH, dispatch repair jobs, throttle |

Rationale:

- The EC store already has `flush_repairs()` (write-back queued shard repairs
  from degraded reads) and `repair_store()` (rebuild all objects on one failed
  store). These are bounded, local operations that the EC store can own
  without external coordination.
- Broader repair orchestration (a node failure affects many stripes across
  many objects) must consume the placement planner to select new targets and
  the receipt system to publish replacement receipts. This exceeds the EC
  store's local scope and belongs to the recovery loop orchestrator described
  in `ERASURE_CODING_PLACEMENT_DESIGN.md` section 5.
- The EC store provides the per-stripe rebuild primitive; the orchestrator
  schedules, dispatches, and throttles.

Concrete contract:

- `ErasureCodedStore::repair_shard(stripe_id, shard_idx, reconstructed_data, target_store)` is
  the primitive the EC store exposes to the recovery orchestrator.
- `ErasureCodedStore::flush_repairs()` remains the local degraded-read repair
  path.
- Stripe enumeration, TideCRUSH re-placement, and repair job scheduling live
  in the recovery loop orchestrator, which consumes the EC store as a repair
  worker.
- `Pool::repair_with_receipt` is the pool-level repair entry point; for EC
  objects it delegates to the recovery orchestrator, which in turn drives the
  EC store's per-shard repair primitive.

### 4. Write-Path: Inline Encode

Write ingestion produces EC-encoded extents inline: a `put` call splits the
payload into stripes, encodes each stripe, and writes all shards before
returning.

Rationale:

- The current EC store already does inline encode in `put_named()`. There is
  no evidence of a queue, and the existing code calls `encode()` synchronously
  before writing.
- Inline encode keeps the write path simple and consistent with the replicated
  write path, where `Pool::put_with_receipt` writes all copies inline.
- An async encode queue is a potential future optimization for large-object
  or high-throughput workloads, but it introduces a durability window (data
  acknowledged before parity is written) and complicates the receipt model
  (the receipt must record shards that may not yet exist). The initial
  authority model does not open that window.

Concrete contract:

- `Pool::put_with_receipt` for EC objects: placement selects targets → EC store
  encodes inline → writes all shards → persists receipt → returns.
- No async encode queue in the initial authority surface. A future
  `async_encode_queue` design issue may revisit this when throughput benchmarks
  justify the added complexity.

### 5. Single EC Authority Owner

The `crates/tidefs-erasure-coded-store` crate is the single EC store authority
surface for local encode, decode, read, and per-stripe repair. It is the
implementation authority for:

- stripe encode from payload bytes using `tidefs-erasure-coding`;
- stripe decode/reconstruction from surviving shards;
- per-shard digest envelope wrapping and verification;
- local repair queue and per-store rebuild;
- consumption of placement targets from the placement planner and receipt
  authority.

The EC store does not own:

- device-level placement selection (placement planner / TideCRUSH);
- receipt generation and publication (pool / receipt authority);
- failure-domain topology (membership epoch);
- recovery loop orchestration (recovery orchestrator, future);
- erasure profile catalog management (catalog, future).

The classification row in `docs/workspace-package-classification.md` can be
updated from "planned authority surface; follow-up issue required" to
"current product component; capability claims remain limited by the review
register" once the follow-up implementation issues below are completed.

## Follow-Up Implementation Issues

Each follow-up issue has a non-overlapping expected write set and should be
worked sequentially or by non-overlapping owners.

1. **EC-store receipt integration**: Wire `ErasureCodedStore` into
   `Pool::put_with_receipt` and `Pool::get` so that EC objects consume
   placement receipts. Expected write set: `crates/tidefs-pool/`,
   `crates/tidefs-erasure-coded-store/` (API changes only).

2. **EC-store placement planner integration**: Replace the local
   `compute_shard_to_store()` identity fallback with consumption of
   placement-planner output for all EC store paths. Expected write set:
   `crates/tidefs-erasure-coded-store/`, `crates/tidefs-placement-planner/`
   (API extensions).

3. **EC-store repair-with-receipt integration**: Wire
   `ErasureCodedStore::repair_shard()` into `Pool::repair_with_receipt` so
   that pool-level repair dispatches to the EC store's per-shard repair
   primitive. Expected write set: `crates/tidefs-pool/`,
   `crates/tidefs-erasure-coded-store/`.

4. **Recovery loop orchestrator**: Implement the recovery loop described in
   `ERASURE_CODING_PLACEMENT_DESIGN.md` section 5: member-failure stripe
   enumeration, TideCRUSH re-placement, repair job dispatch, and throttling.
   Expected write set: new crate or
   `crates/tidefs-recovery-orchestrator/`, `crates/tidefs-erasure-coded-store/`
   (repair primitive).

5. **EC profile catalog registration**: Register the erasure family catalog
   profiles (`EC-4+2`, `EC-8+3`, etc.) as compile-time records consumable by
   the placement planner and receipt system. Expected write set:
   `crates/tidefs-replication-model/` (profile records),
   `crates/tidefs-erasure-coded-store/` (profile consumption).

6. **Background scrub for EC**: Implement the periodic scrub cycle described
   in `ERASURE_CODING_PLACEMENT_DESIGN.md` section 5.1 trigger 2: enumerate
   stripes, verify shard checksums, enqueue repair. Expected write set:
   `crates/tidefs-erasure-coded-store/` (scrub entry point), new or existing
   background task infrastructure.

7. **Erasure read path stress and validation**: Validate the degraded-read
   path, multi-stripe reconstruction, shard-digest verification, and repair
   queue under concurrent read/write workloads. Expected write set: tests
   in `crates/tidefs-erasure-coded-store/`, possibly
   `validation/erasure-coded-store/`.

## Non-Decisions

These questions are explicitly deferred; they are not answered by this
authority document and should be raised as design or investigation issues
before implementation depends on them:

- Whether to add an async encode queue (deferred pending throughput
  benchmarks).
- Whether TideCRUSH placement should be cached or computed per-read (open
  question 1 in `ERASURE_CODING_PLACEMENT_DESIGN.md`).
- Whether the recovery loop uses cooperative or preemptive scheduling (open
  question 3).
- Whether the erasure profile catalog should be compile-time or runtime
  (open question 4).
- Whether EC-2+1 should use the XOR optimization path (open question 2; the
  GF(2^8) engine already dispatches to XOR for single parity).

## References

- `docs/ERASURE_CODED_LAYOUT_OW306.md` — XOR single-parity layout model
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` — TideCRUSH and recovery loop design
- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` — receipt authority model
- `docs/workspace-package-classification.md` — crate classification
- `crates/tidefs-erasure-coded-store/` — current EC store runtime
- `crates/tidefs-erasure-coding/` — RS engine
- `crates/tidefs-replication-model/` — EC profile, policy, and durability model
- GitHub issue #748 — this authority decision
