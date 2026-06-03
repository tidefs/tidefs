# allocator / reclaim / free-space schema family `P2-02` (v0.311)

This document settles the production storage allocator family for tidefs.

It is the source-of-truth for how the live system owns, allocates, frees, relocates, and reclaims physical space across:
- Rust userspace policy_authority/posix_filesystem_adapter/block_volume_adapter runtimes,
- future Rust-for-Linux adapter and kernel-family deployments,
- reserve-protected authority state,
- charter-serving data state,

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`

## 1. Decisive design choices

The allocator is no longer allowed to be vague.
The production system uses the following fixed structural choices:

1. **Segmented extent allocator with publication-aware delayed free**
   - all physical bytes belong to a segment class and segment
   - allocations return physical extents inside segments
   - frees become reusable only after publication / fence conditions make them safe

2. **Authority-first reserve law**
   - allocator admission is subordinate to claim/reserve law
   - reclaim runs before protected reserve floors are violated

3. **Authoritative free state is simple; performance indexes are rebuildable**
   - authoritative free-space truth is:
     - segment state + counters
     - by-offset free runs
     - pending-free records
     - allocation commits / relocation receipts
   - by-size heaps, victim score queues, and shard hot summaries are runtime mirrors only

4. **No in-place compaction**
   - reclaim is copy-forward relocation into fresh extents followed by segment drain
   - this keeps successor/publication law aligned with storage movement law

5. **One schema family for userspace and future kernel space**
   - Rust userspace and Rust-for-Linux variants share the same record families and allocator law
   - only runtime ownership, queueing, and memory mechanics differ

6. **Volume / block export is not special sovereignty**
   - `block_volume_adapter` uses dedicated segment classes and stricter alignment/fragmentation rules
   - it still consumes the same allocator family and the same reserve law

## 2. Storage unit hierarchy

### 2.1 Fundamental units

- **grain**: 4 KiB
  - minimum accounting and checksum unit
  - minimum free-run split/merge unit

- **extent**
  - contiguous run of grains inside one segment
  - returned by the allocator
  - may be grouped into replica/parity sets by higher layers

- **segment**
  - fixed-size allocation/reclaim unit
  - one segment belongs to exactly one segment class and one storage region
  - reclaim acts on segments, not arbitrary scattered extents

- **storage region**
  - contiguous slice of a device assigned to one region class
  - provides placement and reserve isolation

- **allocator shard**
  - runtime authority over a subset of segment classes / regions
  - used to partition locks, queues, reclaim work, and hot summaries

### 2.2 Initial segment classes

The design is definitive about the *family* and the initial required classes.
Sizes remain part of `SegmentClassRecord`, so future additional classes do not require a structural redesign.

| Segment class | Default size | Primary use | Reclaim posture |
|---|---:|---|---|
| `seg.authority.log` | 8 MiB | publication records, receipts, tickets, fences | highest protection, fastest drain |
| `seg.authority.state` | 32 MiB | authoritative ledgers, roots, domain state | highly protected |
| `seg.data.general` | 32 MiB | general file/object data | normal cleaner path |
| `seg.data.large` | 128 MiB | large sequential object/blob data | throughput-biased |
| `seg.block.volume` | 32 MiB | block/volume data with low-fragmentation target | alignment-strict, low-fragmentation reclaim |
| `seg.product.hot` | 16 MiB | hot rebuildable products | reclaim early |
| `seg.product.cold` | 64 MiB | colder product materializations | reclaim early |
| `seg.rebuild.scratch` | 32 MiB | relocation / rebuild scratch | escrow-backed and temporary |

### 2.3 Region classes

| Region class | Allowed segment classes | Reserve stance |
|---|---|---|
| `region.authority` | `seg.authority.*` | protected by reserve floors |
| `region.data` | `seg.data.*`, `seg.block.volume` | normal authority/data reserve rules |
| `region.rebuild` | `seg.rebuild.scratch` | escrow-backed temporary region |

A device may host several regions from different classes, but region-class boundaries are authoritative and may not be crossed by an allocation commit.

## 3. Authoritative record families

The allocator family introduces the following authoritative records.

| Record | Key fields | Role |
|---|---|---|
| `StorageDeviceRecord` | `device_id`, `fault_domain_id`, `capacity_bytes`, `logical_block_size`, `physical_block_size`, `trim_capable`, `zone_mode`, `region_root_ref` | authoritative device contract |
| `StorageRegionRecord` | `region_id`, `device_id`, `region_class`, `byte_offset`, `byte_length`, `allowed_segment_classes[]`, `reserve_floor_refs[]`, `policy_ref` | authoritative placement slice |
| `SegmentClassRecord` | `segment_class_id`, `segment_bytes`, `grain_bytes`, `min_run_grains`, `preferred_alignment_bytes`, `reclaim_policy_ref`, `allocation_bias_class`, `allowed_region_classes[]` | authoritative segment-class law |
| `SegmentRecord` | `segment_id`, `region_ref`, `segment_class_ref`, `state`, `byte_offset`, `live_grains`, `dead_grains`, `pending_free_grains`, `largest_free_run_grains`, `open_epoch_ref`, `seal_receipt_ref`, `retire_receipt_ref` | authoritative segment state |
| `PhysicalExtentRecord` | `extent_id`, `segment_ref`, `grain_offset`, `grain_count`, `content_class`, `checksum_ref`, `placement_class`, `replica_group_ref`, `live_refcount`, `birth_receipt_ref`, `death_receipt_ref` | authoritative physical extent identity |
| `FreeRunRecord` | `free_run_id`, `segment_ref`, `grain_offset`, `grain_count`, `next_by_offset_ref`, `prev_by_offset_ref`, `birth_receipt_ref`, `merge_epoch_ref` | authoritative reusable free range |
| `AllocatorShardRecord` | `allocator_shard_id`, `owned_region_refs[]`, `owned_segment_class_refs[]`, `free_run_root_refs[]`, `open_segment_refs[]`, `largest_run_summary`, `hot_summary_epoch`, `checkpoint_ref` | authoritative shard partition |
| `AllocationTicketRecord` | `allocation_ticket_id`, `domain_id`, `claim_ref`, `segment_class_ref`, `requested_bytes`, `alignment_bytes`, `escrow_refs[]`, `expiry`, `ticket_state`, `issuance_receipt_ref` | authoritative staged reservation |
| `AllocationCommitRecord` | `allocation_commit_id`, `allocation_ticket_ref`, `extent_refs[]`, `prepare_anchor_ref`, `publication_requirement_ref`, `orphan_sweep_policy_ref`, `commit_receipt_ref` | authoritative occupied-space commit |
| `PendingFreeRecord` | `pending_free_id`, `extent_ref`, `safe_after_publication_ref`, `safe_after_fence_ref`, `bytes_released`, `release_class`, `release_receipt_ref` | authoritative delayed-free state |
| `ReclaimDebtRecord` | `reclaim_debt_id`, `segment_ref`, `debt_class`, `target_reclaim_bytes`, `victim_score`, `reserve_pressure_ref`, `blocking_refs[]`, `issue_receipt_ref` | authoritative reclaim obligation |
| `RelocationIntentRecord` | `relocation_intent_id`, `source_segment_ref`, `target_segment_class_ref`, `live_extent_refs[]`, `escrow_ref`, `intent_state`, `issue_receipt_ref`, `commit_receipt_ref` | authoritative relocation / drain plan |
| `ReclaimCheckpointRecord` | `reclaim_checkpoint_id`, `allocator_shard_ref`, `checkpoint_epoch`, `segment_summary_root_ref`, `victim_set_digest`, `free_grains_total`, `pending_free_total`, `seal_receipt_ref` | authoritative allocator checkpoint |

## 4. Runtime mirrors and caches (non-authoritative)

These structures are allowed only as rebuildable runtime acceleration:

- `LargestRunHeap`
- `VictimScoreHeap`
- `OpenSegmentCursor`
- `SegmentHeatMap`
- `ShardHotSummaryCache`
- `ExtentLookupCache`
- `PendingFreeFrontierCache`
- `RegionPressureGauge`

If any of these are lost, the system must rebuild them from:
- `SegmentRecord`
- `FreeRunRecord`
- `AllocationCommitRecord`
- `PendingFreeRecord`
- `ReclaimDebtRecord`
- `ReclaimCheckpointRecord`

## 5. Allocation classes and reserve interaction

### 5.1 Allocation classes

| Allocation class | Default segment classes | Reserve / budget posture |
|---|---|---|
| `alloc.authority.publication` | `seg.authority.log` | protected reserve floor |
| `alloc.authority.state` | `seg.authority.state` | protected reserve floor |
| `alloc.data.general` | `seg.data.general`, `seg.data.large` | normal authority/data claim law |
| `alloc.block.volume` | `seg.block.volume` | strict alignment, low-fragmentation priority |
| `alloc.product.hot` | `seg.product.hot` | surplus-only |
| `alloc.product.cold` | `seg.product.cold` | surplus-only |
| `alloc.rebuild.scratch` | `seg.rebuild.scratch` | must be backed by reserve escrow |

### 5.2 Admission law

Allocation proceeds only if all are true:

1. the request has a valid `ClaimRecord` or other authorizing domain request,
2. the target class is allowed by policy,
3. reserve floors remain satisfiable after the admission,
4. any required escrow is already staged,
5. no cutover / failover / repair freeze forbids the target region.

If these are not all true, the allocator must:
- deny,
- trigger reclaim,
- degrade products,
- or require operator/override action,

but it may **not** silently trespass into protected reserve or another region class.

## 6. Allocation path algorithms

### 6.1 `choose_segment_class_for_claim()`
Inputs:
- allocation class
- size hint
- sequential/random hint
- volume / alignment hint
- policy refs

Outputs:
- chosen `segment_class_id`
- fallback class set
- minimum alignment
- reclaim sensitivity class

### 6.2 `quote_and_stage_allocation_ticket()`
Inputs:
- claim ref
- requested bytes
- chosen segment class
- reserve / escrow state
- shard summaries

Outputs:
- `AllocationTicketRecord`
- denial receipt
- optional reclaim trigger

Rules:
- tickets expire if not committed
- tickets reserve accounting headroom, but reusable bytes do not move until commit
- tickets may be batched for one publication prepare set

### 6.3 `allocate_free_runs_from_shard()`
Inputs:
- allocation ticket
- allocator shard
- open segments
- free-run trees

Outputs:
- selected `FreeRunRecord` slices
- optional new open segment
- optional reclaim trigger

Rules:
- first try open segment of the selected class
- then sealed segment with a sufficiently large free run
- then free segment promotion to open
- then reclaim
- final policy is best-fit within class, locality-biased inside shard

### 6.4 `seal_allocation_commit()`
Inputs:
- allocation ticket
- written extent payloads
- prepare anchor ref
- future publication requirement

Outputs:
- `PhysicalExtentRecord` set
- `AllocationCommitRecord`
- updated `SegmentRecord` / `FreeRunRecord` state
- commit receipt

Rules:
- commit makes bytes occupied immediately
- commit does not by itself free superseded extents
- commit records the orphan-sweep policy if later publication never happens

### 6.5 `materialize_pending_frees_after_publication()`
Inputs:
- publication receipt / fence frontier
- pending free set
- segment summaries

Outputs:
- released `FreeRunRecord`s
- updated segment counters
- release receipts

Rules:
- no free space becomes reusable until safe-after conditions are satisfied
- release merges adjacent free runs by offset
- largest-run summaries update from authoritative by-offset truth

### 6.6 `score_reclaim_victims()`
Inputs:
- shard summaries
- segment live/dead ratios
- pending-free backlog
- reserve pressure
- product/service floor state

Outputs:
- `ReclaimDebtRecord` set
- ordered victim candidates

Victim score favors:
- high dead bytes
- low live bytes
- low authority criticality
- low service-floor dependence
- low fence-blocking / escrow dependency

### 6.7 `relocate_live_extents_and_drain_segment()`
Inputs:
- relocation intent
- live extents
- target class
- reserve escrow
- publication/fence state

Outputs:
- new extent commits
- pending frees for previous extents
- drained or retired source segment

Rules:
- relocation itself uses normal allocation commits
- source segment can retire only after all previous extents become safely free
- rebuild-scratch allocations must be released when the relocation closes

### 6.8 `reconcile_allocator_shard_checkpoint()`
Inputs:
- segment records
- free runs
- commits
- pending frees
- reclaim debts

Outputs:
- `ReclaimCheckpointRecord`
- corrected hot summaries
- divergence finding if replay sees impossible state

## 7. Orphan, crash, and replay law

The allocator must stay correct across crash / replay boundaries.

### 7.1 Tickets
- expired tickets without commits are dropped
- their headroom reservation vanishes with no free-space mutation

### 7.2 Commits without publication
- `AllocationCommitRecord` is real occupied space
- if later replay proves no publication path can still reference it, it becomes orphan reclaim input
- orphaned commits are turned into `PendingFreeRecord`s by replay / sweep law, never by silent disappearance

### 7.3 Pending frees
- pending frees survive crashes
- replay recomputes whether their publication/fence prerequisites are now satisfied
- only then are free runs reinserted

### 7.4 Reclaim checkpoints
- checkpoints are summaries, not sovereignty
- replay may rebuild them from authoritative allocator records

## 8. Userspace and kernel runtime consequences

### 8.1 Userspace policy_authority / posix_filesystem_adapter / block_volume_adapter — continuity: Policy Authority (`policy_authority`), POSIX Filesystem Adapter (`posix_filesystem_adapter`), Block Volume Adapter (`block_volume_adapter`)

Required runtime subsystems:
- `AllocatorShardService`
- `OpenSegmentService`
- `FreeRunTree`
- `ReclaimPlanner`
- `RelocationWorker`
- `PendingFreeFrontierService`
- `AllocatorReplayService`

Thread / queue split:
- per-shard allocation workers
- background reclaim workers
- relocation copy workers
- checkpoint / replay workers

### 8.2 Kernel variants

Future kernel variants must preserve the same allocator family while changing only runtime mechanics:
- per-CPU or per-node hot summaries may exist, but are mirrors only
- `bio` / folio / DMA pinning may affect staging buffers, not allocator truth
- kernel fast paths may not invent private free-space state

## 9. Rust module / crate map

The allocator family should map to these Rust components:

- `tidefs-claim_reserve_witness-space-model`
- `tidefs-claim_reserve_witness-space-alloc`
- `tidefs-claim_reserve_witness-space-reclaim`
- `tidefs-claim_reserve_witness-space-replay`
- `tidefs-claim_reserve_witness-space-observe`
- future kernel counterpart:
  - `tidefs-kspace-space`


This subsystem is not "done" unless the production test plan eventually includes all of these families:

1. allocator property tests
   - split/merge correctness
   - no overlapping extents
   - no negative free space

2. replay / crash tests
   - ticket expiry
   - orphan commit sweep
   - pending-free replay

3. reserve pressure tests
   - protected reserve never violated
   - products denied/reclaimed first

4. reclaim tests
   - segment drain correctness
   - no lost live extent under relocation

5. block export tests
   - block_volume_adapter aligned allocation / fragmentation control

6. distributed tests
   - failover / repair / fence backlog interacting with pending free and escrow

## 11. Completion effect on the production ledger

This pass is intended to move:
- **`P2-02` from L1 to L3**


It should also sharpen, but not yet fully close:
- the explicit `memory_arena_0` memory-domain / arena / ownership-token law in `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`
- `P4-03` pressure / reclaim / reserve interaction
- `P6-02` block flush / discard / durability law
- `P8-03` replication / relocation data flows
