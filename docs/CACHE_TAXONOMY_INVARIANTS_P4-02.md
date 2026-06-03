# cache taxonomy and invariants (P4-02) (v0.312)

This document is the production-depth source-of-truth for the tidefs cache lattice.

It answers the question:

**What caches, mirrors, writeback states, and memory-owned runtime structures are allowed to exist in a live tidefs system, and what must they never be allowed to become?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `docs/ALLOCATOR_RECLAIM_FREE_SPACE_SCHEMA_FAMILY_P2-02.md`
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`

## Metrics snapshot

| Metric | Count |
|---|---:|
| Named memory domains | 8 |
| Named cache classes | 9 |
| Mandatory cache invariants | 18 |
| Dirty / writeback state machines | 3 |
| Userspace-kernel split points | 6 |
| New runtime schema families introduced here | 8 |
| New algorithm families introduced here | 7 |

## 1. Non-negotiable rules

1. **No cache is authoritative truth.**
   If losing a structure changes legal publication truth, reserve safety, or repair truth, that structure is misclassified and belongs in authority state, not in a cache.

2. **Every cache entry is anchor-bound.**
   Every entry must carry enough authority anchors, freshness-fence refs, and policy revision refs to prove what truth epoch it reflects.

3. **Every cache class is budgeted.**
   Caches and runtime mirrors live under named memory domains and budget domains; they may not silently borrow protected reserve.

4. **Dirty state is explicit.**
   Any mutable cached bytes that can affect publication, writeback, or charter-visible answers must live inside a named dirty-window state machine.

5. **Products and caches are distinct.**
   Product instances are governed by recipe/service-floor law. Caches are runtime memory structures. Some product instances may be served *through* caches, but cache admission does not mint product authority.

6. **Userspace and kernel variants share the same logical cache law.**
   Only mechanics differ: allocation primitives, pinning mechanics, page ownership, and queue APIs.

7. **Every cache class has an eviction law and a poison law.**
   “Keep it until OOM” is forbidden.

8. **No adapter may hide sovereignty in an adapter-local cache.**
   posix_filesystem_adapter, block_volume_adapter, control_plane, and explanation_query may keep mirrors and accelerators, but they may not keep the only copy of policy/admission/exactness/freshness truth.

## 2. Memory domains

Memory domains are not just “arenas.” They are the accounting and reclaim boundaries that runtime caches must obey.

### `memory_domain_0.authority_immutable`
For sealed canonical requests, receipts, authority anchors, witness summaries, and replay-safe immutable blobs.

- reclaim class: last resort, only by reference-counted retirement
- allocation sources:
  - userspace: sealed slab arenas plus file-backed object stores
  - kernel: kmalloc/slab plus immutable folio-backed buffers
- reserve interaction: protected reserve eligible

### `memory_domain_1.authority_mutable_hot`
For hot mutable authority-adjacent state:
- head/root lookup mirrors
- domain/lease/epoch current-state mirrors
- inflight publication metadata

- reclaim class: tightly bounded, shrink only after state is checkpointed or mirrored elsewhere
- reserve interaction: protected reserve eligible

### `memory_domain_2.staging_dirty`
For mutable dirty windows and publication/writeback staging.

Contains:
- posix_filesystem_adapter dirty file-page windows
- block_volume_adapter dirty range windows
- publication-side prepared successor payload staging
- relocation-copy staging

- reclaim class: cannot evict blindly; must flush, abort, or compact through state machines
- reserve interaction: protected reserve eligible up to declared floors

### `memory_domain_3.adapter_serving_hot`
For hot charter-serving mirrors:
- posix_filesystem_adapter path/dentry/inode mirrors
- posix_filesystem_adapter handle and dir-stream mirrors
- block_volume_adapter logical-to-extent and queue mirrors

- reclaim class: high-pressure reclaimable
- reserve interaction: no protected reserve borrowing

### `memory_domain_4.product_serving`
For explanation_query and other product-serving caches:
- answer fragments
- locality-serving summaries
- planning/ranking mirrors
- witness-assist hot fragments

- reclaim class: reclaim before touching protected reserve floors
- reserve interaction: declared surplus only

### `memory_domain_5.observe_hot`

- reclaim class: aggressive compact/reclaim allowed

### `memory_domain_6.rebuild_relocation_temp`
For rebuild/recovery/repair temporary working sets and relocation buffers.

- reclaim class: bounded by explicit repair/rebuild reserve classes
- reserve interaction: protected reserve eligible only through explicit reserve escrow

### `memory_domain_7.kernel_pinned_dma`
For kernel-only pinned folios/pages, DMA-safe mappings, bio payloads, and outstanding page loans.

- reclaim class: not directly reclaimable; must drain via loan/pin release law
- reserve interaction: protected reserve eligible only through pinned-byte budgets and explicit pressure telemetry

## 3. Cache taxonomy

Each class has a fixed design rule role.

| Class | Memory domain | Purpose | Authority relation | Reclaim priority |
|---|---|---|---|---:|
| `cutover_control_0.authority_read_mirror` | `memory_domain_0`, `memory_domain_1` | immutable revision/facet/head/policy read acceleration | mirror only | 6 |
| `cutover_control_1.publication_staging` | `memory_domain_2` | prepared successor and receipt staging | authority-adjacent but not sealed truth | 9 |
| `cutover_control_2.allocator_hot_summary` | `memory_domain_1`, `memory_domain_6` | free-run heaps, shard summaries, reclaim victim queues | rebuildable mirror over allocator truth | 7 |
| `cutover_control_3.posix_filesystem_adapter_namespace_mirror` | `memory_domain_3` | path/dentry/inode/xattr/dir-cookie mirrors | adapter mirror only | 5 |
| `cutover_control_4.posix_filesystem_adapter_page_writeback` | `memory_domain_2`, `memory_domain_3` | buffered file data, mmap/writeback windows | charter-serving dirty cache | 8 |
| `cutover_control_5.block_volume_adapter_mapping_queue` | `memory_domain_2`, `memory_domain_3`, `memory_domain_7` | LBA->extent mirrors, request windows, completion mirrors | charter-serving dirty/cache hybrid | 8 |
| `cutover_control_6.product_runtime` | `memory_domain_4` | explanation_query answer fragments, locality/planning/witness-assist fragments | product-serving only | 3 |
| `cutover_control_8.session_fence` | `memory_domain_1`, `memory_domain_5` | transport/session/cohort/fence mirrors | runtime mirror over distributed truth | 4 |

Reclaim priority is ordinal only: higher means “protect longer.” It does **not** override reserve floors or dirty-state law.

## 4. Entry-header law

Every cache entry, regardless of class, carries a common header family.

### Mandatory header fields
- `cache_class_id`
- `memory_domain_id`
- `entry_key_digest`
- `anchor_vector_ref`
- `freshness_fence_vector_ref`
- `policy_revision_ref`
- `exactness_class`
- `freshness_class`
- `budget_domain_ref`
- `reserve_guard_class`
- `dirty_state_class`
- `entry_size_bytes`
- `birth_counter`
- `last_hit_counter`
- `rebuild_cost_class`
- `evictability_class`
- `poison_state`

### Header invariants
1. Entries without an anchor vector may not claim exact or freshness-bounded answers.
2. Entries in `memory_domain_2.staging_dirty` must have a non-`clean` dirty state.
3. Entries claiming `exactness.exact` must name the publication receipt or projection-root receipt they reflect.
4. Entries lacking a budget domain are invalid except in explicitly exempt tiny bootstrap classes.
5. Poisoned entries may be served only if the charter allows degraded-but-valid behavior and the response envelope says so.

## 5. Dirty / writeback state machines

### 5.1 `dirty_writeback_0.posix_filesystem_adapter.writeback` — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)
For buffered posix_filesystem_adapter file data and mmap-backed dirty pages.

States:
- `clean`
- `dirty_open`
- `dirty_sealed`
- `writeback_inflight`
- `publication_wait`
- `clean_published`
- `error_poisoned`

Allowed transitions:
- `clean -> dirty_open`
- `dirty_open -> dirty_sealed`
- `dirty_sealed -> writeback_inflight`
- `writeback_inflight -> publication_wait`
- `publication_wait -> clean_published`
- any state -> `error_poisoned` on unrecoverable writeback/publication mismatch

### 5.2 `dirty_writeback_1.block_volume_adapter.range_flush` — continuity: Block Volume Adapter (`block_volume_adapter`)
For block_volume_adapter dirty block windows and flush/FUA semantics.

States:
- `clean`
- `dirty_range`
- `flush_pending`
- `fua_pending`
- `durable_clean`
- `error_poisoned`

Rules:
- `FUA` may bypass long residency in `dirty_range`, but it still emits canonical receipts.
- flush/FUA completion must not claim durability until required authority/publication receipts and storage flush semantics are satisfied.

### 5.3 `dirty_writeback_2.publication_payload`
For payloads staged for successor publication or repair/relocation publication.

States:
- `prepared_unsealed`
- `sealed_ready`
- `publication_inflight`
- `receipt_issued`
- `retired`
- `error_poisoned`

Rules:
- `prepared_unsealed` payload may be abandoned without truth effect
- `receipt_issued` payload becomes immutable replay material until retention law says otherwise


### Admission law
Every admission checks:
1. class-level memory domain eligibility
2. budget-domain debit availability
3. reserve-floor impact
4. anchor/fence completeness
5. duplicate-key coexistence rules
6. dirty-state legality for the class

A read hit is legal only if:
- anchor vector is still within allowed frontier,
- policy revision is still compatible,
- required fence class is satisfied,
- and the charter allows the exactness/freshness classes carried by the entry.

### Eviction law
Eviction uses class-specific policy, but globally obeys:
1. reclaim `cutover_control_7` then `cutover_control_6` before touching protected reserve domains
2. reclaim `cutover_control_3` before `cutover_control_0` when reserve pressure is adapter-only
3. dirty classes (`cutover_control_1`, `cutover_control_4`, `cutover_control_5`) must drain through dirty-state transitions, not hard-evict
4. `memory_domain_7.kernel_pinned_dma` is not evicted; it is drained by pin/loan release

### Poison law
Entries become poisoned when:
- anchor mismatch cannot be reconciled,
- publication receipt contradicts staged payload,
- dirty window loses required writeback witnesses,
- or transport/session state violates fence progression.

Poisoned entries must emit observability signals and either:
- degrade via charter-visible response class, or

## 7. Userspace / kernel split points

### Split 1 — allocator backing
- userspace: arena/slab allocators plus mmap-backed large-object pools
- kernel: slab/folio allocators and page-pool style backing

### Split 2 — page cache
- userspace posix_filesystem_adapter: explicit page/writeback cache object family in tidefs
- kernel posix_filesystem_adapter: Linux folio/page-cache integration with tidefs metadata mirrors around it

### Split 3 — block queues
- userspace block_volume_adapter: queue windows and completion mirrors in process memory
- kernel block_volume_adapter: bio/request and request_queue-owned state

### Split 4 — pinned bytes
- userspace: registered buffers / io_uring fixed buffers / userspace DMA-safe pools if used
- kernel: pinned folios/pages and bio vectors via explicit pin tokens

### Split 5 — wait/notification model
- userspace: work-stealing pools, epoll/io_uring, bounded async queues
- kernel: workqueues, completions, wait queues, RCU-visible generation pointers

### Split 6 — memory pressure source
- userspace: self-observed RSS/arena pressure plus cgroup signals
- kernel: shrinkers, memcg pressure, page reclaim callbacks, folio pressure

## 8. Rust type and trait families

### Type families
- `MemoryDomainId`
- `CacheClassId`
- `CacheEntryKeyDigest`
- `AnchorVector`
- `FenceVector`
- `DirtyStateClass`
- `PoisonState`
- `BudgetDebitRef`
- `ReserveGuardClass`
- `WritebackWindowId`
- `PageLoanToken`
- `PinnedRangeToken`

### Trait / service families
- `CacheClassPolicy`
- `CacheAdmissionGate`
- `CacheValidator`
- `CacheEvictor`
- `DirtyWindowCoordinator`
- `WritebackReceiptBinder`
- `PageLoanBroker`
- `PressureSignalSource`
- `PressureResponsePlanner`
- `CacheObservabilityEmitter`

## 9. Canonical schema families introduced here

| Family | Role |
|---|---|
| `MemoryDomainRecord` | authoritative declaration of domain budgets, reserve eligibility, and reclaim class |
| `CacheClassRecord` | authoritative declaration of one cache class and its invariants |
| `CacheEntryHeaderRecord` | common header law for all cache entries |
| `CacheShardStateRecord` | runtime mirror for shard-local pressure, counters, and generation refs |
| `DirtyWindowRecord` | runtime record for mutable charter-serving dirty windows |
| `CacheAdmissionReceipt` | canonical admission/ejection/degrade receipt family |
| `MemoryPressureStateRecord` | runtime mirror of pressure inputs, reclaim stage, and reserve threat class |

## 10. Canonical algorithm families introduced here

| Algorithm | Purpose |
|---|---|
| `classify_memory_domain_for_allocation()` | chooses memory domain and reserve class for a new allocation |
| `admit_cache_entry_under_budget_and_fence()` | performs admission checks and emits admission receipts |
| `choose_cache_shard_and_generation()` | assigns the entry to a shard/generation domain |
| `seal_dirty_window_for_writeback_or_publication()` | transitions mutable windows into committed writeback/publication stages |
| `compact_or_evict_cache_class_under_pressure()` | executes class-aware reclaim and compaction |
| `drain_page_loans_and_pins_for_cutover_or_failover()` | releases non-evictable pinned/paged state before cutover/failover |

## 11. Production implementation consequences

### Userspace Rust
The first userspace implementation should have dedicated crates/modules for:
- cache type families
- memory domain / arena management
- dirty-window coordination
- posix_filesystem_adapter page/writeback caching
- block_volume_adapter range/queue caching
- pressure control

Suggested crate families:
- `tidefs-mem-types`
- `tidefs-cache-core`
- `tidefs-cache-pressure`
- `tidefs-posix_filesystem_adapter-cache`
- `tidefs-block_volume_adapter-cache`

### Kernel Rust-for-Linux
The future kernel variant should preserve the same logical class/domain law, while swapping mechanics:
- page cache and folios instead of userspace page slabs
- shrinkers / memcg pressure instead of userspace RSS pressure
- pin/loan tokens for folios/bios instead of userspace fixed-buffer handles

### Anti-regression rule
No future implementation may claim “we already have caches” unless it names:
- cache class,
- memory domain,
- admission law,
- dirty-state machine,
- eviction law,
- and observability fields.

If any of those are missing, the cache is not designed yet.
