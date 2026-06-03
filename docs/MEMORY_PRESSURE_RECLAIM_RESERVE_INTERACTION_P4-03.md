# memory pressure / reclaim / reserve interaction (P4-03) (v0.313)

This document is the production-depth source-of-truth for how tidefs reacts when live memory demand, dirty backlog, pin pressure, and reserve obligations collide.

It answers the question:

**How does a live tidefs system decide what to reclaim, what to flush, what to throttle, what to degrade, and what to protect when memory pressure rises, without letting products or adapters silently eat authority reserve?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md`
- `docs/ALLOCATOR_RECLAIM_FREE_SPACE_SCHEMA_FAMILY_P2-02.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## Metrics snapshot

| Metric | Count |
|---|---:|
| Pressure signal families | 8 |
| Pressure stages | 6 |
| Protected reserve classes | 5 |
| Action families in the reclaim plan | 9 |
| New runtime / governance schema families introduced here | 9 |
| New algorithm families introduced here | 9 |
| Operator truth / alert classes introduced here | 6 |
| Test / stress campaign families introduced here | 7 |

## 1. Non-negotiable rules

1. **Protected reserve floors outrank cache warmth and product usefulness.**
   If pressure threatens publication, repair, relocation, cutover, or pinned-byte reserve floors, reclaim must first cut product/runtime service before protected floors are touched.

2. **Dirty memory is not evictable memory.**
   Dirty windows must transition through explicit drain/flush/publication state machines. “Drop dirty cache under pressure” is forbidden.

3. **Pins and DMA loans are pressure obligations, not invisible debt.**
   Pinned bytes, bio payload loans, and DMA-safe mappings must be accounted for explicitly and may force throttle/freeze stages.

4. **Pressure response is staged, not ad hoc.**
   A live system moves through named pressure stages and emits receipts/telemetry when crossing them.

5. **Authority-serving domains degrade last.**
   `memory_domain_0`, `memory_domain_1`, `memory_domain_2`, `memory_domain_6`, and `memory_domain_7` are protected by reserve classes. `memory_domain_4` and `memory_domain_5` yield first, then `memory_domain_3`, then selected parts of `memory_domain_1`.

6. **Userspace and kernel variants obey the same logical law.**
   The mechanics differ (RSS/memcg/shrinkers/folios), but the pressure stages, reserve classes, and action order stay the same.

7. **Pressure truth must be operator-visible.**
   If the system denies admissions, degrades products, or freezes charters because of pressure, operators must be able to see exactly which reserve class or pressure source forced that behavior.

## 2. Pressure signal families

A pressure controller instance always consumes a canonical signal set.

### `sig0.domain_resident_bytes`
Resident bytes per memory domain and per cache class.

### `sig1.dirty_backlog_bytes`
Dirty bytes per dirty-state family plus writeback queue depth and oldest-dirty age.

### `sig2.pin_loan_bytes`
Pinned folio/page bytes, DMA loan counts, bio payload loan bytes, and uninterruptible kernel pin counts.

### `sig3.reserve_floor_threat`
How close each protected reserve class is to violation.

### `sig4.allocation_stall_rate`
Recent allocation retries/failures by domain/class, including `GFP` pressure in-kernel and allocator stalls in userspace.

### `sig5.io_completion_lag`
Completion lag for writeback, relocation, flush/FUA, and publication-adjacent IO.

### `sig6.product_service_pressure`
How much of current memory is charter-serving product floor vs discretionary product surplus.

### `sig7.external_pressure_hint`
External signals such as memcg pressure, reclaim callbacks, cgroup OOM warning, failover freeze request, or operator-imposed emergency limit.

## 3. Pressure stages

The pressure controller operates in one named stage at a time.

| Stage | Meaning | Typical action posture |
|---|---|---|
| `pressure_stage_0.steady` | healthy headroom | normal admission, background compaction only |
| `pressure_stage_1.warm` | rising pressure | early compact/evict on surplus classes, no user-visible degrade |
| `pressure_stage_2.active_reclaim` | sustained pressure | reclaim `memory_domain_5`/`memory_domain_4` aggressively, compact `memory_domain_3`, begin product ratchet |
| `pressure_stage_3.hard_throttle` | authority-adjacent pressure | throttle new dirtying ops, slow product refresh, force dirty drain |
| `pressure_stage_4.reserve_protect` | protected reserve threatened | deny new discretionary admissions, freeze nonessential product growth, force pin/dirty drain |
| `pressure_stage_5.emergency_freeze` | imminent reserve violation / unrecoverable pin pressure | stop discretionary work, hold selected adapters, allow only reserve-recovery / publication / failover-safe drains |

- reclaim target was met,
- dirty backlog fell below stage thresholds,
- reserve threat cleared,
- and pins/loans are back within the allowed envelope.

## 4. Protected reserve classes

Memory pressure must honor these named reserve classes.

| Reserve class | Protected domains | Purpose |
|---|---|---|
| `memory_reserve_0.publication_hot` | `memory_domain_0`, `memory_domain_1`, `memory_domain_2` | enough hot memory to finish in-flight publication and seal receipts |
| `memory_reserve_1.repair_relocation` | `memory_domain_6` plus selected `memory_domain_2` | enough working set to complete repair / relocation already admitted |
| `memory_reserve_2.failover_cutover` | `memory_domain_1`, `memory_domain_5`, `memory_domain_7` | enough memory to freeze, hand off, and emit cutover/failover receipts |
| `memory_reserve_3.pinned_dma_floor` | `memory_domain_7` | enough safe headroom around pinned/DMA bytes to avoid deadlocking IO progress |

These floors are policy-governed and may vary by deployment class, but they are never optional.

## 5. Pressure-controller records

### `PressureControllerPolicyRecord`
Authoritative declaration of thresholds, reserve classes, stage transitions, and denial/degrade policies.

Fields:
- `pressure_policy_id`
- `policy_revision_ref`
- `memory_domain_refs[]`
- `signal_threshold_table_ref`
- `reserve_floor_refs[]`
- `stage_transition_table_ref`
- `deny_policy_ref`
- `degrade_policy_ref`
- `operator_visibility_policy_ref`

### `PressureWatermarkRecord`
Canonical stage thresholds for one domain/class/signal tuple.

### `DomainPressureStateRecord`
Runtime mirror of per-domain resident/dirty/pinned/evictable bytes, hottest offenders, and current stage contribution.

### `ReclaimActionPlanRecord`
One planned reclaim cycle: target bytes, ordered actions, stop conditions, and receipts it must emit.

### `PressureThrottleTicketRecord`
Typed throttle / denial record issued to adapters, products, or worker pools under `pressure_stage_3+`.

### `DirtyDrainIntentRecord`
An explicit intent to drain dirty windows for one class/range/fence requirement under pressure.

### `PinDrainIntentRecord`
An explicit intent to drain pinned pages/folios/DMA loans before stage downgrade or failover/cutover.

### `ReserveThreatReceipt`
Canonical receipt that a reserve class entered or exited threat state.

### `PressureEscalationReceipt`
Canonical receipt for stage transition, freeze activation, or recovery downgrade.

## 6. Canonical control loop

### 6.1 Sample and classify
1. collect the full signal vector (`sig0..sig7`)
2. update `DomainPressureStateRecord` mirrors
3. evaluate each reserve class against configured floors
4. classify the global stage (`pressure_stage_0..pressure_stage_5`)
5. emit `PressureEscalationReceipt` when the stage changes

### 6.2 Compute reclaim targets
For the current stage, compute:
- target bytes to reclaim by domain/class
- dirty bytes that must drain to permit downgrade
- pin bytes that must be released
- admissions that must be denied or throttled
- products that must ratchet, degrade, or reclaim

### 6.3 Build the reclaim action plan
`ReclaimActionPlanRecord` is ordered.
The default order is:
1. compact / reclaim `memory_domain_5.observe_hot`
2. reclaim `memory_domain_4.product_serving`
4. ratchet or pause product refreshes/service floors
5. force dirty-window sealing and drain from `memory_domain_2`
6. compact low-priority `memory_domain_1.authority_mutable_hot` mirrors that are rebuildable
7. drain page loans / DMA pins / queue windows (`memory_domain_7`)
8. if needed, deny new dirtying admissions / freeze selected adapters
9. if still needed, enter `pressure_stage_5.emergency_freeze`

### 6.4 Execute and verify
After each action group:
- resample signals
- verify reserve threat class
- stop when targets are satisfied
- if not satisfied and action plan is exhausted, escalate stage and emit receipts

## 7. Reclaim and degrade law by domain

### `memory_domain_5.observe_hot`
- reclaim first
- compact aggressively
- only replay/falsifier-required fragments survive deep pressure

### `memory_domain_4.product_serving`
- reclaim second
- obey product family reclaim priority and service-floor rules
- product service may degrade before any protected reserve is touched

### `memory_domain_3.adapter_serving_hot`
- reclaim third
- adapters must fall back to slower rehydrate paths rather than keeping hidden sovereignty

### `memory_domain_2.staging_dirty`
- never hard-evict
- must drain via `DirtyDrainIntentRecord`
- drain ordering respects charter and durability constraints

### `memory_domain_1.authority_mutable_hot`
- compact cautiously
- only rebuildable mutable mirrors may shrink
- hot domain/lease/epoch / publication-coordination state remains protected

### `memory_domain_0.authority_immutable`
- immutable sealed truth
- not pressure-victim except by lawful retirement / archive movement

### `memory_domain_6.rebuild_relocation_temp`
- governed by repair/relocation reserve classes
- may shrink only if corresponding repair/relocation law allows abort or staged rollback

### `memory_domain_7.kernel_pinned_dma`
- not evictable
- only drains through explicit release of loans, DMA completions, queue-drain, or pin-release law

## 8. Dirty drain and pin drain law

### Dirty drain
A dirty drain may be triggered by:
- `pressure_stage_3+`
- reserve threat to `memory_reserve_0` or `memory_reserve_1`
- failover/cutover preparation
- operator pressure override

Dirty drain ordering:
1. low-value product-backed dirtied cache windows
2. posix_filesystem_adapter buffered writeback windows with no strict fence urgency
3. block_volume_adapter queue/range windows without FUA
4. publication payload windows only as allowed by publication ordering

A dirty drain is successful only when:
- required writeback fence receipts are emitted
- required publication receipts or durability receipts exist
- corresponding dirty windows transition to a clean or retired state

### Pin drain
Pin drain must run when:
- `memory_reserve_3.pinned_dma_floor` is threatened
- failover/cutover is in progress
- memcg/global pressure says pinned bytes are blocking reclaim

Pin-drain actions include:
- quiesce queue windows
- complete or abort eligible IO
- revoke low-priority registered-buffer pools
- force workers to return page loans
- delay new large IO admissions until pins fall below threshold

## 9. Adapter and charter consequences

### POSIX Filesystem Adapter (posix_filesystem_adapter continuity)
- under `pressure_stage_3+`, new dirtying writes may be throttled or short-admitted
- under `pressure_stage_4+`, discretionary mmap/page-cache growth is denied
- under `pressure_stage_5`, only drain/flush/publication-safe operations continue
- adapters must surface pressure-denial truth via canonical response classes; no private “try later” folklore

### Block Volume Adapter (block_volume_adapter continuity)
- queue admission, registered buffers, and outstanding range windows are pressure-accounted
- FUA/flush work keeps priority under `memory_reserve_0` / `memory_reserve_3`
- large write/discard/zero admissions may be throttled or denied under `pressure_stage_4+`

### Control Plane (control_plane continuity)
- control-plane reads continue unless global emergency freeze says otherwise
- control-plane writes that increase pressure or product service may be denied under `pressure_stage_4+`

### Explanation Query (explanation_query continuity)
- explanation_query answers may degrade in freshness/service class under `pressure_stage_2+`
- at `pressure_stage_4+`, only fields whose service floor still survives may continue to materialize hot product state

## 10. Userspace and kernel implementation split

### Userspace Rust
Pressure sources:
- RSS / allocator stats
- memcg pressure signals if available
- worker queue backlog
- writeback lag
- registered-buffer usage

Planned crate families:
- `tidefs-mem-pressure-types`
- `tidefs-mem-pressure-core`
- `tidefs-posix_filesystem_adapter-pressure`
- `tidefs-block_volume_adapter-pressure`
- `tidefs-product-pressure`

### Kernel Rust-for-Linux
Pressure sources:
- memcg reclaim callbacks
- shrinkers
- folio/page reclaim pressure
- workqueue backlog
- bio/request queue depth
- pinned folio / DMA map counts

Kernel modules must preserve the same stage/reserve/action law, with kernel-native mechanics only.

## 11. Operator surfaces and truth

The live system must expose pressure truth through named operator surfaces.

Required surface families:
- `pressure stage now`
- `reserve class threat now`
- `top victim cache/product classes`
- `dirty drain backlog`
- `pin/loan backlog`
- `denials / throttles / freezes by charter`

Operator-facing receipts and summaries must reference:
- `PressureEscalationReceipt`
- `ReserveThreatReceipt`
- `PressureThrottleTicketRecord`
- `ReclaimActionPlanRecord`

## 12. Test / stress requirements


Required campaign families:
1. memcg/global-pressure eviction ordering
2. dirty-backlog pressure with concurrent publication
3. pin/loan drain under heavy `block_volume_adapter` queue load
4. pressure + failover/cutover overlap
5. product-service ratchet under reserve threat
6. emergency-freeze recovery and downgrade correctness
7. operator-truthfulness / alert fidelity

## 13. Anti-regression rules

- no future implementation may say “we reclaim under memory pressure” without naming the pressure stage and reserve class
- no adapter may keep a private pressure policy
- no product may keep a hidden service floor outside the declared policy/budget law
- no dirty bytes may become silently droppable under pressure
- no pinned-byte growth may remain unaccounted-for

## 14. Production implementation consequences

The next implementation tasks must treat pressure control as a first-class service family, not as a few callbacks sprinkled around caches.

The first future planning work should therefore expect dedicated modules for:
- pressure signal collection
- pressure stage classification
- reclaim plan building
- dirty drain orchestration
- pin/loan drain orchestration
- charter-facing throttle / denial rendering
