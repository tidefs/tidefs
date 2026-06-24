# fault injection / chaos / corruption campaigns (P10-02) (v0.330)

This document is the source-of-truth for the production-depth fault-injection, chaos, corruption, and disaster-campaign law.

It answers the question:


See also:
- `docs/POSIX_CHARTER_TEST_XFSTESTS_MATRIX_P5-04.md`
- `docs/BLOCK_ACCEPTANCE_STRESS_HARNESS_MATRIX_P6-04.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md`
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `docs/FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md`
- `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`
- `docs/TRACES.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for break-and-prove work:

- one coordinating family: **`family.chaos_corruption.cutover_control_0`**
- one execution law: **`law.inject_observe_recover_gate.cutover_control_0`**
- one canonical proof chain for every serious fault or corruption campaign:
  - **fault catalog -> row binding -> hook binding -> schedule window -> workload/oracle pair -> observed state delta -> recovery/repair receipt set -> chaos artifact manifest -> failure bucket or gate receipt**

This means tidefs is no longer allowed to say only:
- “we crashed a node and it seemed fine”,
- “we flipped some bytes and recovery probably worked”,
- “the failover drill looked clean”,
- or “the soak test was noisy but green enough”.

It must instead say:
- which typed fault or corruption class was injected,
- which row id and subject family owned the proof obligation,
- which hook family and schedule window performed the injection,
- which workload and oracle pair made the fault meaningful,
- which legal outcomes were expected,
- which forbidden outcomes were checked explicitly,
- which recovery/repair receipts closed the row,
- and which gate receipt admitted, blocked, or forced rollback/cutover refusal.

The anti-regression rule is explicit:

**A fault campaign is never valid merely because a system kept running. It is valid only when the fault class, target selector, seed/schedule, recovery obligations, forbidden outcomes, and artifact contract are all declared and preserved.**

## 2. Scope and boundaries

This document governs:
- the typed fault and corruption catalog,
- the stable injection-hook families,
- the scheduler and seed/replay law,
- workload/oracle pairing rules,
- recovery and forbidden-outcome law,
- chaos-specific artifact classes and failure buckets,
- and the gate effects for smoke, quick, release, cutover, rollback, and soak/disaster profiles.

The adjacent secret/key-material lifecycle law is now explicit in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, the numeric KPI/SLO law is now explicit in `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`, and the operator truth-surface law is now explicit in `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`. This document still settles the production campaign grammar that those later items must obey.

## 3. Campaign family law

### 3.1 Matrix family and row shape

The detailed campaign matrix is now fixed as:
- **`matrix.chaos.corruption.cutover_control_0`**

Every concrete `cutover_control_0` row must declare at least:
- `fault_catalog_ref`
- `subject_family_ref`
- `target_selector_ref`
- `hook_binding_ref`
- `schedule_template_ref`
- `workload_family_ref`
- `oracle_binding_ref`
- `expected_legal_outcome_refs[]`
- `forbidden_outcome_refs[]`
- `required_recovery_receipt_class_refs[]`
- `required_artifact_class_refs[]`
- `gate_class_refs[]`

The anti-regression rule is explicit:

**No chaos row may exist as “inject something around this subsystem”. The fault class, target, expected legal outcomes, and forbidden outcomes must all be first-class fields.**

### 3.2 Minimum suite families

Tool names remain execution backends only.
The stable contract lives in named suite families.

The production design now requires these minimum `cutover_control_0` suite families:

1. **`suite.cutover_control_0.transport.time_clock_0`**
   - link pause, drop, reorder, latency, and partition faults

2. **`suite.cutover_control_0.process.time_clock_1`**
   - crash, restart, wipe, quiesce, and kill-before-ack faults

3. **`suite.cutover_control_0.storage_media.time_clock_2`**
   - bit-flip, truncation, stale-copy, zeroed-range, and flush-omission corruption

4. **`suite.cutover_control_0.time.time_clock_3`**
   - drift, heartbeat gaps, lease-expiry races, and stale-fence observations

5. **`suite.cutover_control_0.resource.time_clock_4`**

6. **`suite.cutover_control_0.charter_posix_filesystem_adapter.time_clock_5`**
   - Linux-facing `posix_filesystem_adapter` rows under injected faults while unit-test, FUSE smoke, and `xfstests` backends execute

7. **`suite.cutover_control_0.charter_block_volume_adapter.time_clock_6`**
   - Linux-facing `block_volume_adapter` rows under injected faults while block, guest-fs, and `fio`/raw-block backends execute

8. **`suite.cutover_control_0.runtime_cluster.time_clock_7`**
   - membership, failover, fence, rebuild, and handoff under transport/process/time faults

9. **`suite.cutover_control_0.shadow_cutover.time_clock_8`**
   - shadow parity, cutover admission, rollback, and re-entry while faults are active

10. **`suite.cutover_control_0.disaster.time_clock_9`**
    - paired-fault, cascading, and soak/disaster campaigns across longer windows

### 3.3 Current lab grounding rule

- cluster-link hooks for pause, drop, reorder, latency, and lane-budget pressure,
- cluster lifecycle hooks for crash, restart, and wipe,
- file-backed media corruption by in-place byte flip,
- deterministic trace fault ops,
- and storm/robustness scenarios that already combine these into real replayable exercises.

Future Rust userspace and future kernel-facing harnesses may replace implementation mechanics, but they may **not** replace these semantic hook families with a different bucket grammar or a different proof language.

## 4. Typed fault and corruption catalog

### 4.1 Transport and link faults

The mandatory transport fault classes are:
- `fi.transport.pause_link`
- `fi.transport.drop_next`
- `fi.transport.reorder_next`
- `fi.transport.latency_stretch`
- `fi.transport.bandwidth_clamp`
- `fi.transport.partition_bidir`

These faults are legal against distributed rows, shadow-pair rows, and cutover rows where message ordering or delivery matters.

Expected legal outcomes may include:
- delayed progress,
- leadership change,
- catch-up replay,
- explicit fencing,
- or gate refusal.

Forbidden outcomes include:
- split-brain publication,
- silent loss of committed authority state,
- hidden divergence between peers,
- or operator-visible truth that omits the active partition/fault state.

### 4.2 Process and runtime faults

The mandatory runtime fault classes are:
- `fi.process.crash_subject`
- `fi.process.restart_subject`
- `fi.process.wipe_local_state`
- `fi.process.quiesce_worker_group`
- `fi.process.kill_before_ack`

These faults apply to nodes, authorities, adapters, queue workers, and cutover participants.

Expected legal outcomes may include:
- explicit refusal before mutation,
- replay/restart recovery,
- rejoin with receipts,
- state transfer,
- or rollback/cutover block.

Forbidden outcomes include:
- durable success reported without replay-safe closure,
- stale lease/session survival after crash,
- silent queue loss,
- or resumed service without visible degraded state.

### 4.3 Storage-media and corruption classes

The mandatory corruption/media classes are:
- `cm.storage.bitflip.checkpoint`
- `cm.storage.bitflip.metadata`
- `cm.storage.bitflip.payload`
- `cm.storage.truncate_tail`
- `cm.storage.replay_stale_copy`
- `cm.storage.zeroed_range`
- `cm.storage.flush_omission`
- `cm.storage.partial_header`

Every corruption row must name:
- the target artifact family,
- the scope selector or offset class,
- the detection path,
- and the admissible recovery class.

Expected legal outcomes may include:
- checksum or envelope rejection,
- quarantine,
- scan fallback,
- lawful rebuild,
- repair publication,
- or operator-visible refusal.

Forbidden outcomes include:
- silent acceptance of corrupted bytes,
- mutated truth based on unverifiable artifacts,
- or replay that invents structure instead of quarantining it.

### 4.4 Time and coherence faults

The mandatory time/coherence fault classes are:
- `fi.time.drift_forward`
- `fi.time.drift_backward`
- `fi.time.heartbeat_gap`
- `fi.time.lease_expiry_race`
- `fi.time.stale_fence_view`

Expected legal outcomes may include:
- suspicion,
- re-election,
- explicit fence closure,
- degraded exactness/freshness render,
- or refusal pending recovery.

Forbidden outcomes include:
- dual leaders,
- stale writes admitted as current,
- hidden freshness lies,
- or override/session validity surviving an explicit time-health quarantine.


The mandatory resource/operator fault classes are:
- `fi.resource.mem_pressure`
- `fi.resource.reserve_floor_pressure`
- `fi.resource.queue_credit_exhaustion`
- `fi.operator.override_expiry_midflight`
- `fi.operator.policy_publish_conflict`

Expected legal outcomes may include:
- throttling,
- graceful degrade/deny,
- operator-visible block,
- or explicit rollback.

Forbidden outcomes include:
- reserve-floor breach,
- expired override reuse,
- policy forks hidden behind local process state,
- or a chaos run that changes truth but emits no audit chain.

## 5. Injection-hook law

### 5.1 Stable hook families

The campaign law now fixes these stable hook families:

1. **`hook.cutover_control_0.transport.link_lane`**
   - inject pause/drop/reorder/latency/bandwidth faults on a typed directional or bidirectional link and lane family

2. **`hook.cutover_control_0.runtime.subject_lifecycle`**
   - inject crash/restart/wipe/quiesce faults on a typed subject (node, daemon, worker group, export queue, pilot)

3. **`hook.cutover_control_0.storage.region_mutator`**
   - inject bit-flip, truncation, zeroing, stale-copy, or partial-header corruption against a declared artifact/offset class

4. **`hook.cutover_control_0.time.subject_clock`**
   - inject drift, heartbeat gaps, deadline shifts, or stale-fence views against a typed time subject

5. **`hook.cutover_control_0.resource.pressure_domain`**

6. **`hook.cutover_control_0.operator.surface_interruption`**
   - interrupt publish, override, rollback, or cutover steps at a declared runbook stage

### 5.2 Hook declaration rule

Every hook binding must declare at least:
- `hook_family_ref`
- `subject_selector_ref`
- `fault_class_refs[]`
- `safety_scope_ref`
- `restore_or_heal_action_ref`
- `replayability_class`
- `artifact_capture_rule_ref`

No campaign may rely primarily on unnamed shell commands, ad hoc signal delivery, or manual packet filtering as its proof mechanism.
Those may exist as backend mechanics, but only behind one of the named hook families above.

### 5.3 Current-tree mapping note

The current repository already has concrete hooks that map directly into this family set:
- cluster harness methods for pause/drop/reorder/crash/restart/wipe,
- deterministic per-lane latency and budget controls,
- trace-schema fault actions for replayable cluster runs,
- and file-backed device corruption for recovery tests.

That current-tree grounding is important because `P10-02` is not inventing a fantasy future harness. It is standardizing the semantics the repo already partially exercises.

## 6. Scheduler and determinism law

### 6.1 Campaign depth classes

The mandatory campaign-depth classes are:
- `campaign.cutover_control_0.single_fault`
- `campaign.cutover_control_1.paired_fault`
- `campaign.cutover_control_2.cascading_fault`
- `campaign.cutover_control_3.shadow_cutover_fault`
- `campaign.cutover_control_4.soak_disaster`

### 6.2 Schedule grammar

Every campaign run must declare:
- a canonical seed vector,
- the ordered schedule windows,
- fault-open and fault-heal steps,
- concurrency limits,
- observation windows,
- workload and oracle bindings per phase,
- and the terminal recovery or refusal condition.

Pseudo-random exploration is legal only when the seed vector, schedule template, and resulting fault sequence are captured so the run can be replayed.

### 6.3 Admissibility rules

- A paired fault is legal only if a row explicitly names the pair or its pair class.
- More than one irreversible corruption class may be active at once only in `campaign.cutover_control_4.soak_disaster` rows.
- Every fault must have either a heal path or an explicitly declared irreversible terminal scope.
- Shadow-cutover chaos may not erase row identity, artifact classes, or bucket grammar when moving from reference to shadow or from shadow to authoritative target.

## 7. Recovery and forbidden-outcome law

### 7.1 Normalized legal outcomes

Every `cutover_control_0` row must end in one of these normalized legal outcome classes:
- `legal.refuse_without_mutation`
- `legal.degrade_and_continue`
- `legal.fence_and_failover`
- `legal.quarantine_and_repair`
- `legal.rebuild_and_replay`
- `legal.rollback_and_reenter`

### 7.2 Mandatory forbidden outcomes

Every `cutover_control_0` row must check at least the relevant subset of these forbidden outcomes:
- `forbidden.silent_corruption_accept`
- `forbidden.success_without_durability`
- `forbidden.split_brain_authority`
- `forbidden.unbounded_reserve_erosion`
- `forbidden.cutover_with_open_divergence`

A row is incomplete if it does not name which forbidden outcomes are being checked.

### 7.3 Recovery proof rule

A campaign may claim recovery only when it emits the recovery/repair/failover receipts appropriate to its row, such as:
- repair publication receipts,
- rebuild or relocation receipts,
- failover or handoff receipts,
- replay/scan fallback proof,
- rollback receipts,
- and the closing gate receipt.

No “the system stabilized eventually” narrative is sufficient on its own.

## 8. Artifact map and bucket grammar

### 8.1 Mandatory chaos artifact classes

Every `cutover_control_0` campaign must emit these minimum artifact classes:

1. **fault catalog snapshot**
   - exact injected class set and row bindings

2. **hook binding manifest**
   - concrete hook families and subject selectors

3. **schedule/seed manifest**
   - replayable seed vector and phase sequence

4. **topology and policy snapshot**
   - environment, membership, policy, and variant state before injection

5. **corruption target manifest**
   - target artifact families, offset classes, or subject selectors

6. **pre-fault health vector**
   - anchor, fingerprint, queue, reserve, freshness, and session baseline state

7. **post-fault observation vector**
   - observed divergence, errors, degraded state, and recovery progress

8. **recovery receipt set**
   - repair/rebuild/failover/rollback/scan receipts linked to the row ids

9. **forbidden-outcome scan summary**
   - explicit yes/no classification for the forbidden outcomes the row promised to check

10. **gate receipt or stop ticket**
    - admission, refusal, rollback block, or stop-ship effect

Missing artifact classes are campaign failures, not clerical omissions.

### 8.2 Normalized chaos failure buckets

The chaos/corruption program now fixes these canonical bucket families:
- `bucket.cutover_control_0.transport_divergence`
- `bucket.cutover_control_0.authority_split_brain`
- `bucket.cutover_control_0.durability_lie`
- `bucket.cutover_control_0.corruption_not_quarantined`
- `bucket.cutover_control_0.repair_or_rebuild_not_lawful`
- `bucket.cutover_control_0.replay_nonconvergence`
- `bucket.cutover_control_0.reserve_breach`
- `bucket.cutover_control_0.operator_truth_gap`
- `bucket.cutover_control_0.unknown_or_unreplayable_hook`

These buckets must remain stable across archived lab, Rust shadow, Rust authoritative userspace, mixed deployments, and future kernel-heavy variants.

## 9. Gate integration law

### 9.1 Smoke and quick gates

- `gate.dev.smoke` must include at least one high-signal single-fault row for every touched subject family and every newly introduced hook family.
- `gate.premerge.quick` must include all changed hook families and any paired-fault rows marked `quick_required` by the matrix.

### 9.2 Release and cutover gates

- `gate.release.variant` must include all release-required `cutover_control_0` rows for the target variant.
- `gate.cutover.shadow` must include shared row ids across reference, shadow, and target variants while relevant faults are active.
- `gate.rollback.reentry` must prove rollback or re-entry under at least one real cutover fault row, not only under happy-path parity.

### 9.3 Non-waivable rules

Temporary waivers still flow through `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`, but a waiver may **not**:
- hide a forbidden outcome,
- hide missing chaos artifacts,
- convert a falsified release-required chaos row into a real pass,
- or admit cutover when `forbidden.cutover_with_open_divergence` remains unresolved.



- deterministic cluster-fault hooks and trace ops,
- restart/wipe/partition storm scenarios,
- media-corruption robustness tests around checkpoint fallback,
- FUSE smoke and `xfstests` backends,
- block acceptance backends,

### 10.2 Remaining production items that consume this law

- **`P10-03`** is now explicit in `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`; it adds KPI and regression-threshold law to the same `cutover_control_0` runs instead of inventing a new performance-only chaos language.
- **`P11-03`** must preserve hook-family semantics when the first Rust userspace staircase begins.
- **`P7-01`** must require future kernel module families to inherit the same `cutover_control_0` row ids and bucket grammar.
- **`P2-05`** now supplies the shared checkpoint/snapshot/replay-cursor anchor law that these corruption rows must target; later variants may refine the rows, but they may not create a second persistence-fault grammar.
- **`P9-03`** now does that in `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`; later variants may refine rows, but they may not change the artifact or gate language.
- **`P9-04`** now adds secret/key-specific handle, lease, and rotation law; any future secret-focused chaos rows must still stay inside this same campaign grammar.

## 11. Anti-regression rules

1. **No ad hoc chaos result without a typed fault catalog, hook binding, and seed/schedule manifest.**
2. **No corruption row without an explicit detection path and forbidden-outcome scan.**
3. **No gate pass without the recovery receipts the row declared in advance.**
4. **No variant may invent a local-only chaos bucket grammar.**
5. **No shadow or cutover move may reduce the chaos surface that was required for the earlier variant.**
7. **No operator narrative may hide which faults were injected, which forbidden outcomes were checked, or which blockers remain open.**

## 12. Result

`P10-02` is closed when the repo can say, in production terms:
- which typed fault and corruption classes exist,
- which stable hook families execute them,
- how campaigns are scheduled and replayed,
- which legal and forbidden outcomes must be checked,
- which artifacts every chaos campaign must emit,
- and how those campaigns affect smoke, quick, release, cutover, rollback, and disaster gates.

That condition is now met.

## 13. Storage-Intent Fault Validation Matrix (P10-02-SI, #863)

This section defines the storage-intent-specific validation matrix that proves
ack, placement, media, and WAN promises under destructive faults. It extends
the `cutover_control_0` campaign law with storage-intent row families, fault
classes, forbidden outcomes, and artifact requirements.

### 13.1 Scope And Relationship To Other Work

This matrix owns fault, chaos, corruption, refusal, and recovery proof
obligations for storage intent. It does not own:

- latency, tail, throughput, RPO, wear, and cost budget rows (#850);
- publishing-facing claim boundaries and claim-registry wording (#875);
- evidence-query snapshots (#913), service objectives (#915), or
  result/refusal evidence (#920) — each fault row must carry a ref to those
  evidence producers, but this matrix does not define them;
- lifecycle/generation evidence (#881);
- membership/quorum authority (#750);
- ordering/replay evidence (#894);
- capacity/admission evidence (#898);
- recovery/degradation evidence (#900);
- policy-rollout evidence (#901);
- tenant-isolation evidence (#902);
- prediction-accountability evidence (#845);
- temporal evidence (#903);
- media-capability evidence (#904);
- decision-frontier evidence (#905);
- preflight-simulation evidence (#926);
- prefetch/residency decisions (#967) or executor actions (#972).

Rows in this matrix carry pending refs, query/refusal refs, or typed
"not yet produced" states for evidence classes owned by those issues.

Every storage-intent fault row must record the #913 evidence-query snapshot,
#915 service objective when latency/RPO/wear/cost is part of the promise, and
#920 result/refusal evidence for the caller-visible outcome. A destructive run
without those refs may diagnose behavior, but it must not validate claims,
receipt retirement, degraded visibility, or policy satisfaction.

#### 13.1.1 Companion-Reference Summary

| Issue | Role | Row-Binding Rule |
| --- | --- | --- |
| #850 | Performance budgets | Cross-link rows where latency, tail, throughput, RPO, wear, or cost are part of the promise |
| #875 | Claim registry | Product claims and successor wording remain gated by #875 claim ids and status |
| #913 | Evidence-query snapshots | Every row must record the #913 snapshot used |
| #915 | Service objectives | Bind when latency/RPO/wear/cost is part of the promise |
| #920 | Result/refusal | Bind for caller-visible outcome |
| #881 | Lifecycle evidence | Consume for write-age, stability, snapshot, clone, and reclaim evidence |
| #750 | Membership authority | Consume for epoch, quorum, witness, and fencing evidence |
| #894 | Ordering/replay | Preserve for barrier scope, dependency closure, replay idempotency |
| #897 | Trust/domain | Consume for identity, domain, session-security, key-epoch, authorization, residency, quarantine |
| #898 | Capacity admission | Consume for allocation tickets, reserve escrow, dirty-window, ENOSPC |
| #900 | Recovery/degradation | Consume for repair-source receipts, replacement receipts, degraded visibility |
| #901 | Policy rollout | Consume for revision provenance, stage state, in-flight fences, convergence |
| #902 | Tenant isolation | Consume for budget-owner, isolation scope, fair-share, noisy-neighbor |
| #845 | Prediction accountability | Consume for confidence, action class, payback, cooldown |
| #903 | Temporal evidence | Consume for timebase, clock-health, skew, expiry |
| #904 | Media capability | Consume for persistence domain, flush/FUA, atomicity, health |
| #905 | Decision frontier | Consume for candidate sets, hard-gate results, score vectors |
| #926 | Preflight simulation | Consume with non-authority markers |
| #967 | Prefetch residency | Consume for prefetch/cache-trial fault injections |
| #972 | Prefetch executor | Consume for executor failures |

### 13.2 Storage-Intent Fault Classes

The mandatory storage-intent fault classes extend the base catalog (section 4)
with guarantee-specific and evidence-specific injections:

#### 13.2.1 Guarantee-Bound Faults

| Class | Injection | Legal Subject Families |
| --- | --- | --- |
| `fi.storage_intent.kill_before_ack` | Kill subject process/worker before durable ack emission | All ack-emitting subjects |
| `fi.storage_intent.crash_after_ack` | Crash subject after ack emission but before cutover/replay persistence | All ack-emitting subjects |
| `fi.storage_intent.volatile_media_loss` | Power-loss or media-reset against volatile media before flush | `volatile-local`, `volatile-replicated`, `intent-backed-RAM` |
| `fi.storage_intent.replicated_volatile_loss` | One replica lost while the other survives | `volatile-replicated` |
| `fi.storage_intent.intent_backing_loss` | Intent-log or backing media lost after ack | `intent-backed-RAM`, `local-intent` |
| `fi.storage_intent.full_placement_interrupted` | Crash or media fault during full-placement write | `full-placement` |
| `fi.storage_intent.quorum_under_replication` | Quorum intent under transport partition or member loss | `quorum-intent`, `geo-intent` |
| `fi.storage_intent.geo_async_lag_cutoff` | WAN partition or bandwidth clamp during geo-async catch-up | `geo-async` |
| `fi.storage_intent.geo_intent_partition` | WAN/internet partition during geo-intent acknowledgment | `geo-intent` |

#### 13.2.2 Transport And Partition Faults For Storage Intent

| Class | Injection |
| --- | --- |
| `fi.storage_intent.transport.quorum_partition` | Bidirectional partition between quorum members during intent acknowledgment |
| `fi.storage_intent.transport.geo_latency_stretch` | Latency stretch beyond RPO/RTO envelope during geo catch-up or geo-intent ack |
| `fi.storage_intent.transport.geo_bandwidth_clamp` | Bandwidth clamp below geo catch-up or replication minimum |
| `fi.storage_intent.transport.rdma_absent_tcp_baseline` | RDMA path removed; TCP/internet path remains |

#### 13.2.3 Cache And Serving-Trial Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.cache_only_trial_loss` | Cache device or memory loss while serving-trial bytes are present with no durable backing |
| `fi.storage_intent.stale_cache_serve` | Stale cache generation served as latest read |
| `fi.storage_intent.stale_snapshot_serve` | Stale snapshot generation used for read serving |
| `fi.storage_intent.geo_async_stale_read` | Geo-async lag causes stale read without freshness-refusal evidence |
| `fi.storage_intent.digest_mismatch_serve` | Digest-suite mismatch during degraded read or reconstruction |

#### 13.2.4 Prediction And Hint Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.hint_only_confidence_as_authority` | Low-confidence hint accepted as authority-movement justification |
| `fi.storage_intent.one_off_hotness_misprediction` | One-off access pattern mispredicted as durable hotness; expensive movement admitted |
| `fi.storage_intent.missing_outcome_evidence_as_success` | Missing or refused #912 attribution evidence treated as successful payback |
| `fi.storage_intent.failed_payback_retry_no_cooldown` | Failed payback retried without cooldown, unbounded wear or foreground budget spent |
| `fi.storage_intent.tenant_manufactured_confidence` | Tenant-manufactured confidence crossing #902 isolation scopes |
| `fi.storage_intent.contradiction_state_ignored` | Contradiction or confounded state ignored during admission |

#### 13.2.5 Signal Materialization Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.unbounded_per_file_tracking` | Unbounded per-file signal tracking consuming metadata or evidence-write reserves |
| `fi.storage_intent.telemetry_writes_hidden_from_wear` | Telemetry/persistence writes not counted in wear accounting |
| `fi.storage_intent.signal_consuming_protected_reserves` | Signal persistence consuming protected sync/repair/evacuation/receipt-retirement/metadata/flash-wear reserves |
| `fi.storage_intent.memory_only_sketch_as_durable_proof` | Memory-only sketch or sampled summary treated as durable evidence |
| `fi.storage_intent.sampled_away_evidence_inflated` | Sampled-away or dropped signal evidence inflated into high confidence |
| `fi.storage_intent.dropped_checkpoint_hidden` | Dropped predictor checkpoint hidden from explanation |
| `fi.storage_intent.observability_overhead_omitted` | Observability overhead omitted from performance or attribution rows |

#### 13.2.6 Temporal Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.unknown_clock_skew_as_fresh` | Unknown clock skew accepted as fresh evidence |
| `fi.storage_intent.backwards_time_as_progress` | Backwards time accepted as progress |
| `fi.storage_intent.stale_clock_health_for_rpo` | Stale clock-health samples accepted for RPO measurement |
| `fi.storage_intent.sequence_lag_as_wall_clock_lag` | Sequence lag reported as wall-clock lag without conversion evidence |
| `fi.storage_intent.expired_key_window_accepted` | Expired key/authorization window accepted |
| `fi.storage_intent.rollout_deadline_crossed_silently` | Rollout deadline crossed without refusal or operator-visible degraded state |
| `fi.storage_intent.ttl_expiry_as_reclaim_authority` | TTL expiry treated as reclaim authority without lifecycle/receipt evidence |

#### 13.2.7 Media And Wear Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.flash_wear_reserve_exhaustion` | Endurance reserve exhausted during promotion, defrag, rebake, rebuild, or relocation |
| `fi.storage_intent.write_amplification_budget_pressure` | Write-amplification budget breached during promotion, defrag, rebake, rebuild, or relocation |
| `fi.storage_intent.flush_omission` | Flush/FUA omitted during placement or relocation; volatile cache survives |
| `fi.storage_intent.stale_copy` | Stale media copy served instead of current generation |
| `fi.storage_intent.truncation` | Data truncated at media boundary without detection |
| `fi.storage_intent.bitflip` | Bitflip in metadata, payload, or checkpoint without detection or quarantine |
| `fi.storage_intent.zeroed_range` | Range zeroed by firmware or media fault without detection |
| `fi.storage_intent.device_loss` | Device removed, failed, or identity-drifted mid-operation |

#### 13.2.8 Trust And Domain Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.missing_session_security` | Required session security missing for remote/repair/geo/RAM role |
| `fi.storage_intent.stale_trust_epoch` | Stale trust epoch accepted for authority |
| `fi.storage_intent.stale_or_revoked_key_epoch` | Stale or revoked key epoch accepted |
| `fi.storage_intent.wrong_tenant_security_domain` | Wrong tenant or security domain accepted for cross-domain role |
| `fi.storage_intent.missing_authorization_audit` | Missing authorization or audit evidence for role |
| `fi.storage_intent.residency_violation` | Residency-forbidden domain accepted |
| `fi.storage_intent.compromised_repair_source` | Compromised or quarantined peer accepted as repair source |
| `fi.storage_intent.illegal_cross_domain_sharing` | Illegal cross-domain dedup or sharing accepted |
| `fi.storage_intent.quarantined_peer_as_authority` | Quarantined peer accepted as authority |

#### 13.2.9 Data-Shape And Transform Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.wrong_key_epoch` | Wrong key epoch used for encryption/decryption |
| `fi.storage_intent.illegal_dedup_domain` | Illegal dedup domain crossing isolation or trust boundary |
| `fi.storage_intent.malformed_compression_frame` | Malformed compression frame accepted without refusal |
| `fi.storage_intent.digest_suite_mismatch` | Digest-suite mismatch during verification |
| `fi.storage_intent.mounted_transform_refusal_state` | Mounted transform block or refusal state ignored |
| `fi.storage_intent.ec_under_width_reconstruction` | EC reconstruction attempted with fewer than width shards |

#### 13.2.10 Allocator And Layout Faults

| Class | Injection |
| --- | --- |
| `fi.storage_intent.stale_mirror_only_free_run` | Stale mirror-only free-run evidence accepted as authority |
| `fi.storage_intent.wrong_generation_segment` | Wrong-generation segment evidence accepted |
| `fi.storage_intent.pending_free_reuse_before_fence` | Pending-free bytes reused before fence or generation advance |
| `fi.storage_intent.zone_write_pointer_incompat` | Zone/write-pointer incompatibility hidden during placement |
| `fi.storage_intent.under_aligned_block_volume` | Under-aligned block-volume placement accepted |
| `fi.storage_intent.enospc_hidden` | ENOSPC or reserve exhaustion hidden behind successful placement claim |
| `fi.storage_intent.mirror_evidence_as_authority` | Allocator mirror evidence accepted as authority without primary verification |

### 13.3 Row Families

#### 13.3.1 Minimum Row Families

Every storage-intent fault row must bind to one of these subject families:

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.volatile_local` | `volatile-local` ack class | `kill_before_ack`, `crash_after_ack`, `volatile_media_loss` |
| `row.si.fault.volatile_replicated` | `volatile-replicated` ack class | `kill_before_ack`, `crash_after_ack`, `replicated_volatile_loss`, `quorum_under_replication` |
| `row.si.fault.local_intent` | `local-intent` ack class | `kill_before_ack`, `crash_after_ack`, `intent_backing_loss`, `flush_omission` |
| `row.si.fault.remote_volatile_plus_local` | `remote-volatile-plus-local` ack class | `kill_before_ack`, `crash_after_ack`, `replicated_volatile_loss`, `transport.quorum_partition` |
| `row.si.fault.quorum_intent` | `quorum-intent` ack class | `kill_before_ack`, `crash_after_ack`, `quorum_under_replication`, `transport.quorum_partition`, `transport.rdma_absent_tcp_baseline` |
| `row.si.fault.full_placement` | `full-placement` ack class | `kill_before_ack`, `crash_after_ack`, `full_placement_interrupted`, `device_loss`, `bitflip`, `truncation` |
| `row.si.fault.geo_async` | `geo-async` ack class | `geo_async_lag_cutoff`, `transport.geo_latency_stretch`, `transport.geo_bandwidth_clamp`, `geo_async_stale_read` |
| `row.si.fault.geo_intent` | `geo-intent` ack class | `kill_before_ack`, `crash_after_ack`, `geo_intent_partition`, `transport.geo_latency_stretch`, `transport.rdma_absent_tcp_baseline` |

#### 13.3.2 Cache And Serving-Trial Row Families

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.cache_only_trial` | Cache-only serving trial | `cache_only_trial_loss`, `stale_cache_serve` |
| `row.si.fault.stale_read_serve` | Read-serving path | `stale_cache_serve`, `stale_snapshot_serve`, `geo_async_stale_read`, `digest_mismatch_serve` |

#### 13.3.3 Prediction And Hint Row Families

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.hint_misprediction` | Prediction/admission path | `hint_only_confidence_as_authority`, `one_off_hotness_misprediction`, `missing_outcome_evidence_as_success` |
| `row.si.fault.payback_cooldown_loop` | Payback/cooldown path | `failed_payback_retry_no_cooldown`, `tenant_manufactured_confidence`, `contradiction_state_ignored` |

#### 13.3.4 Signal Materialization Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.signal_materialization` | Signal/predictor path | All signal materialization faults from 13.2.5 |

#### 13.3.5 Temporal Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.temporal` | Time/clock/expiry path | All temporal faults from 13.2.6 |

#### 13.3.6 Media And Wear Row Families

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.flash_wear` | Flash media | `flash_wear_reserve_exhaustion`, `write_amplification_budget_pressure` |
| `row.si.fault.media_corruption` | All durable media | `flush_omission`, `stale_copy`, `truncation`, `bitflip`, `zeroed_range`, `device_loss` |
| `row.si.fault.hdd_defrag_crash` | HDD defrag | `kill_before_ack`, `crash_after_ack` (during defrag) |
| `row.si.fault.ssd_relocation_crash` | SSD relocation | `kill_before_ack`, `crash_after_ack` (during relocation) |
| `row.si.fault.ram_authority_failure` | RAM/volatile authority | `volatile_media_loss` (proving volatile receipts never satisfy durable POSIX barriers) |

#### 13.3.7 Trust And Domain Row Families

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.trust_domain` | Trust/domain path | All trust/domain faults from 13.2.8 |

#### 13.3.8 Data-Shape Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.data_shape` | Transform/integrity path | All data-shape faults from 13.2.9 |

#### 13.3.9 Allocator Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.allocator_layout` | Allocator/layout path | All allocator faults from 13.2.10 |

#### 13.3.10 Relocation Anti-Thrash Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.relocation_anti_thrash` | Relocation governor | `failed_payback_retry_no_cooldown` (movement debt), `stale_mirror_only_free_run` (reserve erosion), `flash_wear_reserve_exhaustion` (wear budget breach) |

#### 13.3.11 Mixed-Media Repair And Rebuild Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.mixed_media_repair` | Repair/rebuild path | `device_loss` (one media class), `quorum_under_replication`, `bitflip`, `stale_copy`, `compromised_repair_source`, `ec_under_width_reconstruction` |

#### 13.3.12 Policy Rollback Row Family

| Row Family | Subject | Required Fault Classes |
| --- | --- | --- |
| `row.si.fault.policy_rollback_conflict` | Policy rollout path | `kill_before_ack` (during publish), `crash_after_ack` (during stage transition), `rollout_deadline_crossed_silently` |

### 13.4 Row Binding Contract

Every `row.si.fault.*` entry must declare at least:

| Field | Content |
| --- | --- |
| `row_identity_ref` | Row family and id, storage-intent subject class, policy revision, and gate class refs |
| `fault_catalog_ref` | Typed fault classes injected, including guarantee-bound, transport, cache, prediction, signal, temporal, media, trust, data-shape, and allocator classes as appropriate |
| `subject_family_ref` | Storage-intent ack class, serving-trial, prediction, relocation, repair, or rollout subject |
| `target_selector_ref` | Dataset, pool, tenant, media role, transport lane, or domain selector |
| `hook_binding_ref` | Hook family and subject selector from section 5, specialized for storage-intent targets |
| `schedule_template_ref` | Ordered fault-open, fault-heal, observation, and recovery-replay windows |
| `workload_family_ref` | Workload envelope matching the subject's guarantee class (e.g., WAL stream for intent, VM image for full placement, bulk write for geo-async) |
| `oracle_binding_ref` | Oracle that checks receipt classes, forbidden outcomes, and policy satisfaction |
| `evidence_query_snapshot_ref` | #913 snapshot identity used for the row's evidence cut |
| `service_objective_ref` | #915 objective when latency, RPO, wear, or cost are part of the promise (otherwise "not applicable") |
| `result_refusal_ref` | #920 result/refusal evidence for caller-visible outcome |
| `expected_legal_outcome_refs[]` | Normalized legal outcomes from section 7.1 plus storage-intent-specific outcomes (see 13.5) |
| `forbidden_outcome_refs[]` | Storage-intent forbidden outcomes the row must check (see 13.6) |
| `required_recovery_receipt_class_refs[]` | Receipt classes that must exist after recovery |
| `required_artifact_class_refs[]` | Storage-intent artifact classes (see 13.8) |
| `gate_class_refs[]` | Smoke, quick, release, cutover, rollback, or disaster gate refs |
| `companion_refs` | Cross-references to #850 performance rows, #875 claim ids, and other pending-evidence issues |

### 13.5 Storage-Intent Legal Outcome Classes

In addition to the base `cutover_control_0` legal outcome classes (section 7.1),
storage-intent rows add:

| Outcome | Meaning |
| --- | --- |
| `legal.si.refuse_without_weakening` | Refuse the request while preserving the requested guarantee floor; no silent downgrade |
| `legal.si.degrade_visible` | Degrade to a weaker state with explicit operator-visible receipt, lag, or volatility evidence |
| `legal.si.cache_only_trial_survives` | Cache-only trial surviving a fault as non-authoritative; no durable or placement receipts claimed |
| `legal.si.replacement_before_retirement` | Replacement receipt published before old locator or source receipt retirement |
| `legal.si.cooldown_after_failed_payback` | Cooldown triggered after failed payback; no unbounded retry or wear erosion |
| `legal.si.policy_rollback_preserves_receipts` | Rollback restores prior revision admission but preserves receipts earned during the failed stage |
| `legal.si.repair_with_degraded_visibility` | Repair completes with operator-visible degraded state, policy floors, and foreground protection |

### 13.6 Storage-Intent Forbidden Outcomes

Every storage-intent fault row must check at least the relevant subset of these
forbidden outcomes. In addition to the base forbidden outcomes from section 7.2:

#### 13.6.1 Durability And Receipt Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.durable_success_without_receipt_evidence` | Durable success reported without the receipt evidence required by the requested floor |
| `forbidden.si.hidden_downgrade_durable_to_volatile` | Hidden downgrade from durable to volatile ack class |
| `forbidden.si.hidden_downgrade_geo_intent_to_geo_async` | Hidden downgrade from geo-intent to geo-async |
| `forbidden.si.cache_or_trial_as_durable_authority` | Cache-only or serving-trial state reported as durable authority |
| `forbidden.si.split_brain_receipt_publication` | Split-brain receipt publication across partitioned domains |
| `forbidden.si.volatile_receipt_as_durable_barrier` | Volatile receipt satisfying durable POSIX barrier (fsync, fdatasync, O_DSYNC, FUA) |

#### 13.6.2 Trust And Domain Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.remote_authority_missing_trust_evidence` | Remote, shared, repair, geo, or replicated-RAM authority accepted with missing trust/domain evidence |
| `forbidden.si.stale_trust_or_key_accepted` | Stale trust epoch, stale/revoked key epoch accepted for authority role |
| `forbidden.si.wrong_domain_accepted` | Wrong tenant, security, or administrative domain accepted |
| `forbidden.si.unauthorized_peer_accepted` | Missing authorization or audit evidence for peer role |
| `forbidden.si.residency_violation_accepted` | Residency-forbidden domain accepted for authority or data placement |
| `forbidden.si.compromised_or_quarantined_accepted` | Compromised or quarantined peer accepted as repair source or authority |
| `forbidden.si.illegal_cross_domain_dedup` | Illegal cross-domain dedup or sharing accepted |

#### 13.6.3 Placement And Retirement Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.old_placement_retired_without_replacement` | Old placement or locator retired before replacement receipt publication |
| `forbidden.si.relocation_hides_reserve_breach` | Flash-wear, capacity, or transport reserve breach hidden behind successful relocation |
| `forbidden.si.defrag_replacement_not_published` | HDD defrag or SSD relocation retires old locator before replacement receipt exists |

#### 13.6.4 Prediction And Payback Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.hint_only_as_authority_movement` | Hint-only confidence accepted as authority movement justification |
| `forbidden.si.missing_outcome_as_success` | Missing outcome evidence treated as successful payback |
| `forbidden.si.failed_payback_retried_without_cooldown` | Failed payback retried without cooldown; unbounded wear or foreground budget spent |
| `forbidden.si.tenant_manufactured_confidence_crossing_isolation` | Tenant-manufactured confidence crossing isolation scopes |
| `forbidden.si.contradiction_ignored_during_admission` | Contradiction or confounded state ignored during admission |
| `forbidden.si.cooldown_loop_hides_reserve_erosion` | Retry/cooldown loops that spend unbounded wear or foreground budget after failed payback |
| `forbidden.si.stale_placement_hidden_by_cooldown` | Movement debt, cooldown, and failed payback hiding stale placement, reserve erosion, or retry loops |

#### 13.6.5 Signal Materialization Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.unbounded_per_file_tracking` | Unbounded per-file signal tracking consuming metadata or evidence-write reserves |
| `forbidden.si.telemetry_hidden_from_wear_accounting` | Telemetry/signal writes hidden from wear accounting |
| `forbidden.si.signal_consuming_protected_reserves` | Signal persistence consuming protected sync/repair/evacuation/receipt-retirement/metadata/flash-wear reserves |
| `forbidden.si.memory_only_as_durable_proof` | Memory-only sketches or sampled summaries treated as durable proof |
| `forbidden.si.sampled_away_inflated_to_confidence` | Sampled-away or dropped signal evidence inflated into high confidence |
| `forbidden.si.dropped_checkpoint_hidden_from_explanation` | Dropped predictor checkpoint hidden from operator explanation |
| `forbidden.si.observability_overhead_omitted` | Observability overhead omitted from performance or attribution rows |

#### 13.6.6 Temporal Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.unknown_clock_skew_as_fresh` | Unknown clock skew accepted as fresh evidence |
| `forbidden.si.backwards_time_as_progress` | Backwards time accepted as progress |
| `forbidden.si.stale_clock_health_for_rpo` | Stale clock-health samples accepted for RPO |
| `forbidden.si.sequence_lag_as_wall_clock_lag` | Sequence lag reported as wall-clock lag without conversion evidence |
| `forbidden.si.expired_key_window_accepted` | Expired key or authorization window accepted |
| `forbidden.si.rollout_deadline_crossed_silently` | Rollout deadline crossed without refusal or operator-visible degraded state |
| `forbidden.si.ttl_expiry_as_reclaim_authority` | TTL expiry treated as reclaim authority without lifecycle/receipt evidence |

#### 13.6.7 Media And Wear Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.flash_wear_reserve_breach_hidden` | Flash-wear reserve exhaustion hidden behind successful relocation or placement |
| `forbidden.si.write_amplification_budget_breach_hidden` | Write-amplification budget breach hidden during promotion, defrag, rebake, rebuild, or relocation |
| `forbidden.si.media_corruption_accepted_silently` | Bitflip, truncation, zeroed range, flush omission, or stale copy accepted without detection or quarantine |
| `forbidden.si.device_loss_hidden` | Device loss hidden; receipts or reads served from missing media without degraded visibility |
| `forbidden.si.ram_authority_as_durable_barrier` | RAM/volatile authority accepted as satisfying durable POSIX barriers |

#### 13.6.8 Data-Shape Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.stale_data_shape_accepted` | Stale, wrong-domain, wrong-key-epoch, or under-width data-shape evidence accepted as satisfied |
| `forbidden.si.malformed_transform_accepted` | Malformed compression frame, digest-suite mismatch, or illegal transform accepted |
| `forbidden.si.ec_under_width_as_valid` | EC reconstruction under minimum width accepted as valid data |

#### 13.6.9 Allocator Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.mirror_evidence_as_authority` | Allocator mirror evidence accepted as authority without primary verification |
| `forbidden.si.pending_free_reused_too_early` | Pending-free bytes reused before fence or generation advance |
| `forbidden.si.reserve_exhaustion_hidden` | ENOSPC or reserve exhaustion hidden behind successful placement claim |
| `forbidden.si.under_aligned_placement_accepted` | Under-aligned block-volume placement accepted |
| `forbidden.si.wrong_generation_segment_accepted` | Wrong-generation segment evidence accepted for placement |

#### 13.6.10 Capacity And Admission Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.stale_allocation_ticket_accepted` | Stale allocation ticket accepted for admission |
| `forbidden.si.expired_reserve_escrow_accepted` | Expired reserve escrow accepted |
| `forbidden.si.pending_free_counted_early` | Pending-free bytes counted before fence or generation advance |
| `forbidden.si.dirty_window_overcommit` | Dirty-window overcommit accepted without refusal |
| `forbidden.si.protected_floor_borrowing` | Protected sync/repair/evacuation/receipt-retirement floor borrowed without authorization |
| `forbidden.si.old_plus_new_cow_omission` | Old-plus-new COW omissions during relocation |
| `forbidden.si.relocation_scratch_exhaustion_hidden` | Relocation scratch exhaustion hidden behind successful placement |
| `forbidden.si.geo_backlog_overflow_hidden` | Geo backlog overflow hidden behind successful catch-up claim |

#### 13.6.11 Recovery And Degradation Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.no_quorum_success` | Success reported without quorum when quorum is required |
| `forbidden.si.stale_receipt_repair_source` | Stale receipt used as repair source |
| `forbidden.si.under_width_reconstruction` | Under-width reconstruction accepted as valid |
| `forbidden.si.corrupt_source_accepted` | Corrupt source accepted without quarantine or refusal |
| `forbidden.si.old_epoch_after_healing` | Old epoch data accepted after healing completion |
| `forbidden.si.fenced_or_draining_source_accepted` | Fenced or draining data source accepted for repair |
| `forbidden.si.quarantined_repair_source_accepted` | Quarantined or wrong-domain repair source accepted |
| `forbidden.si.read_repair_without_reserve` | Read repair performed without reserve headroom |
| `forbidden.si.missing_replacement_at_retirement` | Replacement receipt missing at old-receipt retirement |
| `forbidden.si.hidden_degraded_state` | Degraded state hidden from operator after fault |

#### 13.6.12 Operator Explanation Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.explanation_omits_active_degradation` | Operator explanation omits active degradation after fault |
| `forbidden.si.explanation_omits_remote_lag` | Operator explanation omits remote lag or geo-async backlog |
| `forbidden.si.explanation_omits_volatility` | Operator explanation omits volatility or weaker-than-requested guarantee |
| `forbidden.si.explanation_omits_policy_refusal` | Operator explanation omits policy refusal reason |
| `forbidden.si.explanation_omits_skipped_relocation` | Operator explanation omits skipped relocation, cooldown, or failed payback |
| `forbidden.si.explanation_omits_reserve_pressure` | Operator explanation omits active capacity, wear, or transport reserve pressure |

#### 13.6.13 Prefetch And Residency Forbidden Outcomes

| Forbidden Outcome | Description |
| --- | --- |
| `forbidden.si.prefetched_bytes_as_durable_receipt` | Prefetched bytes satisfying durable ack or placement receipts |
| `forbidden.si.cache_only_trial_as_latest_read` | Cache-only trial serving stale latest reads after fault |
| `forbidden.si.one_pass_scan_causing_persistent_promotion` | One-pass scan causing persistent flash/PMem promotion |
| `forbidden.si.low_confidence_hint_as_authority_movement` | Low-confidence hints causing authority movement |
| `forbidden.si.dropped_sampled_evidence_as_high_confidence` | Dropped/sampled predictor evidence becoming high confidence |
| `forbidden.si.unknown_waf_cost_treated_as_free` | Unknown WAF/cost treated as free |
| `forbidden.si.archive_restore_uncertainty_hidden` | Archive restore uncertainty hidden from reads |
| `forbidden.si.wan_lag_as_latest_freshness` | WAN lag accepted as latest freshness |
| `forbidden.si.old_receipts_retired_before_replacement` | Old receipts retired before replacement or source-retirement evidence |
| `forbidden.si.executor_populated_as_durable_ack` | Executor-populated bytes satisfying durable ack or placement receipts |
| `forbidden.si.executor_staging_retires_old_receipts` | Executor staging retiring old receipts |
| `forbidden.si.dropped_executor_work_hidden` | Dropped or failed executor work hidden from #849 cost accounting |
| `forbidden.si.unknown_execution_cost_as_free` | Unknown execution cost treated as free |
| `forbidden.si.rdma_absence_as_correctness_failure` | RDMA absence treated as correctness failure |
| `forbidden.si.cache_only_staged_survives_as_authority` | Cache-only staged data surviving a fault as if authoritative |

### 13.7 Deterministic Seed And Artifact Requirements

Every storage-intent fault campaign must produce:

| Artifact Class | Content |
| --- | --- |
| `artifact.si.fault.seed_manifest` | Deterministic seed vector for fault schedule, workload generation, and topology assignment |
| `artifact.si.fault.fault_schedule` | Ordered fault-open and fault-heal steps with concurrency limits and observation windows |
| `artifact.si.fault.workload_envelope` | Workload parameters including operation mix, IO size distribution, fsync density, thread count, duration, and data footprint |
| `artifact.si.fault.environment_profile` | Topology, membership, media classes, policy revisions, transport lanes, and variant state |
| `artifact.si.fault.pre_fault_receipt_set` | Receipt state before injection including ack class distribution, placement receipts, geo lag, cache state, and prediction snapshots |
| `artifact.si.fault.post_fault_receipt_set` | Receipt state after recovery including surviving receipts, replacement receipts, degraded receipts, and refused/lost receipts |
| `artifact.si.fault.prediction_snapshot` | Prediction confidence, action class, trial state, movement debt, payback window, and cooldown state before and after injection |
| `artifact.si.fault.payback_cooldown_verdict` | Payback outcome, cooldown trigger state, retry count, wear/capacity/foreground budget consumed, and refusal/defer decision |
| `artifact.si.fault.recovery_decision_set` | Recovery decisions including repair-source selection, reconstruction width, replacement receipt publication, old-receipt retirement, and degraded-visibility state |
| `artifact.si.fault.forbidden_outcome_scan` | Explicit yes/no/not-applicable classification for every forbidden outcome the row declared |
| `artifact.si.fault.explanation_projection` | Operator-visible explanation including active degradation, lag, volatility, refusal reasons, skipped relocations, cooldowns, and failed payback |
| `artifact.si.fault.gate_receipt` | Admission, refusal, rollback block, or stop-ship effect for the declared gate class |

Missing artifact classes are campaign failures, not clerical omissions (same as
base P10-02 rule in section 8).

### 13.8 Cross-Reference Index To Companion Issues

Every storage-intent fault row should include a `companion_refs` block that
maps companion issue responsibilities:

| Companion Issue | Cross-Reference Rule |
| --- | --- |
| #850 | Cross-link rows where latency, tail, throughput, RPO, wear, or cost are part of the promise. Fault rows do not satisfy #850 performance budgets; they only prove correctness under faults at the declared envelope. |
| #875 | Product claims and successor wording remain gated by #875 claim ids and status. Destructive evidence does not upgrade a planned or blocked claim. |
| #913 | Every row must record the evidence-query snapshot identity used. Unknown, stale, or refused snapshots block validation. |
| #915 | Bind service objective when latency, RPO, wear, or cost is part of the promise. Rows without a latency/RPO/wear/cost objective may record "not applicable." |
| #920 | Bind result/refusal evidence for the caller-visible outcome. Every row must record whether the request was satisfied, refused, or degraded. |
| #881 | Lifecycle evidence for write age, stability, snapshot/clone/receive-base retention, orphan-held bytes, dead-pending reclaim, and destroy/tombstone state. |
| #750 | Membership/quorum authority for epoch identity, roster ownership, quorum-write dispatch, witness-set role, node join/drain lifecycle, and epoch/fence enforcement. |
| #894 | Ordering/replay evidence for barrier scope, dirty epoch, dependency closure, replay idempotency, intent sequence, publication boundary, and completion state. |
| #897 | Trust/domain evidence for authenticated identity, admin/security/tenant domain, session-security posture, key epoch, authorization/audit refs, residency, sharing-domain compatibility, and compromise/quarantine refusal. |
| #898 | Capacity/admission evidence for allocation tickets, reserve escrow, pending-free counts, dirty-window, protected floors, COW omissions, relocation scratch, geo backlog, and ENOSPC/refusal. |
| #900 | Recovery/degradation evidence for no-quorum success, stale repair source, under-width reconstruction, corrupt source, old epoch after healing, fenced/draining source, quarantined repair source, read repair without reserve, missing replacement at retirement, and hidden degraded state. |
| #901 | Policy rollout evidence for source policy provenance, compiled revision publication, change class, downgrade authorization, stage state, in-flight fences, convergence frontiers, and rollback/re-entry. |
| #902 | Tenant/isolation evidence for budget-owner identity, tenant/domain refs, isolation scope, resource-vector budgets, fair-share windows, burst/borrow/debt, starvation, noisy-neighbor harm, reserve exemptions, and throttle/refusal. |
| #845 | Prediction accountability evidence for confidence, action class, shadow/admitted decision, measured outcome, payback/harm, cooldown, and confidence-update. |
| #903 | Temporal evidence for timebase identity, clock health, skew/uncertainty, sequence frontiers, expiry/deadline refs, and temporal refusal. |
| #904 | Media capability evidence for device/namespace identity, persistence domain, flush/FUA/barrier semantics, volatile-cache policy, atomicity/granularity, protocol/geometry, health/freshness, role eligibility, and typed refusal. |
| #905 | Decision frontier evidence for decision identity, candidate sets, hard-gate results, score vectors, selected candidates, deterministic tie-breakers, reserve/admission refs, counterfactual baselines, payback/harm anchors, and refusal/defer state. |
| #926 | Preflight simulation evidence with non-authority markers. Forbidden outcomes include receipt emission, policy activation, source retirement, satisfaction, payback closure, attribution, or claim proof from simulation-only evidence. |
| #967 | Prefetch/residency decision evidence for dataset-scoped policy, access-pattern class, action-class authorization, promotion/demotion candidates, and dwell/cooldown. |
| #972 | Prefetch executor evidence for executor-populated bytes, stale executor evidence, over-budget execution, interrupted staging, WAN stall, verification failure, scheduler refusal, cache eviction, and crash/restart. |

### 13.9 Implementation Status

| Component | Status | Owner |
| --- | --- | --- |
| Storage-intent fault class catalog (13.2) | Defined here | #863 |
| Row family bindings (13.3–13.4) | Defined here | #863 |
| Legal outcome classes (13.5) | Defined here | #863 |
| Forbidden outcome catalog (13.6) | Defined here; runtime proof unvalidated | #863 |
| Artifact requirements (13.7) | Defined here; artifact format owned by follow-up issues | #863 |
| Companion cross-references (13.8) | Defined here; pending-evidence refs preserved | #863 |
| Runtime fault injection hooks for storage intent | Not yet implemented | Future implementation issue |
| Deterministic seed scheduling for storage-intent rows | Not yet implemented | Future implementation issue |
| Forbidden-outcome scanning automation | Not yet implemented | Future implementation issue |
| Claim validation against fault rows | Gated by #875 | Future implementation/validation issue |

### 13.10 Validation Tier

This slice (P10-02-SI, #863) is documentation/source-inspection only.
Validation is `git diff --check` for formatting and whitespace integrity.

Runtime/destructive proof belongs to later implementation and validation
issues, executed in CI/reference environments when the host meets the TideFS
heavy-work disk floor. This matrix defines the proof obligation; it does not
execute or validate the runtime behavior.
