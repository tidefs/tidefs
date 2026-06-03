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
