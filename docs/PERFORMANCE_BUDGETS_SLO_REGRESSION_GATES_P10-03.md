# performance budgets / SLO / regression gates (P10-03) (v0.364)

This document is the source-of-truth for the production-depth performance-budget, SLO, and regression-gate law.

It answers the question:

**How does tidefs turn fast-path behavior, tail risk, failover disruption, policy/control responsiveness, and migration pause windows into one typed gate language instead of benchmark folklore, dashboard screenshots, or “it felt fast enough” operator judgment?**

See also:
- `docs/FAULT_INJECTION_CHAOS_CORRUPTION_CAMPAIGNS_P10-02.md`
- `docs/POSIX_CHARTER_TEST_XFSTESTS_MATRIX_P5-04.md`
- `docs/BLOCK_ACCEPTANCE_STRESS_HARNESS_MATRIX_P6-04.md`
- `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`
- `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`
- `docs/OPERATOR_MANUAL_DYNAMIC_TUNING_AND_REALTIME_OBSERVABILITY.md`
- `docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md`
- `docs/FIRST_RUST_USERSPACE_IMPLEMENTATION_STAIRCASE_P11-03.md`
- `docs/KERNEL_MODULE_FAMILY_MATRIX_ROLLOUT_ORDER_P7-01.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for performance truth:

- one coordinating family: **`family.performance_budget.performance_budget_0`**
- one execution law: **`law.measure_normalize_budget_gate.performance_budget_0`**
- one canonical proof chain for every release-relevant performance claim:
  - **row binding -> workload envelope -> environment profile -> comparator set -> measurement vector -> normalized KPI vector -> budget evaluation -> regression bucket set -> gate receipt**

This means tidefs is no longer allowed to say only:
- “fio was fast enough”,
- “xfstests stayed green so performance is probably okay”,
- “the Rust shadow felt comparable”,
- “failover only paused briefly”,
- or “the control-plane call returned soon enough on my laptop”.

It must instead say:
- which subject family and workload envelope were measured,
- which environment profile and noise policy applied,
- which KPIs were mandatory for the row,
- which absolute and relative budget thresholds were in force,
- which baseline or comparator set was used,
- which regression buckets opened,
- and which shared gate receipt admitted, blocked, or forced rollback/cutover refusal.

The anti-regression rule is explicit:

**A row is never performance-closed merely because average throughput improved. It is closed only when the row’s required latency, tail, throughput, disruption-window, and recovery-window budgets all pass under one declared workload envelope and environment profile.**

## 2. Scope and boundaries

This document governs:
- the typed KPI families for release and cutover decisions,
- the workload-envelope families used by userspace-first and future kernel variants,
- environment-profile and noise-policy law,
- absolute and relative budget-threshold law,
- regression bucket grammar,
- performance artifact requirements,
- and how performance proof feeds smoke, quick, release, cutover, rollback, and soak/disaster gates.

This document now consumes the exact build / packaging / feature matrix that materializes benchmark and gate executables in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`.

That boundary is deliberate.
`P10-03` fixes the performance grammar and numeric gate law.


One clarification is important:
- `reserve` / `product-admission` **budget domains** from earlier design rule remain about scarce-capacity and utility governance,
- while `performance_budget_0` **performance budgets** are about latency, throughput, tail, disruption, and recovery thresholds.

They interact, but they are not the same thing and may not be conflated.

## 3. Matrix family and suite law

### 3.1 Matrix family and row shape

The detailed performance matrix is now fixed as:
- **`matrix.performance.budget.performance_budget_0`**

Every concrete `performance_budget_0` row must declare at least:
- `subject_family_ref`
- `workload_envelope_ref`
- `environment_profile_ref`
- `noise_policy_ref`
- `kpi_family_refs[]`
- `budget_threshold_refs[]`
- `baseline_policy_ref`
- `required_artifact_class_refs[]`
- `gate_class_refs[]`
- optional `linked_cc0_row_refs[]`
- optional `linked_mx0_row_refs[]`

The anti-regression rule is explicit:

**No row may exist as “run perf around this subsystem.” The workload envelope, environment profile, KPI families, threshold classes, and comparator set must all be first-class fields.**

### 3.2 Minimum suite families

Tool names remain execution backends only.
The stable contract lives in named suite families.

The production design now requires these minimum `performance_budget_0` suite families:

1. **`suite.performance_budget_0.policy_authority.publish_commit.test_profile_0`**
   - successor publication, admission, and request-family commit latency/throughput

2. **`suite.performance_budget_0.posix_filesystem_adapter.metadata_hotset.test_profile_1`**
   - lookup/create/unlink/rename and hot metadata-path behavior for `posix_filesystem_adapter`

3. **`suite.performance_budget_0.posix_filesystem_adapter.stream_mix.test_profile_2`**
   - warm/cold read-write mixes, `fsync`, and `mmap`/writeback-visible data-path behavior for `posix_filesystem_adapter`

4. **`suite.performance_budget_0.block_volume_adapter.random_queue.test_profile_3`**
   - random/direct queue throughput and latency under `ublk` / block-export pressure

5. **`suite.performance_budget_0.block_volume_adapter.flush_barrier.test_profile_4`**
   - flush/FUA/discard/zero paths and durability-barrier cost

6. **`suite.performance_budget_0.control_plane.policy_publish_activate.test_profile_5`**
   - dry-run, publish, activate, rollback, and admission-latency behavior for `control_plane`

7. **`suite.performance_budget_0.secret_key_policy_0.lease_rotate.test_profile_6`**
   - lease issuance, revocation drain, and rotation/rewrap latency windows for `secret_key_policy_0`

8. **`suite.performance_budget_0.explanation_query.query_render.test_profile_7`**
   - answer/render latency for exact, stale, degraded, and deep-lineage `explanation_query` requests

9. **`suite.performance_budget_0.runtime_recovery_0.failover_resume.test_profile_8`**
   - failover, fence, degrade/deny visibility, replay catch-up, and service-resume windows

10. **`suite.performance_budget_0.migration_cutover_0.cutover_pause.test_profile_9`**
    - shadow cutover, rollback/re-entry, and stage-pause windows for `migration_cutover_0` / `userspace`

### 3.3 Workload-envelope classes

Every `performance_budget_0` row must bind to one named workload envelope.
The minimum workload-envelope families are:
- `envelope.performance_budget_0.meta_hotset.e0`
- `envelope.performance_budget_0.read_write_mix.e1`
- `envelope.performance_budget_0.sequential_stream.e2`
- `envelope.performance_budget_0.sync_durable_write.e3`
- `envelope.performance_budget_0.random_block_export.e4`
- `envelope.performance_budget_0.policy_publish_activate.e5`
- `envelope.performance_budget_0.secret_lease_rotation.e6`
- `envelope.performance_budget_0.query_render.e7`
- `envelope.performance_budget_0.failover_resume.e8`
- `envelope.performance_budget_0.cutover_pause_resume.e9`

No budget may be expressed only against a tool default profile or an undocumented benchmark script.

## 4. KPI families, environment profiles, and numeric budget law

### 4.1 Mandatory KPI families

The production design now fixes these KPI families:

1. **`kpi.performance_budget_0.latency.core`**
   - p50 / p95 / p99 latency for the declared envelope

2. **`kpi.performance_budget_0.tail_amplification`**
   - p99 / p50 ratio and maximum stall window

3. **`kpi.performance_budget_0.throughput.floor`**
   - MiB/s, ops/s, or request/s floor for the row

4. **`kpi.performance_budget_0.disruption.window`**
   - visible pause, refusal, or degrade window during failover/cutover

5. **`kpi.performance_budget_0.recovery.window`**
   - time to legal steady state after the event or run starts

6. **`kpi.performance_budget_0.freshness.propagation`**
   - commit/publish to visible-freshness lag where the row requires it

7. **`kpi.performance_budget_0.control_surface.latency`**
   - `control_plane` / `secret_key_policy_0` / operator-facing latency classes

8. **`kpi.performance_budget_0.query_render.latency`**
   - `explanation_query` render and lineage-query latency classes

9. **`kpi.performance_budget_0.pressure.efficiency`**
   - reserve burn, memory growth, or CPU-per-unit-work ceilings for the row

10. **`kpi.performance_budget_0.success.rate`**
    - bounded refusal/error rate under the declared envelope, excluding intentionally degraded or policy-refused outcomes

A row may use only the subset that applies, but the subset must be declared.

### 4.2 Mandatory environment profiles

The production design now requires these environment profiles:

| Environment profile | Purpose |
|---|---|
| `env.performance_budget_0.dev_local.e0` | workstation/laptop smoke and local iteration |
| `env.performance_budget_0.ci_vm.e1` | constrained CI or ephemeral premerge environment |
| `env.performance_budget_0.single_node_ref.e2` | reference single-node release host |
| `env.performance_budget_0.cluster_ref.e3` | reference clustered release/cutover host set |
| `env.performance_budget_0.mixed_kernel_ref.e4` | mixed userspace/kernel reference environment |
| `env.performance_budget_0.soak_disaster_ref.e5` | prolonged soak/disaster reference environment |

Gate law depends on profile:
- `e0` and `e1` may close smoke/quick sentinel rows,
- `e2` and `e3` are mandatory for release-required userspace rows,
- `e4` is mandatory once mixed userspace/kernel rows exist,
- and `e5` is mandatory for declared soak/disaster rows.

### 4.3 Noise-policy law

Every environment profile must bind one noise policy.
The mandatory noise policies are:
- `noise.performance_budget_0.local.n0`
- `noise.performance_budget_0.ci_conservative.n1`
- `noise.performance_budget_0.reference_host.n2`
- `noise.performance_budget_0.cluster_event.n3`

The minimum rules are:
- warmup time and warmup samples must be declared,
- sample count may not be “until it looks stable”,
- percentile calculations must use raw operation samples or declared histogram merges, not average-of-averages,
- and a run whose variance exceeds the row’s declared noise tolerance becomes `unknown`, not a silent pass.

### 4.4 Default numeric budget classes

The production design now fixes the first stable numeric budget classes.
These are **gate floors**, not marketing claims.
A later policy revision may tighten them, but may not silently loosen them.

| Budget class | Applies to | Required floor / ceiling |
|---|---|---|
| `budget.performance_budget_0.policy_authority.publish_commit.r0` | `policy_authority` publish/admission rows | on `e2`: p95 <= 30 ms, p99 <= 100 ms; on `e3`: p95 <= 150 ms, p99 <= 500 ms; publish-to-visible-freshness p95 <= 250 ms |
| `budget.performance_budget_0.posix_filesystem_adapter.metadata_hotset.r1` | hot metadata path rows | on `e2`/`e4`: p95 <= 4 ms, p99 <= 15 ms; relative throughput >= 85% of previous admitted variant on same row |
| `budget.performance_budget_0.posix_filesystem_adapter.stream_mix.r2` | `posix_filesystem_adapter` data-path stream/mixed rows | throughput >= 60% of incumbent local-fs comparator; no non-sync p99 stall > 100 ms |
| `budget.performance_budget_0.block_volume_adapter.random_queue.r3` | random block-export rows | throughput >= 65% of previous admitted variant or declared raw-block comparator; p99 <= 25 ms |
| `budget.performance_budget_0.block_volume_adapter.flush_barrier.r4` | flush/FUA/barrier rows | on `e2`: p95 <= 35 ms, p99 <= 125 ms; on `e3`/`e4`: p95 <= 150 ms, p99 <= 500 ms |
| `budget.performance_budget_0.control_plane.policy_activate.r5` | `control_plane` dry-run/publish/activate/rollback rows | dry-run p95 <= 100 ms, p99 <= 300 ms; activate or rollback p95 <= 300 ms, p99 <= 1 s |
| `budget.performance_budget_0.secret_key_policy_0.lease_rotate.r6` | `secret_key_policy_0` lease/rotate/revoke rows | lease issue p95 <= 20 ms, p99 <= 75 ms; revoke-drain p95 <= 2 s, p99 <= 10 s; leaf-rotation cutover <= 300 s |
| `budget.performance_budget_0.explanation_query.query_render.r7` | `explanation_query` answer/render rows | warm answer p95 <= 50 ms, p99 <= 200 ms; deep-lineage answer p95 <= 300 ms, p99 <= 1.2 s |
| `budget.performance_budget_0.runtime_recovery_0.failover_resume.r8` | failover/fence/recovery rows | degraded/refusal state visible <= 1 s after fence trigger; resumed legal service p95 <= 15 s, p99 <= 60 s |
| `budget.performance_budget_0.migration_cutover_0.cutover_pause.r9` | cutover/rollback/re-entry rows | cutover pause p95 <= 3 s, p99 <= 15 s; rollback re-entry p95 <= 30 s, p99 <= 120 s |

### 4.5 Relative regression-lock law

Absolute floors alone are not enough.
The design now also fixes these relative regression locks:

- no `release_required` row may regress more than **15%** on required p95 latency against the previous admitted variant unless the budget record itself changes by policy,
- no `release_required` row may regress more than **10%** on required throughput against the previous admitted variant unless the budget record itself changes by policy,
- no `shadow_cutover` row may regress more than **10%** against the shadow/reference comparator on declared cutover-critical KPIs,
- no steady-state row may exceed a **p99/p50** tail-amplification ratio of **10x**,
- and no declared degraded/fault row may exceed a **p99/p50** tail-amplification ratio of **20x**.

A row that violates a regression lock opens a bucket even if its absolute floor barely passes.

## 5. Baseline, comparator, and measurement law

### 5.1 Baseline policy families

Every `performance_budget_0` row must declare one baseline policy family.
The mandatory families are:
- `baseline.performance_budget_0.absolute_contract.b0`
- `baseline.performance_budget_0.previous_admitted_variant.b1`
- `baseline.performance_budget_0.incumbent_charter_peer.b2`
- `baseline.performance_budget_0.shadow_target_pair.b3`
- `baseline.performance_budget_0.degraded_fault_window.b4`

Typical use:
- `b0` for hard SLO rows,
- `b1` for release regression lock,
- `b2` where a Linux-facing or block-facing incumbent comparator matters,
- `b3` for cutover parity,
- `b4` for fault/degraded rows shared with `cutover_control_0`.

### 5.2 Environment manifest rule

Every run that hopes to close a `performance_budget_0` row must emit an environment snapshot that includes at least:
- host class and CPU count,
- memory size and cgroup limit if present,
- kernel baseline,
- storage backend class,
- network/cluster shape if relevant,
- feature gates and variant ref,
- background-load declaration,
- cache-state declaration,
- and the exact noise policy bound to the run.

A performance claim without an environment manifest is invalid.

### 5.3 Measurement-vector rule

Every run must emit a measurement vector that includes at least the KPIs required by the row, plus:
- the row id,
- the comparator refs used,
- warmup discard count,
- sample count,
- normalization rule ref,
- and the resulting verdict class.

Where relevant, the measurement vector must also include:
- reserve delta,
- memory-growth delta,
- CPU utilization summary,
- queue-depth summary,
- and linked fault/cutover phase refs.

### 5.4 Absolute-plus-relative decision law

A release-relevant row passes only when all of these are true:
- its absolute budget class passes,
- its relative regression lock passes,
- its environment profile is admissible for the target gate,
- and all required artifacts exist.

This forbids the common failure mode where a row passes because one comparator improved while tail latency, pause windows, or failover recovery quietly regressed.

## 6. Regression bucket grammar

### 6.1 Mandatory bucket classes

The performance program now fixes these canonical bucket families:
- `bucket.performance_budget_0.absolute_floor_breach`
- `bucket.performance_budget_0.relative_regression_lock_breach`
- `bucket.performance_budget_0.tail_amplification_breach`
- `bucket.performance_budget_0.environment_or_noise_invalid`
- `bucket.performance_budget_0.failover_recovery_window_breach`
- `bucket.performance_budget_0.cutover_pause_window_breach`
- `bucket.performance_budget_0.control_surface_slo_breach`
- `bucket.performance_budget_0.secret_policy_latency_breach`
- `bucket.performance_budget_0.pressure_efficiency_breach`
- `bucket.performance_budget_0.comparator_or_baseline_divergence_unexplained`

These buckets must remain stable across archived lab, Rust shadow, Rust authoritative userspace, mixed userspace/kernel, and future kernel-heavy variants.

### 6.2 Blocking rules

Any of the following is release-blocking unless a stricter law says otherwise:
- `bucket.performance_budget_0.absolute_floor_breach` on a `release_required` row,
- `bucket.performance_budget_0.relative_regression_lock_breach` on a `release_required` row,
- `bucket.performance_budget_0.failover_recovery_window_breach` on a row bound to `runtime_recovery_0` or `cutover_control_0`,
- `bucket.performance_budget_0.cutover_pause_window_breach` on a row bound to `migration_cutover_0` or `userspace`,
- or `bucket.performance_budget_0.environment_or_noise_invalid` on any row required by the target gate.

### 6.3 Truthfulness rule

A performance bucket may never be rewritten into a narrative-only success because another KPI improved.
For example:
- higher throughput may not hide a cutover-pause breach,
- good p50 may not hide a p99 tail breach,
- and a faster control-plane dry-run may not hide a slow policy activation or secret-lease drain.


Every serious `performance_budget_0` campaign must emit these minimum artifact classes:

1. **workload-envelope manifest**
   - exact workload class, parameters, and row bindings

2. **environment profile snapshot**
   - hardware/runtime/kernel/variant/noise-policy state

3. **baseline/comparator manifest**
   - absolute budget refs, previous admitted variant refs, incumbent or shadow comparators

4. **raw measurement fragments**
   - histograms, counters, event windows, or other raw metric fragments

5. **normalized KPI vector**
   - canonical p50/p95/p99/throughput/disruption/recovery outputs

6. **budget evaluation summary**
   - per-threshold pass/fail results and regression-lock result

7. **regression bucket set**
   - normalized blockers/non-blockers with row lineage

8. **fault/cutover join manifest**
   - linked `cutover_control_0` or `migration_cutover_0` phase refs when the row requires them

9. **coverage/gate input snapshot**
   - which `performance_budget_0` rows are now covered or blocked for the target profile

10. **gate receipt or stop ticket**
    - release/cutover/rollback admission verdict or explicit blocking action

Missing artifact classes are performance failures, not clerical omissions.

## 8. Gate integration law

### 8.1 Budget gate classes

The production design now fixes these budget-gate classes:
- `gate.performance_budget_0.g0.smoke_sentinel`
- `gate.performance_budget_0.g1.quick_required`
- `gate.performance_budget_0.g2.release_variant`
- `gate.performance_budget_0.g3.shadow_cutover`
- `gate.performance_budget_0.g4.rollback_reentry`
- `gate.performance_budget_0.g5.soak_disaster`

They do **not** replace it.

### 8.2 Smoke and quick rules

- `gate.performance_budget_0.g0.smoke_sentinel` must include at least one sentinel row for every changed subject family and every newly introduced fast path.
- `gate.performance_budget_0.g1.quick_required` must include all rows marked `quick_required`, plus any `control_plane`, `secret_key_policy_0`, `runtime_recovery_0`, or `migration_cutover_0` rows touched by the change.

### 8.3 Release, cutover, rollback, and soak rules

- `gate.performance_budget_0.g2.release_variant` requires all release-required rows for the target variant on their required environment profiles.
- `gate.performance_budget_0.g3.shadow_cutover` requires shared-row comparison across reference, shadow, and target variants plus cutover-pause and recovery-window closure.
- `gate.performance_budget_0.g4.rollback_reentry` requires rollback/re-entry window closure under the same row ids used for cutover admission.
- `gate.performance_budget_0.g5.soak_disaster` requires long-duration rows, tail-amplification closure, and any linked `cutover_control_0` rows declared by the target profile.

### 8.4 Non-waivable rules

Temporary overrides still flow through `docs/AUTHN_AUTHZ_OVERRIDE_AUDIT_MODEL_P9-02.md`, but a waiver may **not**:
- hide an open performance bucket,
- hide a missing comparator or invalid environment profile,
- convert a failed `release_required` or `shadow_cutover` row into a real pass,
- or admit cutover when pause-window or recovery-window budgets remain open.

### 8.5 Adaptive-governor profile law

The production design now requires one shared bounded workload-reaction family:
- coordinating refinement family: `family.adaptive_governor.adaptive_governor_0`
- execution law: `law.observe_classify_bias_act_verify.adaptive_governor_0`

The minimum stable bias profiles are:
- `profile.adaptive_governor_0.efficiency.l2`
- `profile.adaptive_governor_0.efficiency.l1`
- `profile.adaptive_governor_0.balanced.l0`
- `profile.adaptive_governor_0.performance.l1`
- `profile.adaptive_governor_0.performance.l2`
- `profile.adaptive_governor_0.manual_pin.m0`

These profiles bias performance posture. They do **not** alter correctness, durability, quorum, or failure-domain minimums.

### 8.6 Safe actuator law

`adaptive_governor_0` may bias only admitted actuator classes such as:
- `actuator.adaptive_governor_0.prefetch_window.a0`
- `actuator.adaptive_governor_0.cache_floor_eviction_bias.a1`
- `actuator.adaptive_governor_0.dirty_seal_window.a2`
- `actuator.adaptive_governor_0.lane_credit_batch.a3`
- `actuator.adaptive_governor_0.foreground_background_bandwidth.a4`
- `actuator.adaptive_governor_0.rebuild_relocation_concurrency.a5`
- `actuator.adaptive_governor_0.replica_read_fanout.a6`
- `actuator.adaptive_governor_0.query_render_depth.a7`
- `actuator.adaptive_governor_0.materialization_retention_bias.a8`
- `actuator.adaptive_governor_0.materialization_build_refresh_budget.a9`

A profile may bias how tidefs spends lawful slack. It may not create a second admission, durability, placement, split-brain, or hidden materialization-utility law.

### 8.7 Observe / classify / verify law

Every serious live-duty row that depends on adaptive behavior must follow one shared control-loop pattern:
- observe fast-window and steady-window signals,
- classify the dominant workload and current stress posture,
- propose one bounded actuator delta under the effective profile,
- verify the change against tail, freshness, refusal, and pressure guards,
- and either keep or roll back the change.

A change that improves average throughput while harming declared tail/freshness/refusal goals is not a legal success.

### 8.8 Scope and override law

The effective `adaptive_governor_0` profile may be bound at cluster, pool/authority-domain, dataset/volume, runbook, or temporary session scope. Narrower scopes override broader scopes. Temporary manual pins must be TTL-bound and visibly rendered through `truth_view`; hidden permanent local overrides are forbidden.

## 9. Relationship to the rest of the production design

### 9.1 `P10-01` test architecture

`P10-01` is the shared row/profile/artifact/gate grammar.
`P10-03` does not replace it.
It fills the previously reserved `matrix.performance.budget.performance_budget_0` namespace with:
- typed workload envelopes,
- typed KPI families,
- numeric budget classes,
- and regression bucket law.

### 9.2 `P10-02` chaos / corruption campaigns

Rows that care about failover, degrade/deny visibility, replay catch-up, cutover under stress, or pressure-driven tail behavior must join `performance_budget_0` to `cutover_control_0`, not invent a separate performance-disaster language.

### 9.3 `P9-03` runbooks

Upgrade, failover, cutover, and rollback runbooks now inherit numeric performance/disruption floors.
A move is not complete merely because the procedural steps were legal; the shared `performance_budget_0` gates must also pass where the runbook declares them.

### 9.4 `P9-04` secret / policy storage / key-handling law

`P10-03` now fixes numeric ceilings for:
- lease issuance,
- revocation drain,
- activation latency,
- and rotation windows.

That means `secret_key_policy_0` is no longer allowed to be “secure but however slow it turns out.”

### 9.5 `P11-03` first Rust userspace staircase

`P10-03` now adds numeric floors to `gate.userspace.release_variant` and `gate.userspace.archive_ready` through shared `performance_budget_0` rows.
The userspace move may not invent a migration-local performance pass.

### 9.6 `P7-01` kernel rollout and `P11-04` later kernel progression

`P11-04` is now explicit in `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md`. Future kernel-family admission must inherit the same `performance_budget_0` row ids, workload envelopes, comparator rules, and gate grammar across the fixed `kernel_gateway` stage ladder. Crossing into the kernel may change the measured numbers, but it may not change the proof language.

### 9.7 `P10-04` operator truth surfaces

`P10-04` is now explicit in `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`.
That law renders:
- workload envelopes,
- budget classes,
- comparator refs,
- bucket sets,
- effective governor profile and recent actuator changes,
- and gate receipts
through shared `truth_view` surfaces, provenance badges, trace joins, and render receipts.

It may not invent a second performance narrative detached from `performance_budget_0` artifacts.

## 10. Anti-regression rules

1. **No performance claim without a named row, workload envelope, and environment profile.**
2. **No average-only pass; tail, throughput, and disruption-window budgets must be checked when the row requires them.**
3. **No release pass if the previous admitted variant or declared comparator is missing for a row that requires relative regression lock.**
4. **No cutover or rollback pass if pause-window or recovery-window budgets remain open.**
5. **No fault-stressed performance claim outside declared `cutover_control_0` joins.**
6. **No secret, policy, query, or operator-facing surface may escape `performance_budget_0` because it is “not the data path.”**
8. **No dashboard or narrative may hide which budget class failed or which comparator opened the bucket.**
9. **No static fixed-behavior implementation may claim compliance with `performance_budget_0` if it ignores the shared `adaptive_governor_0` observe/classify/bias/verify model where live adaptation is declared.**
10. **No full static topology or per-node cost table may stand in for measured runtime topology when a row depends on distributed or cluster behavior.**

## 11. Result

`P10-03` is closed when the repo can say, in production terms:
- which performance matrix family exists,
- which suite families execute it,
- which workload envelopes and environment profiles are legal,
- which KPI families and numeric thresholds are binding,
- which relative regression locks must hold,
- which artifacts every serious performance campaign must emit,
- and how smoke, quick, release, cutover, rollback, and soak/disaster gates consume those results.

That design condition is now met.

## 12. Implementation status (tracking)

This section is the runtime tracking ledger for issue #1154.
The design specification in sections 1-11 is complete.
Rudimentary measurement infrastructure, budget evaluation, regression bucket
tracking, and gate integration now exist via #6161 (see 12.12.1-12.12.5);
the remaining gaps are tracked in the tables below.

### 12.1 Suite families — 2 of 10 implemented

|---|---|---|---|
| 1 | `suite.performance_budget_0.policy_authority.publish_commit.test_profile_0` | **not-implemented** | — |
| 2 | `suite.performance_budget_0.posix_filesystem_adapter.metadata_hotset.test_profile_1` | **not-implemented** | Prior #6132 SourceModel/CargoUnit schema module retired; requires measured mounted-FUSE or QEMU artifacts |
| 3 | `suite.performance_budget_0.posix_filesystem_adapter.stream_mix.test_profile_2` | **not-implemented** | Prior #6132 SourceModel/CargoUnit schema module retired; requires measured mounted-FUSE or QEMU artifacts |
| 4 | `suite.performance_budget_0.block_volume_adapter.random_queue.test_profile_3` | **not-implemented** | — |
| 5 | `suite.performance_budget_0.block_volume_adapter.flush_barrier.test_profile_4` | **not-implemented** | — |
| 6 | `suite.performance_budget_0.control_plane.policy_publish_activate.test_profile_5` | **not-implemented** | — |
| 7 | `suite.performance_budget_0.secret_key_policy_0.lease_rotate.test_profile_6` | **not-implemented** | — |
| 8 | `suite.performance_budget_0.explanation_query.query_render.test_profile_7` | **not-implemented** | — |
| 9 | `suite.performance_budget_0.runtime_recovery_0.failover_resume.test_profile_8` | **not-implemented** | — |
| 10 | `suite.performance_budget_0.migration_cutover_0.cutover_pause.test_profile_9` | **not-implemented** | — |

### 12.2 KPI families — 2 of 10 tracked

|---|---|---|---|
| 1 | `kpi.performance_budget_0.latency.core` | **tracked** | #6132: `FusePerfMeasurements.latency_p50_us` / `latency_p99_us` / `latency_p999_us` per workload family |
| 2 | `kpi.performance_budget_0.tail_amplification` | **not-tracked** | — |
| 3 | `kpi.performance_budget_0.throughput.floor` | **tracked** | #6132: `FusePerfMeasurements.throughput_mb_s` and `FusePerfBudgetTarget.throughput_floor_mb_s` per workload family |
| 4 | `kpi.performance_budget_0.disruption.window` | **not-tracked** | — |
| 5 | `kpi.performance_budget_0.recovery.window` | **not-tracked** | — |
| 6 | `kpi.performance_budget_0.freshness.propagation` | **not-tracked** | — |
| 7 | `kpi.performance_budget_0.control_surface.latency` | **not-tracked** | — |
| 8 | `kpi.performance_budget_0.query_render.latency` | **not-tracked** | — |
| 9 | `kpi.performance_budget_0.pressure.efficiency` | **not-tracked** | — |
| 10 | `kpi.performance_budget_0.success.rate` | **not-tracked** | — |

### 12.3 Numeric budget classes — 0 of 10 enforced

|---|---|---|---|
| 1 | `budget.performance_budget_0.policy_authority.publish_commit.r0` | **not-enforced** | — |
| 2 | `budget.performance_budget_0.posix_filesystem_adapter.metadata_hotset.r1` | **not-enforced** | — |
| 3 | `budget.performance_budget_0.posix_filesystem_adapter.stream_mix.r2` | **not-enforced** | — |
| 4 | `budget.performance_budget_0.block_volume_adapter.random_queue.r3` | **not-enforced** | — |
| 5 | `budget.performance_budget_0.block_volume_adapter.flush_barrier.r4` | **not-enforced** | — |
| 6 | `budget.performance_budget_0.control_plane.policy_activate.r5` | **not-enforced** | — |
| 7 | `budget.performance_budget_0.secret_key_policy_0.lease_rotate.r6` | **not-enforced** | — |
| 8 | `budget.performance_budget_0.explanation_query.query_render.r7` | **not-enforced** | — |
| 9 | `budget.performance_budget_0.runtime_recovery_0.failover_resume.r8` | **not-enforced** | — |
| 10 | `budget.performance_budget_0.migration_cutover_0.cutover_pause.r9` | **not-enforced** | — |

### 12.4 Workload-envelope classes -- 10 defined, 1 executed at runtime

All 10 workload-envelope families (`e0` through `e9`) exist as design
contracts only. No workload-envelope manifest, parameter binding, or
row-linked execution exists at runtime.


All 6 environment profiles (`e0` through `e5`) are design contracts only.
No environment snapshot, hardware/runtime/kernel/variant capture, or
noise-policy binding exists at runtime.

### 12.6 Noise policies — 4 defined, 0 enforced

All 4 noise policy families (`n0` through `n3`) exist as design contracts.
at runtime.

### 12.7 Baseline policy families — 5 defined, 0 bound to runtime

All 5 baseline policy families (`b0` through `b4`) exist as design
contracts only. No baseline/comparator manifest binding exists at runtime.

### 12.8 Regression bucket classes — 10 defined, 0 tracked

|---|---|---|---|
| 1 | `bucket.performance_budget_0.absolute_floor_breach` | **not-tracked** | — |
| 2 | `bucket.performance_budget_0.relative_regression_lock_breach` | **not-tracked** | — |
| 3 | `bucket.performance_budget_0.tail_amplification_breach` | **not-tracked** | — |
| 4 | `bucket.performance_budget_0.environment_or_noise_invalid` | **not-tracked** | — |
| 5 | `bucket.performance_budget_0.failover_recovery_window_breach` | **not-tracked** | — |
| 6 | `bucket.performance_budget_0.cutover_pause_window_breach` | **not-tracked** | — |
| 7 | `bucket.performance_budget_0.control_surface_slo_breach` | **not-tracked** | — |
| 8 | `bucket.performance_budget_0.secret_policy_latency_breach` | **not-tracked** | — |
| 9 | `bucket.performance_budget_0.pressure_efficiency_breach` | **not-tracked** | — |
| 10 | `bucket.performance_budget_0.comparator_or_baseline_divergence_unexplained` | **not-tracked** | — |

### 12.9 Required artifact classes — 10 defined, 0 emitted

All 10 artifact classes (workload-envelope manifest, environment profile
snapshot, baseline/comparator manifest, raw measurement fragments,
normalized KPI vector, budget evaluation summary, regression bucket set,
fault/cutover join manifest, coverage/gate input snapshot, gate receipt or
stop ticket) exist as design requirements only. No artifact has been emitted
by any runtime measurement campaign.

### 12.10 Adaptive governor — not implemented

`family.adaptive_governor.adaptive_governor_0` with 6 bias profiles
(`efficiency.l2` through `manual_pin.m0`) and 10 actuator classes
(prefetch, cache eviction, dirty seal, lane credit, bandwidth, rebuild
concurrency, replica fanout, query depth, materialization retention,
materialization build budget) exists as design contract only. The
observe/classify/bias/verify control loop is not implemented.

### 12.11 Gate classes -- 6 defined, 1 integrated

|---|---|---|---|
| 2 | `gate.performance_budget_0.g1.quick_required` | **not-integrated** | — |
| 3 | `gate.performance_budget_0.g2.release_variant` | **not-integrated** | — |
| 4 | `gate.performance_budget_0.g3.shadow_cutover` | **not-integrated** | — |
| 5 | `gate.performance_budget_0.g4.rollback_reentry` | **not-integrated** | — |
| 6 | `gate.performance_budget_0.g5.soak_disaster` | **not-integrated** | — |

### 12.12 Relative regression locks — enforced via RegressionLock

The five relative regression locks (15% p95 latency, 10% throughput, 10%
shadow/cutover parity, 10x steady-state tail, 20x degraded/fault tail)
are now enforced at row recording time via #6161; see 12.12.4 for the
code-level mechanism.


### 12.12.1 Measurement-source enforcement (issue #6161)

not from placeholder schema entries. The `MeasurementSource` enum now
distinguishes `Measured` from `SchemaOnly` on every performance gate row:

- `PerformanceGateEntry.measurement_source` defaults to `SchemaOnly`.
- `GateRunner::record()` auto-sets `Measured` for live-runtime tiers with
  non-empty KPI vectors; everything else stays `SchemaOnly`.
  `is_live_runtime()` + `Measured`.
- `PerformanceMatrix::summary()` reports `runtime_pass` and `code_only_pass`
  separately.
  plus subject-completeness.
- `FusePerfBudgetEngine::record_source_model()` and `record_cargo_unit()`
  explicitly set `SchemaOnly`; source-model-only rows no longer close the
  register.

SourceModel/CargoUnit/Kbuild rows are not maintained as standalone
performance-budget deliverables. The matrix shape belongs in the generic
`performance_gate` machinery, but suite implementation requires measured
runtime/comparator artifacts.

### 12.12.2 Artifact requirement enforcement (issue #6161 step 2)

Live-runtime tier rows (MountedUserspace through FullKernelNoDaemon) now
carry an `ArtifactRequirement` that gates PASS status. The requirement
mandates:

- `artifact_path`: measurement artifact file must be present.
- `comparator`: at least one comparator ref (ext4 baseline, previous-admitted
  variant, raw block, etc.) must be declared.
- `noise_policy`: the environment's noise policy must have a non-empty
  `ref_id`.
- `kpis`: a non-empty normalized KPI vector is required.
- `env_profile`: the environment manifest must have a non-empty
  `profile_ref`.

`GateRunner::record()` auto-applies `ArtifactRequirement::live_runtime()` for
all live-runtime tiers and calls `PerformanceGateEntry::enforce_artifact_requirements()`.
If the row was marked Pass but fails any artifact check, it is downgraded
to Refuse with a note listing the missing artifacts. Code-only tiers
(SourceModel, CargoUnit, Kbuild) carry `ArtifactRequirement::none()` and
are exempt.

`MatrixSummary` and `ReceiptSummary` now report `artifact_gap`: the count
of live-runtime rows that fail artifact requirements.  The markdown render
includes this metric.  `GateReceiptRow` surfaces `artifacts_satisfied` per
row.

Non-executable rows (no harness, no device, blocked environment) remain
FAIL/BLOCKED/REFUSED as appropriate.


### 12.12.3 Comparator manifest and harness (issue #6161 step 3)

Performance gate rows now carry a  field populated by the
Performance gate rows carry a `comparators` field populated by
`ComparatorHarness`, which executes fio benchmarks against incumbent
filesystems and captures baseline KPI vectors:

- `ComparatorKind` enumerates five types:
  `Ext4Posix` (fio against ext4 mount on the same backend device),
  `RawBlockBaseline` (fio against raw block device for ublk rows),
  `PreviousTideFS` (previous-admitted variant for regression lock),
  `ZfsStaged` (ZFS unavailable — release blocker for superiority claims),
  `CephStaged` (Ceph unavailable — release blocker for superiority claims).
- `ComparatorManifest::comparators_for(subject)` returns the required
  comparator kinds per subject row (e.g., `mounted-fuse` needs ext4 +
  ZFS + Ceph; `ublk-direct` needs raw-block + ext4; kernel rows are
  staged with all three primary kinds).
- `ComparatorHarness::run_all(subject, kinds)` runs ext4 and raw-block
  comparators via `FioHarness` (creates a 512 MiB ext4 image, mounts
  it, runs fio, captures baseline KPIs, then unmounts and cleans up).
  Execution failures (no fio binary, no mkfs.ext4, mount failure) return
  staged `ComparatorRun` entries with blocker notes.
- `ComparatorRun` records `executed` status, `baseline_kpis`, and an
  optional `blocker` reason; staged runs include ZFS/Ceph as visible
  release blockers.
- `GateRunner::run_comparators(harness)` populates `comparators` on each
  live-runtime `PerformanceGateEntry` and tracks all `ComparatorRun`
  entries in the `GateReceipt.comparator_runs` field.
- `ComparatorRun::to_comparator_ref()` produces `ComparatorRef` entries
  suitable for budget evaluation and regression-lock checks (see 12.12.4).
- `ComparatorKind::requires_execution()` returns true only for `Ext4Posix`
  and `RawBlockBaseline`; `is_staged()` returns true for `ZfsStaged` and
  `CephStaged`.

The ZFS and Ceph comparators remain staged/unavailable, keeping the
superiority-claim release blocker visible in all receipts.

### 12.12.4 Numeric budget and regression lock enforcement (issue #6161 step 4)

P10 numeric budget classes (section 4.4) and relative regression locks
(section 4.5) are now automatically enforced at row recording time:

- `NumericBudget` holds absolute thresholds: `throughput_floor_mb_s`,
  `latency_p95_ceiling_us`, `latency_p99_ceiling_us`, `iops_floor`,
  and a `budget_class_ref`.
- `RegressionLock` holds relative rules: `p95_latency_regression_pct`
  (default 15%), `throughput_regression_pct` (default 10%), and
  `tail_amplification_max` (steady-state 10x, degraded 20x).
- `BudgetBucket` enumerates violation types: absolute thresholds
  (`ThroughputFloor`, `LatencyP95Ceiling`, `LatencyP99Ceiling`,
  `IopsFloor`), relative regressions (`LatencyRegression`,
  `ThroughputRegression`, `TailAmplification`), and data gaps
  (`NoComparator`, `InvalidNoiseProfile`, `InsufficientSamples`,
  `MissingArtifact`).
- `PerformanceGateEntry::evaluate_budget()` checks KPI values against
  declared budgets, opens buckets per violation, and downgrades PASS to
  FAIL if any release-blocking bucket is open.
- `GateRunner::record()` auto-applies `default_numeric_budget_for(subject)`
  and `RegressionLock::release_required()` for live-runtime tiers, then
  calls `evaluate_budget()`.
- `MatrixSummary` and `ReceiptSummary` now include `budget_gap` (rows
  with open budget buckets).  The markdown render includes this metric.
- `GateReceiptRow` surfaces `budget_buckets` as a list of label strings.

### 12.12.5 Gate receipt rendering and release-ready gating (issue #6161 step 5)

The complete enforcement chain feeds into a single `GateReceipt` that can
be inspected through `render_markdown()`:

- **`GateReceipt::render_markdown()`**: Produces a complete markdown report
  with summary metrics (total, runtime_pass, code_only_pass, failed, refused,
  budget decision, artifacts_satisfied, budget_buckets), comparator runs
  (ref_id, executed, KPI count, blocker), and notes.
- **`release_ready`**: Now requires all four gates:
  1. Subject completeness (`invariant_holds`)
  3. Zero artifact gap (all live-runtime rows satisfy artifact requirements)
  4. Zero budget gap (no budget violations on any row)
  A receipt with open artifact or budget gaps is `NOT READY` regardless of
  pass counts.
- `build_current_head_receipt` and `build_current_head_with_benches` both
  produce full-featured receipts with render_markdown available.

This means performance work items remain open while measured gates are
missing: the receipt explicitly shows which artifacts, comparators, and
budgets are still outstanding.

### 12.13 Summary

| Category | Defined | Implemented |
|---|---|---|
| Suite families | 10 | 2 (#6132: metadata_hotset, stream_mix) |
| KPI families | 10 | 2 (#6132: latency.core, throughput.floor) |
| Numeric budget classes | 10 | 3 (posix_stream_mix, block_random_queue, general_purpose; enforced via NumericBudget/RegressionLock) |
| Workload-envelope classes | 10 | 0 |
| Environment profiles | 6 | 0 |
| Noise policies | 4 | 0 |
| Baseline policy families | 5 | 0 |
| Regression bucket classes | 10 | 1 (BudgetBucket enum: 10 variants) |
| Required artifact classes | 10 | 1 (ArtifactRequirement::live_runtime enforced) |
| Adaptive governor bias profiles | 6 | 0 |
| Adaptive governor actuator classes | 10 | 0 |
| Gate classes | 6 | 1 (smoke_sentinel: code-only passes demoted) |
| Relative regression locks | 5 | 1 (enforced via RegressionLock) |
| Measurement-source enforcement | — | integrated (#6161) |
| Artifact requirement enforcement | — | integrated (#6161) |
| Comparator manifest and harness | — | integrated (#6161) |
| Numeric budget enforcement | — | integrated (#6161) |
| Gate receipt rendering | — | integrated (#6161: render_markdown on GateReceipt + PerformanceMatrix) |

Issue #1154 tracks closure: when each category reaches its minimum
implemented count and the coordinating family
`family.performance_budget.performance_budget_0` executes at runtime with
