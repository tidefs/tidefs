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

The design now also requires these storage-intent `performance_budget_0` suite families.
Every storage-intent row must bind its ack class, workload envelope, prediction
confidence class, action class, media/topology/proximity profile, trust/domain
evidence, data-shape evidence, allocator/layout evidence, and comparator set.

Required evidence refs per row:
  * `service_objective_ref` from #915 (blocking for caller-visible outcome rows, schema/readiness-only otherwise)
  * `evidence_query_snapshot_ref` from #913
  * `measurement_attribution_ref` from #912
  * `result_refusal_ref` from #920 (blocking for caller-visible outcome rows, schema/readiness-only otherwise)
  * `comparator_evidence_ref` from #928 and `claim_id_ref` from #875 (blocking for comparator/superiority rows, schema/readiness-only otherwise)

Rows missing those refs are schema/readiness artifacts only, not performance,
durability, WAN, wear, cost, RPO, comparator, or successor proof.

11. **`suite.performance_budget_0.storage_intent.small_sync_local_intent.r10`**
    - small-sync write acknowledgment latency for local intent (single-node, single-media-class)
    - KPI families: latency.core, tail_amplification, success.rate
    - evidence refs: #915, #913, #912, #920, #898 (capacity admission), #750 (membership/epoch), #894 (ordering/replay)

12. **`suite.performance_budget_0.storage_intent.small_sync_quorum_intent.r11`**
    - small-sync write acknowledgment latency for quorum/geo intent (multi-node, multi-failure-domain)
    - KPI families: latency.core, tail_amplification, success.rate, freshness.propagation
    - evidence refs: #915, #913, #912, #920, #750, #894, #846 (transport path), #897 (trust/domain)

13. **`suite.performance_budget_0.storage_intent.full_placement_fsync.r12`**
    - durability-barrier latency for full-placement fsync/FUA
    - KPI families: latency.core, tail_amplification, throughput.floor, success.rate
    - evidence refs: #915, #913, #912, #920, #898, #750, #894

14. **`suite.performance_budget_0.storage_intent.vm_fua_barrier_tail.r13`**
    - VM FUA/barrier tail latency under concurrent foreground I/O
    - KPI families: latency.core, tail_amplification, disruption.window
    - evidence refs: #915, #913, #912, #920, #898

15. **`suite.performance_budget_0.storage_intent.metadata_storm_fsyncdir.r14`**
    - metadata-storm p99 latency and fsyncdir behavior under high create/unlink/rename pressure
    - KPI families: latency.core, tail_amplification, throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #922 (metadata/namespace)

16. **`suite.performance_budget_0.storage_intent.read_serving_source.r15`**
    - read-serving latency per source class (cache, trial, RAM, local/remote receipt, degraded, snapshot, geo, archive)
    - includes stale/refresh/refusal rate per source class
    - KPI families: latency.core, tail_amplification, freshness.propagation, success.rate
    - evidence refs: #915, #913, #912, #920, #844 (read serving), #856 (source classes), #900 (recovery/degradation)

17. **`suite.performance_budget_0.storage_intent.degraded_read_reconstruction.r16`**
    - degraded-read reconstruction latency and repair-on-read foreground/wear/cost budget
    - KPI families: latency.core, tail_amplification, throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #900, #904 (media capability)

18. **`suite.performance_budget_0.storage_intent.streaming_ingest_throughput.r17`**
    - streaming ingest throughput with measured flash wear per TiB logical writes
    - must prove no flash wear explosion under sustained streaming writes
    - KPI families: throughput.floor, pressure.efficiency, success.rate
    - evidence refs: #915, #913, #912, #920, #845 (media wear ledger/wear), #904

19. **`suite.performance_budget_0.storage_intent.data_shape_selection.r18`**
    - data-shape selection behavior under latency, throughput, CPU, WAN, capacity, and wear budgets
    - covers record sizing, compression, checksum/digest, dedup, encryption, EC, archive conversion
    - KPI families: latency.core, throughput.floor, pressure.efficiency, success.rate
    - evidence refs: #915, #913, #912, #920, #878 (data-shape selection), #842 (rebake payback)

20. **`suite.performance_budget_0.storage_intent.allocator_layout_behavior.r19`**
    - allocator/layout behavior under fragmentation, free-run scarcity, zone/alignment, block-volume, ENOSPC, and reclaim-debt pressure
    - KPI families: latency.core, tail_amplification, throughput.floor, pressure.efficiency, success.rate
    - evidence refs: #915, #913, #912, #920, #843 (placement planning), #898

21. **`suite.performance_budget_0.storage_intent.one_pass_scan_no_promotion.r20`**
    - one-pass scan behavior proving no persistent flash promotion without explicit policy and payback
    - KPI families: pressure.efficiency, success.rate
    - evidence refs: #915, #913, #912, #920, #967 (prefetch/residency), #972 (executor outcomes)

22. **`suite.performance_budget_0.storage_intent.hot_read_cache_trial.r21`**
    - hot read cache-only serving trial benefit/cost measurement
    - cache hit rate, trial benefit, foreground disruption, capacity cost
    - KPI families: latency.core, throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #967, #972, #844

23. **`suite.performance_budget_0.storage_intent.persistent_hot_promotion.r22`**
    - persistent hot serving promotion benefit/cost including dwell, wear reservation, and payback
    - must track: promotion dwell, wear reservation consumed, payback verdict, cooldown state
    - KPI families: latency.core, throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #967, #972, #848 (relocation), #845 (wear)

24. **`suite.performance_budget_0.storage_intent.phase_change_anti_thrash.r23`**
    - phase-changing sparse workload anti-thrash behavior
    - must prove that sparse-to-dense or dense-to-sparse phase changes do not trigger unbounded promotion/demotion cycles
    - KPI families: latency.core, tail_amplification, throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #967, #848

25. **`suite.performance_budget_0.storage_intent.noisy_tenant_isolation.r24`**
    - noisy/adversarial multi-tenant prediction suppression and budget isolation
    - must prove that one tenant's bulk/scan/relocation work does not destroy another tenant's p99 sync latency
    - KPI families: latency.core, tail_amplification, throughput.floor, success.rate
    - evidence refs: #915, #913, #912, #920, #902 (tenant/isolation), #901 (policy rollout)

26. **`suite.performance_budget_0.storage_intent.hdd_defrag_benefit.r25`**
    - HDD defrag benefit under seek-heavy and scan-heavy workloads
    - KPI families: latency.core, throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #848, #904

27. **`suite.performance_budget_0.storage_intent.ssd_relocation_waf.r26`**
    - SSD relocation WAF benefit/cost and failed-payback cooldown behavior
    - must track: WAF delta, wear reservation, payback verdict, cooldown, skipped-move reasons
    - KPI families: throughput.floor, pressure.efficiency
    - evidence refs: #915, #913, #912, #920, #848, #845, #904

28. **`suite.performance_budget_0.storage_intent.rebake_payback.r27`**
    - rebake payback for compression, dedup, record sizing, checksum/digest, EC, and archive conversion
    - must track: CPU cost, read amplification, degraded-read cost, rebake throughput
    - KPI families: latency.core, throughput.floor, pressure.efficiency, success.rate
    - evidence refs: #915, #913, #912, #920, #842, #878, #900

29. **`suite.performance_budget_0.storage_intent.rebuild_repair_foreground.r28`**
    - rebuild/repair foreground protection
    - must prove rebuild does not destroy foreground p99 latency or exhaust recovery reserves
    - KPI families: latency.core, tail_amplification, throughput.floor, recovery.window
    - evidence refs: #915, #913, #912, #920, #900, #898

30. **`suite.performance_budget_0.storage_intent.geo_async_rpo_lag.r29`**
    - geo-async RPO lag under WAN and internet envelopes
    - must track: timebase/skew/frontier evidence, catch-up rate, RPO ceiling
    - KPI families: freshness.propagation, recovery.window, throughput.floor
    - evidence refs: #915, #913, #912, #920, #846, #750, #894

31. **`suite.performance_budget_0.storage_intent.trust_domain_changes.r30`**
    - trust-domain and key-epoch changes under remote, repair, geo, cross-domain sharing, and internet envelopes
    - must include wrong-domain, stale-key, missing-authorization, residency, and quarantine cases
    - KPI families: latency.core, success.rate, freshness.propagation
    - evidence refs: #915, #913, #912, #920, #897, #750

32. **`suite.performance_budget_0.storage_intent.geo_intent_latency.r31`**
    - geo-intent acknowledgment latency under the same WAN/internet path envelopes as r29
    - KPI families: latency.core, tail_amplification, success.rate
    - evidence refs: #915, #913, #912, #920, #846, #750, #897

33. **`suite.performance_budget_0.storage_intent.ram_volatile_intent_latency.r32`**
    - RAM volatile and RAM intent-backed acknowledgment latency
    - must distinguish volatile RAM (no durability) from intent-backed RAM (receipt-persisted)
    - KPI families: latency.core, tail_amplification, success.rate, freshness.propagation
    - evidence refs: #915, #913, #912, #920, #847 (RAM authority), #904

34. **`suite.performance_budget_0.storage_intent.media_wear_per_tib.r33`**
    - media wear per TiB logical writes across all media classes (NVMe, SSD, HDD)
    - must track: logical bytes, estimated media bytes, WAF, flash wear per TiB logical writes
    - KPI families: pressure.efficiency, success.rate
    - evidence refs: #915, #913, #912, #920, #845, #904, #957 (media-native convergence)

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

Storage-intent workload envelope extensions:
  * `envelope.performance_budget_0.storage_intent.small_sync_local.e10`
    small sync workload, single media class, local topology
  * `envelope.performance_budget_0.storage_intent.small_sync_quorum.e11`
    small sync workload, quorum topology, WAN/internet paths
  * `envelope.performance_budget_0.storage_intent.full_placement_fsync.e12`
    full-placement fsync/FUA workload with concurrent foreground I/O
  * `envelope.performance_budget_0.storage_intent.metadata_storm.e13`
    high-rate create/unlink/rename/fsyncdir workload
  * `envelope.performance_budget_0.storage_intent.read_multi_source.e14`
    read workload spanning cache, trial, RAM, local/remote receipt, degraded, snapshot, geo, archive sources
  * `envelope.performance_budget_0.storage_intent.degraded_reconstruction.e15`
    degraded/repair workload with missing or corrupt storage targets
  * `envelope.performance_budget_0.storage_intent.streaming_ingest.e16`
    sustained streaming write ingest measuring flash wear
  * `envelope.performance_budget_0.storage_intent.data_shape_selection.e17`
    workload exercising data-shape selection under latency/throughput/CPU/WAN/capacity/wear budgets
  * `envelope.performance_budget_0.storage_intent.allocator_pressure.e18`
    allocator/layout workload under fragmentation, free-run scarcity, zone/alignment, ENOSPC pressure
  * `envelope.performance_budget_0.storage_intent.one_pass_scan.e19`
    one-pass scan workload with flash promotion measurement
  * `envelope.performance_budget_0.storage_intent.hotset_promotion.e20`
    hot-set promotion/demotion workload measuring dwell, wear reservation, and payback

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

Storage-intent KPI family extensions:

11. **`kpi.performance_budget_0.storage_intent.wear_per_tib`**
    - flash wear per TiB logical writes, WAF, media bytes consumed per logical byte

12. **`kpi.performance_budget_0.storage_intent.cost.per_byte`**
    - network egress, CPU cost, memory growth, evidence-storage cost per unit work

13. **`kpi.performance_budget_0.storage_intent.movement.debt`**
    - movement debt delta, payback window, cooldown state, skipped-move reasons

14. **`kpi.performance_budget_0.storage_intent.prediction.confidence`**
    - prediction confidence class, action class, missing-outcome evidence, failed-payback counts,
      wrong-domain or stale-key refusal counts

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
Storage-intent environment profile extensions:
  * `env.performance_budget_0.storage_intent.wan_internet.e6`
    WAN and internet path environment for geo/RPO/trust-domain rows
  * `env.performance_budget_0.storage_intent.multitenant_adversarial.e7`
    multi-tenant noisy-neighbor environment for isolation rows


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

Storage-intent numeric budget classes (schema/readiness floors -- runtime measurement evidence belongs to later implementation/validation issues):

| Budget class | Applies to | Required floor / ceiling |
|---|---|---|
| `budget.performance_budget_0.storage_intent.small_sync_local.r10` | small sync local intent rows | p50 <= 0.5 ms, p95 <= 2 ms, p99 <= 10 ms (NVMe); p50 <= 2 ms, p95 <= 10 ms, p99 <= 50 ms (SSD); tail amplification <= 10x steady-state |
| `budget.performance_budget_0.storage_intent.small_sync_quorum.r11` | small sync quorum intent rows | p95 <= 5 ms under quorum ack; p99 <= 25 ms; tail amplification <= 10x steady-state |
| `budget.performance_budget_0.storage_intent.full_placement_fsync.r12` | full-placement fsync rows | p95 <= 35 ms, p99 <= 125 ms (local); p95 <= 150 ms, p99 <= 500 ms (quorum/geo) |
| `budget.performance_budget_0.storage_intent.vm_fua_barrier_tail.r13` | VM FUA/barrier tail rows | p99 <= 10 ms under concurrent foreground I/O; no p99 stall > 100 ms |
| `budget.performance_budget_0.storage_intent.metadata_storm_fsyncdir.r14` | metadata storm rows | p95 <= 4 ms, p99 <= 15 ms (hot path); p99 fsyncdir <= 50 ms; relative throughput >= 85% of previous admitted variant |
| `budget.performance_budget_0.storage_intent.read_serving_source.r15` | read serving source rows | p95 <= 2 ms (cache hit); p95 <= 10 ms (local receipt); p95 <= 50 ms (degraded); stale/refresh rate <= 5% under declared envelope |
| `budget.performance_budget_0.storage_intent.degraded_read_reconstruction.r16` | degraded read reconstruction rows | p95 <= 25 ms (single-missing); p99 <= 100 ms; repair-on-read foreground impact <= 15% p99 regression |
| `budget.performance_budget_0.storage_intent.streaming_ingest_throughput.r17` | streaming ingest throughput rows | throughput >= 80% of raw device baseline; WAF <= 1.5; flash wear per TiB logical writes <= 1.2 TiB media bytes |
| `budget.performance_budget_0.storage_intent.data_shape_selection.r18` | data-shape selection rows | latency impact <= 10% p95 regression vs baseline shape; CPU cost <= 2x baseline per unit work |
| `budget.performance_budget_0.storage_intent.allocator_layout_behavior.r19` | allocator/layout rows | p99 <= 2x baseline under 80% capacity utilization; ENOSPC refusal rate <= 1% under declared envelope |
| `budget.performance_budget_0.storage_intent.one_pass_scan_no_promotion.r20` | one-pass scan rows | flash promotion bytes = 0 without explicit policy; scan throughput >= 80% of raw device baseline |
| `budget.performance_budget_0.storage_intent.hot_read_cache_trial.r21` | hot read cache trial rows | cache hit rate improvement >= 20% vs baseline; foreground p99 impact <= 5% |
| `budget.performance_budget_0.storage_intent.persistent_hot_promotion.r22` | persistent hot promotion rows | promotion dwell >= 60 s; wear reservation consumed <= declared budget; payback within declared window |
| `budget.performance_budget_0.storage_intent.phase_change_anti_thrash.r23` | phase-change anti-thrash rows | promotion/demotion cycle count <= 3 per phase change; p99 impact <= 2x steady-state |
| `budget.performance_budget_0.storage_intent.noisy_tenant_isolation.r24` | noisy tenant isolation rows | protected tenant p99 sync latency <= 2x baseline under noisy neighbor; noisy tenant throughput capped per isolation budget |
| `budget.performance_budget_0.storage_intent.hdd_defrag_benefit.r25` | HDD defrag rows | seek-heavy p95 improvement >= 30% post-defrag; scan throughput improvement >= 20% |
| `budget.performance_budget_0.storage_intent.ssd_relocation_waf.r26` | SSD relocation WAF rows | WAF delta <= 0.5 per relocated TiB; payback within declared window; failed-payback cooldown enforced |
| `budget.performance_budget_0.storage_intent.rebake_payback.r27` | rebake payback rows | compression ratio improvement >= declared target; CPU cost within declared budget; read amplification <= 2x |
| `budget.performance_budget_0.storage_intent.rebuild_repair_foreground.r28` | rebuild/repair rows | foreground p99 <= 1.5x baseline during rebuild; recovery window <= declared RTO |
| `budget.performance_budget_0.storage_intent.geo_async_rpo_lag.r29` | geo-async RPO rows | RPO lag <= 60 s under declared WAN envelope; catch-up rate >= 80% of WAN throughput |
| `budget.performance_budget_0.storage_intent.trust_domain_changes.r30` | trust-domain change rows | key-epoch change p99 stall <= 5 s; wrong-domain refusal latency <= 1 ms; residency violation refusal rate = 100% |
| `budget.performance_budget_0.storage_intent.geo_intent_latency.r31` | geo-intent latency rows | p95 <= 50 ms (WAN); p99 <= 200 ms; tail amplification <= 10x |
| `budget.performance_budget_0.storage_intent.ram_volatile_intent_latency.r32` | RAM intent latency rows | volatile RAM p50 <= 10 us, p99 <= 50 us; intent-backed RAM p50 <= 50 us, p99 <= 200 us |
| `budget.performance_budget_0.storage_intent.media_wear_per_tib.r33` | media wear rows | WAF <= 1.5 for NVMe ingest; WAF <= 2.0 for SSD; logical to media byte ratio reported per media class |

The budgets above are **gate-floor schema/readiness values only**.
Runtime measurement evidence belongs to later implementation/validation issues.
No row closes because average throughput improved; required tail, disruption,
recovery/RPO, and wear/cost budgets must pass under the declared envelope.

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

### 5.4.1 Storage-intent artifact requirement classes

For storage-intent rows, these additional artifact classes are mandatory:

  * `artifact.performance_budget_0.storage_intent.ack_class_receipt`
    per-row ack-class receipt: requested class, earned class, refusal state, downgrade reason

  * `artifact.performance_budget_0.storage_intent.media_topology_profile`
    media/topology/proximity profile snapshot: RAM, NVMe, SSD, HDD, rack, DC, WAN, internet, RDMA-absent baseline

  * `artifact.performance_budget_0.storage_intent.trust_domain_evidence`
    trust/domain evidence snapshot: key epoch, authorization/audit refs, residency, sharing-domain, quarantine/refusal state

  * `artifact.performance_budget_0.storage_intent.data_shape_evidence`
    data-shape evidence: record size, compression, checksum/digest, dedup, encryption, EC, archive shape,
    CPU cost, read amplification, transform refusal state

  * `artifact.performance_budget_0.storage_intent.allocator_layout_evidence`
    allocator/layout evidence: fragmentation score, free-run pressure, seek/locality, alignment,
    zone/write-pointer constraints, pending-free safety, reclaim debt

  * `artifact.performance_budget_0.storage_intent.movement_debt_evidence`
    movement-debt evidence: debt delta, payback window, cooldown state, skipped-move reasons

  * `artifact.performance_budget_0.storage_intent.wear_cost_evidence`
    wear/cost evidence: logical bytes, estimated media bytes, WAF, flash wear per TiB logical writes,
    network egress cost, CPU cost, evidence-storage cost

  * `artifact.performance_budget_0.storage_intent.prediction_confidence_evidence`
    prediction confidence evidence: confidence class, action class, missing-outcome counts,
    failed-payback verdicts, wrong-domain/stale-key refusal counts

  * `artifact.performance_budget_0.storage_intent.comparator_evidence`
    comparator evidence snapshot: comparator set identity, environment profile, claim id from #875,
    comparator configuration from #928, measurement equivalence proof or refusal

Rows that must cite comparator evidence (#928) or claim ids (#875) to make
product-superiority claims: r15, r16, r17, r22, r26, r27, r28, r29, r31, r32, r33.
All other rows are schema/readiness artifacts only until linked evidence is live.

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
| 11 | `suite.performance_budget_0.storage_intent.small_sync_local_intent.r10` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 12 | `suite.performance_budget_0.storage_intent.small_sync_quorum_intent.r11` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 13 | `suite.performance_budget_0.storage_intent.full_placement_fsync.r12` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 14 | `suite.performance_budget_0.storage_intent.vm_fua_barrier_tail.r13` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 15 | `suite.performance_budget_0.storage_intent.metadata_storm_fsyncdir.r14` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 16 | `suite.performance_budget_0.storage_intent.read_serving_source.r15` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 17 | `suite.performance_budget_0.storage_intent.degraded_read_reconstruction.r16` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 18 | `suite.performance_budget_0.storage_intent.streaming_ingest_throughput.r17` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 19 | `suite.performance_budget_0.storage_intent.data_shape_selection.r18` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 20 | `suite.performance_budget_0.storage_intent.allocator_layout_behavior.r19` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 21 | `suite.performance_budget_0.storage_intent.one_pass_scan_no_promotion.r20` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 22 | `suite.performance_budget_0.storage_intent.hot_read_cache_trial.r21` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 23 | `suite.performance_budget_0.storage_intent.persistent_hot_promotion.r22` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 24 | `suite.performance_budget_0.storage_intent.phase_change_anti_thrash.r23` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 25 | `suite.performance_budget_0.storage_intent.noisy_tenant_isolation.r24` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 26 | `suite.performance_budget_0.storage_intent.hdd_defrag_benefit.r25` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 27 | `suite.performance_budget_0.storage_intent.ssd_relocation_waf.r26` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 28 | `suite.performance_budget_0.storage_intent.rebake_payback.r27` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 29 | `suite.performance_budget_0.storage_intent.rebuild_repair_foreground.r28` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 30 | `suite.performance_budget_0.storage_intent.geo_async_rpo_lag.r29` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 31 | `suite.performance_budget_0.storage_intent.trust_domain_changes.r30` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass |
| 32 | `suite.performance_budget_0.storage_intent.geo_intent_latency.r31` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 33 | `suite.performance_budget_0.storage_intent.ram_volatile_intent_latency.r32` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |
| 34 | `suite.performance_budget_0.storage_intent.media_wear_per_tib.r33` | **defined-schema-only** | #850: #915 #913 #912 #920 required for runtime pass; #875 #928 required for comparator claims |

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
| 11 | `kpi.performance_budget_0.storage_intent.wear_per_tib` | **defined-schema-only** | #850 |
| 12 | `kpi.performance_budget_0.storage_intent.cost.per_byte` | **defined-schema-only** | #850 |
| 13 | `kpi.performance_budget_0.storage_intent.movement.debt` | **defined-schema-only** | #850 |
| 14 | `kpi.performance_budget_0.storage_intent.prediction.confidence` | **defined-schema-only** | #850 |


Storage-intent KPI families 11-14 (wear_per_tib, cost.per_byte, movement.debt, prediction.confidence) added by #850 as defined-schema-only.
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
| 11 | `budget.performance_budget_0.storage_intent.small_sync_local.r10` | **defined-schema-only** | #850 |
| 12 | `budget.performance_budget_0.storage_intent.small_sync_quorum.r11` | **defined-schema-only** | #850 |
| 13 | `budget.performance_budget_0.storage_intent.full_placement_fsync.r12` | **defined-schema-only** | #850 |
| 14 | `budget.performance_budget_0.storage_intent.vm_fua_barrier_tail.r13` | **defined-schema-only** | #850 |
| 15 | `budget.performance_budget_0.storage_intent.metadata_storm_fsyncdir.r14` | **defined-schema-only** | #850 |
| 16 | `budget.performance_budget_0.storage_intent.read_serving_source.r15` | **defined-schema-only** | #850 |
| 17 | `budget.performance_budget_0.storage_intent.degraded_read_reconstruction.r16` | **defined-schema-only** | #850 |
| 18 | `budget.performance_budget_0.storage_intent.streaming_ingest_throughput.r17` | **defined-schema-only** | #850 |
| 19 | `budget.performance_budget_0.storage_intent.data_shape_selection.r18` | **defined-schema-only** | #850 |
| 20 | `budget.performance_budget_0.storage_intent.allocator_layout_behavior.r19` | **defined-schema-only** | #850 |
| 21 | `budget.performance_budget_0.storage_intent.one_pass_scan_no_promotion.r20` | **defined-schema-only** | #850 |
| 22 | `budget.performance_budget_0.storage_intent.hot_read_cache_trial.r21` | **defined-schema-only** | #850 |
| 23 | `budget.performance_budget_0.storage_intent.persistent_hot_promotion.r22` | **defined-schema-only** | #850 |
| 24 | `budget.performance_budget_0.storage_intent.phase_change_anti_thrash.r23` | **defined-schema-only** | #850 |
| 25 | `budget.performance_budget_0.storage_intent.noisy_tenant_isolation.r24` | **defined-schema-only** | #850 |
| 26 | `budget.performance_budget_0.storage_intent.hdd_defrag_benefit.r25` | **defined-schema-only** | #850 |
| 27 | `budget.performance_budget_0.storage_intent.ssd_relocation_waf.r26` | **defined-schema-only** | #850 |
| 28 | `budget.performance_budget_0.storage_intent.rebake_payback.r27` | **defined-schema-only** | #850 |
| 29 | `budget.performance_budget_0.storage_intent.rebuild_repair_foreground.r28` | **defined-schema-only** | #850 |
| 30 | `budget.performance_budget_0.storage_intent.geo_async_rpo_lag.r29` | **defined-schema-only** | #850 |
| 31 | `budget.performance_budget_0.storage_intent.trust_domain_changes.r30` | **defined-schema-only** | #850 |
| 32 | `budget.performance_budget_0.storage_intent.geo_intent_latency.r31` | **defined-schema-only** | #850 |
| 33 | `budget.performance_budget_0.storage_intent.ram_volatile_intent_latency.r32` | **defined-schema-only** | #850 |
| 34 | `budget.performance_budget_0.storage_intent.media_wear_per_tib.r33` | **defined-schema-only** | #850 |


Storage-intent numeric budget classes r10-r33 added by #850 as defined-schema-only. Budgets are gate-floor schema/readiness values; runtime measurement evidence belongs to later implementation/validation issues.
### 12.4 Workload-envelope classes -- 10 defined, 1 executed at runtime

All 10 workload-envelope families (`e0` through `e9`) exist as design
contracts only. No workload-envelope manifest, parameter binding, or
row-linked execution exists at runtime.


Storage-intent workload envelope extensions `e10` through `e20` are added by #850 as defined-schema-only. No workload-envelope manifest, parameter binding, or row-linked execution exists at runtime.

All 6 environment profiles (`e0` through `e5`) are design contracts only.
No environment snapshot, hardware/runtime/kernel/variant capture, or
noise-policy binding exists at runtime.


Storage-intent environment profile extensions `e6` (WAN/internet) and `e7` (multitenant-adversarial) are added by #850 as defined-schema-only. No environment snapshot or noise-policy binding exists at runtime.
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

### 12.12.5 Gate receipt rendering and performance-gate readiness (issue #6161 step 5)

The complete enforcement chain feeds into a single `GateReceipt` that can
be inspected through `render_markdown()`:

- **`GateReceipt::render_markdown()`**: Produces a complete markdown report
  with summary metrics (total, runtime_pass, code_only_pass, failed, refused,
  budget decision, artifacts_satisfied, budget_buckets), comparator runs
  (ref_id, executed, KPI count, blocker), and notes.
- **`perf_gate_ready`**: Now requires all four performance-gate conditions:
  1. Subject completeness (`invariant_holds`)
  2. At least one runtime validation row
  3. Zero artifact gap (all live-runtime rows satisfy artifact requirements)
  4. Zero budget gap (no budget violations on any row)
  A receipt with open artifact or budget gaps renders `Performance gate: NOT READY`
  regardless of pass counts.
  **Scope note**: This `perf_gate_ready` field is a performance-gate-local receipt
  scoped to the `performance_budget_0` matrix rows only. It is not a whole-product
  release-readiness verdict. The release-readiness boundary, including the
  evidence families a verdict must consume and explicit non-claims, is defined in
  `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.
- `build_current_head_receipt` and `build_current_head_with_benches` both
  produce full-featured receipts with render_markdown available.

This means performance work items remain open while measured gates are
missing: the receipt explicitly shows which artifacts, comparators, and
budgets are still outstanding.



### 12.13 Summary

| Category | Defined | Implemented |
|---|---|---|
| Suite families | 10 (base) + 24 (storage intent) | 2 (#6132: metadata_hotset, stream_mix) + 0 (storage intent schema-only) |
| KPI families | 10 (base) + 4 (storage intent) | 2 (#6132: latency.core, throughput.floor) + 0 (storage intent schema-only) |
| Numeric budget classes | 10 (base) + 24 (storage intent) | 3 (posix_stream_mix, block_random_queue, general_purpose; enforced via NumericBudget/RegressionLock) + 0 (storage intent schema-only) |
| Workload-envelope classes | 10 (base) + 11 (storage intent) | 0 |
| Environment profiles | 6 (base) + 2 (storage intent) | 0 |
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
