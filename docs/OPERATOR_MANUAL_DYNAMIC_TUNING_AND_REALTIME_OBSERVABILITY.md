# operator manual - dynamic tuning and real-time observability (v0.422)

This manual explains the operator-facing behavior of tidefs' workload-reactive design.

It answers the practical question:

**How should an administrator think about performance-versus-efficiency control, automatic topology handling, and real-time large-cluster observability without turning tidefs into a pile of hidden subsystem knobs or static deployment lore?**

See also:
- `docs/DISTRIBUTED_OPERATOR_TRUTH_SURFACES_OW307A.md` through `OW307E.md`
- `docs/DISTRIBUTED_OPERATOR_PRODUCT_SURFACE_BLOCKER_MAP_OW307D.md`
- `docs/DEBUGGING_WORKFLOWS.md`
- `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`
- `docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`

- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`
- `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md`
- `docs/PREVIEW_USER_MANUAL.md`

- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`
- `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`

## 1. Safety rule

Tidefs is designed to be **dynamic**, but not arbitrarily self-rewriting.

Automatic behavior may bias:
- latency-versus-efficiency posture,
- cache/prefetch behavior,
- background work rate,
- transport lane share,
- and replica-read locality.

Automatic behavior may **not** rewrite:
- durability semantics,
- quorum law,
- failover authority law,
- failure-domain minimums,
- or any other correctness-bearing invariant.

If a requested or inferred change would cross that boundary, the correct result is refusal, hold, or visible degradation, not a "smart" silent shortcut.

## 2. Bias profiles

The minimum stable bias profiles are:

| Profile | Intent | Typical bias |
|---|---|---|
| `profile.adaptive_governor_0.efficiency.l2` | strongest safe efficiency skew | reduce speculation, keep background work smooth, limit cache growth and fanout, favor lower CPU/network cost per useful unit of work |
| `profile.adaptive_governor_0.efficiency.l1` | moderate efficiency skew | similar to `l2` but less aggressive about shrinking speculation and concurrency |
| `profile.adaptive_governor_0.balanced.l0` | default posture | treat foreground performance and resource efficiency as co-equal, favor the do-no-harm path |
| `profile.adaptive_governor_0.performance.l1` | moderate performance skew | keep hot sets resident longer, increase safe queue/prefetch posture, and protect foreground latency over background throughput |
| `profile.adaptive_governor_0.performance.l2` | strongest safe performance skew | highest admitted hot-set retention and request urgency within declared guardrails; background work yields aggressively to foreground demand |
| `profile.adaptive_governor_0.manual_pin.m0` | temporary forced posture | explicit, TTL-bound operator override used only for bounded windows such as benchmarks, incident response, or migration |

The profile model is intentionally coarse.
Operators choose a named posture.
Subsystem-local private tuning dialects are not the supported operating model.

## 3. Scope and precedence

Bias may be bound at these scopes:

1. pool-cluster default
2. authority-domain / dataset / volume / product-surface scope
3. transition or runbook scope
4. temporary session or incident scope

Precedence is always narrower-over-broader.
A temporary override must include a bounded lifetime or explicit clearance path.
Permanent undocumented overrides are not acceptable operating practice.

`pool-cluster default` is deliberate: the durable sovereign object is one pool-cluster. Live cluster views are projections over that same object, not a second durable configuration root.

## 4. What tidefs may change automatically

The dynamic control loop may bias only admitted actuator classes.
The minimum stable actuator classes are:

| Actuator class | Effect |
|---|---|
| `actuator.adaptive_governor_0.prefetch_window.a0` | widen or narrow speculative read-ahead / warmup posture |
| `actuator.adaptive_governor_0.cache_floor_eviction_bias.a1` | keep hot working sets resident longer or evict sooner |
| `actuator.adaptive_governor_0.dirty_seal_window.a2` | seal dirty windows earlier or later within already-legal publication/writeback constraints |
| `actuator.adaptive_governor_0.lane_credit_batch.a3` | change lane credit and batching posture for control / demand / background traffic |
| `actuator.adaptive_governor_0.foreground_background_bandwidth.a4` | protect foreground demand or let background progress catch up |
| `actuator.adaptive_governor_0.rebuild_relocation_concurrency.a5` | slow or accelerate rebuild / relocation fanout within declared safety bounds |
| `actuator.adaptive_governor_0.replica_read_fanout.a6` | choose narrower or wider read fanout and locality preference |
| `actuator.adaptive_governor_0.query_render_depth.a7` | reduce or deepen optional render/detail cost where exactness law already permits it |
| `actuator.adaptive_governor_0.materialization_retention_bias.a8` | retain useful built products longer or reclaim them earlier when pressure or efficiency bias rises |
| `actuator.adaptive_governor_0.materialization_build_refresh_budget.a9` | widen or narrow how much lawful build/refresh effort the system may spend on expensive answers |

These are **biases**, not sovereignty transfers.
They tune how the system spends lawful slack.
They do not change what is lawful.

## 5. What tidefs must never change dynamically

The following are not tuning surfaces:

- correctness or integrity invariants,
- quorum math,
- authority-holder legality,
- split-brain refusal behavior,
- minimum failure-domain spread,
- secret/key truth,
- archive/deletion truth,
- or stage-gate proof requirements.

If a profile asks for something illegal, the system must keep the invariant and surface the refusal.

## 6. How workload reaction works

The adaptive control loop is one shared pattern:

1. **observe**
   - collect fast-window, steady-window, and slow-window signals
2. **classify**
   - determine the dominant workload and stress posture
3. **bias**
   - compute one bounded actuator plan under the effective profile
4. **act**
   - stage only the admitted changes
5. **verify**
   - check tail, freshness, refusal, pressure, and debt guards
6. **keep or revert**
   - retain the change if it helped; roll it back if it harmed the declared priorities

The minimum workload classes are:

- metadata hotset
- sequential / streaming
- random / latency-critical
- sync-durable write heavy
- rebuild / relocation pressure
- failover / cutover / recovery window
- mixed / emergent unknown

The system should react quickly enough for live posture changes to matter, but with hysteresis strong enough to avoid noisy flapping.

Live PID cohorts, binary/image identity, service identity, and request-shape vectors may all contribute to classification, but only as ephemeral hints. They must decay into reusable workload signatures rather than becoming durable authority.

## 6.1 Workload signatures and materialized products

Tidefs does not treat expensive answers as incidental caches.
The active `workload_model_0` law now requires the system to:

1. observe live request and pressure windows,
2. classify the current workload signature with confidence and decay,
3. enumerate candidate expensive answers that could help,
4. score them under cost, utility, freshness, reserve, and topology facts,
5. build, refresh, retain, demote, or reclaim them,
6. and make that behavior visible through one shared truth surface.

Known workload libraries are allowed, but the system must also handle emergent workloads that do not match a predeclared signature.
Operators should not have to predefine a static application catalogue to get lawful adaptation.

## 7. Automatic topology handling

Full static topology configuration is forbidden as product truth.

That means operators should **not** have to maintain:
- adjacency matrices,
- preferred-neighbor files,
- per-link cost tables,
- or hand-authored routing folklore.

Instead tidefs must derive usable topology from:
- observed RTT / jitter / loss / goodput,
- lane-pressure behavior,
- catch-up / state-transfer cost,
- current failure-domain bindings,
- and optional hard labels when auto-inventory cannot safely infer a physical boundary.

Allowed manual input is intentionally narrow:
- site / room / rack / chassis / power-domain labels,
- hard deny rules,
- and explicit operator assertions of a physical fact that cannot be discovered safely.

That input constrains the graph.
It does not replace the graph.

## 8. Required real-time views

The operator-truth layer must provide, at minimum, these live views:

| View family | Purpose |
|---|---|
| `view.truth_view.cluster_topology.v0` | current inferred topology graph and current path classes |
| `view.truth_view.path_heatmap.v1` | live link/path quality heatmap across the cluster |
| `view.truth_view.failure_domain_spread.v2` | current spread state for authority, replicas, witnesses, and shadow participants |
| `view.truth_view.governor_timeline.v3` | current effective profile plus the recent actuation timeline |
| `view.truth_view.workload_classifier.v4` | current workload-class decisions and confidence/guard state |
| `view.truth_view.capacity_pressure.v5` | memory, reclaim, background debt, rebuild debt, and foreground/background trade state |
| `view.truth_view.materialization_utility.v6` | which expensive answers are currently built, their utility/cost state, and recent build/refresh/reclaim decisions |
| `view.truth_view.foreign_materialization.v7` | foreign caches/accelerators the system is observing but does not own directly, plus their current pressure and masking effect |

These are not optional dashboard cosmetics.
They are the minimum views an operator needs to understand *why* the cluster is behaving the way it is.

## 9. Minimum live metric families

At minimum, the cluster should expose these metric families through the shared truth layer:

| Metric family | Meaning |
|---|---|
| `metric.adaptive_governor_0.link_rtt.m0` | current path latency class |
| `metric.adaptive_governor_0.link_jitter_loss.m1` | path stability / retransmit / jitter condition |
| `metric.adaptive_governor_0.lane_credit_pressure.m2` | transport-lane pressure, starvation, and backlog state |
| `metric.adaptive_governor_0.foreground_tail.m3` | foreground p95/p99 latency and visible stall windows |
| `metric.adaptive_governor_0.cache_hotset_efficiency.m4` | useful cache residency versus waste / churn |
| `metric.adaptive_governor_0.background_debt.m5` | rebuild, relocation, writeback, and drain backlog |
| `metric.adaptive_governor_0.rebuild_impact.m6` | effect of background repair on foreground service |
| `metric.adaptive_governor_0.placement_spread_risk.m7` | current spread health and degraded-domain risk |
| `metric.workload_model_0.signature_confidence.m8` | classification confidence and decay state for active workload signatures |
| `metric.workload_model_0.materialization_roi.m9` | utility returned by built products relative to their current cost |
| `metric.workload_model_0.materialization_churn.m10` | build/refresh/reclaim rate and instability of the product economy |
| `metric.workload_model_0.foreign_materialization_pressure.m11` | observed pressure or masking effect from non-owned caches/accelerators |

The point is not to maximize the raw number of counters.
The point is to make live behavior legible under one truth grammar.

## 10. How to use the profiles in practice

A good operating posture is:

- start with `balanced.l0`,
- move to `performance.l1` or `performance.l2` for latency-sensitive incidents, benchmarks, or hot windows,
- move to `efficiency.l1` or `efficiency.l2` when the cluster is stable and the goal is lower resource cost or gentler background maintenance,
- and use `manual_pin.m0` only for bounded, auditable windows.

Do not turn the system into a permanently pinned emergency posture.
If a cluster needs that to survive, the correct next step is to investigate workload classification, placement risk, or capacity debt, not to normalize the emergency mode.

## 11. Large-cluster troubleshooting questions

When the cluster is under stress, the operator should be able to answer these questions quickly:

1. What is the **effective profile** right now?
2. What workload class did the system think it was serving?
3. What actuator change was made most recently?
4. Did that change help or hurt foreground tail latency?
5. Which links or failure domains are currently degraded?
6. Is the cluster protecting foreground demand at the expense of background progress, or vice versa?
8. Which materialized products did the system build, refresh, or reclaim recently?
9. Did those products actually pay for themselves, or are they becoming churn/debt?

If those questions cannot be answered from the live truth surfaces, the operator experience is incomplete.

The typed truth surfaces that answer these questions are defined in:
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (truth-view law with mandatory surface classes, provenance/exactness/freshness rendering, and carrier verification),
- `docs/DISTRIBUTED_OPERATOR_TRUTH_SURFACES_OW307A.md` through `OW307E.md` (typed placement, health, rebuild, and risk records with deterministic demo rows and summary aggregation).

## 12. Bottom line

The supported operator model is:

- choose a named posture,
- let the system react within bounded actuator law,
- watch the shared live truth surfaces,
- and intervene only with scoped, TTL-bound overrides when needed.

The unsupported operator model is:

- hand-configure the whole topology,
- hand-tune every subsystem separately,
- or infer cluster behavior from disconnected logs and screenshots.
