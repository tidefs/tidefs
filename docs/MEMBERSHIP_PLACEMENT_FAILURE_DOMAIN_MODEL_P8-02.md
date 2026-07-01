# membership / placement / failure-domain model (P8-02) (v0.364)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This imported document records historical production-depth membership,
placement, and failure-domain target language for tidefs.

It answers the question:

**How does tidefs decide which nodes and services may vote, learn, witness, host authority, store replicas, shadow-compare, or remain quarantined; how are those decisions bound to failure domains and current membership epochs; and what exact law prevents split-brain or single-cell collapse from being hand-waved as "the cluster will sort it out"?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md`
- `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`
- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270)
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md`

## 1. Core result

The production design now has one explicit family for distributed
membership/placement truth:

- one coordinating family: **`family.membership_placement_failure_domain.membership_placement_0`**
- one graph law: **`law.membership_epoch_placement_separation.membership_placement_0`**
- **6 stable member classes**
- **4 stable config classes**
- **6 stable failure-domain classes**
- **8 stable placement-intent classes**
- **7 stable verdict classes**
- one canonical anti-split-brain chain:
  - **member inventory -> failure-domain binding -> config epoch -> cohort population -> placement intent -> readiness/health scan -> verdict -> commit or quarantine receipt**

This means tidefs is no longer allowed to say only:

- "membership is just whatever nodes are up,"
- "a leader will probably fail over to some other node,"
- "replica placement can be decided per service,"
- "witnesses are just a test harness idea,"
- or "failure-domain spread can wait until a future cluster layer."

It must instead say:

- which membership class each participant currently holds,
- which config epoch governs the participant,
- which failure-domain vector the participant belongs to,
- which cohort populations that epoch produces under `transport_session_0`,
- which placement intent is being evaluated,
- which separation rule or degraded exception was applied,
- and which receipt or hazard record proves why the decision was admitted, held, downgraded, or quarantined.

The anti-regression rule is explicit:

**No election helper, transport endpoint, replica mover, control-plane planner, runbook, or future kernel/user-space service may become lawful distributed authority unless it uses the declared `membership_placement_0` member classes, config classes, failure-domain classes, placement intents, verdict classes, and split-brain hazard law fixed here.**

## 2. Scope and boundaries

This document governs:

- participant classes for voting, learning, witness duty, data placement, shadow duty, and quarantine,
- committed membership epoch grammar, including bootstrap, normal, joint, and quarantine-scoped views,
- failure-domain inventory from device to region,
- rules that populate `transport_session_0` cohorts from the current membership epoch,
- explicit hold/quarantine behavior when separation or quorum proof is insufficient,
- and the grounding of those rules in the current deterministic cluster harness.

This document now consumes the explicit `governance_surface_0` authority-service law in `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`.

That boundary is deliberate.
`P8-02` fixes **who may belong where and how separation is proved**.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future prose:

- the OW-302 executable source slice now lives in `crates/tidefs-membership-epoch` and binds the first deterministic `membership_placement_0` model into the workspace.

Production `membership_placement_0` extends those anchors by adding:

- explicit failure-domain inventory,
- witness-only / data-only / shadow-only / quarantined participant classes,
- declared authority-home and successor placement intents,
- and receipt-bearing split-brain hazard / placement verdict law.

### 3.1 OW-302 executable source slice

`crates/tidefs-membership-epoch` is the current implementation-tracked non-release model for this law.
It implements the record and protocol names from this document directly:

- `ClusterMemberRecord`, `MembershipConfigRecord`, `MemberFailureDomainBindingRecord`, `CohortPopulationRecord`, `MembershipPlacementVerdictRecord`, `MembershipTransitionRecord`, and `SplitBrainHazardRecord`;
- `inventory_members_and_classify_participation_roles()`, `bind_member_to_failure_domain_vector()`, `synthesize_membership_config_epoch_and_quorum_sets()`, `populate_transport_session_cohorts_from_membership_epoch()`, `derive_authority_home_and_failover_successor_candidates()`, `derive_replica_targets_from_failure_domain_policy()`, `evaluate_transition_catchup_and_readiness()`, `issue_membership_or_placement_verdict()`, `detect_split_brain_hazard_and_force_hold_or_quarantine()`, and `control_membership_placement_failure_domain_protocol()`;
- failure/rejoin tests for separated failover admission, same-rack domain-gap hold, split-brain refusal, learner rejoin catch-up before joint config, and quarantined-member cohort/placement exclusion.

This source slice is intentionally deterministic and local. It is not a
networked consensus runtime. It exists so later distributed-runtime work has a
epoch, split-brain refusal, learner rejoin, or placement behavior.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Stable member classes | 6 |
| Stable config classes | 4 |
| Stable failure-domain classes | 6 |
| Stable placement-intent classes | 8 |
| Stable verdict classes | 7 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. Membership epoch and participant-class law

### 5.1 Stable config classes

| Config class | Purpose |
|---|---|
| `config.membership_placement_0.bootstrap.c0` | initial seed config for a new authority domain; the only legal path that may skip joint reconfiguration |
| `config.membership_placement_0.normal.c1` | steady committed config with one voter set and zero or more non-voting members |
| `config.membership_placement_0.joint.c2` | reconfiguration epoch with `old_voters` and `new_voters`; dual-majority is mandatory |
| `config.membership_placement_0.quarantined.c3` | reduced emergency view used only for hold, drain, witness collection, or quarantine; it may not publish ordinary new authority by itself |

### 5.2 Stable member classes

| Member class | Purpose |
|---|---|
| `member.membership_placement_0.voter.m0` | counts for membership quorum and may host an authority home or named failover successor when admitted by placement law |
| `member.membership_placement_0.learner.m1` | receives log/state-transfer catch-up, may appear in transition cohorts, but never counts for quorum or primary authority |
| `member.membership_placement_0.data_only.m3` | legal target for replica, rebuild, relocation, and bulk demand-serving work, but never a config voter |
| `member.membership_placement_0.quarantined.m5` | excluded from new authority, new replica placement, and new cohort admission until a clearance receipt exists |

### 5.3 Membership invariants

1. Every admitted participant has exactly one primary member class in the current membership epoch.
2. `m0.voter` is the only class that may appear in the authoritative voter sets for `c1` or `c2`.
3. `m1.learner` may only promote to `m0.voter` after catch-up to the declared frontier and a committed transition receipt.
4. `m2.witness_only`, `m3.data_only`, and `m4.shadow_only` may join specific `transport_session_0` cohorts, but none of them may silently become quorum voters.
5. `m5.quarantined` must be removed from new cohort population, new placement verdicts, and new authority-home selection until the quarantine is explicitly cleared.
6. Removing or demoting a voter requires both cohort drain and config-epoch commit; "we stopped sending it traffic" is not a legal membership change.

## 6. Failure-domain hierarchy and placement-intent law

### 6.1 Stable failure-domain classes

| Failure-domain class | Purpose |
|---|---|
| `fd.membership_placement_0.device.f0` | per-device separation for durable payload placement and device-loss accounting |
| `fd.membership_placement_0.node.f1` | host-level failure cell for process crash, reboot, or node loss |
| `fd.membership_placement_0.chassis.f2` | shared enclosure / power / backplane failure cell |
| `fd.membership_placement_0.rack.f3` | rack-local correlated-loss cell |
| `fd.membership_placement_0.zone.f4` | availability-zone / room / fabric-isolation cell |
| `fd.membership_placement_0.region.f5` | large-area geographic or operator-boundary isolation cell |

### 6.2 Stable placement-intent classes

| Placement-intent class | Purpose |
|---|---|
| `placement.membership_placement_0.authority_home.p0` | preferred live home for one authority domain |
| `placement.membership_placement_0.failover_successor.p1` | legal successor candidates for authority movement under `W5-06` |
| `placement.membership_placement_0.voter_spread.p2` | required separation shape for quorum-bearing voters |
| `placement.membership_placement_0.learner_staging.p3` | catch-up or warm-spare placement pending promotion or drain |
| `placement.membership_placement_0.witness_spread.p4` | witness-only placement required for specific quorum/risk classes |
| `placement.membership_placement_0.replica_target.p5` | steady-state durable replica placement for immutable data or metadata |
| `placement.membership_placement_0.rebuild_relocate_target.p6` | temporary or permanent target chosen during rebuild, relocation, or reclaim |

### 6.3 Stable verdict classes

| Verdict class | Meaning |
|---|---|
| `verdict.membership_placement_0.admit.v0` | placement or membership change is fully legal under current epoch and separation policy |
| `verdict.membership_placement_0.admit_degraded.v1` | legal but below preferred spread/service shape; must be visible as degraded |
| `verdict.membership_placement_0.hold_catchup.v2` | transition blocked until catch-up, replay, or state-transfer frontier is satisfied |
| `verdict.membership_placement_0.hold_domain_gap.v3` | transition or placement blocked because required failure-domain separation is missing |
| `verdict.membership_placement_0.refuse_policy_or_capacity.v5` | policy, reserve, or package/service ceiling forbids the move |
| `verdict.membership_placement_0.quarantine.v6` | participant or domain is unsafe enough that it must exit new authority/placement decisions entirely |

### 6.4 Placement invariants

1. Every authority-home or replica placement verdict names the current membership epoch and the required failure-domain spread class.
2. `p0.authority_home` and `p1.failover_successor` may not collapse into a forbidden common domain cell when policy demands separation.
5. When spread is impossible, tidefs must emit `v1`, `v2`, `v3`, `v5`, or `v6`; it may not silently squeeze all responsibility into one node/rack/zone and call the placement "good enough."

### 6.4.1 OW-303 executable failure-domain placement slice

`crates/tidefs-membership-epoch` now binds the OW-303 placement row to source:

- `FailureDomainPlacementPolicy` declares the placement class, required replica count, required failure-domain class, and anti-affinity class.
- `AntiAffinityClass::Strict` holds placement when the requested replica count cannot be satisfied by separated failure-domain cells.
- `AntiAffinityClass::DegradedVisible` may select a duplicate-domain target only as a visible degraded verdict.
- `FailureDomainPlacementPlan` records selected members/domains, duplicate-domain candidates, excluded members, and the resulting `MembershipPlacementVerdictRecord`.
- `plan_failure_domain_placement_from_policy()` chooses targets deterministically by failure-domain id and member id, not by caller input order.

It covers deterministic ordering, strict anti-affinity hold behavior, degraded-visible duplicate-domain placement, and exclusion of witness-only, shadow-only, down, or quarantined members from durable replica targets.
This remains an executable placement model; it is not a claim that networked placement execution, replication, rebuild, or rebalance is implemented.

### 6.5 Automatic topology inference and anti-static rule


The hard rules are:
- full static adjacency matrices are forbidden as product truth,
- per-node preferred-neighbor files are forbidden as product truth,
- manual cost tables are forbidden as product truth,
- optional operator labels may express hard physical constraints or facts that auto-inventory cannot infer safely,
- but ranking and candidate selection must still come from measured topology, path quality, failure-domain state, and current service cost.

Placement is therefore allowed to be adaptive, but only with hysteresis and receipt-bearing visibility. Durable data placement may not churn on noise; foreground locality selection may adapt faster than durable replica movement.

## 7. Cohort population and anti-split-brain law

### 7.1 `transport_session_0` cohort population rules

`P8-01` fixed **how** cohorts work.
`P8-02` now fixes who may populate them:

| `transport_session_0` cohort | Allowed `membership_placement_0` participant classes |
|---|---|
| `cohort.transport_session_0.peer_pair.k0` | any non-quarantined admitted pair |
| `cohort.transport_session_0.authority_domain_control.k1` | `m0.voter` plus declared `m1.learner` catch-up participants only |
| `cohort.transport_session_0.replica_set.k3` | `m0.voter`, `m1.learner`, and `m3.data_only` as admitted by `p5`/`p6` verdicts |
| `cohort.transport_session_0.state_transfer.k4` | `m0.voter`, `m1.learner`, and selected `m3.data_only` targets |
| `cohort.transport_session_0.shadow_compare.k5` | authoritative participants plus `m4.shadow_only` observers |
| `cohort.transport_session_0.transition_stage.k6` | only participants named by one committed transition or runbook stage |

### 7.2 Anti-split-brain invariants

1. Every authority move, voter-set change, or placement verdict is bound to one committed `membership_epoch_ref`.
2. Voter addition or removal must go through `c2.joint` unless the cluster is in the one-time `c0.bootstrap` case.
3. `c3.quarantined` may hold, drain, and collect witness proof, but it may not silently crown a new ordinary authority holder.
4. If two holders or two incompatible epochs look simultaneously plausible, tidefs must emit `SplitBrainHazardRecord` and only hold, quarantine, or explicit `W5-06` abort/commit paths remain legal.
5. A participant may not be both `m5.quarantined` and selected in an authority-home, failover-successor, or durable-replica verdict.
6. Replica or witness spread may degrade visibly, but authority cannot "just fail over" into an unverified same-cell successor without an explicit hazard-free verdict.

### 7.3 Adaptation hysteresis

Foreground read-locality and cohort-attachment preferences may adapt on faster windows than durable placement. Authority-home selection, voter spread, and durable replica movement must use slower windows and explicit hold/drain/receipt rules so the cluster does not thrash when network conditions wobble briefly.

## 8. New authoritative records

This design introduces **10 new record families**.

| Record | Purpose |
|---|---|
| `ClusterMemberRecord` | authoritative declaration / runtime mirror of one participant's current member class, capabilities, and health |
| `MembershipConfigRecord` | committed membership epoch with config class, voter sets, learner sets, and linked receipts |
| `FailureDomainRecord` | authoritative failure-domain cell and its parent/health/policy linkage |
| `MemberFailureDomainBindingRecord` | durable mapping from one participant to its device/node/chassis/rack/zone/region vector |
| `CohortPopulationRecord` | authoritative/runtime mirror of which members may populate one `transport_session_0` cohort under one epoch |
| `AuthorityPlacementIntentRecord` | declared authority-home or failover-successor placement obligation for one authority domain |
| `ReplicaPlacementIntentRecord` | declared replica / rebuild / relocation target obligation for one subject |
| `MembershipPlacementVerdictRecord` | committed verdict that admits, degrades, holds, refuses, or quarantines a placement or transition |
| `MembershipTransitionRecord` | typed learner/voter/drain/quarantine transition with catch-up frontier and blockers |
| `SplitBrainHazardRecord` | authoritative finding when competing holders/epochs/domains make ordinary movement illegal |

### 8.1 Record field guidance

At minimum these records carry the following key fields:

| Record | Key fields |
|---|---|
| `ClusterMemberRecord` | `member_id`, `member_class_ref`, `identity_ref`, `service_capability_refs[]`, `current_membership_epoch_ref`, `health_class`, `quarantine_state_ref`, `digest` |
| `MembershipConfigRecord` | `membership_epoch_id`, `config_class_ref`, `version_index`, `voter_set_refs[]`, `learner_set_refs[]`, `observer_set_refs[]`, `joint_old_set_refs[]`, `joint_new_set_refs[]`, `issuance_receipt_ref`, `digest` |
| `FailureDomainRecord` | `failure_domain_id`, `failure_domain_class_ref`, `parent_domain_ref`, `member_refs[]`, `separation_policy_ref`, `health_class`, `availability_receipt_ref`, `digest` |
| `MemberFailureDomainBindingRecord` | `binding_id`, `member_ref`, `failure_domain_vector_refs[]`, `device_or_region_refs[]`, `binding_source_class`, `last_verified_receipt_ref`, `digest` |
| `CohortPopulationRecord` | `population_id`, `membership_epoch_ref`, `cohort_class_ref`, `eligible_member_refs[]`, `excluded_member_refs[]`, `attachment_policy_ref`, `issuance_receipt_ref`, `digest` |
| `AuthorityPlacementIntentRecord` | `placement_intent_id`, `authority_domain_ref`, `placement_class_ref`, `primary_member_ref`, `successor_candidate_refs[]`, `required_failure_domain_class_ref`, `quorum_class_ref`, `fence_policy_ref`, `digest` |
| `ReplicaPlacementIntentRecord` | `placement_intent_id`, `subject_ref`, `placement_class_ref`, `required_replica_count`, `required_domain_spread_class`, `preferred_member_refs[]`, `forbidden_member_refs[]`, `source_receipt_refs[]`, `digest` |
| `MembershipPlacementVerdictRecord` | `verdict_id`, `membership_epoch_ref`, `placement_intent_ref`, `selected_member_refs[]`, `selected_domain_refs[]`, `verdict_class_ref`, `degraded_reason_refs[]`, `issuance_receipt_ref`, `digest` |
| `MembershipTransitionRecord` | `transition_id`, `subject_member_ref`, `from_member_class_ref`, `to_member_class_ref`, `required_catchup_frontier_ref`, `blocking_reason_refs[]`, `open_receipt_ref`, `close_receipt_ref`, `digest` |
| `SplitBrainHazardRecord` | `hazard_id`, `authority_domain_ref`, `membership_epoch_ref`, `conflicting_holder_refs[]`, `conflicting_domain_refs[]`, `hazard_class`, `required_hold_or_quarantine_ref`, `resolution_receipt_ref`, `digest` |

## 9. Canonical algorithms and protocol families

This design introduces **10 new algorithm / protocol families**.

| Algorithm / protocol | Purpose |
|---|---|
| `inventory_members_and_classify_participation_roles()` | declare participant classes and current service eligibility |
| `bind_member_to_failure_domain_vector()` | map a member into the device/node/chassis/rack/zone/region hierarchy |
| `synthesize_membership_config_epoch_and_quorum_sets()` | produce `c0`/`c1`/`c2`/`c3` config epochs with explicit quorum sets |
| `populate_transport_session_cohorts_from_membership_epoch()` | derive eligible transport-session populations from the current epoch and class rules |
| `derive_authority_home_and_failover_successor_candidates()` | choose lawful authority-home and successor sets from policy, health, and separation |
| `derive_replica_targets_from_failure_domain_policy()` | choose replica/rebuild/relocation targets from domain spread policy |
| `plan_failure_domain_placement_from_policy()` | choose deterministic failure-domain targets with strict anti-affinity or degraded-visible duplicate-domain policy |
| `evaluate_transition_catchup_and_readiness()` | decide whether learner promotion, drain, or demotion may proceed |
| `issue_membership_or_placement_verdict()` | emit admit / degrade / hold / refuse / quarantine verdicts with receipts |
| `control_membership_placement_failure_domain_protocol()` | distributed protocol family governing epoch, class, cohort, placement, and hazard decisions together |

### 9.1 Protocol law

`control_membership_placement_failure_domain_protocol()` obeys these rules:
- every decision binds to one committed membership epoch,
- ordinary voter-set changes must pass through `c2.joint`,
- cohort population is derived from epoch + member class, never hidden local lists,
- placement checks run against declared failure-domain vectors and separation policy,
- insufficient spread yields `v1`, `v2`, `v3`, `v5`, or `v6`, never silent acceptance,
- and only after a committed verdict may `W5-06`, `P8-03`, `control_plane`, or `operator_runbook_0` advance a live move.

## 10. Whole-system operational paths now fixed

1. new physical node joins the cluster -> `ClusterMemberRecord` starts as `m1.learner` -> `evaluate_transition_catchup_and_readiness()` waits for log/state-transfer frontier -> `c2.joint` config is committed -> node becomes `m0.voter` without leader-local quorum folklore
2. planned drain or upgrade of a voter -> `AuthorityPlacementIntentRecord` selects `p1.failover_successor` candidates in separated failure domains -> transition stage and witness proof run -> previous voter demotes or exits only after config and placement receipts agree
3. new publication or rebuild obligation appears -> `ReplicaPlacementIntentRecord` chooses `p5.replica_target` or `p6.rebuild_relocate_target` across `failure_domain_0..f5` -> verdict is admitted or degraded visibly -> `P8-03` transfer/verify work proceeds without per-service placement drift

## 11. Acceptance effect on the design pack

With this law settled:

- `P8-02` becomes detailed enough for later implementation planning,
- the full `P8` distributed-runtime / coordination workstream is now at `L3`,
- the repo now has one explicit answer to who may vote, learn, witness, host authority, store replicas, shadow-compare, or remain quarantined,
- `transport_session_0`, `W5-06`, `P8-03`, `control_plane`, `operator_runbook_0`, `truth_view`, and `shadow_pilot_0` now share one epoch/placement/separation grammar,
- and the full production design ledger is now at `L3`, so later work is user-directed refinement or implementation discipline rather than missing seam/deletion law.
