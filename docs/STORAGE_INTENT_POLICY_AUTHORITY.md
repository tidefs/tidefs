# Storage Intent Policy Authority

Issue: #839
Date: 2026-06-21
Status: design authority for follow-up implementation slices

This document defines TideFS storage intent as a native cross-cutting
architecture contract. It is not a tiering add-on, a defrag feature, a cache
mode, or a DRBD-style replication-mode enum. It is the policy and evidence
language that write admission, fsync, placement, transport, media choice,
relocation, RAM pools, and operator explanations must converge on.

The core rule is:

> TideFS must not choose between fast and honest. Every successful
> acknowledgment must carry a named guarantee receipt, and the system must
> optimize the path that earns that receipt.

Data shape belongs in that same contract. Record size, compression, checksum
suite, dedup scope, encryption boundary, erasure shape, coalescing, and rebake
are not local transform preferences once they affect latency, flash lifetime,
WAN cost, read amplification, rebuild behavior, or repair identity.

Allocator geometry belongs there too. Fragmentation, free-run availability,
zone or erase-block alignment, pending-free safety, reclaim debt, and physical
locality are not background trivia once they decide whether defrag, compaction,
placement, or rebake will help or hurt.

Lifecycle evidence is the same class of truth. Write age, overwrite/delete
windows, snapshot and clone retention, receive-base dependencies, orphan-held
bytes, dead-pending reclaim, and destroy/tombstone state decide whether moving
bytes is wise, legal, or dangerous.

Cluster membership evidence is equally native. A quorum, geo, replicated-RAM,
remote-read, drain, or split-brain decision is not legal because a network path
looked fast. It is legal only when the receipt cites the membership epoch,
roster, quorum set, witness/data role, failure-domain binding, and fence state
owned by the membership authority.

Ordering and replay evidence are the matching local truth. A low-latency sync
reply is not honest because an intent record exists somewhere. It is honest
only when the receipt proves the caller-visible barrier scope, dependency set,
replay identity, committed-root or intent publication boundary, and completion
state that make the acknowledged bytes recoverable in the right order.

Trust-domain evidence is the security counterpart. A remote, WAN, internet,
cross-tenant, encrypted, deduplicated, replicated-RAM, repair, or geo decision
is not legal because the path is reachable or the peer is in a roster. It is
legal only when the receipt cites the authenticated identity, administrative or
security domain, tenant/policy domain, key epoch, authorization, and audit
evidence that make that participant eligible for the role.

Capacity admission evidence is the resource counterpart. A write, sync,
placement, repair, relocation, rebake, or geo catch-up plan is not legal because
bytes might become free eventually. It is legal only when the receipt or
admission record cites the logical, physical, dirty-window, allocation-ticket,
reserve-escrow, and recovery headroom that lets the policy complete without
stealing from protected sync, repair, evacuation, or receipt-retirement
reserves.

Recovery/degradation evidence is the failure counterpart. A degraded read,
repair, rebuild, partition-healing, geo catch-up, or receipt-retirement decision
is not legal because some surviving bytes can be found. It is legal only when
the receipt cites the source receipts, reconstruction width, missing/corrupt
targets, partition/fence state, repair obligation, replacement receipt
publication, and visibility/refusal law that make the weaker or healing state
honest.

Policy rollout evidence is the time counterpart. A new policy revision is not
legal because a property was edited or a caller asked for a different shape. It
is legal only when publication, stage, rollback, downgrade authorization,
in-flight fences, convergence frontiers, and mixed-revision explanation say
which operations use the old revision, which use the new revision, and which
receipts still owe convergence.

Tenant and budget isolation evidence is the fairness counterpart. A plan is not
high-performance because aggregate throughput improved while one dataset's bulk
stream, rebuild, relocation, or geo catch-up destroys another tenant's p99 sync
latency. It is legal only when budget-owner, isolation-scope, fair-share,
borrowing/debt, starvation, noisy-neighbor, reserve-exemption, and
throttle/refusal evidence say who is paying, who is protected, and which work is
allowed to proceed under pressure.

Prediction accountability evidence is the learning counterpart. A hotness,
lifetime, compression, scan, WAN, or relocation prediction is not trustworthy
because it once looked plausible. It is useful only when observation provenance,
confidence, action class, shadow/admitted decision, measured outcome, payback
or harm, cooldown, and confidence-update evidence say what was predicted, what
TideFS did, and whether the result should make the next similar action easier
or harder to admit.

Temporal evidence is the timebase counterpart. RPO lag, stale-read age,
receive-base freshness, policy-stage deadlines, lease or key expiry, TTL
retention, prediction cooldown, and payback windows are not honest because two
events have timestamps. They are useful only when timebase identity, clock
health, skew or uncertainty bounds, sequence frontiers, expiry/deadline refs,
and temporal refusal evidence say which ages and lags are comparable.

Media capability evidence is the device-semantics counterpart. A target is not
eligible for durable intent, PMem authority, block-volume FUA, ZNS placement,
or archive durability because it was labeled NVMe, SSD, HDD, PMem, RAM, or
remote. It is eligible only when persistence domain, flush/FUA behavior,
volatile-write-cache policy, atomicity, namespace identity, protocol/geometry,
health, freshness, and role-eligibility evidence say the media can legally play
that role.

Decision-frontier evidence is the optimizer-accountability counterpart. A plan
is not high-performance, cost-effective, or gentle to flash because the selected
candidate says so. It is reviewable only when candidate set, hard-gate
rejections, score vector, selected plan, tie-breakers, reserve refs,
counterfactual baseline, and outcome/payback anchors say which legal choices
existed, which ones were refused or unknown, why the winner won, and how the
next similar decision will learn from the result.

Action-execution evidence is the actuation counterpart. A planner decision is
not execution, a target write is not cutover, and a replacement receipt is not
permission to retire the source by itself. Authority-changing work is legal
only when action identity, step state, idempotency/replay, source protection,
target verification, publication boundary, abort/rollback state, and budget
outcome evidence prove how the selected plan moved from intention to durable
effect.

Service-objective evidence is the workload contract counterpart. A path is not
low-latency, high-throughput, RAM-fast, WAN-safe, flash-friendly, or
competitively better because one score or benchmark artifact says so. It is
eligible only when a compiled objective binds the policy revision, workload
phase, operation mix, latency percentiles, tail/jitter, throughput,
concurrency, queueing, degradation, topology/media profile, isolation, cost,
wear, attribution, query snapshot, and refusal evidence that make that claim
true for the declared envelope.

Measurement-attribution evidence is the causality counterpart. A p99 drop,
throughput gain, cache-hit change, flash-write reduction, egress saving, or
payback result is not proof that the selected policy/action caused it merely
because the numbers were measured nearby. It is usable only when measurement
identity, subject scope, policy revision, workload envelope, environment/noise
profile, sample window, comparator/counterfactual lineage, decision/action refs,
metric vector, confounder state, attribution verdict, and retention refs say
whether the outcome belongs to the intervention and what it may legally
influence.

Evidence-query snapshots are the consistency counterpart. A planner,
reconciler, executor, read path, explanation surface, performance row, fault
row, or claim gate is not allowed to assemble its own truth by racing live
indexes or scanning whatever local cache is warm. It may use an evidence set
only when query identity, subject scope, policy revision, freshness frontier,
included evidence refs, source-index generations, completeness verdict,
retention rule, and refusal/degradation state say the set is one lawful cut for
that consumer.

Evidence-retention evidence is the proof-lifetime counterpart. Storage intent
must not create an unbounded write-amplifying metadata system, but it also must
not compact away the receipts, decision frontiers, outcomes, cooldowns, fault
artifacts, or claim evidence still needed to prove correctness. Evidence is
retainable, summarizable, redactable, or purgeable only when dependency,
frontier, claim, cooldown, and audit evidence say the proof is no longer needed
in exact form.

## Non-Claims

This document does not implement runtime behavior, change POSIX durability
semantics, add a production persistent WAL, prove RDMA, prove distributed
availability, enable mounted device-level compression or encryption, implement
deduplication or erasure coding, or claim performance superiority over OpenZFS,
Ceph, DRBD, or any other system.

It defines authority boundaries and follow-up work. Runtime and performance
claims require issue-scoped implementation and validation evidence.

## Why The First-Order Design Was Not Enough

The tempting model is three axes:

- guarantee or sync/async acknowledgment class;
- proximity or latency domain;
- throughput or workload class.

That model is necessary, but it is too shallow. Labels do not make data safe,
fast, cheap, or kind to flash. A `fast` tier can be a data-loss footgun. A
`remote-memory` reply can be weaker than local durable intent. A defragger can
improve HDD reads while wasting SSD lifetime. A WAN replica can be valuable for
RPO while being impossible to use as a low-latency POSIX sync target. A cache
cannot become authority merely because operators want memory-speed storage.

The native design therefore has five layers:

1. A requested storage intent policy.
2. A predictor that estimates workload, topology, media, wear, and cost.
3. A planner that chooses a legal placement, acknowledgment, and relocation
   strategy under hard policy constraints.
4. Receipts that prove what was actually earned before acknowledgment.
5. Feedback that tightens future placement without weakening already requested
   guarantees.

Prediction may optimize, but it may not lie. Placement may adapt, but it may
not weaken the acknowledgment contract. Relocation may improve layout, but it
must preserve durable locator authority.

## Design Principles

1. Policy precedes placement. Placement is an implementation of an intent, not
   the intent itself.
2. Evidence beats labels. An acknowledgment class is valid only when the
   required receipt evidence exists.
3. Durability barriers do not silently degrade. `fsync`, `fdatasync`,
   `O_DSYNC`, FUA, and stable NFS-style writes must either earn the configured
   durability floor or return a typed error/refusal.
4. Unsafe fast modes must be product-visible, operator-visible, and
   receipt-visible. TideFS must not grow a hidden equivalent of
   `sync=disabled` for a POSIX mount.
5. Cache is not authority. RAM-backed authority requires explicit volatile,
   replicated-volatile, persistent-memory, or intent-backed semantics.
6. RDMA is an accelerator, not a correctness dependency. TCP-class transport
   remains the baseline, including internet paths.
7. Write amplification and flash lifetime are first-class placement costs.
   Moving data is not free just because a device is fast.
8. Relocation, defrag, compaction, rebake, rebuild, evacuation, archive
   migration, and geo catch-up are one family of receipt-preserving optimizer
   actions.
9. The operator must be able to ask: what guarantee did this write request,
   what guarantee did it receive, where are the bytes, what is lagging, what
   did it cost, and why was that placement chosen?
10. Performance truth needs workload envelopes. TideFS does not get to claim
    speed from a single throughput number while hiding p99 latency, write
    amplification, rebuild cost, or RPO lag.

## Native Object Model

### Record Contract

#841 owns the shared record surface. It must define enough structure that local
filesystem, placement, transport, scheduler, relocation, validation, and
operator code can exchange storage-intent evidence without inventing local
policy dialects.

The core records are:

| Record | Purpose |
| --- | --- |
| `StorageIntentPolicy` | Requested durable/authoritative behavior after policy compilation. |
| `StorageIntentPolicyId` and `StorageIntentPolicyRevision` | Stable identity for the compiled policy snapshot used by one operation or planning epoch. |
| `StorageIntentReceipt` | Earned acknowledgment evidence for one operation, range, or convergence step. |
| `StorageIntentEvidenceRef` | Reference to placement receipts, local intent records, transport/path evidence, media/cost ledgers, scheduler admission records, or validation artifacts. |
| `StorageIntentEvidenceQuerySnapshot` | Query identity, consumer class, subject/policy scope, temporal/freshness frontier, included evidence refs, source-index generations, completeness verdict, retention/refusal state, and replay/audit anchors owned by #913 and consumed by planners, reconciler, read serving, actions, attribution, explanation, performance, fault, and claims gates. |
| `StorageIntentMembershipEvidence` | Reference projection of membership epoch, committed roster, quorum-set identity, witness/data role, failure-domain binding, drain/fence state, and split-brain hazard state owned by #750. |
| `StorageIntentOrderingEvidence` | Barrier, dependency, replay, dirty-epoch, intent-sequence, commit/root publication, and completion evidence owned by #894. |
| `StorageIntentMetadataNamespaceEvidence` | Namespace and metadata-operation evidence for inode/directory/xattr/ACL/small-object mutation scope, VFS/namespace authority refs, metadata locality, fsyncdir and namespace-intent receipts, small-object shape, metadata write-amplification, and typed metadata refusal owned by #922. |
| `StorageIntentTrustEvidence` | Security, administrative-domain, tenant-domain, key-epoch, authorization, audit, and compromise/quarantine evidence owned by #897 and sourced from the security, authz, transport, and transform authorities. |
| `StorageIntentCapacityAdmissionEvidence` | Logical/physical headroom, allocation-ticket, claim/reserve ledger, dirty-window, pending-free, reserve-pressure, and ENOSPC/refusal evidence owned by #898 and sourced from capacity, allocator, reserve, scheduler, and lifecycle authorities. |
| `StorageIntentRecoveryEvidence` | Degraded state, source receipt set, reconstruction width, missing/corrupt/stale target evidence, read-repair/rebuild obligation, replacement receipt publication, old-receipt retirement, partition/healing, RPO/RTO lag, and refusal evidence owned by #900 and sourced from placement receipts, scrub/repair/rebuild, membership, trust, ordering, capacity, layout, and lifecycle authorities. |
| `StorageIntentPolicyRolloutEvidence` | Policy source provenance, compiled policy revision, publication transaction, change class, downgrade authorization, stage state, in-flight fence, convergence frontier, rollback/re-entry, supersession, and refusal evidence owned by #901 and sourced from policy config, authz/audit, operator runbook, satisfaction, and receipt authorities. |
| `StorageIntentIsolationEvidence` | Tenant, dataset, policy/budget-owner, workload-class, isolation-scope, fair-share, burst, borrowing/debt, starvation, noisy-neighbor, reserve-exemption, throttle/defer, and refusal evidence owned by #902 and sourced from trust/domain, scheduler, resource-governor, cost, capacity, wear, transport, performance, and fault authorities. |
| `StorageIntentWorkloadEvidence` | Bounded workload observations, prediction confidence, hint provenance, signal materialization and collection-cost refs, action class, shadow/trial/admitted decision refs, outcome/payback/harm refs, cooldown, misprediction, and confidence-update evidence owned by #845 and consumed by placement, scheduling, relocation, explanation, performance, and fault gates. |
| `StorageIntentTemporalEvidence` | Timebase identity, clock-health, skew/uncertainty, evidence age, event/frontier stamp, lag/staleness, expiry/deadline, sequence-to-time conversion, and temporal refusal evidence owned by #903 and consumed by geo, read-serving, lifecycle, rollout, trust, prediction, relocation, performance, and fault gates. |
| `StorageIntentMediaCapabilityEvidence` | Device/media identity, persistence domain, flush/FUA/barrier semantics, volatile-cache policy, atomicity/granularity, protocol/geometry capability, health/freshness, role eligibility, and refusal evidence owned by #904 and consumed by ack receipts, placement, layout, wear, RAM/PMem, relocation, explanation, performance, and fault gates. |
| `StorageIntentDecisionEvidence` | Decision identity, candidate frontier, hard-gate results, score vector, selected candidate, tie-breaker, reserve/admission refs, counterfactual baseline, payback/harm anchors, and refusal/defer evidence owned by #905 and consumed by placement, scheduling, read-serving, relocation, explanation, performance, fault, and claims gates. |
| `StorageIntentActionExecutionEvidence` | Action identity, decision/admission refs, step state, idempotency/replay proof, source protection, target verification, publication/cutover boundary, abort/rollback state, outcome/budget accounting, and execution refusal evidence owned by #911 and consumed by relocation, rebake, repair, read-serving, receipt retirement, explanation, performance, fault, and claims gates. |
| `StorageIntentServiceObjectiveEvidence` | Objective identity, policy/workload/operation scope, latency percentile and tail/jitter envelope, throughput/burst/dwell/concurrency/queueing profile, degradation/RPO/RTO ties, topology/media/environment profile, isolation/cost/wear budget refs, decision/admission/action/query/attribution refs, comparator/claim refs, and refusal state owned by #915 and consumed by planning, scheduling, read serving, relocation, explanation, performance, fault, and claims gates. |
| `StorageIntentResultRefusalEvidence` | Caller-visible result identity, request/idempotency token, policy/query/decision/receipt refs, failed hard-gate or objective refs, degraded-visible state, response-registry projection, errno/block/API/render mapping, retryability, delivery/index refs, and retention/audit refs owned by #920 and consumed by adapters, retries, explanation, traces, performance, fault, and claims gates. |
| `StorageIntentMeasurementAttributionEvidence` | Measurement identity, subject scope, policy/workload/environment/noise binding, sample window, comparator/counterfactual lineage, decision/action/admission refs, metric/KPI/cost/wear vectors, confounder state, attribution verdict, and allowed-use/refusal evidence owned by #912 and consumed by prediction, relocation, explanation, performance, fault, and claims gates. |
| `StorageIntentEvidenceRetention` | Evidence identity, dependency graph, retention class, proof root, compaction/summarization rule, safe purge frontier, retention media/cost/privacy envelope, and retention refusal evidence owned by #910 and consumed by evidence producers, explanation, performance, fault, claims, recovery, rollout, and cleanup gates. |
| `StorageIntentDataShape` | Requested and earned encoded shape for a range or generation, including record sizing, transform ordering, digest suite, dedup/encryption/EC compatibility, and rebake evidence. |
| `StorageIntentLayoutEvidence` | Allocator and physical-layout evidence for fragmentation, free runs, alignment, zone/write-pointer state, pending frees, reclaim debt, and locality. |
| `StorageIntentLifecycleEvidence` | Generation and retention evidence for write age, stability, snapshots, clones, receive bases, orphans, destroy/tombstone state, and reclaim frontiers. |
| `StorageIntentExplanation` | Renderable projection of policy, receipt, lag, volatility, cost, and refusal reasons. |

The record contract follows the existing receipt and binary-schema discipline:

- records use stable canonical spellings and explicit ids/revisions;
- authority records are `no_std`-suitable and do not depend on local filesystem,
  transport runtime, FUSE, operator UI, or platform-width types;
- optional serialization is a transport or artifact projection, not the durable
  authority unless the consuming issue explicitly defines that wire/on-disk
  format;
- unknown discriminants, non-zero reserved fields, malformed widths, and
  unsupported versions fail closed for authority paths;
- high-cardinality observations are bounded by sketches, histograms, digests,
  top-K sets, or evidence references rather than unbounded per-file/per-range
  vectors;
- existing `TierGoal`, pool-label `DeviceClass`, transport lane, and placement
  policy types are input projections or adapters, not storage-intent authority.

Most importantly, receipt satisfaction is a predicate, not an enum comparison.
A caller or planner must ask whether a specific receipt set satisfies a
specific policy revision under the declared failure, proximity, media, RPO,
cost, and degradation requirements. A `geo-async` receipt can satisfy a local
durability floor with explicit remote lag, but it must not satisfy a
`geo-intent` floor. A full local placement receipt may satisfy local durability
but still fail a remote-site requirement. A volatile replicated receipt may
survive a primary process failure but still fail a power-loss durability
barrier.

The #841 type/model slice should therefore expose tested helpers or equivalent
model predicates for:

- ack receipt class versus requested guarantee floor;
- ordering/replay legality, including caller-visible barrier scope,
  dependency closure, replay idempotency, and commit/root publication state;
- metadata/namespace legality, including inode and directory identity,
  generation, raw-name, parent/child relation, link-count, cookie, xattr/ACL
  namespace, small-object cohort, namespace intent, directory fsync, metadata
  locality, directory index, small-file shape, lookup/cache projection,
  metadata wear, and typed conflict/refusal state;
- local, node, rack, datacenter, WAN, internet, and geo failure-domain
  dimensions;
- membership epoch, committed-roster, quorum-set, witness-role, fence/drain,
  and split-brain legality;
- trust/security-domain legality, including peer identity, admin/security
  domain, tenant/policy domain, key epoch, authorization, audit, compromise,
  quarantine, and regulatory/residency refusal state;
- capacity/admission legality, including logical quota/domain headroom,
  physical allocation class headroom, dirty-window reserve, allocation ticket,
  reserve escrow, pending-free safety, protected floor, and ENOSPC/refusal
  state;
- recovery/degradation legality, including source receipt set, reconstruction
  width, degraded visibility, repair obligation, no-quorum or partition state,
  replacement receipt publication, old-receipt retirement, RPO/RTO lag, and
  hidden-downgrade refusal state;
- policy rollout legality, including source provenance, compiled policy
  revision, publication transaction, change class, downgrade authorization,
  stage state, in-flight fences, convergence frontier, rollback/re-entry, and
  mixed-revision explanation state;
- tenant and budget isolation legality, including budget-owner identity,
  isolation scope, fair-share floor/ceiling, burst and borrowing law,
  usage/debt ledger, starvation state, noisy-neighbor harm, reserve exemption,
  and throttle/defer/refusal state;
- workload and prediction legality, including observation window, sample mass,
  hint provenance, contradiction state, action class, decision id, shadow/trial
  state, measured outcome, payback or harm, cooldown, and confidence-update
  state;
- service-objective legality, including objective identity, workload phase,
  operation mix, latency percentile and tail/jitter bounds, throughput floor or
  ceiling, burst/dwell window, concurrency and queue profile, degradation/RPO/RTO
  treatment, topology/media/environment scope, isolation/cost/wear refs,
  admission/action/query/attribution refs, comparator/claim refs, and typed
  refusal state;
- result/refusal legality, including request or idempotency token, caller
  surface, operation class, policy revision, evidence-query snapshot,
  decision-frontier refs, earned receipt or failed hard-gate refs,
  degraded-visible state, response-registry scope/truth-cut/render/refusal
  class, POSIX/block/API/trace projection, retryability, delivery/index refs,
  and retention/audit refs;
- temporal legality, including timebase identity, monotonic or wall-clock
  domain, skew or uncertainty bound, evidence age, event/frontier stamp,
  expiry/deadline state, sequence-to-time conversion, and temporal refusal
  state;
- media capability legality, including device identity, namespace/pool binding,
  persistence domain, flush/FUA/barrier semantics, volatile-cache policy,
  atomic write granularity, protocol/geometry capability, health/freshness,
  role eligibility, and media-capability refusal state;
- decision-frontier legality, including decision identity, candidate-set
  digest, hard-gate result set, score vector, selected candidate, tie-breaker,
  reserve/admission refs, counterfactual baseline, payback/harm anchors,
  unknown-cost handling, and decision refusal/defer state;
- action-execution legality, including action identity, selected decision ref,
  reserve/admission refs, step state, idempotency key, replay generation, source
  receipt protection, target verification, publication/cutover boundary,
  abort/rollback state, outcome/budget accounting, and execution refusal state;
- measurement-attribution legality, including measurement identity, subject
  scope, policy revision, workload envelope, environment/noise profile, temporal
  sample, comparator/counterfactual lineage, decision/action/admission refs,
  metric/KPI vectors, cost/wear deltas, confounder/censoring state, attribution
  verdict, and allowed-use/refusal state;
- evidence-query legality, including query identity, consumer class, subject
  scope, policy revision, request/action/read/validation context, temporal
  frontier, included evidence refs, source-index generations, freshness/staleness
  bounds, completeness verdict, replay/audit anchors, retention dependency, and
  query refusal/degradation state;
- evidence-retention legality, including evidence identity, dependency graph,
  retention class, proof root, compaction rule, summarization fidelity,
  redaction/audit state, tombstone state, safe purge frontier, retention media
  budget, cost/privacy envelope, and retention refusal state;
- volatile, durable-intent, full-placement, and RPO/lag dimensions;
- media-role legality, including cache versus RAM authority separation;
- data-shape legality, including transform compatibility, digest/integrity
  floors, dedup/encryption-domain rules, and rebake replacement evidence;
- allocator/layout legality, including alignment, free-space, zone, pending-free,
  generation, and reclaim-debt boundaries;
- lifecycle/generation legality, including retained roots, receive bases,
  orphan holds, destroy state, and reclaim-frontier boundaries;
- explicit refusal reasons when no legal receipt set satisfies the policy.

### StorageIntentPolicy

Every durable or authoritative placement decision consumes a
`StorageIntentPolicy` shape, whether the policy was explicit, inherited from a
dataset, derived from a mount profile, or generated by an internal repair path.

The policy has these logical fields:

| Field | Meaning |
| --- | --- |
| `guarantee_floor` | Minimum acknowledgment evidence needed before reporting success. |
| `visibility_profile` | Whether weaker acknowledgments may be returned to callers or must fail closed. |
| `ordering_policy` | Required barrier scope, dependency closure, replay idempotency, dirty-epoch sealing, intent sequence, and committed-root/publication boundary. |
| `proximity_domain_set` | Allowed latency/topology domains for serving, intent, replica, and archive roles. |
| `membership_epoch_policy` | Required epoch freshness, quorum-set identity, witness/data role, failure-domain binding, drain/fence treatment, and split-brain refusal law. |
| `trust_domain_policy` | Required security/admin/tenant domain eligibility, session-security posture, key epoch, authorization/audit refs, cross-domain sharing law, compromise/quarantine treatment, and regulatory/residency refusal law. |
| `capacity_admission_policy` | Required logical/physical headroom, quota/slop law, allocation-ticket and reserve-escrow treatment, dirty-window reserve, pending-free eligibility, protected-floor law, and ENOSPC/refusal behavior. |
| `recovery_degradation_policy` | Required degraded-mode visibility, reconstruction width, read-repair/rebuild obligation, no-quorum/partition handling, RPO/RTO lag, replacement receipt publication, old-receipt retirement, and hidden-downgrade refusal behavior. |
| `policy_rollout_policy` | Required revision publication, staging, downgrade authorization, old-receipt grandfathering, convergence obligation, rollback/re-entry, supersession, and mixed-revision explanation behavior. |
| `isolation_policy` | Required tenant/dataset/workload budget owner, fair-share floor and ceiling, burst/borrow/debt law, noisy-neighbor treatment, starvation override, reserve-exemption, and throttle/refusal behavior. |
| `media_role_policy` | Which media classes may hold intent, metadata, serving data, cold data, read cache, or scratch data. |
| `metadata_namespace_policy` | Required metadata-operation scope, namespace-intent and fsyncdir receipt law, inode/generation/link/cookie conflict guards, directory/xattr/ACL locality, small-object inline or packed shape, metadata wear budget, and metadata-refusal behavior. |
| `workload_shape` | Workload envelope the planner should optimize for without changing hard guarantees. |
| `service_objective_policy` | Required latency percentile/tail/jitter envelope, throughput floor or ceiling, burst/dwell/concurrency/queueing profile, degradation/RPO/RTO tie-in, topology/media/environment scope, isolation/cost/wear budget refs, comparator/claim boundary, and refusal/defer behavior before a workload may be called fast, low-latency, high-throughput, RAM-fast, WAN-safe, flash-friendly, or superior to an incumbent. |
| `prediction_control_policy` | Required confidence, dwell, shadow-evaluation, action-class threshold, feedback, cooldown, and misprediction treatment before prediction-driven movement or serving promotion is legal. |
| `temporal_policy` | Required timebase, skew/uncertainty, freshness, expiry, lag, deadline, and sequence-frontier evidence before wall-time or age-based claims are legal. |
| `media_capability_policy` | Required persistence domain, flush/FUA, atomicity, namespace identity, volatile-cache, protocol/geometry, health, and freshness predicates for each media role. |
| `decision_audit_policy` | Required candidate retention, hard-gate result retention, score-vector dimensions, unknown-cost treatment, deterministic tie-breakers, counterfactual baseline, and outcome/payback attachment for planner and optimizer decisions. |
| `action_execution_policy` | Required action step state, idempotency/replay proof, source protection, target verification, publication/cutover boundary, abort/rollback treatment, and execution outcome accounting for authority-changing actions. |
| `measurement_attribution_policy` | Required sample window, measurement source, baseline/counterfactual, noise/confounder treatment, attribution verdict, cross-scope transfer rule, and refusal behavior before outcome metrics may train prediction, close payback, drive movement, spend wear budget, or support claims. |
| `evidence_query_policy` | Required evidence cut scope, freshness frontier, source-index generation, completeness verdict, redaction/compaction handling, replay/audit anchor, and refusal/degradation behavior before consumers may act on a set of evidence. |
| `evidence_retention_policy` | Required retention class, dependency retention, proof-root/tombstone treatment, compaction fidelity, redaction/audit treatment, safe purge frontier, retention media placement, and evidence metadata budget for storage-intent proof. |
| `data_shape_policy` | Record sizing, compression, checksum/digest, dedup, encryption, EC/archive, coalescing, and rebake constraints. |
| `layout_geometry_policy` | Allocator class, physical layout, fragmentation, zone/alignment, free-space, pending-free, and reclaim constraints. |
| `lifecycle_policy` | Generation age, retention, receive-base, orphan, destroy/tombstone, and reclaim-frontier constraints. |
| `cost_model` | Relative cost weights for latency, tail, throughput, media wear, capacity, power, network egress, and operator money. |
| `wear_budget` | Per-device or per-class write budget available for this policy and relocation class. |
| `relocation_policy` | When the system may rewrite, rebake, promote, demote, defrag, or evacuate data. |
| `degradation_policy` | Whether to refuse, block, serve stale-forbidden errors, or return explicit lower-class receipts under failure. |
| `explanation_scope` | Minimum operator-visible reason data that must be preserved. |

The policy is a tradeoff envelope, not a single tier label. It separates hard
floors from optimizer weights:

| Axis | Hard-floor examples | Optimizer examples |
| --- | --- | --- |
| Acknowledgment | durable local intent, quorum intent, geo intent, explicit volatile | group size, sharding, pipelining, full-placement delay |
| Ordering and replay | fsync/fdatasync/O_DSYNC/FUA barrier scope, replay idempotency, dependency closure, committed-root or durable-intent boundary | group commit shape, sharded intent lane, coalescing window, replay-index layout |
| Latency and tail | p99 sync or FUA ceiling, max queue time before refusal | prefer local NVMe/PMem, reduce metadata fan-out, cache read hot sets |
| Throughput | minimum ingest or rebuild rate under foreground protection | larger records, direct cold placement, batching, EC/archive shape |
| Data shape and integrity | checksum/digest suite, encryption domain, mounted transform block state, dedup/EC compatibility | record size, compression level, coalescing, dedup verdict, EC/archive shape |
| Allocation geometry | alignment, reserve, free-space, pending-free, zone/write-pointer compatibility | choose low-seek layout, largest legal free run, segment class, drain victim |
| Lifecycle and retention | retained roots, receive bases, orphan holds, destroy state, reclaim frontier | defer flash full placement for young bytes, favor cold retained generations |
| Membership and fencing | committed roster epoch, quorum-set identity, witness/data role, fence/drain legality, split-brain refusal | prefer stable nearby quorum, avoid draining peers, reduce epoch-churn disruption |
| Trust and security domain | authenticated peer/principal identity, admin/security/tenant domain, key epoch, authorization, audit, residency, quarantine | prefer same-admin-domain peers, encrypted carriers, low-risk domains, tenant-local sharing |
| Distance and failure domain | node/rack/DC/site/region spread, internet path allowed or refused | nearest legal peer, measured RTT/loss/bandwidth scoring |
| RPO/RTO | maximum remote lag or recovery window | delta batching, compression, catch-up lane priority |
| Capacity and reserve | logical quota/slop, physical free-space class, allocation ticket, dirty-window reserve, protected repair/sync floors, pending-free safety | choose lower-amplification shape, delay optimizer, trigger reclaim, batch convergence |
| Recovery and degradation | source receipt set, reconstruction width, visible degraded state, repair obligation, no-quorum/partition refusal, replacement receipt before retirement | prioritize repair, choose cheaper reconstruction source, batch rebuild, tune read-repair foreground cost |
| Policy revision rollout | published revision, change class, downgrade authorization, in-flight fence, convergence frontier, rollback receipt, mixed-revision visibility | stage cohorts, prioritize convergence, batch rematerialization, defer low-risk generations |
| Tenant and budget isolation | budget owner, isolation scope, p99/tail floor, fair-share floor/ceiling, borrowing law, reserve-exemption, throttle/refusal state | donate unused share, schedule bursts, rebalance lanes, demote noisy background work |
| Action execution | idempotency key, step state, source protection, target verification, cutover/publication proof, abort/rollback visibility | batch copy work, pause/retry, choose cheaper safe source, delay source retirement |
| Measurement attribution | valid sample window, comparator/counterfactual, noise/confounder bounds, decision/action refs, attribution verdict | choose shadow experiment, observation window, conservative cooldown, transfer scope |
| Evidence query | query cut identity, included evidence refs, freshness frontier, completeness verdict, source-index generations | choose bounded query width, cached projection, replay depth, redaction scope |
| Wear and money | critical write reserve, WAF ceiling, egress/capacity budget | promote/demote only when payback beats movement debt |

A candidate must satisfy all hard floors before scoring. Cost weights may pick
among legal candidates, but they may not trade away durability, failure-domain
spread, RPO, or explicit latency floors unless a new compiled policy revision
permits the weaker visible result.

### Policy Sources And Compilation

`StorageIntentPolicy` is a compiled snapshot, not a bag of ad hoc hints
recomputed independently by each subsystem. The compiler resolves the current
policy sources into one immutable revision that write admission, fsync,
placement, relocation, transport, RAM authority, performance gates, and
operator explanation can all cite.

Policy sources are ordered from broad defaults to request-specific inputs:

| Source | Purpose |
| --- | --- |
| Pool default | Baseline durability, proximity, media, and cost posture for new datasets. |
| Dataset policy | Inheritable operator policy, including durability floor, placement shape, unsafe-mode opt-in, RPO/RTO, cost envelope, and relocation allowance. |
| Mount or product profile | Product contract such as POSIX-durable, block-volume flush/FUA, explicit scratch, geo-replica, archive, or unsafe throughput-first profile. |
| File/range policy | Optional narrow override for objects that need different serving or retention behavior; unsupported forms must be explicit refusals, not ignored hints. |
| Caller request | Operation flags such as sync, direct, FUA, barrier, stable write, cache bypass, or caller-provided lifetime hint. |
| Internal maintenance intent | Repair, evacuation, rebake, relocation, scrub, reclaim, and geo catch-up intents generated by TideFS itself. |

Resolution is not last-writer-wins. Each source participates in a typed merge:

- product and mount profiles set the external contract that callers see;
- caller flags such as sync, FUA, barrier, and stable write can tighten the
  current operation's required receipt, but they cannot lower a durable product
  floor;
- caller lifetime, hotness, and cache hints may influence workload prediction
  and placement scoring, but they are non-authoritative until compiled into a
  policy revision;
- file/range overrides can narrow placement or retention only when the dataset
  policy permits that override class;
- internal maintenance intents can request repair, evacuation, or geo-catch-up
  privileges, but they still obey the source policy's receipt-retirement and
  degradation law;
- explicit unsafe or volatile profiles require named operator opt-in and must
  produce receipts that expose the weaker guarantee.

Contradictory sources produce a compiled refusal, not a hidden compromise. A
POSIX-durable mount profile plus a volatile caller hint is still durable or
refused. A geo-intent dataset plus a local-only media pool is refused or
admitted as explicitly degraded only when the policy says degradation is
allowed and visible. A cost or wear budget can delay or refuse work, but it may
not secretly lower the acknowledgment floor.

The compiler must produce:

- a policy id and monotonically changing policy revision;
- source-policy provenance refs, previous and target revision refs, policy
  epoch, and policy publication transaction or commit boundary;
- rollout change class, stage state, downgrade authorization requirement,
  old-receipt treatment, in-flight fence requirements, and convergence
  obligation for the revision;
- budget-owner, isolation-scope, fair-share, borrowing/debt, starvation,
  noisy-neighbor, reserve-exemption, and throttle/refusal requirements;
- service-objective envelope requirements for the workload/operation class,
  including latency percentiles, tail/jitter, throughput, burst/dwell windows,
  concurrency, queueing, degradation/RPO/RTO, topology/media/environment scope,
  isolation, cost, wear, comparator, and refusal behavior;
- the effective guarantee floor and failure-domain floor;
- the ordering, replay, barrier, dirty-epoch, and dependency requirements;
- the membership epoch, quorum, witness, drain/fence, and split-brain evidence
  requirements;
- the trust/security-domain, key-epoch, authorization, audit, compromise, and
  residency requirements;
- the capacity admission, allocation-ticket, reserve-escrow, dirty-window,
  pending-free, protected-floor, and ENOSPC/refusal requirements;
- the recovery/degradation, reconstruction-width, repair-obligation,
  no-quorum/partition, RPO/RTO-lag, replacement-receipt, and old-receipt
  retirement requirements;
- the action-execution step, idempotency/replay, source-protection,
  target-verification, publication/cutover, abort/rollback, and outcome-accounting
  requirements;
- the measurement-attribution sample, comparator/counterfactual, noise/confounder,
  transfer-scope, verdict, allowed-use, and refusal requirements;
- the evidence-query cut scope, freshness frontier, source-index generation,
  completeness, replay/audit, redaction/compaction, retention, and refusal
  requirements;
- the evidence-retention class, dependency/proof-root requirements, compaction
  fidelity, tombstone, safe-purge, redaction/audit, and evidence metadata budget
  requirements;
- the visibility/degradation law for weaker receipts;
- allowed and forbidden proximity domains by role;
- allowed and forbidden media roles by class and generation;
- cost, wear, capacity, network, and foreground-disruption budgets;
- relocation rights and convergence requirements;
- an explanation/audit record naming which sources participated.

Consumers must not locally reinterpret raw dataset properties or mount options
when a compiled storage-intent policy exists. The compiled snapshot is the
authority for one operation or planning epoch. Dataset property frameworks,
pool placement policy, and mount profiles remain source authorities for their
own fields; storage intent owns the cross-source resolution into a single
requestable contract.

Policy change semantics are part of the contract:

1. Strengthening a guarantee may apply to new writes immediately, but old bytes
   are not considered upgraded until replacement receipts or convergence
   evidence exist.
2. Weakening a durable or geo guarantee requires explicit operator consent and
   must be visible as a policy revision. It may not silently transform already
   acknowledged durable data into a weaker product claim.
3. Enabling volatile or unsafe profiles is opt-in, named, and receipt-visible.
4. Unsupported combinations fail closed at compile time when possible, and at
   admission time with typed refusal when topology or media evidence changes.
5. Internal maintenance intents may ask for special privileges such as repair
   reserve or evacuation priority, but they still cite the policy revision and
   may not bypass receipt retirement rules.
6. A published revision becomes applicable only through #901 rollout evidence.
   A raw source edit is not an active storage-intent language until the
   publication transaction, stage state, and in-flight fences say so.
7. Old receipts are immutable history. They may be grandfathered, converged, or
   refused for future use under the current policy, but a policy change does not
   rewrite the guarantee that was actually earned.
8. A revision that is superseded, rolled back, or retired cannot accept new work
   unless the rollout evidence says the work is rollback repair, receipt
   retirement, or other bounded re-entry for old obligations.
9. In-flight fsync/FUA, repair, relocation, rebake, geo catch-up, archive restore,
   and receipt retirement must either finish under their fenced revision or
   re-enter through a new revision with explicit rollback/retry evidence.

### StorageIntentReceipt

Every successful acknowledgment returns or records a `StorageIntentReceipt`
projection. It names what was earned, not merely what was requested.

The receipt must bind:

- requested policy id and revision;
- policy rollout refs where a revision change shaped admission, including
  source policy ref, compiled revision ref, publication transaction, stage
  state, in-flight fence, convergence frontier, or rollback/re-entry ref;
- tenant/budget isolation refs where shared resources shaped admission,
  including budget-owner, isolation-scope, fair-share, burst/borrow/debt,
  starvation, noisy-neighbor, reserve-exemption, and throttle/refusal refs;
- earned acknowledgment class;
- subject id, object key, inode/range, or request id;
- payload digest, range digest, or replay digest as appropriate;
- ordering evidence refs for barrier scope, dirty epoch, dependency closure,
  replay idempotency, intent sequence, and commit/root publication state;
- intent-log receipt refs when replayable intent was used;
- placement receipt refs when durable placement was reached;
- transport/path evidence refs when remote receipt participated;
- membership epoch ref, committed roster hash or equivalent roster identity,
  quorum-set identity, witness/data participant roles, placement epoch, and
  fencing context;
- trust/security-domain refs, authenticated peer/principal identity, key epoch,
  authorization/audit refs, and compromise/quarantine state where remote,
  cross-domain, encrypted, dedup/shared, repair, or geo evidence participates;
- capacity/admission refs for logical and physical headroom, allocation tickets,
  claim/reserve receipts, dirty-window reserve, pending-free safety,
  reserve-pressure state, and any ENOSPC/refusal outcome that shaped the
  result;
- recovery/degradation refs for source receipt set, reconstruction width,
  missing/corrupt/stale targets, repair or rebuild obligation, partition/healing
  state, replacement receipt publication, old-receipt retirement, RPO/RTO lag,
  and any visible degraded or refusal outcome that shaped the result;
- action-execution refs for action id, step state, idempotency/replay proof,
  source protection, target verification, publication/cutover boundary,
  abort/rollback state, and any execution refusal that shaped the result;
- failure domains represented in the receipt;
- media class and persistence semantics for each receipt participant;
- known missing work such as geo lag, archive conversion, or background
  full-placement completion;
- `lost_if` and `survives` summaries suitable for operator explanation.

Receipts are not marketing. They are the bridge between caller semantics,
crash recovery, placement, and operator UAPI.

## Evidence Query Snapshots And Consistent Cuts

#913 owns the storage-intent evidence-query snapshot projection. It does not
produce the underlying receipts, choose placement, reconcile satisfaction,
execute actions, run measurements, or render operator UI. It gives those
consumers a bounded, replayable, freshness-aware evidence cut so they do not
race live evidence producers or rebuild storage-intent truth from subsystem
local indexes.

This is the scalability counterpart to the evidence model. TideFS may have
thousands of devices, tenants, datasets, paths, actions, and validation
artifacts. Requiring every consumer to scan every proof record would be slow,
and allowing every consumer to read whatever projection is nearby would be
wrong. A query snapshot is the narrow contract between those extremes: enough
evidence to decide the requested question, with explicit completeness and
staleness semantics.

Evidence-query snapshots must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `query_identity_ref` | Names query id, snapshot id, consumer class, producer/component version, subject scope, policy id/revision, request/action/read/validation context, and temporal refs. |
| `included_evidence_ref` | Lists receipt, ordering, membership, trust/domain, capacity, recovery, rollout, isolation, workload/prediction, temporal, media-capability, decision-frontier, action-execution, measurement-attribution, retention, data-shape, layout, lifecycle, transport, wear, cost, validation, and claim refs included for this purpose. |
| `source_index_generation_ref` | Binds every included evidence family to source catalog/index generation, producer watermark, compaction/tombstone generation, redaction state, and replay/audit anchor. |
| `freshness_frontier_ref` | Records time/sequence/epoch freshness, allowed staleness by evidence family, policy-revision fence, membership/trust/media/capacity invalidation frontier, and crossed-frontier refusal. |
| `completeness_verdict_ref` | Declares complete-for-purpose, partial-admissible, degraded-visible, unknown-evidence, blocked, refused, or unsafe-visible for the query's consumer class. |
| `query_refusal_ref` | Names missing-index, stale-index, contradictory-cut, mixed-policy, mixed-epoch, over-broad-query, compacted-proof-insufficient, redaction-blocked, unauthorized-evidence, unavailable-producer, or unsupported-query refusal reasons. |
| `retention_replay_ref` | Points to #910 retention state for exact evidence, summary proof roots, tombstones, audit holds, and replay depth required by decisions, actions, measurements, explanations, gates, and claims. |

Hard evidence-query laws:

1. A consumer may not treat an unbounded live scan, cache-local guess, stale
   projection, dashboard sample, or mixed-policy evidence bundle as
   storage-intent authority. It needs a #913 snapshot or a typed refusal.
2. #874 satisfaction reconciliation consumes query snapshots. It may decide a
   state from the evidence cut, but it may not race each evidence producer
   independently and call the result one coherent current truth.
3. #905 decision-frontier evidence must record the query snapshot used for hard
   gates and score inputs. Rejected, unknown, and selected candidates must be
   replayable against the same cut until #910 permits compaction.
4. #911 action execution must revalidate or replan when the query snapshot that
   admitted an action becomes stale, superseded, contradicted, or outside the
   action's freshness window before cutover/source retirement.
5. #912 measurement attribution binds the measurement to the query snapshot
   that selected or executed the intervention. Otherwise a metric cannot prove
   what evidence the decision saw.
6. Redacted, compacted, or summarized evidence can be used only when the query
   snapshot records that the weaker proof form is complete enough for that
   consumer. If not, the result is unknown, blocked, degraded-visible, or
   refused.
7. Operator explanations, performance rows, fault rows, and claims must expose
   the evidence cut when their answer depends on a storage-intent state. Missing
   or refused #913 evidence is a claim blocker, not an implementation detail.

## Satisfaction Reconciliation Loop

Storage intent is a closed control loop, not a one-shot planner output. #874
owns the read-only reconciler that compares one compiled policy revision with
the current evidence set and publishes the satisfaction state other subsystems
must act on.

The reconciler consumes #913 evidence-query snapshots over policy snapshots,
policy rollout evidence, tenant/isolation evidence, ack receipts, placement
receipts, transport path evidence, capacity/admission evidence,
recovery/degradation evidence, action-execution evidence, media-wear and
non-wear cost ledgers, workload signal snapshots, scheduler admission evidence,
RAM authority receipts, relocation state, and validation artifacts. It does not
recompute policy, select new placement, retire old receipts, emit ack receipts,
execute relocation, or race producers outside the query cut. Its job is to make
the current truth machine-readable:

| State | Meaning |
| --- | --- |
| `satisfied` | Current receipts and evidence satisfy the compiled policy revision. |
| `converging` | The ack floor was earned, but full placement, geo, archive, or cost convergence remains pending and visible. |
| `degraded-visible` | The policy explicitly permits a weaker temporary state, and the weaker state is surfaced to callers/operators. |
| `unknown-evidence` | Required evidence is absent, stale, malformed, or contradictory, so satisfaction cannot be inferred. |
| `blocked` | Repair, relocation, geo catch-up, evidence refresh, or reserve recovery is required before success can be claimed. |
| `refused` | No legal receipt set can satisfy the policy under current media, topology, or cost constraints. |
| `unsafe-volatile` | The policy intentionally requested weaker volatile/unsafe behavior and the receipt truth exposes that weaker guarantee. |

Missing, stale, malformed, wrong-policy-revision, superseded-revision,
missing-rollout-fence, missing-budget-owner, over-budget, illegal-borrow,
reserve-theft, noisy-neighbor-harm, under-reserved, expired-reserve,
under-width, wrong-epoch, wrong-failure-domain, wrong-lifecycle,
wrong-reconstruction-width, missing-repair-obligation, unknown-cost,
unknown-WAF, stale-action, partial-action, missing-cutover, cache-only,
stale-query-snapshot, partial-query-cut, mixed-policy evidence, or contradictory
evidence cannot satisfy a durable, geo, isolation, or low-latency floor by
accident. They must become an explicit unknown, blocked, degraded, refused, or
unsafe-visible state according to the compiled policy's degradation law.

This loop is what keeps the whole design native. A predictor may believe a
range is hot, a planner may propose a move, a scheduler may admit a lane, and a
relocation worker may publish replacement bytes, but TideFS only claims policy
satisfaction when the reconciler can cite the receipts and evidence that prove
it. Conversely, when evidence decays or policy strengthens, the reconciler is
the common trigger for visible convergence, repair, relocation, or refusal
instead of each subsystem inventing its own drift detector.

Rollout stage is evidence, not a hidden side channel. A revision may be
`active-for-new-writes` while existing generations reconcile as `converging`;
`rollback-required` normally projects as `blocked` or `refused`; `superseded`
cannot satisfy new work; and `rolled-back` means future admission has returned
to the restored revision while old receipts and partial-stage obligations remain
visible until converged or retired.

## Result, Refusal, And Caller Projection

#920 owns the storage-intent result/refusal evidence projection. It does not
promote `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md` beyond its
historical-input classification or replace any current response/refusal runtime
successor. Instead, it is the storage-intent outcome record that the response
or refusal runtime consumes when a write, read, fsync, FUA, placement decision,
relocation action, operator request, or retry becomes caller-visible.

This boundary exists because a precise internal policy decision is not enough.
The last inch can still lie: a no-quorum refusal can become generic `EIO`, a
stale evidence cut can become a timeout, a degraded read can look exact, a
failed service objective can hide behind success, or a lower acknowledgment
class can be returned as if it satisfied the requested floor. TideFS must make
that impossible by carrying typed result evidence to the surface that replies.

Result/refusal evidence must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `result_identity_ref` | Names result id, request or idempotency token, operation class, caller/surface class, subject scope, policy id/revision, rollout stage, and temporal/frontier refs. |
| `evidence_query_snapshot_ref` | Names the #913 cut used for result derivation, including completeness, freshness, redaction, compaction, source-index generation, and query-refusal state. |
| `decision_result_ref` | Names the #905 decision frontier, selected candidate, rejected/unknown hard gates, score vector refs, tie-breaker, defer/refusal state, and counterfactual baseline. |
| `earned_receipt_ref` | Carries the exact `StorageIntentReceipt` when success or degraded-visible success is legal, including ack class, placement/RPO/RTO/volatility/lag shape, and known remaining work. |
| `failed_gate_ref` | Cites ordering, membership, trust/domain, capacity, recovery, rollout, isolation, temporal, media-capability, service-objective, action, attribution, retention, layout, lifecycle, wear, cost, or transport blockers that make success illegal. |
| `degraded_visibility_ref` | Records #900/#874 degraded-visible state, source receipt set, reconstruction width, missing/corrupt/stale targets, repair obligation, no-quorum/partition state, RPO/RTO lag, and visibility law. |
| `admission_result_ref` | Records #862/#902/#898 lane, queue/admission result, throttle/defer state, budget owner, borrow/debt, reserve exemption, starvation override, or noisy-neighbor protection. |
| `action_result_ref` | Records #911 step state, idempotency/replay state, cutover/publication state, abort/rollback state, source-retirement blocker, and execution refusal for long-running or maintenance work. |
| `response_registry_projection_ref` | Names response-registry scope, truth-cut, render class, refusal class, retention class, delivery commit, index row, and recall binding for the visible answer. |
| `caller_projection_ref` | Names the POSIX errno or FUSE reply, block completion, control-plane JSON/API reply, trace result, operator fieldset, redaction, retry hint, and audit ref emitted to the surface. |
| `retryability_ref` | Distinguishes retry-safe, retry-after-fresh-evidence, retry-after-capacity, retry-after-rollout, retry-after-repair, retry-conflict, terminal-refusal, and unsafe-to-retry states. |
| `retention_audit_ref` | Points to #910 proof retention, delivery/index retention, replay depth, audit hold, and validation or claim dependencies for the result. |

Hard result/refusal laws:

1. A storage-intent result is selected before render compression. POSIX, block,
   control-plane, trace, and operator surfaces may compress or project the
   result only after #920 evidence and the response-registry refusal class
   exist.
2. Generic collapse is illegal. No-quorum, stale evidence, wrong trust domain,
   reserve exhaustion, unsafe volatile cache, unsupported media role,
   degraded-not-admitted, service-objective failure, rollout fence, action
   rollback, missing retention proof, unsupported surface, or idempotent retry
   conflict must not become unqualified success, generic timeout, generic
   `EIO`, or hidden async/volatile downgrade.
3. A successful result must cite the receipt it actually earned. If the earned
   receipt is weaker than the requested floor, the result is degraded-visible
   only when policy permits that weaker state; otherwise it is blocked,
   refused, or unsafe-visible.
4. A degraded read or repaired read may return bytes only when the result cites
   the source receipts, reconstruction proof, repair obligation, and visibility
   law. Otherwise the read refreshes, blocks, refuses, or reports unknown
   evidence.
5. Retry semantics are part of the result. Duplicate requests, crash replay,
   route failover, and idempotent redelivery must return the same delivery
   digest or a typed retry conflict; they may not create a second success
   narrative for the same token.
6. Scheduler throttles, reserve refusals, rollout holds, evidence-refresh
   waits, degraded-visible results, and terminal refusals must be visible to
   operator explanation and traces. A caller may see a compact errno, but the
   indexed result proof must preserve the typed cause.
7. #920 composes response-registry retention and delivery law. A result that
   promises recall, audit, explanation, validation, or claim evidence is not
   complete until delivery/index/retention refs prove that proof can be found
   again.

## Policy Revision Rollout, Rollback, And Convergence Authority

Storage intent consumes policy sources from #855 and production step grammar
from the operator runbook authority, but it still needs its own time-domain
evidence. #901 owns the storage-intent projection that says when a compiled
revision is published, staged, active, converging, rolled back, superseded, or
refused for a particular scope.

#901 does not persist raw policy configuration, grant privileged overrides,
choose placement, execute relocation, or run validation campaigns. It composes
refs from those authorities into predicates that every storage-intent consumer
can use before admitting new work or reinterpreting old evidence.

The rollout evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `source_policy_ref` | Names the pool, dataset, mount, caller, inherited-default, override, or internal-maintenance source set from #855. |
| `compiled_revision_ref` | Binds the candidate to the immutable `StorageIntentPolicy` id/revision that consumers must cite. |
| `previous_revision_ref` and `target_revision_ref` | Distinguish old, restored, target, and superseding policy languages without rewriting old receipts. |
| `policy_epoch_ref` | Orders policy publication relative to membership, receipt, and runbook events. |
| `publication_transaction_ref` | Proves the compiled revision was durably published or explains why it remained a dry-run/preflight artifact. |
| `source_provenance_set` | Records which policy sources participated and which conflicts or inheritance rules were applied. |
| `change_class` | Classifies strengthen, weaken, lateral, incompatible, emergency override, rollback, re-entry, or retirement changes. |
| `downgrade_authorization_ref` | Cites authz/audit evidence required when a change lowers durability, RPO, trust, recovery, capacity, or visibility floors. |
| `stage_state` | Names draft, dry-run, preflight-admitted, staged, active-for-new-writes, converging-existing, blocked, rollback-required, rolled-back, superseded, retired, or refused. |
| `scope_selector` | Names the pool, dataset, mount, file, range, generation, cohort, or internal-maintenance scope affected by the revision. |
| `old_receipt_treatment` | Says whether old receipts are grandfathered, require convergence, are unusable for new claims, or must be refused. |
| `in_flight_fence_ref` | States which writes, sync barriers, reads, repair, rebuild, relocation, rebake, geo catch-up, archive restore, and receipt-retirement actions continue under old or new revision. |
| `convergence_frontier_ref` | Names per-range, per-generation, per-receipt, or per-cohort progress toward the target revision. |
| `replacement_receipt_set_ref` | Proves stronger placement, shape, trust, recovery, or capacity requirements were earned before old-revision satisfaction is claimed. |
| `outstanding_obligation_ref` | Exposes remaining convergence, rollback repair, receipt-retirement, validation, or operator-review work. |
| `rollback_reentry_ref` | Binds rollback anchor, dry-run/preflight result, failed-stage reason, restored revision, rollback receipt, and post-rollback verification. |
| `supersession_ref` | Shows a later revision replaced this one and which obligations remain valid for cleanup. |
| `rollout_refusal_ref` | Gives a typed reason for stale source, conflict, missing authz, unsafe downgrade, fence failure, validation gate failure, convergence debt, or unsupported combination. |

Stage transitions are legal only when their predicates hold:

| Stage | Meaning |
| --- | --- |
| `draft` | Source policy exists but is not a storage-intent language for admission. |
| `dry-run` | The compiler and planner can explain effects, but no new receipt may cite the revision as active. |
| `preflight-admitted` | Capacity, trust, membership, recovery, validation, and runbook refs are sufficient to stage within the selected scope. |
| `staged` | The revision is published for a bounded scope or cohort, with in-flight fences and rollback anchors recorded. |
| `active-for-new-writes` | New operations in scope must cite the new revision, while old receipts keep their historical revision. |
| `converging-existing` | Existing ranges or generations owe replacement receipts, rebake, relocation, repair, or geo catch-up before satisfying the new revision. |
| `blocked` | Evidence, reserve, trust, membership, validation, or runbook prerequisites are missing but the revision is not yet rolled back. |
| `rollback-required` | The stage cannot safely continue; admission must fence new work or re-enter a restored revision. |
| `rolled-back` | Future admission uses the restored revision, while rollback receipts and remaining obligations stay visible. |
| `superseded` | A later revision replaced this one; new work cannot cite it except for bounded cleanup or re-entry. |
| `retired` | No live receipt, convergence, rollback, or explanation dependency still needs the revision. |
| `refused` | The change cannot become active for the selected scope under current evidence or policy. |

Hard rollout laws:

1. Publication is not activation. A compiled revision can exist for dry-run,
   comparison, and operator explanation without admitting new writes.
2. Activation for new writes requires a publication transaction, scope selector,
   stage state, and in-flight fence. Missing one of those is
   `unknown-evidence`, `blocked`, or `refused`.
3. Strengthening may gate new operations immediately, but old generations reach
   stronger satisfaction only after replacement receipts, convergence frontiers,
   and old-receipt retirement law say so.
4. Weakening requires downgrade authorization and audit refs, and it must not
   turn prior durable, geo, recovery, trust, or capacity promises into weaker
   product claims.
5. Reads, repair, rebuild, relocation, rebake, geo catch-up, RAM authority,
   block-volume flush/FUA, and receipt retirement must choose the policy
   revision by receipt identity and rollout fence, not by a mutable global
   property lookup.
6. Relocation across a revision boundary must publish target receipts for the
   target revision before claiming convergence, and it must preserve source
   receipts until rollback and old-receipt retirement law allow retirement.
7. Rollback is a receipt-producing operation. It restores future admission to a
   previous or superseding revision, but it does not erase receipts earned while
   the failed revision was staged.
8. Superseded revisions remain visible until no live receipt, retained
   generation, receive base, geo backlog, repair obligation, or operator claim
   still depends on their explanation.
9. Product claims and comparator claims may cite a rollout only when #875
   records whether the behavior is planned, blocked, or validated for the
   specific revision-change class.

## Access Pattern Inventory

The predictor must model access patterns as continuous signals rather than
forced labels. The table below names the initial workload families TideFS must
understand well enough to choose sane placement and relocation behavior.

| Pattern | Signals | Good default shape | Avoid |
| --- | --- | --- | --- |
| Small sync WAL | small sequential writes, high fsync density, low write size variance | Sharded durable intent on high-endurance low-latency media; group where legal; full placement later | Full cold-data rewrite on every sync; single global SLOG bottleneck |
| Database data file | random overwrites, hot ranges, mixed fsync/fdatasync | Write redirection, small extents for hot random regions, durable intent floor, promote stable hot reads only | Read-modify-write amplification and flash promotion on transient churn |
| VM/block image | random writes, FUA/barriers, discard, large mixed reads | Barrier-aware intent lanes, extent roles by hotness, stable receipt refs, discard-informed reclaim | Treating all writes as streaming or all data as cold EC |
| Metadata storm | create/unlink/rename/xattr, directory churn, fsyncdir | Metadata on low-latency media, batched durable namespace intents, hot directory index locality | Pool-wide commit for single directory sync |
| Package/build tree | temp files, rename-overwrite, deletes, short lifetimes | Young-generation placement with durable intent only until stability; cheap reclaim | Promoting every short-lived byte to flash full placement |
| Interactive source/home tree | small reads/writes, editor fsync, mixed source and generated files | Metadata-hot serving, young-generation build outputs, stable source/config read locality | Treating the whole tree as one hot or one cold class |
| Small-file fanout/maildir/object shards | tiny payloads, metadata-data coupling, directory fanout, fsyncdir | Co-locate metadata and small payloads on low-latency media, shard hot directories, age cold tiny objects together | Scattering every tiny payload across remote/slow media independently |
| Container/image layers | immutable content-addressed blobs, clone fanout, startup read bursts | Shared compressed/dedup base layers, hot manifests/indexes, clone refs instead of rewrites | Copying layers per container or promoting one pull burst to flash authority |
| Append logs | sequential append, periodic fsync, high compressibility maybe | Coalesced extents, range intents, large sequential layout once stable | Tiny extents forever or forced random HDD placement |
| Time-series/log aggregation | append-only hot window, TTL, compaction/downsample, high compression | Durable intent for hot window, compressed large records after stability, lifecycle-aware TTL reclaim | Rewriting soon-to-expire windows repeatedly on flash |
| Large streaming ingest | large sequential writes, low reuse, low sync density | Direct HDD/EC/cold placement, large records, avoid flash unless policy asks | Flash writeback cache that doubles media writes |
| Sequential read/media | large sequential reads, low mutation | HDD/EC layout optimized for scan, optional prefetch, limited flash pinning | Hot-cache pollution from single-pass scans |
| Analytics/ML training set | large immutable shards, repeated epochs, hot manifests/indexes | Cold sequential or EC data, hot metadata/index serving role, scan-aware prefetch | Promoting an entire corpus to flash after one training pass |
| Hot small read set | high reuse, small random reads, low mutation | DRAM/flash read cache, optional serving replica on NVMe, no authority unless receipt-backed | Confusing cache hit with durable placement |
| Sparse/random scientific | large sparse files, mixed scan/random phases | Per-range shaping, prediction confidence before rebake | Whole-file policy flips after brief phase changes |
| Snapshot/send/receive | long sequential copy, pinned old versions, remote lag | Snapshot-aware extents, delta transfer, remote backlog receipts | Relocating pinned generations without receipt stability |
| Scrub/repair/rebuild | background reads/writes, degraded risk, foreground protection | Budgeted relocation lanes, receipt repair, low-priority unless risk escalates | Letting repair saturate foreground latency or flash wear |
| Geo replication | high RTT, loss/jitter, costed egress, RPO objective | Local/quorum ack plus explicit RPO lag or remote durable intent for geo-sync | Pretending speed-of-light latency is optional |
| Cold archive | low reads, long retention, cost sensitivity | HDD/EC/archive media, large records, low relocation frequency | Keeping cold data on expensive high-endurance flash |
| Ephemeral scratch | high speed, low durability need, caller accepts loss | RAM or local volatile pool with explicit receipt class | Reporting POSIX durable success from volatile state |
| Multi-tenant noise | competing foreground/background classes | Per-class budgets, tenant/workload isolation, tail SLO gates | Average throughput wins that destroy p99 latency |

## Prediction And Feedback

The predictor is not a single classifier. It is a bounded signal plane consumed
by placement, writeback, prefetch, relocation, and performance gates.

### Signal Levels

| Level | Scope | Examples |
| --- | --- | --- |
| L0 request | one operation | size, offset, flags, sync class, direct/buffered, FUA, caller hint |
| L1 subject | inode/object/range | reuse distance, hotness, write lifetime, fsync density, overwrite rate |
| L2 dataset | dataset or volume | read/write mix, metadata rate, snapshot pin horizon, compression value |
| L3 pool | whole pool | capacity pressure, rebuild pressure, foreground tail risk |
| L4 device | one device | queue depth, latency, bandwidth, error rate, wear, temperature, WAF estimate |
| L5 path | peer/path | RTT, jitter, loss, bandwidth, congestion, carrier, admin/geographic domain |
| L6 policy | operator intent | cost, RPO/RTO, durability floor, performance floor, degradation law |

All high-cardinality state must be bounded with decay, sketches, histograms,
top-K sets, or explicit promotion. No per-file or per-range signal may become
an unbounded memory leak.

Signal collection has a cost and is part of the design, not an invisible
observer. Hotness counters, directory sketches, per-range histories, derived
views, predictor checkpoints, and operator-facing telemetry may consume CPU,
memory, durable metadata writes, flash endurance, and evidence-retention space.
The default shape is cheap, lossy, decayed, and memory-local. Persistent signal
state must be aggregated, sampled, rate-limited, or piggybacked on existing
commit/evidence publication boundaries unless the compiled policy explicitly
admits stronger materialization.

Prediction evidence must therefore record the materialization mode that produced
it. A high-confidence vector from bounded in-memory sketches is useful for
queueing, prefetch, shadow evaluation, or cache trials, but it is not the same
as a durable historical proof. A persistent signal record can support later
payback, attribution, explanation, and claims only when #844/#856 cost, #902
budget ownership, #910 retention, and #913 query-snapshot evidence prove that
recording the signal was itself legal.

### Predictable Properties

TideFS can often predict:

- whether a write is likely to be overwritten or deleted soon;
- whether an extent should be small, large, compressed, or EC encoded;
- whether a read is a one-time scan or a stable hot set;
- whether small payloads should be co-located with metadata or aged as a cold
  tiny-object group;
- whether immutable shared data such as container layers or training shards can
  use clone/dedup/compressed placement instead of per-consumer rewrites;
- whether retention/TTL windows make expensive relocation pointless before
  reclaim;
- whether a sync workload benefits from sharded local intent, remote quorum
  intent, or full immediate placement;
- whether an HDD layout should be optimized for streaming or random locality;
- whether a flash device is worth spending write lifetime on for the object;
- whether a WAN path can satisfy an RPO target without blocking foreground
  writes;
- whether relocation will pay for itself before the next workload phase.

TideFS must not predict:

- that a caller no longer needs the guarantee it asked for;
- that a cache copy is durable authority;
- that remote receipt exists before transport/fencing evidence exists;
- that a weaker ack can be hidden behind a stronger API success.

### Control Loop

The adaptive loop is:

1. Observe request, subject, lifecycle, device, path, temporal, and policy
   signals.
2. Cite the compiled storage-intent policy revision for the operation or
   planning epoch.
3. Reconcile current receipts and evidence into a satisfaction state.
4. Compute a confidence-scored workload vector with bounded observation,
   materialization mode, collection cost, contradiction, and hint-provenance
   evidence.
5. Generate candidate acknowledgment, serving, durable-placement, or
   relocation plans, and record prediction-decision refs for shadow, trial, or
   admitted actions.
6. Reject candidates that do not meet hard guarantee, failure-domain, trust,
   temporal, lifecycle, capacity, wear, or operator-policy constraints.
7. Estimate latency, tail, throughput, write amplification, recovery risk, and
   money/egress cost for remaining candidates.
8. Reserve placement, transport, capacity, dirty-byte, signal-persistence, and
   wear budgets.
9. Admit and dispatch the selected work through the scheduler/resource-governor
   lanes that match its action class.
10. Publish receipts before claiming stronger placement or retiring older
    locators.
11. Reconcile the new evidence back into a satisfaction state.
12. Feed observed result, payback, harm, cooldown, refusal, and confidence
    update evidence back into the predictor.

Low-confidence predictions may tune queueing, prefetch, or shadow plans. They
must not trigger expensive relocation until hysteresis and benefit/cost gates
are satisfied.

The satisfaction state is also the actuation boundary:

| State | Allowed response |
| --- | --- |
| `satisfied` | Serve normally; optional optimizers may run only under payback, wear, and foreground-disruption budgets. |
| `converging` | Schedule bounded convergence, geo catch-up, archive conversion, or full-placement work while exposing the pending state. |
| `degraded-visible` | Serve only the degradation shape the policy permits, with operator/caller-visible explanation and repair/convergence pressure. |
| `unknown-evidence` | Refresh, remeasure, scrub, or revalidate evidence; do not infer satisfaction from stale topology or cache state. |
| `blocked` | Escalate repair, relocation, reserve recovery, or geo catch-up according to policy priority and scheduler budgets. |
| `refused` | Return a typed refusal or keep the operation unadmitted; do not silently choose a weaker guarantee. |
| `unsafe-volatile` | Preserve the explicit unsafe/volatile receipt boundary and exclude the state from durable POSIX or geo claims. |

### Confidence And Action Classes

Prediction confidence is an admission input, not a decorative score. A
workload vector must carry the observation window, sample mass, decay age,
contradiction state, and hint provenance that produced its confidence.
Operator or caller hints can seed a vector, but hints alone cannot make an
authority-changing move high confidence.

Different actions require different confidence:

| Action | Minimum evidence |
| --- | --- |
| queue tuning, batching, prefetch | low confidence; droppable under pressure |
| cache-only hot-read trial | medium confidence, budget admission, anchor/fence proof |
| new-write extent shaping | medium confidence plus cooldown against immediate reversal |
| serving-role promotion on flash | high confidence, wear budget, expected dwell time, and payback horizon |
| durable placement movement or authority promotion | high confidence, policy-satisfaction proof, relocation plan, replacement receipts, and old-receipt retirement law |
| guarantee weakening | never by prediction; only explicit policy revision and operator-visible receipt law |

The predictor must distinguish cache promotion from authority promotion. A
cache-only trial may populate RAM or flash serving state quickly because it is
evictable and non-authoritative. An authority promotion changes placement
truth, consumes receipt-retirement rights, and therefore needs the relocation
governor.

Stale, contradictory, or phase-changing signals reduce confidence. A read set
that was hot for one minute, a build tree that is about to be deleted, or a
sparse file that alternates scan and random phases should first produce shadow
plans and cache trials, not whole-object rebake or durable media churn.

### Prediction Accountability

#845 owns the bounded workload and prediction evidence projection. It does not
choose placement, schedule relocation, spend wear budget, or publish receipts.
It records the evidence needed for those consumers to decide whether a
prediction is trustworthy enough for the requested action class.

The prediction evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `observation_window_ref` | Names time, bytes, operations, ranges, and decay horizon behind the vector. |
| `sample_mass_ref` | Prevents one read, one caller hint, or one short burst from becoming high-confidence authority movement. |
| `feature_vector_ref` | Captures bounded hotness, reuse distance, sync density, write lifetime, compression/dedup value, sequentiality, locality, phase, and path signals. |
| `signal_materialization_ref` | Names memory-only sketch, sampled counter, decayed histogram, top-K set, durable summary, derived view, or retained evidence mode, plus sampling, decay, rate-limit, drop, and compaction rules. |
| `signal_collection_cost_ref` | Records CPU, memory, durable metadata writes, flash wear, network emission, evidence-retention bytes, budget-owner, and conservative unknown-cost state for collecting and preserving the signal. |
| `hint_provenance_ref` | Separates caller, operator, inherited policy, historical, and synthetic hints from observed behavior. |
| `contradiction_state` | Records phase changes, one-pass scans, churn, tenant manipulation, stale evidence, or conflicting locality/lifetime signals. |
| `action_class` | Distinguishes queue tuning, prefetch, cache-only trial, new-write shaping, serving promotion, authority promotion, durable relocation, read repair, and geo catch-up. |
| `decision_ref` | Points to #905 decision-frontier evidence binding the prediction to the policy revision, candidate set, rejected candidates, selected action, threshold, score vector, and admission result. |
| `shadow_trial_ref` | Records what TideFS would have done or temporarily served without changing durable authority. |
| `outcome_window_ref` | Measures latency, tail, throughput, reads saved, seeks avoided, media writes avoided, capacity saved, RPO lag, egress, foreground harm, and tenant harm after the action. |
| `measurement_attribution_ref` | Points to #912 evidence saying whether the measured outcome is attributable, partially attributable, confounded, stale, insufficient, contradicted, shadow-only, or refused for the policy/action/environment. |
| `payback_verdict_ref` | Says whether the admitted or shadow action met its payback window. |
| `confidence_update_ref` | Records whether the result raised, lowered, capped, or quarantined confidence for the subject, policy, tenant, device, path, or rule. |
| `cooldown_ref` | Prevents immediate retry, flip-flop movement, repeated flash writes, or cross-tenant manufactured confidence after a bad or ambiguous result. |

Hard prediction laws:

1. Prediction can optimize only after hard receipt, ordering, membership, trust,
   capacity, recovery, rollout, isolation, data-shape, layout, lifecycle, and
   wear gates pass.
2. A hint-only or one-off observation may admit queue tuning, prefetch, shadow
   evaluation, or cache-only trial. It must not admit authority promotion,
   durable relocation, old-receipt retirement, or guarantee weakening.
3. Signal collection and signal persistence are admitted work. They may not
   consume protected sync, repair, evacuation, receipt-retirement, metadata, or
   flash-wear reserves unless #844/#856/#902/#910 evidence says the budget owner,
   cost, retention class, and reserve exemption are legal.
4. Missing, sampled-away, memory-only, compacted, or dropped signal evidence
   lowers the allowed action class. It may explain why TideFS stayed
   conservative, but it may not be inflated into high-confidence durable
   movement or successor claims.
5. Every prediction-driven authority-changing move must leave a decision ref
   and outcome attribution ref. Missing or refused #912 evidence is not success;
   later similar moves become conservative, shadow-only, cooled down, blocked,
   or refused.
6. Failed payback, foreground harm, excessive wear, tenant harm, or confounded
   measurement attribution must lower, cap, or quarantine confidence, record
   movement debt or cooldown, and be visible to explanation, performance rows,
   and fault rows.
7. Predictor confidence may rise only from attributable or explicitly bounded
   partially attributable outcomes. Confounded, stale, insufficient-sample,
   contradicted, or cross-scope measurements may diagnose or force conservative
   cooldown, but they may not make authority-changing actions easier to admit.
8. A tenant, workload, or caller may not train confidence for another owner
   without #902 isolation evidence, #897 trust/domain eligibility, and #912
   transfer-scope evidence for the measurement.
9. Prediction evidence may be compacted or decayed only after no receipt,
   relocation decision, cooldown, claim artifact, operator explanation, or
   measurement-attribution dependency still depends on the detailed result.

## Temporal Evidence, Lag, And Timebase

#903 owns the storage-intent temporal evidence projection. It does not implement
clock synchronization, replace membership epochs, issue leases, or decide
placement. It tells storage-intent consumers whether age, lag, expiry, and
deadline facts are comparable and fresh enough for the requested role.

Temporal evidence must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `timebase_ref` | Names local monotonic time, local wall clock, cluster or consensus time, remote wall clock, sequence/log frontier, or sequence-only evidence. |
| `clock_health_ref` | Cites clock source, synchronization domain, skew bound or unknown-skew state, monotonicity, step/leap behavior, and sample age. |
| `event_frontier_ref` | Binds a write receipt, committed root, policy publication, membership epoch, trust/key epoch, receive source, geo source, remote apply, read source, prediction decision, or relocation outcome to a comparable event or sequence frontier. |
| `lag_staleness_ref` | Reports geo RPO lag, stale-read age, read-serving freshness, archive/restore age, repair/rebuild lag, receive backlog age, or remote catch-up age with its uncertainty. |
| `expiry_deadline_ref` | Records key lease expiry, authorization window, policy rollout stage deadline, in-flight fence deadline, cooldown, payback window, TTL/lifecycle window, retry window, or refusal deadline. |
| `sequence_time_conversion_ref` | Converts sequence/log/byte lag to wall-time only when the source rate, observation window, and uncertainty bound make the conversion conservative. |
| `temporal_refusal_ref` | Gives typed missing-timebase, unknown-skew, stale-sample, crossed-expiry, contradictory-frontier, backwards-time, insufficient-sequence, or unsupported-cross-domain refusal reasons. |

Hard temporal laws:

1. A seconds/minutes/hours RPO, stale-read, freshness, cooldown, payback, TTL,
   lease-expiry, or policy-deadline claim must cite #903 evidence. Otherwise it
   is sequence-only, `unknown-evidence`, `blocked`, or `refused` according to
   policy.
2. A local monotonic duration can govern a local cooldown or local payback
   window, but it cannot prove remote RPO, stale-read freshness, lease expiry,
   or cross-node ordering unless a comparable timebase or sequence frontier is
   cited.
3. Sequence lag is honest sequence lag. It becomes wall-clock lag only when
   sequence-to-time conversion evidence records a conservative rate and
   uncertainty bound.
4. Backwards clocks, large skew, unknown skew, stale clock-health samples, or
   contradictory frontiers must lower the claim to unknown, visible degradation,
   blocked, or refused. They must not be hidden behind a fresh-looking
   timestamp.
5. TTL, lifecycle, and reclaim decisions still need #881 lifecycle,
   receipt-retirement, fence, and layout evidence. Time passing alone does not
   make retained bytes reclaimable.
6. Key leases, authorization windows, trust epochs, and policy-stage deadlines
   remain owned by their authorities. Storage intent consumes their temporal
   refs and refuses to reinterpret them from raw local wall-clock reads.

## Admission, Scheduling, And QoS

Storage intent is enforced at admission and dispatch, not only at placement
time. A compiled policy that asks for low-latency sync behavior must affect
dirty-byte admission, device queues, transport windows, background optimizer
budgets, and speculative work. Otherwise TideFS would know the right answer
while still letting bulk work destroy the tail.

TideFS should map storage-intent work onto the unified lane vocabulary rather
than inventing a second scheduler:

| Work class | Typical lane behavior |
| --- | --- |
| Sync barrier / FUA | latency-critical demand or metadata/control-adjacent work; never droppable; bounded queue time before receipt or refusal |
| Metadata storm | metadata lane with namespace-intent batching and fsyncdir tail budget |
| Ordinary foreground read/write | demand lane with workload and tenant budgets |
| VM/random I/O | demand lane with strict p99/tail amplification budget |
| Bulk ingest | throughput-oriented demand lane with large records and bounded cache admission |
| Speculative prefetch or cache-only hot-read trial | speculative lane; droppable under pressure |
| Authority promotion or policy-satisfaction relocation | background lane unless receipt risk, payback, or policy satisfaction escalates it |
| Defrag/rebake/geo catch-up optimizer | background lane unless policy satisfaction or RPO risk escalates it |
| Repair/evacuation | background or critical escalation according to receipt risk and policy floor |

The scheduler consumes compiled policy, service-objective evidence, workload
signals, resource-governor pressure, media/cost ledgers, and transport evidence.
It may delay, backpressure, drop speculative work, or return typed refusals
according to policy. It may not weaken an acknowledgment receipt, hide volatile
behavior, or retire old placement receipts before replacement receipts exist.
#920 result/refusal evidence is the caller-visible projection of those scheduler
decisions: throttle, defer, admission failure, reserve exhaustion, starvation
override, and noisy-neighbor protection must become typed results rather than
timeout folklore or local queue errors.

Admission evidence must be observable:

- policy id and revision used for classification;
- service-objective id and envelope used for the selected workload and operation
  class;
- tenant, dataset, workload, policy, or internal-maintenance budget owner;
- isolation scope and fair-share window used for classification;
- action class and prediction confidence used for classification;
- selected lane and priority class;
- queue time and dispatch time;
- resource budget that throttled or refused the operation;
- borrowed budget, donation source, debt, reserve-exemption, or starvation
  override used for the operation;
- noisy-neighbor victim/offender state when admission is changed to protect p99
  latency or a protected floor;
- starvation override or repair escalation reason;
- whether the work was dropped, deferred, admitted, or completed;
- the #920 result/refusal ref used when admission, throttle, defer, or
  completion becomes visible to a caller, trace, validation row, or operator.

This is the mechanism that lets TideFS optimize both latency and throughput
without turning one tenant's bulk stream, rebuild, or geo catch-up into another
tenant's p99 failure.

## Tenant, Budget, And Noisy-Neighbor Isolation Authority

Storage intent consumes scheduler, governor, cost, capacity, wear, transport,
trust/domain, and performance evidence, but it still needs a native fairness
projection. #902 owns the storage-intent evidence that says which tenant,
dataset, workload class, policy owner, or internal maintenance reason is allowed
to spend scarce resources while other promises remain protected.

#902 does not dispatch work, partition daemon memory, account money, allocate
space, count flash media writes, authenticate tenants, or run validation
campaigns. It composes refs from those owners into the hard predicates that
admission, receipt emission, planning, relocation, read serving, recovery, and
operator explanation can all consume.

The isolation evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `budget_owner_ref` | Names tenant, dataset, clone family, mount, workload class, policy owner, or internal-maintenance reason charged for the work. |
| `tenant_domain_ref` | Cites #897 tenant/security/admin-domain eligibility so budget ownership is not inferred from a caller string. |
| `isolation_scope_ref` | Binds the decision to pool, dataset, tenant, workload class, media role, proximity domain, transport path, device class, failure domain, or repair/relocation class. |
| `resource_vector_ref` | Names the resources being protected or spent: latency/tail, throughput, queue time, dirty bytes, memory, transport window, device queue, capacity reserve, wear, repair bandwidth, relocation budget, geo backlog, money, or egress. |
| `fair_share_policy_ref` | Defines floor, ceiling, weight, and fairness window for the owner/scope under the compiled policy. |
| `burst_borrow_ref` | Records permitted burst, donor scope, reclaimability, expiry, and whether the borrowed share can be preempted. |
| `isolation_debt_ref` | Tracks consumed burst/debt so repeated short bursts cannot become permanent priority inversion. |
| `starvation_state_ref` | Shows oldest wait, starvation override, bounded progress rule, and whether the override counted against the correct budget. |
| `noisy_neighbor_ref` | Identifies offender scope, victim scope, measured p95/p99 or queue harm, saturated resource vector, pressure age, and mitigation. |
| `reserve_exemption_ref` | Cites policy, recovery, evacuation, quorum-safety, degraded-risk, or operator authorization evidence that allows temporary use of protected resources. |
| `throttle_refusal_ref` | Gives typed throttle, defer, drop, downgrade-visible, or refusal reason for over-budget, unowned work, missing tenant/domain evidence, illegal borrow, reserve theft, starvation, stale pressure, or policy conflict. |

Isolation legality is a hard gate:

1. A global free resource or good average throughput does not prove a tenant,
   dataset, workload, or internal-maintenance action may proceed.
2. Every nontrivial foreground, background, repair, relocation, geo, RAM,
   read-serving, or receipt-retirement action must carry a budget owner or fail
   as unowned work.
3. Scheduler lanes (#862) enforce dispatch, but #902 decides whether the lane
   admission evidence satisfies the compiled isolation policy for the affected
   owner and victim scope.
4. Per-dataset memory partitions (#893), capacity admission (#898), non-wear
   cost (#856), media wear (#844), transport backpressure (#846/#891), and
   workload signals (#845) remain source evidence. None of them alone proves
   cross-resource fairness.
5. Borrowing unused share is legal only when the policy records donor scope,
   expiry, reclaimability, debt, and preemption behavior. Borrowing from sync,
   repair, evacuation, receipt-retirement, or quorum-safety reserve is illegal
   unless a reserve-exemption ref says otherwise.
6. Background optimizers, serving trials, one-pass scans, defrag, rebake,
   rebuild, relocation, and geo catch-up must demote, pause, split, or refuse
   when their measured harm exceeds the protected victim floor.
7. Repair, evacuation, and degraded-risk reduction may preempt ordinary
   fairness only through visible reserve-exemption and debt evidence, so the
   operator can see why normal isolation changed.
8. Internet and WAN work must be charged to both transport/egress budgets and
   tenant or policy owner scopes. A remote backlog may not consume unbounded
   foreground, repair, or egress budget because the path is slow or lossy.
9. Missing, stale, contradictory, over-budget, unowned, illegal-borrow, or
   reserve-theft evidence becomes `unknown-evidence`, `blocked`, `throttled`,
   or `refused`; it is not converted into "best effort" throughput silently.

## Capacity Admission, Reserve, And ENOSPC Authority

Storage intent consumes capacity and reserve evidence, but it does not own the
pool allocator, dataset quota system, reserve ledger, resource governor, or
space-accounting authority. #898 owns the storage-intent capacity/admission
evidence projection and the predicates that decide whether those facts satisfy a
compiled policy role.

Capacity is not only a cost input. Cost tells TideFS whether a plan is
expensive; capacity admission tells TideFS whether the plan is legal to begin or
acknowledge. A plan that hopes reclaim will run later, counts pending frees too
early, consumes repair reserve for an optimizer, or forgets that copy-on-write
must hold old and new bytes at once is not a cheaper plan. It is under-admitted.

Authority boundaries are:

- #680 owns the broad capacity and accounting authority decision for quotas,
  statfs, allocator ownership, and projections;
- allocator/layout evidence (#880) reports free runs, allocation class,
  pending-free frontiers, reclaim debt, alignment, and reserve pressure without
  turning rebuildable mirrors into authority;
- #862 owns demand-side scheduler admission and dispatch under pressure;
- #856 accounts capacity, network, retention, and other non-wear costs, but
  cost snapshots do not prove that admissible headroom exists;
- claim and reserve ledgers provide authoritative obligation and reserve
  receipts where the implementation has wired them;
- storage intent compiles and consumes those refs to decide whether local
  intent, quorum intent, full placement, geo catch-up, repair, relocation,
  rebake, archive/EC, RAM-intent backing, block-volume FUA/flush, or receipt
  retirement can proceed.

The capacity/admission evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `logical_space_domain_ref` | Binds admission to dataset, clone-family, quota, slop, reservation, orphan, snapshot, and receive-base accounting. |
| `physical_allocation_headroom_ref` | Proves physical free-space class, segment class, allocation class, and allocator generation have enough legal headroom. |
| `allocation_ticket_ref` | Shows staged allocator headroom, ticket class, expiry, commit/abort state, and selected allocation class. |
| `claim_reserve_receipt_ref` | Cites claim ledger, reserve ledger, budget domain, reserve class, validation tier, and conservation pressure state. |
| `dirty_window_reserve_ref` | Binds buffered write, mmap, FUA, fsync, intent-log, and writeback admission to dirty-byte and writeback budgets. |
| `critical_reserve_floor_ref` | Protects sync intent, authority metadata, repair, evacuation, rebuild, geo catch-up, and receipt-retirement reserves from background optimizers. |
| `pending_free_frontier_ref` | Proves whether reclaimable or dead-pending bytes are actually reusable under publication, fence, snapshot, generation, and receipt law. |
| `capacity_amplification_ref` | Estimates old-plus-new COW overlap, replicas, EC/archive parity, compression expansion, rebake scratch, relocation scratch, and geo backlog bytes. |
| `admission_state` | Records admitted, blocked, throttled, reclaim-triggered, degraded-visible, refused, expired, released, aborted, or committed. |
| `enospc_refusal_ref` | Carries typed ENOSPC, quota, slop, protected-reserve, stale-ticket, stale-pending-free, or under-reserved refusal. |

Capacity legality is not a retry policy. Pending-free bytes, snapshot-pinned
bytes, clone-held bytes, orphan-held bytes, receive-base-held bytes, and
dead-pending-reclaim bytes are not available until the lifecycle, allocator,
publication, fence, and receipt-retirement evidence says they are. A reclaim
queue entry or largest-run mirror can make a plan promising, but it cannot
satisfy admission by itself.

Capacity admission is role-specific, not a single "pool has space" bit. Local
intent needs dirty-window and intent-media headroom; quorum intent needs each
selected durable participant to have legal reserve; full placement needs
allocation tickets for every required replica or shard; geo catch-up needs local
backlog, transport, remote reserve, and RPO-lag headroom; relocation and rebake
need scratch plus old-plus-new overlap; read repair needs repair reserve before
it may publish replacement authority. Passing one role does not imply another.

Reserve floors are product law. Sync intent, authority metadata, repair,
evacuation, rebuild, geo catch-up, receipt retirement, and block-volume flush
paths need protected headroom. Background defrag, compaction, rebake, hot-data
promotion, one-pass scan caching, archive conversion, or other optimizers may
use surplus or explicitly granted escrow; they must not borrow protected floors
because a benefit model predicts eventual payback.

Copy-on-write and relocation must reserve for overlap. When an old generation
is snapshot-pinned, clone-held, receive-base-held, or protected by an old
receipt, the planner must account for old bytes plus new replacement bytes,
including replicas, parity, intent, scratch, compression expansion, and pending
free delay. It may choose a lower-amplification legal shape, delay convergence,
trigger reclaim, block, degrade visibly, or refuse. It may not acknowledge a
policy floor on future free space.

ENOSPC is a storage-intent state, not just an errno at the bottom of the stack.
The operator and caller should be able to distinguish quota exhaustion, physical
free-space exhaustion, wrong allocation class, stale or expired ticket, pending
free not yet safe, reserve floor protection, dirty-window pressure, and
optimizer refusal. Typed refusal lets TideFS protect durable semantics without
falling back to a hidden weaker acknowledgment.

## Acknowledgment Classes

The acknowledgment class names what TideFS has earned before reporting
success. The classes are evidence labels, not a numeric dominance ladder.
Different products may choose different floors, and a receipt satisfies a floor
only through the policy-specific predicate described in the record contract.

| Ack class | Evidence required before success | Survives | Does not survive | POSIX durability barrier floor |
| --- | --- | --- | --- | --- |
| `volatile-local` | Bytes or deltas accepted in local process/host RAM under budget. | Process-visible reads while alive. | Process crash, host crash, power loss. | No. |
| `volatile-replicated` | Bytes or deltas in RAM on enough fenced peers to satisfy a volatile policy. | Primary process/node failure if a peer remains live and fenced. | Simultaneous power loss, peer loss before promotion, no durable replay. | No. |
| `local-intent` | Replayable durable local intent with payload/range digest, metadata deltas, and flush evidence. | Local crash/power loss while intent media survives. | Loss of the only intent/data device. | Yes for local stable-storage semantics. |
| `remote-volatile-plus-local` | `local-intent` plus remote fenced volatile receipt carrying enough data/delta to recover after primary failure while peer remains live. | Primary node loss when remote peer stays live. | Simultaneous power loss of local and remote volatile state; loss of local durable intent before replay. | Only when the local durable component satisfies the barrier. |
| `quorum-intent` | Replayable durable intents with enough payload/delta on a policy quorum of failure domains. | Minority device/node failure covered by the quorum. | Loss of quorum or malformed epoch/fence evidence. | Yes for distributed sync products with quorum as the floor. |
| `full-placement` | Policy-satisfying placement receipt for all required replicas/shards plus durable locator authority. | Failures inside the declared redundancy policy. | Failures beyond policy, receipt corruption without recovery. | Yes. |
| `geo-async` | Local or quorum durable floor plus explicit remote lag/RPO receipt. | Local policy failures only; remote recovery within recorded RPO if catch-up succeeds. | Immediate remote-site recovery at ack time. | Yes only for the local/quorum floor, not for remote durability. |
| `geo-intent` | Durable replayable intent in another site or region, with path and epoch evidence. | Site loss covered by the remote intent policy. | Region-wide failure beyond policy; speed-of-light latency. | Yes if configured floor is geo intent. |
| `geo-full-placement` | Full placement receipts across required geographic domains. | Declared site/region failures. | Correlated failures beyond policy. | Yes. |
| `archive-ec` | Durable EC/archive placement receipt with recovery width and rebuild policy. | Media failures inside archive policy. | Low-latency serving unless a serving role also exists. | Yes, but usually not latency-optimized. |

`remote-memory` by itself is not a durable class. It is a component of a
larger receipt and must say exactly what happens if the primary node fails, if
the remote process crashes, and if power is lost.

## POSIX Sync And Unsafe Modes

For a POSIX filesystem product, successful `fsync`, `fdatasync`,
`msync(MS_SYNC)`, `O_DSYNC`, and FUA-style block barriers must earn the
configured durability floor. If the floor cannot be earned within the policy,
TideFS must block, retry, or return an error. It must not return success on
`volatile-local` or `volatile-replicated` evidence while presenting itself as a
normal POSIX durable mount.

Fast sync behavior must come from optimizing the path that earns durable
evidence, not from hiding async behavior. TideFS may group, shard, coalesce,
or pipeline local/quorum intent when policy permits, but the receipt must bind
the replayable intent, payload or range digest, policy revision, flush/fence
evidence, and any pending full-placement convergence. Deferring full placement
after a sync reply is legal only when the earned receipt class satisfies the
compiled policy and the missing work is visible.

TideFS may expose an explicit non-POSIX or unsafe product profile for
operators who want maximum speed and accept loss. That profile must:

- have a name that exposes the weaker guarantee;
- return receipts naming the weaker ack class;
- be visible in `tidefsctl` and support bundles;
- be ineligible for claims that require POSIX durable sync behavior.

The goal is not to forbid fast unsafe products. The goal is to make them
honest and unnecessary for normal high-performance sync workloads.

## Ordering, Replay, And Barrier Authority

Acknowledgment class and placement are not enough. A `local-intent` or
`quorum-intent` receipt can be fast and still wrong if it omits the barrier
scope, writes metadata in an unreplayable order, loses a prior writeback error,
or lets recovery apply the same intent twice. #894 owns the storage-intent
ordering-evidence slice.

Ordering evidence must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `operation_scope` | Range write, file fsync/fdatasync, directory fsync, O_DSYNC/FUA, `msync(MS_SYNC)`, syncfs/dataset barrier, relocation cutover, repair, or receipt retirement. |
| `dirty_epoch_ref` | Binds accepted dirty bytes to the lifecycle and writeback boundary that must drain or replay. |
| `barrier_sequence` | Orders caller-visible barriers without forcing unrelated pool-wide serialization. |
| `intent_sequence` | Names durable intent-log or equivalent records used for replay. |
| `replay_idempotency_key` | Proves replay can apply an acknowledged intent exactly once or classify it as a visible error. |
| `dependency_refs` | Names prior writes, metadata deltas, namespace/link-count changes, extent/checksum updates, or remote quorum acks that must precede success. |
| `publication_boundary` | Names the committed root, durable intent boundary, receipt publication, or replacement cutover that makes the operation recoverable. |
| `completion_state` | Records satisfied, pending-convergence, blocked, refused, or failed ordering work. |

Authority laws:

- `fsync`, `fdatasync`, `O_DSYNC`, FUA, `msync(MS_SYNC)`, and `syncfs`
  success must cite ordering evidence for their caller-visible scope.
- Group commit, sharded intent lanes, coalescing, batching, and pipelining are
  legal performance tools only when the evidence preserves required ordering
  and records what convergence remains pending.
- Intent-log markers, flush markers, transaction markers, and dirty epochs are
  evidence inputs. They are not sufficient by themselves unless they also carry
  or identify the bytes and metadata needed for exact replay.
- Namespace operations must preserve parent/child, link-count, rename, and
  directory-fsync dependencies. A data write receipt cannot silently stand in
  for missing namespace ordering evidence.
- Quorum and geo acknowledgments need both membership evidence and ordering
  evidence. A remote peer that received bytes in the right epoch still cannot
  satisfy a barrier if its dependency or replay evidence is incomplete.
- Placement receipts say where bytes or shards are. Ordering evidence says
  whether those bytes satisfy the barrier, replay, dependency, and publication
  contract.
- Missing, stale, unsealed, wrong-root, wrong-range, non-idempotent, partial
  namespace, incomplete metadata-delta, lost writeback-error, under-quorum, or
  contradictory ordering evidence becomes `unknown-evidence`, `blocked`,
  `refused`, or degraded-visible according to policy. It must not be guessed
  from a fast path.

This is the piece that lets TideFS beat slow synchronous designs without
imitating unsafe ones. The implementation may make a sync workload fast by
moving less data, grouping more intelligently, and replaying exact deltas. It
may not make it fast by erasing the order that the caller paid for.

## Metadata, Namespace, And Small-Object Intent

#922 owns the storage-intent metadata/namespace evidence projection. It does
not replace the VFS semantic contract, inode namespace authority, page-cache
writeback authority, or result/refusal law. It composes their refs so metadata
operations can be optimized through storage intent instead of becoming hidden
overhead with local heuristics.

Metadata is not a side channel. Directory entries, inode attributes, link
counts, directory cookies, xattrs, ACLs, small-file inline payloads, namespace
intents, and fsyncdir barriers can dominate p99 latency, flash wear, recovery
time, and user-visible correctness. A storage policy that optimizes data
placement but lets metadata choose its own locality, batching, or refusal story
will lose the workloads that make filesystems feel fast.

Metadata/namespace evidence must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `metadata_subject_ref` | Names dataset, directory inode, inode, xattr/ACL namespace, small-object cohort, directory index, transaction group, or namespace mutation set. |
| `namespace_operation_ref` | Classifies create, mkdir, link, unlink, rename, exchange, setattr, truncate metadata, xattr/ACL mutation, lookup, readdir/readdirplus, fsyncdir, file-fsync metadata dependency, orphan/open-unlink handling, or small-file inline/external transition. |
| `vfs_namespace_authority_ref` | Cites VFS operation semantics, inode identity, generation, parent/child relation, raw name, link-count, directory cookie, root/dataset identity, and conflict-guard refs from the VFS and inode namespace authorities. |
| `namespace_intent_ref` | Binds #894 ordering and #842 ack receipt refs for namespace intent, directory fsync, metadata dependency, root publication, replay idempotency, and crash recovery. |
| `metadata_locality_ref` | Names metadata-hot, sync-intent metadata, directory-index locality, xattr/ACL locality, lookup projection, and cache/trial/authority distinction for metadata serving. |
| `small_object_shape_ref` | Points to #878 data-shape evidence for inline payload, packed small file, xattr payload, directory block, index node, externalization, rebake, or repack decisions. |
| `metadata_cost_ref` | Records metadata write amplification, flash writes, directory rebalance cost, index split/merge cost, small-object repack cost, CPU/read amplification, capacity amplification, and network/geo metadata cost. |
| `metadata_decision_ref` | Names #913 query snapshot, #915 objective, #905 decision frontier, #862 admission lane, #911 action state, #920 result/refusal projection, #912 attribution, and #910 retention refs used for metadata decisions. |
| `metadata_refusal_ref` | Gives typed stale generation, wrong parent, namespace conflict, link-count mismatch, unsupported directory shape, unsafe small-file repack, metadata reserve exhaustion, fsyncdir objective miss, unsupported media role, stale lookup/cache projection, or missing retention proof. |

Hard metadata/namespace laws:

1. VFS semantics decide what an operation means; inode namespace authority owns
   inode identity; storage intent decides only how metadata evidence satisfies a
   policy and which optimized path is legal.
2. A namespace mutation may use sharded intent, grouping, locality-preserving
   placement, packed records, or directory-index compaction only when ordering,
   conflict guards, media capability, capacity reserve, result/refusal, and
   retention evidence all pass for the compiled policy.
3. `fsyncdir`, rename, link/unlink, xattr/ACL mutation, and file fsync metadata
   dependencies are caller-visible barriers when the VFS contract makes them
   so. They need receipts and #920 result evidence; they must not be hidden
   behind data-only success.
4. Metadata-hot is a role, not a truth claim. A directory index or inode table
   copy in RAM or fast flash may serve only under explicit cache, serving-trial,
   RAM-authority, or receipt-backed metadata evidence.
5. Small files and xattrs may be inline, packed, externalized, rebaked, or
   relocated only through data-shape plus metadata evidence. A space or latency
   win may not rewrite namespace identity, link-count semantics, or fsyncdir
   durability.
6. Metadata write amplification is budgeted. Repacking tiny files, splitting
   directory indexes, compacting xattrs, or moving metadata-hot cohorts must
   pay the #844/#856/#912 cost and attribution gates before future confidence,
   claims, or wider rollout can improve.
7. Metadata relocation or rebake cannot retire source metadata authority until
   replacement receipts, ordering, namespace conflict guards, result/refusal,
   and retention proof exist.

## Proximity Domains

Proximity describes path and failure-domain reality. It is not only distance.

| Domain | Meaning |
| --- | --- |
| `process-ram` | Same process memory. Lowest latency, no crash survival. |
| `host-ram` | Same host, different worker/process or kernel/userspace boundary. |
| `host-pmem` | Same host persistent memory or NVDIMM-class storage. |
| `local-nvme` | Local PCIe NVMe storage. |
| `local-ssd` | Local SATA/SAS SSD or equivalent flash. |
| `local-hdd` | Local rotational media. |
| `same-host-peer` | Another local service, VM, or namespace on the host. |
| `same-rack` | Network peer in the same rack/failure cell. |
| `same-dc` | Network peer in the same datacenter. |
| `metro` | Low-latency site pair, typically still latency-visible for sync. |
| `wan` | Cross-region or long-distance private network. |
| `internet` | Public or non-dedicated path; no RDMA assumption. |

Path evidence must include observed and configured RTT, jitter, loss,
bandwidth, queue pressure, carrier, encryption/authentication context, admin
domain, power/failure-domain relation, and measurement age. RDMA may improve a
path evidence record, but absence of RDMA must not make the product
semantically invalid.

## Membership Epoch, Fencing, And Quorum Authority

Storage intent depends on membership truth, but it does not own membership
truth. #750 owns the decision record for the membership epoch authority,
quorum-write dispatch owner, witness-set role, node join/drain lifecycle, and
epoch/fence enforcement. Storage intent consumes that authority through typed
evidence refs.

This boundary is a hard design law:

- transport path evidence may report RTT, loss, bandwidth, carrier, queue
  pressure, and session-local refusal state, but it may not originate roster,
  quorum, witness, or fence decisions;
- placement and receipt code may consume membership and failure-domain refs,
  but it may not recompute membership as a substitute for the authority owner;
- a quorum, geo, remote-volatile, remote-read, relocation, or repair receipt
  must name the membership epoch and quorum/failure-domain evidence under which
  it was earned;
- stale, future, missing, contradictory, wrong-quorum, split-brain, fenced,
  draining-without-policy, or witness-counted-as-data evidence cannot satisfy a
  durable quorum, geo, read-serving, RAM-replication, repair, or relocation
  floor;
- an epoch change after a receipt is earned does not erase the old receipt, but
  new writes, read serving, retirement, and repair must prove whether that old
  receipt is still legal under the current policy and fence state;
- RDMA remains an optional accelerator. TCP and internet paths still need the
  same membership evidence; they are slower, not less correct.

The membership evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `membership_epoch_ref` | Binds a receipt or candidate to the committed membership epoch it used. |
| `committed_roster_identity` | Detects stale, future, forked, or contradictory rosters. |
| `quorum_set_identity` | Proves the write/read/repair plan used the policy-selected quorum set. |
| `failure_domain_binding` | Names node/rack/DC/site/region relation from membership authority, not path inference alone. |
| `participant_role` | Separates data-bearing participants, voters, witnesses, learners, observers, and cache-only peers. |
| `join_drain_fence_state` | Blocks unsafe use of peers that are joining, draining, quarantined, fenced, or departed. |
| `split_brain_hazard_state` | Forces refusal, blocking, or degraded-visible behavior when membership cannot prove one authority view. |
| `receipt_epoch_binding` | Lets recovery and explanation show which epoch made an acknowledgment or placement legal. |

The planner may prefer stable, nearby, low-loss quorum members during scoring,
but membership legality is not a score. A very fast peer in the wrong epoch, a
witness-only peer counted as a data replica, or a draining peer used without an
explicit policy allowance is not a slower candidate. It is illegal.

## Security, Trust, And Administrative Domain Authority

Storage intent consumes security evidence, but it does not implement
cryptography, issue key leases, decide operator authorization, or replace the
transport session boundary. #897 owns the storage-intent trust/domain evidence
projection and the predicates that decide whether those facts satisfy a
compiled storage-intent role.

This boundary matters most when a pool spans the internet, crosses
administrative domains, shares data across tenants, uses encrypted or deduped
data shapes, or promotes remote RAM/repair/read-serving state into an
authoritative role. A reachable encrypted TCP session is useful path evidence.
It is not by itself permission to store tenant data, satisfy a quorum-intent
replica, use a peer as a repair source, or deduplicate across a security
domain.

Authority boundaries are:

- transport security owns session authentication, confidentiality, integrity,
  rekeying, and per-session evidence;
- transport path evidence (#846) may report the session-security context,
  carrier, path age, RTT, loss, jitter, and congestion, but it does not decide
  whether the peer may hold authoritative bytes;
- membership (#750) owns epoch, roster, quorum, witness, fence, drain, and
  split-brain legality, but a roster member can still be the wrong trust or
  tenant domain for a given policy;
- encryption/key-lease and data-shape authorities, including #878 and the
  security docs, own key epoch, key lifecycle, transform, dedup, and sharing
  evidence;
- operator authorization and audit authorities own principal, capability,
  override, and audit-chain decisions;
- storage intent compiles those refs into role-specific hard gates and returns
  typed refusal, blocked, unknown-evidence, or degraded-visible states when
  evidence is absent, stale, contradictory, revoked, or policy-forbidden.

The trust evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `peer_identity_ref` | Binds a remote receipt to authenticated peer or principal evidence, without redoing the handshake locally. |
| `admin_domain_identity` | Decides whether cross-admin placement, repair, read serving, receive, or geo catch-up is permitted. |
| `security_domain_identity` | Separates tenants, secrecy domains, regulatory zones, and operator-defined trust classes. |
| `policy_or_budget_owner_ref` | Attributes remote use, egress, wear, capacity, and noisy-neighbor risk to the right owner. |
| `session_security_ref` | Cites transport session security posture, encryption/authentication state, rekey age, and stale-session refusal. |
| `encryption_key_epoch_ref` | Proves encrypted placement, read serving, repair, rebake, or receive uses the expected key generation and lifecycle state. |
| `sharing_domain_ref` | Proves dedup, reflink, compression dictionary, EC/archive grouping, or shared cold placement is legal across security/tenant boundaries. |
| `authorization_audit_ref` | Binds cross-domain placement, remote repair, receive, geo, or privileged relocation to an operator-authorized decision and audit trail when required. |
| `residency_policy_ref` | Names regulatory, geographic, or operator residency limits that can make a low-cost path illegal. |
| `trust_health_state` | Captures compromise suspicion, quarantine, revocation, stale trust epoch, or missing proof that forces refusal or degradation. |

Trust legality is not a latency score. A near peer in the wrong administrative
domain, a geo target with a stale key epoch, an unaudited cross-domain repair
source, an illegal cross-tenant dedup candidate, or an internet path with
missing required session-security evidence is not a slower candidate. It is
illegal for the role until a new policy revision or fresh evidence says
otherwise.

Public internet paths are therefore allowed as carriers when policy permits
them and the security/trust evidence is strong enough for the requested role.
They are not second-class semantically because they lack RDMA, and they are not
trusted automatically because TLS or session encryption exists. Correctness is
earned by the compiled policy and receipt predicates; RDMA, TCP, TLS, and
carrier choice are only path and security inputs.

## Media Roles

Media class is not enough. TideFS must know what role a device is playing.

| Role | Typical media | Design intent |
| --- | --- | --- |
| `sync-intent` | high-endurance NVMe, PMem, mirrored SSD, sometimes HDD sequential log | Low-latency replayable durability. |
| `metadata-hot` | NVMe/SSD/PMem | Small random metadata and directory locality. |
| `serving-data-hot` | RAM cache, NVMe, SSD | Low-latency reads for stable hot data. |
| `serving-data-warm` | SSD/HDD mix | General serving with moderate cost. |
| `bulk-data-cold` | HDD, EC set, archive object media | Capacity and cost efficiency. |
| `geo-delta` | remote durable intent or compacted deltas | RPO/RTO without full immediate duplication. |
| `scratch-volatile` | RAM/local ephemeral media | Fast explicit loss-tolerant data. |
| `repair-temp` | bounded RAM/NVMe/HDD scratch | Rebuild and relocation working set. |

The same file may have different roles for different ranges and generations.
For example, a database file may keep hot random ranges on NVMe, cold stable
ranges on HDD/EC, and recent sync deltas in a durable intent lane.

## Media Capability And Device Semantics

#904 owns the storage-intent media capability evidence projection. It does not
probe hardware, account wear, expose allocator geometry, choose placement, or
emit ack receipts. It makes media-role eligibility explicit enough that those
consumers do not infer durable behavior from marketing names or broad device
classes.

The media capability evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `device_identity_ref` | Binds a target to stable device, namespace, path/multipath, firmware/capability generation, pool member, and stale-reattach evidence. |
| `persistence_domain_ref` | Distinguishes volatile RAM, cache-only state, PLP-backed volatile cache, ordinary flash, PMem persistence domain, rotational media, remote durable target, archive/object target, and unknown persistence. |
| `flush_fua_semantics_ref` | Proves supported flush, FUA, barrier, cache-policy, passthrough, ordering, and failure semantics for durable roles. |
| `volatile_cache_policy_ref` | States whether volatile device or controller write cache is enabled, protected, bypassed, flushed, or unsafe for the requested role. |
| `atomicity_granularity_ref` | Names logical/physical block size, atomic write unit, torn-write risk, alignment, optimal I/O size, and idempotent replay implications. |
| `protocol_geometry_capability_ref` | Reports rotational seek class, SSD/NVMe behavior, erase-block, ZNS/SMR append/reset constraints, PMem flush/fence requirements, remote/object commit semantics, and queue-depth/latency class. |
| `health_freshness_ref` | Cites SMART/NVMe/PMem health, thermal/error state, device reset, firmware/settings changes, multipath failover, stale probe age, and unknown-capability state. |
| `role_eligibility_ref` | States whether the target may play sync-intent, metadata-hot, serving-data-hot, bulk-data-cold, geo-delta, scratch-volatile, repair-temp, PMem-durable, cache-only, or archive roles. |
| `media_capability_refusal_ref` | Gives typed missing-capability, unknown-persistence, unsupported-flush/FUA, unsafe-volatile-cache, unstable-namespace, wrong-atomicity, unsupported-zone, stale-probe, degraded-health, or unsupported-remote-commit refusal reasons. |

Hard media-capability laws:

1. Device class, media role, path name, controller type, or benchmark result
   does not prove durable eligibility. Durable roles need #904 evidence.
2. A local durable intent, full-placement durability, PMem-durable receipt, or
   block-volume flush/FUA success may cite a device only when persistence,
   flush/FUA/barrier, atomicity, volatile-cache, and identity evidence satisfy
   the compiled policy.
3. A fast target with unknown flush semantics, unsafe volatile write cache,
   stale namespace identity, unsupported FUA, wrong atomic write granularity, or
   stale capability probe is not a slower durable target. It is unknown,
   blocked, unsafe-visible, or refused.
4. PMem durability requires persistence-domain and CPU-cache flush/fence
   evidence, not merely a memory mapping or low latency.
5. ZNS, SMR, append-only, and remote/object targets must satisfy their
   protocol/geometry and commit semantics before placement or rebake can claim
   compatibility.
6. Media cost (#844), layout geometry (#880), capacity admission (#898), and
   ack receipts (#842) consume capability refs. None of them alone may invent
   missing persistence or flush semantics.

## Read Serving And Degraded Reads

Write acknowledgment honesty is not enough. Read source selection must also
consume storage intent so a fast hit does not become stale, under-width, or
non-authoritative truth by accident. #877 owns the storage-intent read-serving
model.

A read-serving decision must distinguish at least these source classes:

- dirty or writeback page-cache bytes that are visible under page-cache law;
- clean page cache whose anchor, fence, and policy revision remain valid;
- cache-only RAM or flash serving trials;
- authoritative RAM, PMem, or durable serving roles;
- local placement receipts;
- remote placement receipts;
- degraded reconstruction from receipt targets;
- snapshot or read-only generation sources;
- geo-async remote sources with explicit lag/RPO;
- archive or restore sources.

Every source must pass freshness and authority predicates before it can serve:

- current inode/object/range identity and namespace or snapshot generation;
- compiled policy id/revision and read freshness profile;
- placement receipt refs or explicit cache/trial anchor refs;
- membership epoch, committed roster identity, lease, participant role, and
  fencing state when remote or clustered state participates;
- trust/security-domain, session-security, key-epoch, sharing-domain,
  authorization, and residency evidence when remote, encrypted, shared, repair,
  or geo state participates;
- capacity/admission evidence when degraded reconstruction will trigger read
  repair, remote refresh, archive restore, serving promotion, or replacement
  receipt publication;
- recovery/degradation evidence when the read uses under-redundant placement,
  reconstructed bytes, repair-required sources, partition-healing state, stale
  geo state, or receipt-retirement-sensitive sources;
- digest/checksum evidence for placement, degraded, or reconstructed bytes;
- transport/path evidence and lag evidence for remote or geo sources;
- stale, missing, or contradictory evidence reason when a candidate is rejected.

Cache-only or serving-trial hits may reduce latency while their anchors and
fences remain valid, but they do not satisfy durable placement, RAM authority,
geo, or successor claims by themselves. If an anchor is stale, the read must
invalidate, refresh, repair, degrade visibly, or refuse according to policy. It
must not fall through to a topology-only guess and call the result satisfied.
#920 binds that final read outcome: exact, degraded-visible, refreshed,
unknown-evidence, blocked, or refused read results must cite the serving source,
rejected candidates, response-registry projection, and caller-visible status.

Degraded reads are legal only when receipt evidence proves the requested bytes
from surviving targets. A digest mismatch, under-width reconstruction, stale
receipt generation, or ambiguous membership epoch must produce a typed error,
unknown-evidence state, or policy-visible degradation instead of returning
unverified bytes. Opportunistic read repair may be useful, but it must reserve
wear, capacity, transport, and scheduler budgets and publish replacement
receipts before changing authority or retiring old receipts.

WAN and internet reads need explicit freshness law. A `geo-async` remote source
may satisfy a disaster-recovery or stale-read profile inside the recorded RPO
lag envelope, but it must not satisfy a latest local POSIX read unless the
compiled policy requested that weaker freshness. `geo-intent` or
`geo-full-placement` reads still need receipt and path evidence for the remote
authority being used; speed-of-light latency is not a correctness exception.

## Recovery, Degraded Mode, And Receipt Retirement Authority

Storage intent consumes recovery facts, but it does not own placement receipt
authority, scrub, repair, rebuild, membership, trust, ordering, capacity, or
relocation execution. #900 owns the storage-intent recovery/degradation evidence
projection and the predicates that decide whether those facts satisfy a compiled
policy role.

This boundary matters whenever TideFS serves while under-width, reconstructs
from surviving shards, repairs on read, rebuilds after loss, heals a partition,
drains a target, catches up a geo peer, or retires an old receipt. The danger is
not only data loss; it is a hidden downgrade where "some bytes were readable"
becomes a fresh read, a durable ack, a full-placement claim, or permission to
free the old authority.

Authority boundaries are:

- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`, #675, and the #18 lineage own
  durable placement receipt authority, source receipts, replacement receipts,
  and receipt-backed repair publication;
- read-serving (#877) owns source selection, but a degraded source must cite
  #900 evidence when it is weaker, reconstructing, repair-required, geo-lagged,
  or receipt-retirement-sensitive;
- relocation/rebuild/geo movement (#848) may execute work, but it cannot declare
  recovery complete or retire sources without replacement receipt and #900
  predicate satisfaction;
- satisfaction reconciliation (#874) consumes #900 evidence to publish exact,
  degraded-visible, blocked, refused, or unknown state;
- validation (#863) proves the forbidden outcomes under injected corruption,
  partition, no-quorum, lag, reserve, and receipt-retirement faults;
- membership (#750), trust/domain (#897), ordering/replay (#894), capacity (#898),
  layout (#880), lifecycle (#881), and data shape (#878) remain the source
  authorities for their evidence slices.

The recovery/degradation evidence projection must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `degradation_policy_ref` | Names whether exact, degraded-visible, stale-read, no-quorum, blocked, refused, or unsafe-visible behavior is permitted for this policy revision. |
| `source_receipt_set_ref` | Binds the read, repair, rebuild, or relocation plan to current placement receipt generation, source targets, payload digest, and redundancy policy. |
| `reconstruction_width_ref` | Proves replicated or EC reconstruction has enough verified sources and rejects under-width, malformed-policy, or stale-generation reconstruction. |
| `target_health_ref` | Names missing, corrupt, stale, quarantined, fenced, draining, wrong-domain, unreachable, or suspect targets without converting them into usable sources. |
| `repair_obligation_ref` | Carries read-repair, scrub finding, repair ticket, rebuild ticket, evacuation, geo catch-up, priority, retry, and repair-debt state. |
| `replacement_receipt_ref` | Proves repaired or rebuilt placement publication before any stronger satisfaction state or source retirement is claimed. |
| `retirement_frontier_ref` | Binds old-receipt retirement to replacement receipt, ordering/replay, lifecycle, capacity, fence, and reclaim-frontier safety. |
| `partition_healing_ref` | Records no-quorum, split-brain hazard, old epoch, fence, witness/data role, and healing frontier state from membership evidence. |
| `rpo_rto_lag_ref` | Records geo, archive, receive, and restore lag relative to policy and exposes when lag exceeds the requested envelope. |
| `recovery_state` | Records exact, degraded-visible, reconstructing, repair-required, rebuild-required, geo-lagged, no-quorum, partitioned, blocked, refused, or unknown-evidence. |
| `recovery_refusal_ref` | Carries typed refusal such as under-width, stale receipt, corrupt source, wrong epoch, fenced peer, quarantined source, wrong trust domain, under-reserved repair, missing replacement receipt, or lag exceeded. |

Degraded state is a visible receipt state, not an implementation mood. If policy
permits a degraded read, the read may be successful while still carrying
repair-required or rebuild-required evidence. If policy requires exact or latest
freshness, the same source set must block or refuse. The caller and operator
must be able to see which guarantee was earned.

No-quorum and partition handling fail closed unless the compiled policy names a
weaker visible mode. A write that cannot earn its configured quorum floor is not
a slow write; it is blocked, refused, or explicitly degraded only when the
policy says that degraded result is legal. Healing after a partition must prove
which epoch, fence, witness/data role, and receipt generation made each result
safe.

Repair, rebuild, and relocation completion require replacement receipts.
Reconstructing bytes, copying bytes, or seeing a successful transfer is not
placement authority. Old receipts, old locators, deadlist entries, and source
targets may retire only after replacement receipt publication plus ordering,
capacity, lifecycle, fence, and reclaim-frontier evidence say retirement is
safe.

## Data Shape, Transforms, And Integrity

#878 owns the storage-intent data-shape boundary. This boundary decides which
encoded shape is legal for a range or generation before placement scoring
chooses among legal candidates. It exists because the same logical bytes can
have very different cost, latency, repair, and security behavior depending on
record size, compression, checksums, deduplication, encryption, EC/archive
shape, and coalescing.

Data shape is not a transform pipeline bolted onto storage after placement. The
planner must consider it together with media, proximity, workload prediction,
wear, cost, and read-serving law:

- small records may protect random overwrite latency and repair granularity,
  while large records may be better for streaming ingest, WAN transfer, and
  cold archive;
- compression can reduce flash writes, HDD bytes, and internet egress, but CPU
  and decompression latency can violate sync or read-serving floors;
- checksums and digest suites are integrity floors with layer-specific meaning,
  not optional speed knobs;
- dedup can reduce capacity and write amplification, but sharing across tenant,
  encryption, or security domains is illegal unless the compiled policy permits
  it and evidence proves compatibility;
- encryption changes the legal compression/dedup order and requires key, nonce,
  and epoch evidence that repair, read-serving, and rebake can cite;
- EC/archive shapes can be excellent for cold capacity and remote durability but
  unacceptable for hot reads, degraded-read tails, or fast rebuild envelopes.

The policy compiler should express at least these logical data-shape fields:

| Field | Meaning |
| --- | --- |
| `record_size_class` | Allowed extent/chunk/stripe sizing, split/coalesce rules, and per-range override law. |
| `compression_policy` | Whether compression is required, allowed, refused, or shadow-evaluated, plus CPU/latency and dictionary/epoch constraints. |
| `integrity_policy` | Required checksum/digest suites and the layer identity each digest proves. |
| `dedup_policy` | Fingerprint identity, sharing domain, collision/security posture, refcount authority, and refusal rules. |
| `encryption_policy` | Plaintext identity boundary, transform order, key/nonce/epoch references, and domain compatibility. |
| `coding_policy` | Replication, EC, archive, stripe, shard, locality, degraded-read, rebuild, and restore-time constraints. |
| `shape_cost_policy` | CPU, memory, read amplification, decompression, WAN, capacity, media-wear, rebuild, and movement-debt budgets. |
| `rebake_policy` | When an existing generation may change record size, compression, dedup, digest, encryption, EC, or archive shape. |

A data-shape evidence record must prove the actual shape that exists, not merely
the shape the planner intended. It should reference the compiled policy
revision, plaintext identity, encoded/compressed/encrypted layer identity,
digest suite, placement receipts, key/nonce/epoch refs when encryption is
involved, EC k/m or equivalent coding parameters, record size, compression and
dedup verdicts, cost/wear accounting refs, and any confidence or refusal reason
that affected the decision.

Identity law is strict:

1. Mounted plaintext identity is not silently changed by a transform.
2. Checksum-layer evidence proves the bytes owned by that layer; it is not by
   itself mounted repair identity.
3. Compression must happen before encryption when the policy wants useful
   compression, unless a later explicit transform authority defines a different
   safe construction.
4. Dedup fingerprints are over the policy-approved identity and domain; they
   cannot cross encryption, tenant, security, or retention domains by accident.
5. Encryption cannot be bypassed to make compression, dedup, repair, recovery,
   or operator inspection convenient.
6. EC/archive shape changes must account for degraded-read tail latency,
   rebuild bandwidth, and restore-time cost before they can satisfy serving or
   RTO floors.
7. Rebake must publish replacement placement and data-shape receipts that
   satisfy the target policy before old shape receipts or locators are retired.

Unknown, stale, malformed, wrong-domain, wrong-key-epoch, under-width, or
missing data-shape evidence cannot satisfy policy. The reconciler must classify
that state as `unknown-evidence`, `blocked`, `refused`, or visible degradation
according to policy. This matters for all read paths too: a cache hit, remote
receipt, degraded reconstruction, geo source, or archive restore must prove it
can decode, verify, decrypt, and reconstruct the requested identity before it is
eligible to serve.

Mounted device-level compression and encryption remain blocked by
`docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md` until that inventory
and its child issues prove the mounted runtime has one transform-aware
authority. The storage-intent data-shape model may describe future legal shapes;
it does not by itself enable those mounted product claims.

## Allocation Geometry, Fragmentation, And Reclaim

#880 owns the storage-intent layout-evidence boundary. This boundary makes
allocator geometry visible to placement and relocation without making planners
recompute allocator internals or trust stale runtime mirrors. It is the evidence
source for questions like: is this target class legal, is there a large enough
free run, would this write cross an erase block or zone boundary, is this
pending free actually safe to reuse, and is defrag worth the rewrite?

The layout evidence model should cover at least:

| Evidence | Meaning |
| --- | --- |
| `allocation_class` | Policy-visible allocation class, segment class, region class, and block-volume alignment constraints. |
| `free_run_summary` | Largest legal runs, free-run fragmentation, class-local scarcity, and confidence/staleness age. |
| `locality_score` | Seek, scan-contiguity, range-map, and physical adjacency evidence for HDD or locality-sensitive media. |
| `media_geometry` | Erase block, zone, write-pointer, reset, optimal I/O size, SMR/ZNS append, or other device geometry. |
| `pending_free_frontier` | Publication, fence, snapshot, receipt, or generation boundary before bytes become reusable. |
| `reclaim_debt` | Segment-drain pressure, victim score, reserve pressure, foreground disruption, and blocker refs. |
| `allocator_generation` | Stale-pointer and stale-layout evidence needed by reads, repair, and relocation. |

Authority boundaries are strict:

- durable allocator, publication, placement, receipt, or fence records are
  authority when the implementation defines them;
- rebuildable mirrors such as largest-run heaps, victim queues, heat maps,
  pressure gauges, and open-segment cursors may guide scoring but cannot satisfy
  policy alone;
- a topology scan or current free-space snapshot cannot retire receipts, admit
  relocation, or claim satisfaction by itself;
- pending-free bytes are not reusable until the publication, fence, snapshot,
  generation, and receipt boundaries say they are safe;
- ENOSPC, reserve pressure, and allocator refusal are visible storage-intent
  states, not hidden retries that silently consume protected sync or repair
  reserves.

Allocation geometry is what makes defrag honest. On rotational media the useful
signal is seek count, scan contiguity, range-map fragmentation, and free-run
shape. On SSD/NVMe the useful signal is normally erase-block or zone alignment,
garbage-collection pressure, metadata fan-out, future write amplification, and
critical reserve protection. On ZNS, SMR, or other sequential-write media, the
write pointer and reset budget are hard constraints before scoring. For block
volumes, alignment and low-fragmentation targets can be stronger than ordinary
file-data layout preferences.

Unknown, stale, mirror-only, wrong-generation, under-aligned, pending-free,
zone-incompatible, or reserve-unsafe layout evidence cannot satisfy policy by
accident. The planner must choose a different legal candidate, admit a bounded
convergence or reclaim action, mark the state unknown/blocked, or refuse
according to policy.

## Flash Lifetime And Write Amplification

Flash endurance is an authority input, not an afterthought. Every flash-backed
device must expose a media cost ledger with at least:

- logical bytes written by TideFS class;
- estimated physical media bytes when available;
- write amplification estimate;
- erase-block or zone alignment quality;
- free-run, fragmentation, locality, and pending-free safety evidence where
  layout producers expose it;
- remaining endurance or wear percentage when available;
- temperature/error health signals;
- reserved write budget for critical intent and recovery work;
- relocation bytes charged by source and reason;
- wear reservations by class, including critical intent, degraded recovery,
  normal foreground, and optimizer budgets;
- movement debt carried by recently relocated subjects;
- expected avoided future media writes and the payback horizon used to justify
  relocation;
- conservative physical-byte estimates when device-reported media bytes are
  absent or stale.

Placement and relocation must reserve wear budget before consuming it. If the
budget is unavailable, the planner must choose a different legal candidate,
defer optimization, or refuse according to policy.

No flash write is free or uncharged. When physical media-write evidence is
missing, the ledger must use a conservative multiplier rather than treating
unknown write amplification as zero. Reservations must expire or be released
when work aborts, but consumed wear and movement debt stay visible for future
planning and operator explanation.

Initial anti-wear laws:

1. Do not promote data to flash after a single read unless an explicit policy
   pins it.
2. Do not use flash as a transparent writeback cache for large cold streams
   when the final placement is HDD/EC and the guarantee can be earned more
   cheaply.
3. Prefer durable intent plus later full placement over writing the same young
   bytes repeatedly to flash-backed full replicas.
4. Use policy-approved data shape before writing to flash: compress, checksum,
   deduplicate, coalesce, or choose smaller/greater record shapes only when the
   compiled policy and transform evidence permit it.
5. Treat high fsync density as a reason to optimize intent lanes, not as a
   reason to rewrite full data objects for every barrier.
6. Treat snapshot-pinned, clone-held, and receive-base-held generations as
   stable candidates for cold placement, not as hot-write candidates.
7. Do not defrag SSD/NVMe merely for contiguousness. SSD relocation needs a
   write-amplification, metadata fan-out, garbage collection, or placement
   satisfaction reason.
8. Preserve a critical write reserve for sync intents, repair, and evacuation.
   Background optimization may not spend that reserve.
9. Do not turn one-pass scans into persistent flash authority. Cache admission
   may be cheap and temporary; placement movement needs a dwell/payback proof.
10. When relocation rewrites flash, charge the actual write and also record
    movement debt that future scoring must overcome before moving the same
    subject back.
11. Prefer demoting or expiring serving trials that miss their predicted
    benefit over extending them with more flash writes.
12. Refuse or delay non-critical optimization before eroding reserves needed
    for durable sync, repair, evacuation, or policy-satisfaction catch-up.
13. Treat pending-free and reclaimable bytes as unavailable until lifecycle,
    allocator, publication, fence, and receipt boundaries prove they are safe to
    reuse.

This is one of the main ways TideFS can be better than naive tiering: it can
be fast without turning expensive flash into a disposable shock absorber for
every cold stream and short-lived temp file.

## Non-Wear Cost And Economic Budgets

Flash wear is only one cost. TideFS also needs an explicit non-wear cost
ledger so the planner can choose the cheapest legal plan without pretending
that far-away replicas, archive capacity, rebuild traffic, or internet egress
are free.

The non-wear cost ledger must track at least:

- logical bytes stored by dataset, generation, media role, and failure domain;
- capacity consumed by replicated, erasure-coded, archive, remote,
  snapshot-pinned, clone-held, and receive-base-held data;
- transport bytes by proximity domain, carrier, peer/site, and reason;
- network egress/ingress cost classes for WAN and internet paths;
- rebuild, repair, evacuation, relocation, and geo catch-up bytes by reason;
- non-wear movement debt for recently relocated subjects, including capacity,
  network, recovery-bandwidth, and foreground-disruption debt;
- payback evidence for non-wear benefits such as capacity saved, RPO lag
  reduced, egress avoided, or rebuild risk reduced;
- retention cost for cold, snapshot-pinned, clone-held, and receive-base-held
  generations;
- operator-defined weights for money, power/energy proxy, scarce capacity,
  scarce bandwidth, and regulatory or administrative domain preference.

Missing or stale cost evidence is not zero. Policy decides whether to use
operator defaults, mark the decision `unknown-cost`, defer an optimizer action,
or refuse a placement that would otherwise look cheap only because accounting
is absent.

The planner uses cost in two phases:

1. hard gates reject candidates that exceed reserved capacity, network,
   foreground, repair, or operator-defined cost ceilings;
2. scoring compares the remaining legal candidates by total expected cost over
   the data's predicted lifecycle, not only by immediate write latency.

This distinction matters. A `quorum-intent` write to nearby high-endurance
media plus later cold convergence can be cheaper than immediate full placement
on scarce flash. A geo-async policy over the internet can be excellent for
RPO, but its egress, catch-up backlog, and restore-time cost must be visible.
An archive object can be inexpensive at rest while still being the wrong
serving plan for a latency-sensitive hot range.

## Relocation, Defrag, Compaction, And Rebake

TideFS relocation is a single family with multiple reasons:

| Reason | Meaning |
| --- | --- |
| `policy-satisfaction` | Current placement no longer satisfies the requested intent. |
| `repair` | A receipt target is missing, corrupt, degraded, or below redundancy. |
| `evacuation` | Device/node/media must be drained. |
| `hdd-defrag` | Rotational layout should be made more sequential or seek-efficient. |
| `ssd-compaction` | Flash layout should reduce future write amplification or metadata fan-out. |
| `rebake` | Record size, compression, dedup, checksum, or EC shape should change. |
| `promotion` | Stable hot data deserves a faster serving role. |
| `demotion` | Cold data should stop consuming expensive media. |
| `geo-catchup` | Remote RPO/RTO target needs progress. |
| `wear-rebalance` | Device endurance or error risk requires load movement. |

Relocation decisions move through an explicit lifecycle:

| State | Meaning |
| --- | --- |
| `observed` | Signals suggest a possible move, but no budget should be spent yet. |
| `shadow-evaluated` | TideFS records the move it would make, predicted benefit, cost, and blockers. |
| `serving-trial` | Optional cache or serving copy exists without changing durable authority. |
| `admitted-move` | Budgets are reserved and a receipt-safe relocation plan is accepted. |
| `replacement-published` | Replacement placement receipts exist and are visible. |
| `old-receipt-retired` | Old locators are retired only after replacement receipt law permits it. |
| `cooldown` | The subject carries movement debt and cannot churn unless policy, repair, or evacuation requires it. |

Every relocation plan must pass:

1. receipt authority check for the current source;
2. hard policy satisfaction for the target;
3. budget admission for foreground impact, dirty bytes, transport, capacity,
   and wear;
4. benefit/cost gate;
5. rollback or no-cutover proof;
6. replacement receipt publication before old receipt retirement.

The benefit/cost gate must account for:

- predicted p50/p95/p99 latency improvement;
- throughput improvement or tail-risk reduction;
- reduced future write amplification;
- reduced HDD seek cost or improved scan speed;
- improved free-run shape, allocator locality, alignment, segment drain, or
  reclaim-debt pressure;
- lifecycle benefit or risk, including young churn avoided, retained-root
  stability, receive-base protection, orphan/destroy blockers, and reclaim
  frontier progress;
- reduced capacity cost;
- improved RPO/RTO or rebuild risk;
- read/write media cost of performing the move;
- flash lifetime consumed by the move;
- network egress and congestion cost;
- foreground latency disruption.

Anti-thrash law is part of relocation authority:

- recently moved subjects carry movement debt in future planner scores;
- ordinary promotion and demotion require a minimum dwell window or an explicit
  reason to override it;
- contradictory signals reset or lower confidence instead of flipping the
  placement back immediately;
- per-range movement is preferred over whole-file movement for phase-changing
  sparse or scientific workloads;
- failed payback creates a cooldown and a skip reason, not an immediate retry
  loop;
- repair, evacuation, and hard policy-satisfaction moves may override cooldown,
  but the override must be receipt-visible and budget-visible.

HDD defrag is therefore real and useful, but it is one optimizer action, not
an architecture center. On HDD it may group hot sequential extents, reduce
seek count, and align with zones. On SSD it normally should not run unless it
reduces future write amplification or metadata overhead. Across WAN paths it
means batching, compression, delta transfer, and queue discipline rather than
local block contiguity.

## Placement Planning Model

The storage-intent planner works in roles, not in a single target list.

1. Decide the acknowledgment plan: which receipt participants are needed
   before success.
2. Decide the serving plan: where reads should land now.
3. Decide the durable placement plan: where bytes or shards must live after
   full policy satisfaction.
4. Decide the background convergence plan: what can be deferred, and what
   receipt records the deferral.
5. Decide relocation constraints: when the current plan should change.

Examples:

- A WAL-heavy dataset may acknowledge on `quorum-intent` using high-endurance
  NVMe/PMem roles, serve recent data from RAM/NVMe, and converge older stable
  ranges to HDD/EC.
- A backup ingest dataset may avoid flash for data entirely, acknowledge on
  local or quorum intent according to policy, and write large compressed
  extents directly to HDD/EC placement.
- A geo dataset may acknowledge locally with an explicit `geo-async` RPO
  receipt, or block for `geo-intent` only when the operator asked for the
  speed-of-light cost.
- A scratch dataset may use `volatile-local` or `volatile-replicated` and be
  excluded from POSIX durable sync claims.

The planner must prefer legal cheap plans over impressive expensive plans. A
fast NVMe write that consumes scarce endurance for data that will die in two
seconds is not genius; it is bad accounting.

## Data Lifecycle Model

Storage intent should treat data age, stability, and retention as first-class
evidence. Most storage systems make poor cost decisions because they materialize
bytes too early into their final expensive form, or reclaim old bytes before
the dependency graph is truly gone. TideFS should separate the lifecycle of a
write from the lifecycle of a durable object.

| Generation | Description | Typical action |
| --- | --- | --- |
| `young-dirty` | Newly accepted dirty bytes, not yet at the requested ack floor. | Admission, coalescing, intent reservation. |
| `young-acknowledged` | Bytes have earned an ack receipt but may not yet have full final placement. | Keep replayable intent, defer expensive shaping if policy allows. |
| `serving-trial` | A cache or serving copy exists because prediction says it may help, but durable authority has not changed. | Measure benefit, expire if payback is weak, preserve cache/authority distinction. |
| `stable-hot` | Bytes survived the short overwrite/delete window and are read often. | Add serving role on RAM/NVMe/SSD if benefit exceeds wear/cost. |
| `stable-warm` | Bytes are useful but not latency-critical. | Normal replicated or mixed-media placement. |
| `stable-cold` | Bytes are retained but rarely read or mutated. | HDD/EC/archive placement, large records, compression or dedup where legal, low relocation churn. |
| `snapshot-pinned` | Older generation cannot be reclaimed because a data-retaining snapshot needs it. | Favor cold placement and avoid needless reshaping. |
| `clone-held` | A writable clone or promoted clone still depends on the generation. | Preserve retention authority, avoid unsafe source retirement. |
| `receive-base-held` | Incremental receive, omitted-content validation, or geo catch-up needs this base identity. | Protect base roots, expose RPO/catch-up dependency. |
| `bookmark-only-nonretaining` | A bookmark names lineage but does not retain data. | Refuse to treat it as a reclaim blocker or receive-base proof. |
| `orphan-held` | Unlinked or destroying namespace state still has open or traversal-owned bytes. | Keep reclaim blocked until orphan/lifecycle evidence drains. |
| `dead-pending-reclaim` | Replacement receipt or namespace state says data is obsolete but reclaim is not yet safe. | Receipt-gated reclaim only. |
| `destroying` or `tombstone` | Dataset lifecycle fences new use or records completed destruction. | Refuse new authority, preserve explanation and replay safety. |

This lifecycle lets TideFS reduce write amplification without weakening
durability. A sync WAL write can earn a durable intent quickly, then be folded
into full placement once the short-lived overwrite/delete window has passed.
A backup stream can bypass flash full placement entirely. A temp-file burst can
die after intent/reclaim without ever consuming expensive serving media.

The `serving-trial` generation is deliberately not durable authority; it is how
TideFS can learn aggressively without letting a cache hit become a placement
claim.

### Lifecycle Evidence And Generation Authority

#881 owns the storage-intent lifecycle-evidence boundary. This boundary is what
lets the predictor say "probably short-lived" while the authority model says
"definitely retained by this root" or "definitely not safe to reclaim yet."
Those statements must not share one untyped hotness bit.

The lifecycle evidence model should cover at least:

| Evidence | Meaning |
| --- | --- |
| `generation_identity` | Subject/range, dataset, lineage, branch/clone, committed-root, and policy revision refs. |
| `lifecycle_class` | Young, stable, snapshot-pinned, clone-held, receive-base-held, orphan-held, dead-pending, destroying, or tombstone state. |
| `retained_root_refs` | Data-retaining snapshot or clone catalog entries, lifecycle pins, committed roots, and consistency evidence. |
| `receive_base_dependency` | Incremental receive base root, omitted-content dependency, lineage manifest, and catch-up/RPO dependency refs. |
| `nonretaining_anchor_refs` | Bookmark or lineage-only anchors that must not be mistaken for data retention. |
| `orphan_destroy_state` | Open-unlinked, orphan-index, destroy traversal, poison/fence, and tombstone state that blocks admission or reclaim. |
| `replacement_reclaim_frontier` | Replacement receipt, old-receipt retirement, publication/fence, deadlist, and segment-reclaim frontier refs. |
| `lifecycle_generation` | Staleness and authority generation needed to reject old roots, stale pins, or contradictory retention evidence. |

Authority boundaries are strict:

- committed roots, snapshot and clone catalog entries, lifecycle pins, receive
  contracts, placement receipts, reclaim receipts, and publication/fence records
  are authority when the implementation defines them;
- workload signals, caller hints, access heat, time-since-write, and phase
  detection may predict lifetime, but they cannot prove that a root is retained,
  reclaimable, or safe to discard;
- bookmarks are non-retaining lineage anchors unless a later current authority
  explicitly changes that rule;
- receive-base and omitted-content dependencies are not optional local history;
  if they are missing, unprotected, wrong-lineage, or checksum-invalid, the
  planner must mark the state blocked/refused/unknown instead of publishing a
  stronger receive or geo catch-up state;
- dead-pending and reclaimable bytes are not capacity until lifecycle, receipt,
  fence, and #880 layout evidence agree that reuse is safe.

Lifecycle evidence must make cost decisions smarter without weakening safety.
Young bytes can avoid expensive full flash placement only after earning the
requested ack receipt. Snapshot-pinned or receive-base-held generations can be
treated as cold placement candidates only when their retaining authority is
current and consistent. Clone-held, orphan-held, destroying, or tombstone states
must feed admission, read-serving, relocation, reclaim, and operator explanation
as typed states, not hidden cleaner side effects.

## Service Objective Envelopes

#915 owns the storage-intent service-objective evidence projection. It does not
replace #845 workload prediction, #850 performance rows, #862 scheduling, #912
measurement attribution, or #875 claims. It gives those consumers the compiled
workload contract they must satisfy, measure, explain, or refuse.

The key distinction is that a workload shape says what TideFS has observed or
expects, while a service objective says which performance envelope is part of
the policy for that subject and operation. A small-sync WAL, VM FUA workload,
metadata storm, streaming ingest, hot-read RAM serving set, rebuild, relocation,
and internet geo stream can all be "fast" in different ways. They need different
tail bounds, throughput floors, queue limits, concurrency assumptions, RPO/RTO
ties, wear budgets, and refusal behavior.

Service-objective evidence must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `objective_identity_ref` | Names objective id, producer, policy id/revision, rollout stage, subject scope, operation class, and temporal generation. |
| `workload_phase_ref` | Binds workload class, phase, request mix, range/object cohort, predictor confidence, action class, and observation/query refs from #845 and #913. |
| `operation_semantics_ref` | Names sync, fdatasync, O_DSYNC, FUA/barrier, stable write, read, prefetch, repair, rebuild, relocation, rebake, geo catch-up, archive restore, or RAM-authority semantics. |
| `latency_tail_ref` | Records p50/p95/p99 or tighter percentile targets, max queue/admission time, jitter/variance limits, tail amplification, warmup/censor rules, and refusal/degradation thresholds. |
| `throughput_burst_ref` | Records throughput floor or ceiling, foreground/background class, burst window, dwell window, batching/coalescing assumptions, and backpressure/refusal law. |
| `concurrency_queue_ref` | Names queue depth, parallelism, dirty-window, lane class, group-commit window, transport outstanding window, and scheduler/admission refs. |
| `environment_profile_ref` | Binds media/topology/profile evidence for RAM, PMem, NVMe, SSD, HDD, rack, datacenter, WAN, internet, RDMA-present or RDMA-absent transport, thermal/device-health state, and trust/domain refs. |
| `degradation_recovery_ref` | Binds degraded-visible behavior, no-quorum or partition treatment, stale-read law, RPO/RTO lag, repair/rebuild obligation, and recovery refs from #900. |
| `budget_cost_wear_ref` | Binds tenant/isolation budget refs, capacity/reserve refs, write-amplification and flash-wear budget, movement debt, egress/power/capacity/operator-money budget, and protected floor refs. |
| `decision_execution_ref` | Points to decision-frontier, scheduler admission, action-execution, evidence-retention, and query snapshot refs that selected, admitted, executed, or refused work under this objective. |
| `attribution_claim_ref` | Names measurement-attribution refs, comparator baseline refs, transfer scope, claim ids, and allowed/refused uses for product or incumbent-comparison language. |
| `objective_refusal_ref` | Gives typed missing-evidence, stale-envelope, impossible-latency, insufficient-throughput, tail-risk, budget-exhausted, degraded-only, unsupported-topology, or comparator-not-valid refusal/defer state. |

Objective families should be concrete enough for operators and tests to see the
tradeoff being made:

| Family | Envelope examples | Refusal examples |
| --- | --- | --- |
| Small sync WAL | fsync p99, max queue time, group-commit window, local or quorum intent ack, high-endurance media budget | no durable intent media, no legal quorum, protected latency floor exhausted |
| VM FUA/barrier | FUA tail, barrier dependency scope, dirty-window reserve, replay identity, foreground isolation | unsupported FUA capability, stale media probe, illegal cache downgrade |
| Metadata storm | create/unlink/rename/xattr/fsyncdir p99, directory hot-set locality, namespace intent lane | pool-wide global commit, hidden tenant p99 damage |
| Streaming ingest | throughput floor, WAF ceiling, large-record/EC/cold-placement shape, flash bypass | flash writeback that doubles media writes, capacity reserve stolen from sync |
| Hot read RAM serving | read latency, hit-rate dwell, cache-only versus RAM-authority boundary, eviction law | cache hit treated as durable authority, failed payback hidden |
| Rebuild/relocation/defrag | foreground p99 protection, movement-debt limit, replacement receipt and old-receipt retirement frontier | rewrite cost exceeds payback, source retired before replacement proof |
| WAN/internet geo | RPO lag, egress budget, RTT/jitter envelope, TCP baseline, trust/domain and residency refs | `geo-intent` claimed without paying WAN latency, stale or unauthorized peer |

Hard service-objective laws:

1. A compiled service objective is a hard gate before scoring when the policy
   makes latency, throughput, tail, RPO, isolation, wear, cost, or comparator
   behavior part of the contract. Candidates that cannot meet the required
   envelope are rejected, degraded-visible, deferred, blocked, or refused before
   the score vector is evaluated.
2. Objectives are scoped evidence. A p99 win for one workload phase, tenant,
   media class, topology, transport, ack shape, or policy revision does not prove
   another objective unless #912 records an allowed transfer and #913 provides a
   complete-for-purpose query snapshot.
3. Throughput may not buy hidden latency damage. Any borrowing from protected
   sync, repair, evacuation, wear, capacity, egress, or tenant-isolation budgets
   must be visible through #902/#898/#844/#856 refs and expire, throttle, defer,
   or refuse according to policy.
4. Service-objective failure is not permission to invent `sync=disabled`.
   TideFS may expose degraded-visible state, throttle, block, or return typed
   refusal, but it must not report durable sync, RAM authority, geo intent, or
   low-latency success when the objective was not earned.
5. #850 performance rows must cite the objective they measure. A row without a
   service-objective ref may be exploratory telemetry, but it cannot close a
   storage-intent performance gate or product/comparator claim.
6. #912 attribution may train prediction, close payback, spend more wear budget,
   or support claims only for the objective scope recorded in the attribution
   verdict. Confounded, stale, contradicted, insufficient, or refused attribution
   can cool down or diagnose but cannot make an objective satisfied.
7. #875 claims must cite objective evidence, attribution evidence, evidence-query
   snapshots, and claim ids before using wording such as fast durable sync,
   low-latency RAM authority, high-throughput ingest, WAN/internet geo behavior,
   flash-wear protection, or better than OpenZFS, Ceph, or DRBD.

## Planner Scoring

Planning is a hard-constraint filter followed by multi-objective scoring.

Hard constraints include:

- requested guarantee floor;
- service-objective envelope legality for the workload and operation class;
- ordering, replay, barrier-scope, dirty-epoch, dependency, and publication
  legality;
- membership epoch, committed-roster, quorum-set, witness/data role, fence,
  drain, split-brain, and failure-domain legality;
- capacity and reservation availability;
- recovery/degradation legality, including source receipts, reconstruction
  width, visible degraded state, repair obligation, partition/no-quorum state,
  replacement receipt publication, and old-receipt retirement;
- temporal legality, including timebase, clock-health, skew/uncertainty,
  evidence age, sequence frontier, lag/staleness, expiry/deadline, and
  temporal refusal state;
- media role eligibility and media capability legality, including persistence
  domain, flush/FUA/barrier semantics, atomicity/granularity, namespace
  identity, volatile-cache policy, health, and stale-probe refusal;
- data-shape compatibility and transform block state;
- allocator/layout compatibility, including alignment, free-space, pending-free,
  and zone/write-pointer state;
- lifecycle/generation compatibility, including retained roots, receive-base
  protection, orphan holds, destroy state, and reclaim-frontier safety;
- wear reserve availability;
- transport/path eligibility;
- operator policy and degradation law.

Only legal candidates reach scoring. The conceptual score is:

The decision frontier that proves hard-gate rejection, scoring inputs,
tie-breaks, selected plan, and counterfactual/payback anchors is #905 evidence.
Planner, read-serving, scheduling, data-shape, and relocation code may produce
local execution details, but they must not invent incompatible winner-only
decision records for authority-changing choices.

```text
score =
    latency_weight       * predicted_latency_cost
  + tail_weight          * predicted_tail_cost
  + throughput_weight    * throughput_shortfall_cost
  + ordering_weight      * barrier_dependency_and_replay_cost
  + wear_weight          * estimated_media_write_cost
  + shape_weight         * cpu_read_amplification_and_rebuild_cost
  + layout_weight        * fragmentation_locality_and_reclaim_cost
  + lifecycle_weight     * churn_retention_and_reclaim_frontier_cost
  + membership_weight    * epoch_churn_quorum_stability_and_drain_risk
  + capacity_weight      * capacity_cost
  + network_weight       * egress_and_congestion_cost
  + recovery_weight      * rebuild_or_rpo_risk
  + disruption_weight    * foreground_interference
  + confidence_weight    * misprediction_risk
  + movement_weight      * recent_movement_debt
  + payback_weight       * payback_failure_risk
  + complexity_weight    * rollback_and_operational_risk
```

The lowest legal score wins, but the planner must preserve the candidate set
and rejection reasons for operator explanation and later learning. A decision
that barely wins on latency while burning critical flash reserve, or barely
wins on capacity while increasing read amplification beyond the policy's tail
budget, should be visible, reviewable, and reversible by policy.

The planner must also use shadow evaluation. Before expensive relocation, it
should record what it would have moved, why, and what benefit it predicted.
Only after repeated confidence should it spend large wear, network, or
foreground disruption budgets.

For every admitted non-repair relocation, the plan must name a payback window:
the time, bytes read, seeks avoided, media writes avoided, RPO lag reduced, or
capacity saved that would make the move worthwhile. If observed benefit misses
the payback window, TideFS should demote or stop extending the trial, record a
skip/cooldown reason, and make the next similar move harder to admit until the
signal changes materially.

## Decision Frontier And Score Evidence

#905 owns the storage-intent decision-frontier evidence projection. It does not
choose placement, execute relocation, emit receipts, train prediction, or render
operator UI. It makes the optimizer's choice auditable enough that future
workers cannot preserve only the winning candidate and lose the safety,
performance, wear, and cost reasons that made the decision legal.

Decision-frontier evidence must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `decision_identity_ref` | Binds the action class, subject scope, policy id/revision, actor/component version, decision epoch, and temporal evidence for one planner, admission, read-serving, rebake, relocation, repair, geo, or receipt-retirement choice. |
| `evidence_query_snapshot_ref` | Names the #913 query snapshot that supplied candidate inputs, hard-gate evidence, score inputs, source-index generations, freshness frontier, completeness verdict, and query refusal state for the decision. |
| `candidate_frontier_ref` | Preserves the bounded candidate set, candidate classes, candidate digest, input evidence refs, deterministic ordering, and whether each candidate was legal, illegal, unknown, deferred, or refused. |
| `hard_gate_result_ref` | Records guarantee, service-objective, ordering, membership, trust, temporal, media-capability, data-shape, layout, lifecycle, capacity, recovery, rollout, isolation, prediction, transport, wear, and operator-policy gates before scoring. |
| `score_vector_ref` | Captures latency, tail, throughput, service-objective shortfall or headroom, ordering/replay, media writes, CPU/read amplification, layout/reclaim, lifecycle/churn, membership/drain, capacity, egress/congestion, recovery/RPO, foreground disruption, confidence, movement debt, payback, and operational-complexity dimensions with units or typed unknown state. |
| `selected_candidate_ref` | Names the selected plan, tie-breaker, reserve/admission refs, shadow/trial/admitted state, rollback or no-cutover proof, and typed defer/refusal when no candidate may run. |
| `counterfactual_payback_ref` | Names the baseline candidate, expected payback window, expected harm ceiling, outcome attachment point, cooldown dependency, and retention requirement for later learning and claims. |

Hard decision-frontier laws:

1. Illegal candidates may be observed and recorded, but they may not reach
   scoring. A scored candidate must already have hard-gate evidence.
2. Hard gates and score vectors may consume only evidence included in the #913
   query snapshot named by the decision. A stale, partial, contradicted, or
   refused query cut makes the decision unknown, deferred, blocked, or refused
   according to policy; it is not a license to use a warmer local index.
3. Required service objectives from #915 are hard gates, not bonus score terms.
   A candidate that misses a required latency, tail, throughput, queueing, RPO,
   isolation, cost, wear, or comparator envelope is illegal, degraded-visible,
   blocked, deferred, or refused before the score vector may rank it.
4. Winner-only records are not authority for adaptive placement, relocation,
   serving promotion, or comparator claims. The relevant rejected, deferred,
   and unknown candidates must remain inspectable until no explanation,
   validation row, outcome update, cooldown, or claim depends on them.
5. Missing, stale, or unitless score dimensions do not score as zero. They
   become `unknown-cost`, `unknown-benefit`, blocked, degraded-visible, or
   refused according to policy.
6. Tie-breakers must be deterministic and evidence-backed. If two candidates
   are equivalent under the score vector, the chosen candidate still records
   the tie-break input and policy revision.
7. A prediction decision ref from #845 may point to #905 evidence, but #845
   does not own every planner score vector. Placement (#843), relocation
   (#848), read serving (#877), scheduling (#862), and rebake/data-shape
   decisions consume the common decision frontier.
8. Outcome, payback, harm, cooldown, and confidence updates must attach back to
   the decision frontier that admitted or shadowed the action.

## Action Execution And Source Retirement

#911 owns the storage-intent action-execution evidence projection. It does not
choose candidates, score plans, schedule lanes, implement a relocation worker,
or render operator UI. It proves whether an admitted authority-changing action
is planned, prepared, copied, verified, published, cut over, aborted, rolled
back, completed, or refused without relying on worker-local state.

Action-execution records must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `action_identity_ref` | Binds action id, action class, subject scope, producer/component version, policy id/revision, execution epoch, temporal refs, and integrity refs. |
| `decision_admission_ref` | Names #905 decision frontier, selected candidate, hard-gate result, counterfactual/payback anchor, #915 service-objective refs, #898 reserve/admission refs, #902 isolation refs, #904 media-capability refs, and #910 retention refs. |
| `admission_query_snapshot_ref` | Names the #913 query snapshot that admitted or last revalidated the action, including freshness window, source-index generations, supersession state, and query refusal/degradation state. |
| `step_state_ref` | Records planned, admitted, prepared, copying, verifying, publishing, cutover, retiring-source, complete, aborted, rolled-back, refused, or unknown state with monotonic step sequence. |
| `idempotency_replay_ref` | Carries stable idempotency key, retry generation, crash-recovery marker, duplicate-suppression rule, replay proof, and stale-action refusal. |
| `source_protection_ref` | Names source receipts, old placement generations, rollback/repair sources, read-serving eligibility during the action, and source-retirement blockers. |
| `target_verification_ref` | Names target receipt candidates, digest/integrity proof, media flush/FUA or barrier proof where relevant, reconstruction width, and partial/degraded refusal. |
| `publication_boundary_ref` | Names replacement receipt publication, ordering evidence, policy-rollout revision, visible degraded/converging state, cutover boundary, and operator explanation refs. |
| `abort_rollback_ref` | Records abort reason, rollback/no-cutover proof, partial-target cleanup law, retained proof, and typed execution refusal. |
| `outcome_budget_ref` | Records work bytes, foreground disruption, media writes, network egress, reserve consumption, outcome/payback attachment, cooldown dependency, and execution cost refusal. |

Hard action-execution laws:

1. A planner decision is not execution evidence. An executor may cite #905, but
   it must publish #911 step evidence before other paths treat work as prepared,
   verified, cut over, aborted, or complete.
2. A target write is not completion. The action is incomplete until target
   verification, publication/cutover, and required ordering/recovery evidence
   exist for the compiled policy.
3. Source receipts may not retire until replacement receipts, ordering evidence,
   recovery/degradation evidence, evidence-retention proof, and action-completion
   evidence all pass.
4. Retries must be idempotent. Duplicate action delivery, crash replay, or worker
   restart must not double-spend reserves, publish contradictory receipts, reuse
   stale target verification, or retire the same source twice.
5. Stale action evidence after policy, media capability, capacity, membership,
   trust/domain, temporal, recovery, or #913 query-snapshot evidence changes
   must block, revalidate, or replan; it may not continue silently under old
   assumptions, and it may not cut over or retire sources from a stale,
   superseded, contradicted, or out-of-window query cut.
6. Aborted, refused, or rolled-back work remains visible until #910 permits
   compaction. Cleanup of partial targets is not permission to erase why the
   action did not cut over.
7. Read-serving during an action must see the action state. A source that is
   protected for rollback or read repair may remain eligible; a target that is
   copied but not verified/published is not authoritative.
8. Caller-visible action results must cite #920. A worker-local failure,
   rollback, no-cutover state, stale action, source-retirement blocker, or
   idempotent retry conflict may be compressed for one surface only after the
   typed result/refusal evidence and response-registry projection exist.

Action-execution examples:

- relocation copies a range to lower-latency media, verifies digest and media
  flush evidence, publishes replacement receipts, then retires source receipts
  only after #911 action-completion and #910 proof-retention blockers clear;
- rebake converts record shape or compression only when the action records the
  old shape, new shape, digest identity, rollback source, publication boundary,
  and outcome/payback ref;
- read repair writes reconstructed bytes as a partial action until target
  verification, replacement receipt publication, and recovery evidence prove the
  repaired copy is policy-satisfying.

## Measurement Attribution And Outcome Causality

#912 owns the storage-intent measurement-attribution evidence projection. It
does not run benchmarks, choose placement, execute actions, train predictors, or
publish product claims. It decides whether a measured outcome may be treated as
caused by a policy decision or executed action strongly enough to influence
prediction, payback, relocation, wear spend, operator explanation, performance
gates, fault rows, or claims.

This is a separate authority surface because TideFS will operate in noisy
systems: phase-changing workloads, warm cache effects, queue contention, thermal
throttling, repair storms, WAN jitter, policy rollout, membership churn, tenant
interference, and measurement harness drift can all make a real metric change
look like optimizer success. Storage intent may diagnose those observations, but
it must not turn them into placement authority without attribution proof.

Measurement-attribution records must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `measurement_identity_ref` | Names measurement id, producer/component version, artifact digest, subject scope, policy id/revision, observation generation, and temporal refs. |
| `workload_environment_ref` | Binds workload envelope, request mix, cache state, environment profile, media/topology profile, noise policy, background-load declaration, and sample freshness. |
| `service_objective_ref` | Names the #915 objective envelope whose latency, tail, throughput, queueing, RPO, wear, cost, isolation, or comparator outcome the measurement may affect. |
| `intervention_lineage_ref` | Points to decision frontier, action execution, admission/scheduler, isolation, capacity, media capability, trust/domain, transport, recovery, rollout, layout, lifecycle, and retention refs that shaped the observed run. |
| `evidence_query_snapshot_ref` | Points to the #913 query snapshot that selected, admitted, or executed the intervention and the completeness/refusal state that limits what the measurement may prove. |
| `sample_window_ref` | Records warmup, sample count, sample mass, duration/byte/op window, censor/drop policy, variance, confidence interval or bounded-uncertainty state, and insufficient-sample refusal. |
| `baseline_counterfactual_ref` | Names previous admitted variant, shadow plan, no-op baseline, incumbent comparator, same-policy cohort, or explicit no-valid-baseline refusal. |
| `metric_vector_ref` | Carries raw metrics and normalized KPI vectors with units: latency/tail, throughput, read amplification, write amplification, media writes avoided or spent, capacity saved, egress, RPO/RTO lag, CPU, foreground disruption, tenant harm, and payback deltas. |
| `confounder_state_ref` | Records concurrent repair/rebuild/relocation, policy rollout, membership or trust epoch change, device health/thermal state, WAN jitter, cache warmup, workload phase change, noisy-neighbor pressure, measurement-source drift, and fault/campaign state. |
| `attribution_verdict_ref` | Declares attributable, partially-attributable-with-bounds, confounded, insufficient-sample, stale, contradicted, shadow-only, or refused. |
| `allowed_use_ref` | States whether the result may diagnose, cool down, train confidence, close payback, admit future movement, spend extra wear budget, retire receipts, support performance/fault evidence, or support a claim, plus the #910 retention dependency. |

Hard measurement-attribution laws:

1. A performance artifact, raw metric, dashboard sample, or action outcome is not
   outcome proof by itself. Authority-changing learning needs #912 evidence.
2. Measurement attribution must bind the #913 query snapshot that selected,
   admitted, or executed the intervention. Missing, stale, contradicted,
   not-complete-for-purpose, or refused query snapshots limit the measurement to
   diagnosis or cooldown; they cannot prove causal improvement.
3. Measurement attribution must bind the #915 service objective whose outcome is
   being updated. A measured p99, throughput, wear, RPO, egress, or cost delta
   can train prediction, close payback, spend wear budget, or support a claim
   only for that objective scope unless an explicit allowed transfer is recorded.
4. Confounded, stale, insufficient-sample, contradicted, or refused measurements
   may diagnose, open investigation, lower confidence, or force conservative
   cooldown. They may not train confidence upward, close payback, justify
   authority-changing movement, retire source receipts, spend extra flash
   movement budget, or support product/comparator claims.
5. Attribution is scoped. A result from one tenant, workload phase, policy
   revision, media class, transport path, topology, or environment does not
   transfer to another scope unless #912 records the transfer rule and the
   relevant #902 isolation, #897 trust/domain, #904 media capability, #846 path,
   and #903 temporal evidence allow it.
6. Baseline and counterfactual lineage must remain inspectable. If the baseline
   is missing, stale, not comparable, or hidden by rollout/fault/noise state, the
   result is shadow-only, partially attributable with bounds, blocked, or refused
   according to policy.
7. #911 may prove the action completed, but #912 proves whether the measured
   benefit or harm belongs to that action. Completed actions with confounded
   outcomes remain complete for receipt safety but unresolved, failed, or cooled
   down for payback and prediction.
8. #850 performance rows, #863 fault rows, and #875 claims may consume metric
   artifacts only through attribution verdicts when adaptive placement,
   relocation, RAM/volatile, WAN/internet, wear, cost, or incumbent-comparator
   claims depend on measured improvement.
9. #910 controls retention of raw evidence, summaries, tombstones, and proof
   roots for attribution. Optional telemetry may expire early, but exact proof
   needed by payback, confidence, movement, validation, explanation, audit, or
   claims may not be purged until #910 records a safe frontier.

## Evidence Retention And Proof Compaction

#910 owns the storage-intent evidence-retention projection. It does not clean
data, implement a claims gate, choose placement, or render operator UI. It
decides whether storage-intent evidence may remain exact, be summarized, be
redacted, be tombstoned, or be purged without weakening receipts, decisions,
recovery state, operator explanation, validation rows, or claims that still
depend on it.

This is a producer and consumer contract, not just a background janitor. Every
authority-changing evidence producer should know the retention class, dependency
shape, and metadata budget before it emits proof that other paths will trust.
Every consumer that wants to retire, compact, or stop carrying proof should be
able to cite the #910 frontier that made the weaker proof form safe.

Evidence-retention records must distinguish at least:

| Evidence field | Storage-intent use |
| --- | --- |
| `evidence_identity_ref` | Names evidence id, evidence kind, producer, policy revision, subject scope, generation or epoch, temporal refs, and integrity/digest refs. |
| `evidence_dependency_ref` | Names receipts, query snapshots, decision frontiers, prediction outcomes, cooldowns, recovery obligations, policy-rollout state, explanations, performance rows, fault artifacts, claim ids, audit/legal holds, and cleanup work that still depend on the evidence. |
| `retention_class_ref` | Classifies replay-critical, receipt-authority, decision-proof, outcome-learning, operator-explanation, validation/fault, claim-artifact, audit/legal, short-lived telemetry, and compactable aggregate evidence. |
| `proof_root_ref` | Names exact-evidence root, summary digest, rejected/unknown-state digest, tombstone generation, producer version, and recovery check needed to prove a compacted record still represents the original evidence set. |
| `query_snapshot_dependency_ref` | Names #913 query snapshots, included evidence refs, source-index generations, and replay windows that require exact evidence, summary proof roots, or tombstones to remain valid. |
| `compaction_rule_ref` | States whether evidence must remain exact or may become digest-preserving summary, histogram/sketch/top-K summary, redacted/audited summary, expired, tombstoned, superseded, or refused-to-compact. |
| `safe_purge_frontier_ref` | Binds purge to sequence/time frontier, policy revision, receipt-retirement frontier, claim-retention boundary, cooldown/payback closure, rollback/re-entry blocker state, and temporal evidence. |
| `retention_cost_privacy_ref` | Records metadata write budget, storage budget, retention-media class, tenant attribution, privacy/redaction requirement, audit refs, and typed retention refusal. |

Hard evidence-retention laws:

1. Exact evidence may be compacted or purged only when #910 evidence proves no
   live receipt, #913 query snapshot, decision frontier, outcome update,
   cooldown, recovery obligation, policy rollout, operator explanation,
   validation row, claim, or audit hold still needs exact proof or an exact
   proof root.
2. Data reclaim is not evidence reclaim. A dead object, retired locator, or
   purged cache entry may still have receipt, decision, recovery, fault, or
   claim evidence that must survive in exact or summarized form.
3. Summaries must preserve refused, unknown, degraded, and rejected-candidate
   states, plus query completeness and refusal state, when those states are
   needed for learning, validation, explanation, or claims. A summary that keeps
   only successful winners is not authority.
4. Evidence metadata has a cost budget. Optional telemetry, low-confidence
   observations, and compactable aggregates must yield before replay-critical,
   receipt-authority, decision-proof, recovery, and claim-artifact evidence.
5. Privacy or tenant redaction may transform evidence only through an audited
   summary that preserves the authority predicates the remaining consumers
   need; redaction is not permission to erase proof silently.
6. If retention proof is missing or stale, the result is
   `unknown-evidence-retention`, blocked, refused, or claim-not-provable
   according to policy, not an implicit purge approval.
7. Authority-changing evidence producers must either publish #910-compatible
   retention identity and dependency refs or mark the record as optional
   telemetry that cannot support receipts, planner decisions, operator
   explanation, validation, or claims.
8. Exact-to-summary and summary-to-tombstone transitions are two-phase. The new
   proof root must be published and recoverable before exact evidence is
   deleted, and crash recovery must never resurrect a state where consumers
   trust a compacted proof that lacks its root.
9. Evidence placement is part of the cost model. Replay-critical and
   receipt-authority proof may require low-latency durable media; cold claim
   artifacts or long-lived decision summaries may move to cheaper or more
   distant media only when their digest anchors, retrieval latency, and failure
   domain still satisfy the dependent policy.
10. Retention compaction itself must be wear-aware. A cleanup pass that spends
    more flash endurance or foreground latency than the proof budget permits is
    throttled, deferred, or refused before it displaces critical intent,
    repair, evacuation, or receipt-retirement work.

Proof-compaction examples:

- a planner decision may compact exact candidate feature vectors into a digest
  plus score-vector summary only after the payback window, cooldown, performance
  row, and claim dependencies no longer require exact rejected candidates;
- relocation may retire old placement receipts only after replacement receipts,
  recovery/degradation evidence, and #910 proof show that exact old-source
  evidence is no longer needed for read repair, rollback, operator explanation,
  or fault validation;
- high-cardinality hotness telemetry may be dropped or sketched before it writes
  another durable flash record, but the outcome and failed-payback state for an
  admitted move remains authority proof until the cooldown and claim boundaries
  close.

## Worked End-To-End Flows

### Small Sync WAL

1. The write arrives with `O_DSYNC`, small size, sequential offset, and high
   fsync density.
2. The predictor identifies a WAL-like vector but does not weaken the sync
   floor.
3. The planner selects sharded `sync-intent` roles on high-endurance low
   latency media, optionally quorum intent when the dataset policy asks for
   distributed sync.
4. Capacity admission proves dirty-window, intent-media, allocation-ticket, and
   sync-reserve headroom for the exact ack role before the write can be
   reported.
5. Ordering evidence binds the dirty epoch, barrier scope, replay idempotency
   key, and dependency refs for the acknowledged range.
6. The ack receipt is `local-intent` or `quorum-intent`, not full cold
   placement.
7. Later convergence folds stable ranges into the file's durable placement.
8. Flash wear is one compact intent write per sync group, not a full-object
   rewrite per barrier.

### Grouped Fsync Without Order Loss

1. Several files issue `fsync` or `fdatasync` close together under a policy that
   permits grouping.
2. The scheduler may batch their durable intent writes and commit/root
   publication work to reduce tail latency and media writes.
3. Ordering evidence still records each file or directory barrier scope,
   dependency closure, replay idempotency key, and completion state.
4. A later barrier may share a batch, but it may not claim an earlier operation
   succeeded unless that operation's dependency set and publication boundary
   passed.
5. If one file has a writeback error, wrong-range intent, or incomplete metadata
   delta, that file's receipt is refused or failed without poisoning unrelated
   legal receipts in the batch.

### Bulk Backup Ingest

1. The write stream is large, sequential, low-reuse, and low sync-density.
2. The planner chooses a legal data shape first: large records, compression
   when CPU and sync floors permit, and direct HDD/EC/cold placement.
3. Capacity admission proves cold allocation-class headroom and refuses to count
   pending-free or snapshot-held bytes before they are reusable.
4. Flash is avoided except for metadata/intent required by the guarantee.
5. The receipt exposes full placement or the local/quorum ack plus pending
   convergence, depending on policy.
6. Readahead/cache admission avoids polluting hot read cache with one-pass
   data.

### Shape-Aware Rebake

1. A stable cold range has repeated evidence that compression or EC/archive
   shape would save flash writes, capacity, or internet egress.
2. The planner shadow-evaluates the rebake and records CPU, read amplification,
   degraded-read, rebuild, and restore-time costs.
3. The relocation governor admits the rebake only when payback, cooldown, wear,
   capacity, transport, foreground, and scratch-overlap budgets pass.
4. The worker writes replacement bytes with data-shape evidence and placement
   receipts for the target policy.
5. Old shape receipts and locators retire only after the replacement receipts
   satisfy policy.
6. A stale key epoch, illegal dedup domain, unknown digest suite, or mounted
   transform block turns the plan into `unknown-evidence`, `blocked`, or
   `refused` instead of a silent weaker shape.

### Snapshot-Pinned Receive Base

1. An old generation is retained by a data-retaining snapshot and also named as
   an incremental receive or geo catch-up base.
2. Lifecycle evidence cites the committed-root identity, snapshot/clone catalog
   entry, lifecycle pin, receive-base contract, and omitted-content dependency.
3. The planner treats the generation as cold/retained for placement and cost, but
   not as reclaimable capacity.
4. Reclaim, demotion, rebake, or relocation may only proceed when retained-root
   authority, replacement receipts, receive-base safety, and #880 layout
   frontiers all remain legal.
5. A bookmark-only anchor, missing base root, wrong lineage, stale pin, or missing
   omitted content makes receive/geo progress blocked or refused instead of
   silently weakening history.
6. Flash is not spent repeatedly reshaping this retained base unless policy and
   payback evidence justify it.

### COW Write Under Snapshot Pressure

1. A write replaces a range whose old generation is snapshot-pinned or
   clone-held.
2. Lifecycle evidence proves the old generation remains retained, so capacity
   admission must reserve old-plus-new overlap instead of assuming overwrite
   frees space.
3. The planner may pick a lower-amplification legal data shape, delay full
   placement, trigger safe reclaim, throttle, or return typed ENOSPC/quota/slop
   refusal.
4. It may not acknowledge a durability floor by betting that later snapshot
   deletion or pending-free reclaim will rescue the plan.

### Relocation Scratch Reserve Exhaustion

1. Defrag, compaction, promotion, or rebake looks profitable by latency, seek,
   write-amplification, or capacity payback.
2. Capacity evidence shows the relocation scratch class or protected
   repair/evacuation floor is exhausted.
3. The optimizer records `blocked`, `throttled`, or `refused` with the exact
   reserve reason and leaves current placement receipts authoritative.
4. Repair or evacuation may still escalate if policy grants critical reserve,
   but optional movement cannot borrow that floor.

### Tenant Bulk Scan Versus Sync WAL

1. Tenant A starts a large sequential scan or backup ingest that can fill device
   queues, transport windows, read cache, and dirty-byte budget.
2. Tenant B runs a small sync WAL workload with an explicit p99/fdatasync floor.
3. #902 isolation evidence names both budget owners, isolation scopes,
   fair-share windows, resource vectors, and the victim p99 floor.
4. The scheduler may donate unused share to Tenant A while Tenant B is idle, but
   the donation carries burst expiry and debt.
5. When Tenant B's queue time or p99 risk approaches the floor, Tenant A's scan
   is demoted, split, throttled, or refused before Tenant B's sync receipt is
   weakened.
6. Operator explanation reports the noisy-neighbor mitigation, borrowed budget
   debt, and any throughput left unused to protect the latency contract.

### Hot Small Read Set

1. Repeated small reads produce a high-confidence hot working set.
2. The scheduler may admit a cache-only RAM or flash serving trial first.
3. Operator explanation says whether the hit path is cache, serving trial, or
   authority.
4. Persistent flash serving promotion requires high confidence, dwell time,
   wear reservation, and payback proof.
5. If the serving role becomes authoritative RAM, it must use a RAM authority
   class and receipts.
6. If measured benefit misses the payback window, the trial expires and the
   skipped authority promotion is explained.

### Phase-Changing Sparse File

1. A large sparse file alternates between scan phases and random hot ranges.
2. The predictor records phase changes and lowers whole-file confidence.
3. The planner may tune prefetch, cache, or shape new writes by range.
4. It must not rebake the whole file or move durable placement after one phase.
5. Per-range relocation requires repeated confidence and its own payback
   window.
6. Conflicting phases produce cooldown or shadow plans rather than media churn.

### Failed Flash Promotion Payback

1. A range appears hot enough for flash serving promotion after repeated reads.
2. #845 prediction evidence records the observation window, sample mass, hint
   provenance, contradiction state, action class, and decision threshold.
3. The planner admits only a serving trial until wear, capacity, isolation, and
   payback gates are strong enough for persistent promotion.
4. After the trial, observed reads saved, p99 benefit, media writes spent,
   foreground harm, and tenant impact miss the payback window.
5. The outcome ref records failed payback; #844 keeps consumed wear and
   movement debt; #902 records any victim impact; #849 can explain the skipped
   authority promotion.
6. The next similar promotion for that subject, tenant, device, or rule starts
   with lower confidence, a cooldown, or shadow-only admission until fresh
   evidence materially changes the prediction.

### HDD Defrag

1. A rotational dataset shows high seek cost, fragmented range maps, and
   stable long-lived extents.
2. The relocation planner estimates scan and tail-latency improvement.
3. It rejects the move if foreground disruption or rewrite cost is too high.
4. If admitted, it writes replacement extents in seek-efficient order and
   publishes replacement receipts before retiring old locations.
5. The same trigger on SSD would not run unless write-amplification or
   metadata fan-out benefit justified the rewrite.

### Internet Geo-Async

1. The path evidence reports high RTT, jitter, and no RDMA assumption.
2. Trust evidence proves the remote peer, administrative domain, session
   security, key epoch, authorization, audit, and residency posture are legal
   for geo catch-up.
3. The dataset policy asks for local durable ack with remote RPO target.
4. The ack receipt is local/quorum durable plus `geo-async` lag, not
   `geo-intent`.
5. The geo catch-up lane batches, compresses, and prioritizes deltas under
   network cost and RPO budget.
6. If trust evidence becomes stale, revoked, wrong-domain, or unauthorized, the
   remote backlog becomes blocked or refused instead of silently using the
   path.
7. Capacity admission separately proves local backlog, transport queue, remote
   allocation, reserve escrow, and catch-up scratch headroom. If the backlog
   exceeds those reserves, RPO risk becomes visible instead of stealing repair
   space.
8. If the operator asks for `geo-intent`, the planner must pay the WAN latency
   before success or return a refusal.

### Cross-Tenant Dedup Refusal

1. Two tenants produce identical payload digests under different security or
   encryption domains.
2. Data-shape evidence may report a dedup opportunity, but trust evidence names
   incompatible tenant/security domains or key epochs.
3. The planner may still use compression, per-tenant cold placement, or
   same-domain sharing where legal.
4. It must not publish a shared placement receipt, refcount, or successor claim
   across the incompatible domains.
5. The operator explanation records the skipped sharing opportunity as a
   policy/security refusal, not as unexplained lost efficiency.

### Quorum Write During Node Drain

1. A dataset requests `quorum-intent` while one nearby peer is draining and
   another peer is witness-only.
2. Membership evidence from #750 names the committed epoch, quorum set,
   participant roles, failure-domain binding, and drain/fence state.
3. The planner may score the nearby draining peer as attractive for latency, but
   it cannot use that peer as data-bearing quorum evidence unless policy permits
   drain participation for this operation.
4. The witness may help the membership protocol if #750 defines that role, but
   it cannot satisfy a data-placement or durable-intent replica slot.
5. If no legal quorum remains, the write blocks, reroutes, returns a typed
   refusal, or receives an explicitly degraded receipt only when the compiled
   policy allows that result.
6. The ack receipt binds the epoch and quorum evidence it actually earned, so a
   later epoch change can be explained and reconciled without rewriting history.

### Degraded Read With Read Repair

1. A read loses one replica or EC shard but still has enough receipt-backed
   verified sources to reconstruct the requested bytes.
2. Recovery evidence cites the source receipt set, reconstruction width,
   payload/digest evidence, missing target, and degraded visibility policy.
3. The read may succeed only under a policy that permits the degraded-visible or
   reconstructed source class; otherwise it blocks, refreshes, or refuses.
4. Read repair needs #898 reserve evidence before it may publish replacement
   authority, and the replacement receipt becomes the proof of healed placement.
5. The operator explanation shows both the successful read source and the
   remaining repair/rebuild obligation.

### Partition Healing No-Quorum Refusal

1. A partition leaves one side with stale epoch evidence, no legal quorum, or a
   split-brain hazard.
2. Membership evidence blocks the side from earning quorum intent or full
   placement, even if the local media and network path look fast.
3. Recovery evidence records `no-quorum`, `partitioned`, `blocked`, or `refused`
   instead of letting the path return an ordinary durable success.
4. Healing requires a fresh epoch/fence frontier, source receipt comparison,
   ordering/replay closure, and any repair or rollback obligation before
   stronger satisfaction can be claimed.

### Rebuild Completion And Receipt Retirement

1. A rebuild or evacuation reconstructs data from receipt-backed sources and
   writes replacement placement.
2. Transfer success is not completion. The replacement receipt must be verified
   and published with ordering, trust, capacity, layout, lifecycle, and recovery
   evidence.
3. Old locators, old receipt targets, deadlist entries, and reclaim tickets may
   retire only after the retirement frontier proves no read, repair, receive,
   snapshot, or geo dependency still needs them.
4. If replacement receipt publication is missing or stale, satisfaction remains
   `blocked` or `unknown-evidence`; reclaim does not get to guess.

### Strengthen Quorum Policy With Existing Local-Intent Receipts

1. A dataset policy changes from local durable intent to quorum durable intent.
2. #901 rollout evidence publishes the target revision as
   `active-for-new-writes` and records old local-intent receipts as
   `converging-existing`, not upgraded.
3. New writes must earn quorum-intent receipts or fail according to policy.
4. Old generations remain readable under their historical receipts only where
   the compiled policy allows grandfathering or visible convergence.
5. Relocation or catch-up workers publish replacement quorum receipts before the
   reconciler may mark the old generations satisfied under the stronger
   revision.
6. Operator explanation shows mixed revision state, convergence frontier, and
   any range that is still protected only by the old local-intent receipt.

### Unsafe Downgrade Refusal

1. An operator or automation tries to weaken a dataset from `geo-intent` to
   `geo-async` or from durable to volatile without the required authorization.
2. Policy source compilation may describe the requested target, but #901 rollout
   evidence records missing downgrade authorization or audit refs.
3. The revision remains `refused`; no new receipt may cite the weaker revision
   as active.
4. Existing durable or geo receipts keep their historical promise and product
   claims cannot be rewritten to the weaker language.
5. The operator explanation reports the downgrade refusal instead of presenting
   the dataset as merely delayed or under-replicated.

### Rollback After Failed Policy Preflight Or Partial Stage

1. A new revision passes compilation but later fails preflight, validation,
   reserve admission, trust evidence, or an in-flight fsync/relocation fence.
2. #901 rollout evidence moves the revision to `rollback-required`, names the
   failed stage reason, and fences new work from ambiguous admission.
3. A rollback receipt restores future admission to the previous or superseding
   revision, but receipts already earned during the stage remain historical
   evidence.
4. Partially staged writes, geo backlog, repair, relocation, and receipt
   retirement either finish under their fenced revision or re-enter through an
   explicit rollback/re-entry ref.
5. Satisfaction remains `blocked`, `converging`, or `refused` until the rollback
   frontier proves no hidden mixed-revision obligation remains.

### RAM Pool

1. A scratch dataset requests `volatile-local` or `volatile-replicated`.
2. The planner uses RAM authority records, not cache records.
3. Receipts say exactly what is lost on process crash, node crash, peer loss,
   or power loss.
4. If the dataset later requests durable sync, it must transition to
   `ram-intent-backed` or refuse.

## RAM And In-Memory Pools

RAM appears in two very different forms:

- cache, which is never authoritative truth;
- explicit volatile authority, which is a product class with named loss
  semantics.

Legal RAM authority classes:

| Class | Evidence | Use |
| --- | --- | --- |
| `ram-volatile-local` | local volatile receipt | single-host scratch, tests, throwaway intermediate data |
| `ram-volatile-replicated` | fenced data-peer volatile receipts with membership epoch and quorum/failure-domain evidence | ultra-low-latency clustered scratch that survives one live-node failure but not power loss |
| `ram-intent-backed` | RAM serving plus durable local/quorum intent | low-latency reads/writes with replayable durability |
| `pmem-durable` | persistent-memory flush/fence evidence | durable low-latency intent or data role |

A RAM pool may be very fast and very useful, including over a cluster, but it
must not be described as a cache when it is authority, and must not be
described as durable unless the evidence survives the relevant crash/power
failure.

## Operator Explanation

Operators need a receipt explanation surface, not a pile of hidden heuristics.
The operator UAPI should eventually answer:

- What policy applies to this dataset/file/range?
- What is the current satisfaction state for that policy revision?
- Which evidence-query snapshot was used for the answer: query id, subject
  scope, consumer class, source-index generations, freshness frontier,
  completeness verdict, included evidence refs, redacted/compacted proof state,
  and missing/stale/refused evidence?
- Which policy revision is draft, staged, active, converging, rolled back,
  superseded, or refused, and what in-flight fence or convergence frontier
  controls old receipts?
- What ack class did the last write/fsync receive?
- Which ordering evidence satisfied the barrier: dirty epoch, intent sequence,
  replay idempotency key, dependency refs, and publication boundary?
- Which placement receipts currently satisfy policy?
- Which source class served a read, and which cache, trial, remote, stale, or
  degraded candidates were rejected?
- Which remote paths are behind, and by how much?
- Which membership epoch, roster, quorum set, witness/data role, and fence or
  drain state made a remote receipt legal or illegal?
- Which authenticated peer, admin/security/tenant domain, key epoch,
  authorization, audit, residency, or quarantine state made a remote, shared,
  repair, or geo candidate legal or illegal?
- Which data is intentionally volatile?
- Which data is pending relocation, rebake, repair, or geo catch-up?
- What data shape applies to this range, which transforms or EC/archive shape
  were selected, and which candidates were rejected or blocked?
- What metadata/namespace evidence applies: inode and directory identity,
  parent/child and link-count guards, directory index locality, xattr/ACL
  locality, small-object shape, namespace-intent receipt, fsyncdir dependency,
  metadata write amplification, stale lookup/cache projection, and metadata
  refusal state?
- What layout evidence applies: fragmentation, largest-run/free-run pressure,
  alignment, zone/write-pointer state, pending-free blockers, and reclaim debt?
- What lifecycle evidence applies: young/stable class, retained roots, snapshot
  or clone pins, receive-base dependencies, orphan/destroy state, and reclaim
  frontiers?
- Which logical quota, physical allocation class, allocation ticket,
  dirty-window, reserve-escrow, protected-floor, pending-free, and typed ENOSPC
  evidence made an operation admitted, blocked, throttled, degraded, or refused?
- Which recovery evidence applies: source receipt set, reconstruction width,
  missing/corrupt/stale targets, no-quorum or partition state, repair/rebuild
  obligation, replacement receipt publication, old-receipt retirement frontier,
  RPO/RTO lag, and typed recovery refusal?
- Which tenant, dataset, workload class, policy owner, or internal-maintenance
  reason owns the budget, which isolation scope was protected, and which
  fair-share, burst, borrow, debt, starvation, noisy-neighbor, reserve-exemption,
  throttle, or refusal evidence shaped admission?
- How much flash endurance did this dataset consume?
- Which relocation jobs were skipped because the wear or foreground-latency
  budget was not worth spending?
- Which predictions are in shadow, serving-trial, admitted-move, cooldown, or
  failed-payback state, and which decision/outcome refs changed confidence?
- Which service objective applies to this operation or range: workload phase,
  operation mix, latency percentiles, tail/jitter, throughput, concurrency,
  queueing, RPO/RTO, topology/media profile, budget refs, and objective refusal
  state?
- Which timebase, clock-health, skew/uncertainty, event frontier, lag,
  staleness, expiry, deadline, or sequence-only evidence made an age-based
  decision legal, degraded, unknown, blocked, or refused?
- Which media capability evidence made this target eligible or ineligible:
  persistence domain, flush/FUA behavior, volatile-cache policy, atomicity,
  namespace identity, protocol/geometry, health, capability generation, and
  refusal reason?
- Which decision frontier was evaluated: candidate set, hard-gate rejection
  reasons, score vector, selected candidate, tie-breaker, counterfactual
  baseline, unknown-cost dimensions, payback window, and deferred/refused
  candidates?
- Which action-execution state applies: action id, selected decision ref,
  admitted/prepared/copying/verifying/publishing/cutover state, idempotency key,
  source protection, target verification, abort/rollback state, and completion
  or refusal reason?
- Which measurement-attribution verdict applies: measurement id, workload and
  environment scope, sample window, baseline/counterfactual lineage, metric/KPI
  deltas, confounder state, transfer scope, and allowed or refused uses?
- Which evidence is retained exactly, summarized, redacted, tombstoned, or
  purgeable, and which receipt, decision, cooldown, recovery, rollout,
  validation, claim, audit, or operator-explanation dependency controls that
  retention state?
- Which result/refusal was returned to the caller: request token, operation and
  surface class, earned receipt or failed gate, degraded-visible state,
  response-registry scope/truth-cut/render/refusal class, retryability, errno or
  API projection, delivery/index refs, and retention/audit proof?
- Which critical wear, capacity, or transport reserves are protecting sync,
  repair, evacuation, or geo catch-up work?
- Which guarantee would be lost if a device, node, rack, or site failed now?

This explanation must be based on receipts, #913 query snapshots, and current
evidence, not on topology recomputation or UI-local cache state alone.

## Performance And Cost Gates

Storage intent requires performance rows that include more than throughput.
Initial row families should cover:

- small sync local intent latency;
- small sync quorum intent latency;
- barrier/order/replay latency for fsync, fdatasync, O_DSYNC/FUA,
  `msync(MS_SYNC)`, syncfs, and directory fsync scopes;
- quorum and geo latency while membership epochs advance, nodes drain, peers are
  fenced, or witnesses are present;
- remote and geo latency while trust epochs, key epochs, authorization/audit
  refs, or residency policy change;
- policy revision rollout behavior for dry-run, preflight, staged,
  active-for-new-writes, converging-existing, rollback, supersession, and
  unsafe downgrade refusal while old and new receipts coexist;
- tenant/workload isolation rows for sync latency protected from bulk ingest,
  one-pass scans, serving trials, rebuild, relocation, and geo catch-up under
  mixed-owner pressure;
- full-placement fsync latency;
- VM FUA/barrier tail latency;
- metadata storm p99, fsyncdir latency, rename/link/unlink/xattr tail, hot
  directory/index locality, small-file inline or packed shape, and metadata
  write-amplification under policy;
- read-serving source latency and stale/refresh/refusal rate by source class;
- degraded read reconstruction latency and repair-on-read foreground cost;
- recovery/degradation behavior for no-quorum refusal, partition healing,
  repair/rebuild obligation, replacement receipt publication, receipt
  retirement, and geo/archive lag under policy;
- streaming ingest throughput without flash wear explosion;
- data-shape selection for record size, compression, checksum/digest, dedup,
  encryption, EC/archive shape, and coalescing under latency and cost floors;
- allocator/layout evidence for fragmentation, free-run scarcity, locality,
  alignment, zone/write-pointer constraints, pending-free safety, and reclaim
  debt;
- capacity/admission evidence for logical quota, physical allocation class,
  allocation-ticket freshness, dirty-window reserve, protected floors,
  old-plus-new COW amplification, relocation scratch, geo backlog reserve, and
  typed ENOSPC/refusal rates;
- lifecycle-aware placement for young churn, stable-hot promotion,
  snapshot/clone/receive-base retention, orphan-held bytes, and dead-pending
  reclaim;
- one-pass scan cache behavior without persistent flash promotion;
- hot read promotion benefit/cost;
- serving-trial payback and cooldown behavior;
- prediction-accountability rows proving missing outcome evidence, failed
  payback, tenant harm, or excessive wear lowers future confidence instead of
  becoming hidden success;
- signal-materialization rows proving access-pattern observation, derived
  views, predictor checkpoints, and operator telemetry stay bounded, rate
  limited, budget-owned, and charged for CPU, memory, evidence bytes, metadata
  writes, and flash wear instead of becoming hidden write amplification;
- temporal rows proving RPO lag, stale-read age, TTL/lifecycle windows,
  lease/key expiry, rollout deadlines, cooldowns, and payback windows cite
  clock-health, skew, frontier, or sequence-only evidence;
- media-capability rows proving sync intent, PMem durability, block-volume
  FUA/flush, ZNS/SMR placement, and remote durable target claims cite
  persistence-domain, flush/FUA, atomicity, namespace, health, and stale-probe
  evidence;
- service-objective rows proving workload phase, operation mix, latency
  percentiles, tail/jitter, throughput, burst/dwell, concurrency, queueing,
  topology/media/environment scope, degradation/RPO/RTO, isolation, cost, wear,
  attribution, query snapshot, and refusal state are compiled before planners,
  schedulers, performance rows, or claims treat a path as fast enough;
- result/refusal rows proving success, degraded-visible success, throttle,
  block, refusal, retry conflict, errno/block/API compression, delivery/index
  retention, and operator/trace projection preserve #920 evidence and
  response-registry truth instead of generic status;
- metadata/namespace rows proving namespace intent, fsyncdir, rename/link/
  unlink, xattr/ACL, directory-index, lookup/readdir, small-object shape,
  metadata locality, and metadata wear decisions cite #922 evidence before
  being treated as fast, durable, low-wear, or claim-worthy;
- decision-frontier rows proving candidate sets, hard-gate rejects, score
  vectors, deterministic tie-breakers, selected plans, unknown-cost handling,
  counterfactual baselines, and payback anchors are preserved for planner,
  read-serving, rebake, relocation, and scheduler decisions;
- action-execution rows proving admitted actions preserve idempotency, source
  protection, target verification, cutover/publication, abort/rollback,
  source-retirement, and outcome/budget evidence across retries and crashes;
- measurement-attribution rows proving outcome metrics bind to policy revision,
  workload envelope, environment/noise profile, sample window, decision/action
  lineage, comparator/counterfactual, confounder state, attribution verdict, and
  allowed-use/refusal state before learning, payback, movement, wear spend, or
  claims consume them;
- evidence-query rows proving planners, reconcilers, read-serving paths,
  actions, measurement attribution, explanations, performance gates, fault rows,
  and claims use bounded #913 snapshots with source-index generations,
  freshness frontiers, completeness verdicts, redaction/compaction state, and
  typed query refusals instead of unbounded live scans or stale local indexes;
- evidence-retention rows proving exact evidence, summaries, redaction,
  proof roots, tombstones, purge frontiers, retention-media placement, metadata
  budgets, and claim/audit holds preserve receipt, decision, recovery, rollout,
  cooldown, explanation, validation, and claim proof without unbounded metadata
  growth or avoidable flash wear;
- phase-changing sparse workload anti-thrash behavior;
- HDD defrag benefit under seek-heavy and scan-heavy workloads;
- SSD relocation write-amplification benefit/cost;
- rebake payback for compression, dedup, record sizing, checksum/digest, EC, and
  archive conversion, including CPU, read amplification, and degraded-read cost;
- rebuild/repair foreground protection;
- geo-async RPO lag under WAN and internet envelopes;
- geo-intent latency under the same path envelopes;
- RAM volatile and RAM intent-backed latency;
- media wear per TiB of logical writes.

Each row must bind:

- requested and earned ack classes;
- service-objective id, workload phase, operation mix, latency/tail and
  throughput envelope, concurrency/queueing profile, degradation/RPO/RTO ties,
  topology/media/environment scope, and objective refusal state;
- reconciled satisfaction state before and after the measured action;
- policy rollout evidence, including source refs, change class, stage state,
  publication transaction, in-flight fence, convergence frontier, rollback or
  supersession refs, and downgrade refusal where relevant;
- isolation evidence, including budget owner, tenant/domain refs, isolation
  scope, fair-share window, resource vector, burst/borrow/debt state,
  starvation state, noisy-neighbor harm, reserve-exemption, and throttle/refusal
  reason where relevant;
- ordering evidence for barrier scope, dirty epoch, dependency closure, replay
  idempotency, intent sequence, and publication boundary;
- membership epoch, quorum-set, participant-role, drain/fence, and
  failure-domain evidence where remote or clustered receipts participate;
- trust/security-domain, session-security, key-epoch, authorization/audit,
  residency, sharing-domain, and quarantine evidence where remote, shared,
  encrypted, repair, or geo receipts participate;
- workload envelope and prediction confidence/action class;
- decision-frontier evidence, including candidate set, rejected/deferred/unknown
  candidates, hard-gate refs, score vector, selected plan, tie-breaker,
  counterfactual baseline, and payback/harm anchor where relevant;
- action-execution evidence, including action id, step state, idempotency/replay
  proof, source protection, target verification, publication/cutover boundary,
  abort/rollback state, source-retirement state, and execution refusal where
  relevant;
- measurement-attribution evidence, including measurement id, sample window,
  warmup/censor/drop policy, workload/environment/noise binding,
  baseline/counterfactual lineage, metric/KPI vectors, confounder state,
  attribution verdict, transfer scope, and allowed/refused uses where relevant;
- evidence-query snapshot evidence, including query id, consumer class, subject
  scope, policy revision, source-index generations, included evidence refs,
  freshness frontier, completeness verdict, redaction/compaction state, replay
  anchor, and query refusal reason where relevant;
- evidence-retention evidence, including retention class, dependent receipts or
  decisions, proof root, compaction rule, safe purge frontier, summary fidelity,
  retention-media class, redaction state, and retention refusal where relevant;
- result/refusal evidence, including result id, request/idempotency token,
  caller/surface class, earned receipt or failed hard gate, degraded-visible
  state, response-registry scope/truth-cut/render/refusal class, retryability,
  errno/block/API/trace projection, delivery/index refs, and retention/audit
  state where relevant;
- metadata/namespace evidence, including operation class, inode/directory
  identity, parent/child relation, link-count/cookie/generation guards,
  namespace-intent receipt, fsyncdir dependency, directory/xattr/ACL locality,
  small-object shape, lookup/cache projection, metadata wear, and metadata
  refusal state where relevant;
- environment/profile, including media and topology;
- media capability evidence, including persistence domain, flush/FUA/barrier
  semantics, atomicity/granularity, namespace identity, volatile-cache policy,
  protocol/geometry, health/freshness, and refusal reason where relevant;
- p50/p95/p99 latency;
- throughput;
- foreground disruption;
- write amplification and flash wear;
- data-shape evidence, CPU cost, read amplification, and transform refusal state
  where relevant;
- allocator/layout evidence, fragmentation score, free-run pressure, alignment,
  pending-free safety, and reclaim debt where relevant;
- capacity/admission evidence, reserve class, ticket generation, pending-free
  frontier, capacity amplification, protected-floor state, and typed refusal
  reason where relevant;
- recovery/degradation evidence, source receipt set, reconstruction width,
  target health, repair/rebuild obligation, replacement receipt, retirement
  frontier, no-quorum/partition state, RPO/RTO lag, and recovery refusal reason
  where relevant;
- lifecycle evidence, retained-root refs, receive-base safety, orphan/destroy
  state, and reclaim-frontier refs where relevant;
- movement debt, payback window, cooldown state, and skipped-move reason where
  relevant;
- capacity and network cost where relevant;
- comparator set and accepted attribution verdict when making ZFS/Ceph/DRBD
  comparisons.

No performance claim should close merely because average throughput improved.
No storage-intent performance row should be treated as more than exploratory
telemetry when it lacks a #915 service-objective envelope for the measured
workload, operation, policy revision, and environment.
No row may treat a compact errno, block completion, timeout, API status, or
trace status as the complete result when #920 evidence is missing, stale,
contradictory, unindexed, or refused.
No adaptive-placement, relocation-payback, wear-savings, RAM-latency,
WAN/internet, or incumbent-comparator claim should close from confounded,
stale, insufficient, contradicted, or refused attribution evidence, or from a
missing, stale, not-complete-for-purpose, mixed-policy, or refused evidence-query
snapshot.

## Fault And Validation Matrix

Performance rows are necessary, but they do not prove storage intent. A fast
acknowledgment is meaningful only when the same requested intent, earned
receipt, placement state, and operator explanation survive the faults that the
ack class claims to cover. Storage-intent validation therefore needs a dedicated
matrix, tracked by #863, that binds policy promises to destructive evidence.

The matrix must cover at least these row families:

- kill-before-ack and crash-after-ack for every acknowledgment class, from
  `volatile-local` through `geo-intent`;
- ordering faults such as unsealed dirty epoch, wrong barrier sequence,
  wrong-root intent, wrong-range replay, non-idempotent replay, incomplete
  namespace dependency, lost writeback error, and transaction marker without
  replayable bytes;
- metadata/namespace faults such as stale inode generation accepted, wrong
  parent or link-count guard ignored, rename conflict hidden, directory fsync
  reported from data-only receipt, xattr/ACL mutation omitted from replay,
  unstable readdir cookie accepted, stale lookup/cache projection treated as
  authority, unsafe small-file repack, metadata reserve exhaustion hidden, and
  metadata-hot role claimed from cache-only state;
- transport partition, latency stretch, bandwidth clamp, packet loss, and
  RDMA-absent TCP/internet paths for quorum and geo modes;
- membership faults such as stale epoch, future epoch, forked roster,
  split-brain hazard, wrong quorum set, fenced peer accepted, draining peer
  counted without policy, witness-only participant counted as data, and
  topology/failure-domain drift;
- trust/security faults such as missing required session security, stale trust
  epoch, revoked or quarantined admin domain, wrong tenant/security domain,
  stale or revoked key epoch, missing authorization/audit evidence, regulatory
  residency violation, cross-domain dedup acceptance, and compromised repair
  source accepted as authority;
- media corruption, flush omission, stale copy, truncation, bit flip, zeroed
  range, device loss, and endurance-reserve exhaustion;
- media capability faults such as unknown persistence accepted as durable,
  unsupported or ignored FUA accepted as success, unsafe volatile write cache
  accepted for sync intent, stale namespace identity accepted after reattach,
  stale capability probe accepted after firmware/settings change, wrong atomic
  write granularity accepted for replay, and ZNS/SMR random-incompatible target
  accepted as ordinary placement;
- decision-frontier faults such as illegal candidates reaching scoring,
  winner-only records accepted for authority-changing movement, stale score
  vector accepted after policy/evidence change, unknown cost treated as zero,
  nondeterministic tie-breaker accepted, rejected candidate reasons discarded,
  and failed payback attached to no original decision;
- workload/signal faults such as unbounded per-file tracking admitted,
  telemetry writes hidden from wear accounting, signal persistence consuming
  protected sync or repair reserve, memory-only sketches treated as durable
  historical proof, sampled-away evidence inflated into high confidence,
  dropped predictor checkpoints hidden from explanation, and observability
  overhead omitted from performance or attribution rows;
- action-execution faults such as target write treated as cutover, crash after
  copy before verification, crash after replacement publication before source
  retirement, duplicate retry double-spending reserves, stale action continuing
  after policy/media/capacity change, rollback source deleted early, partial
  target served as authoritative, and aborted work hidden from operators;
- measurement-attribution faults such as confounded metrics accepted as payback,
  insufficient samples treated as confidence gain, stale baseline accepted for a
  changed policy revision, workload phase change hidden during learning,
  unrelated cache warmup credited to relocation, tenant interference training
  another tenant's predictor, WAN jitter credited to geo policy, thermal/device
  throttling omitted from attribution, and comparator claims made from
  no-valid-baseline measurements;
- evidence-query faults such as no query snapshot accepted as authority, stale
  source index accepted as fresh, partial cut treated as complete, contradictory
  cut hidden, mixed-policy or mixed-epoch evidence merged, over-broad query
  allowed to satisfy a narrow consumer, compacted proof accepted without
  completeness, redaction erasing a required predicate, unauthorized evidence
  included, unavailable producer hidden, and refused query treated as success;
- service-objective faults such as no objective accepted as a performance
  contract, p99 success inferred from average latency, throughput success hiding
  protected queue-time failure, workload phase swapped under the same envelope,
  RAM-latency claim made from cache-only evidence, WAN/internet objective tested
  only on local transport, comparator claim made without objective/baseline
  scope, objective satisfied from a stale #913 cut, and degraded/refused
  objective hidden behind a successful ack receipt;
- result/refusal faults such as no #920 result evidence accepted as a complete
  caller outcome, no-quorum collapsed to generic `EIO`, stale #913 query
  collapsed to timeout, degraded read returned as exact, service-objective
  failure hidden behind success, unsupported media or wrong trust domain hidden
  behind retry, unsafe volatile downgrade rendered as durable success,
  idempotent retry conflict redelivered as a second success, unsupported surface
  render accepted, and delivery/index/retention gap hidden from explanation;
- evidence-retention faults such as exact receipt proof compacted while live,
  decision frontier purged before outcome/cooldown closure, refused/unknown
  candidates dropped from summaries, claim artifact evidence deleted before
  claim retirement, policy-rollout mixed-revision proof compacted too early,
  proof root lost after exact evidence deletion, stale safe-purge frontier
  trusted after rollback, redaction erasing required predicates, optional
  telemetry evicting replay-critical proof, and cleanup write amplification
  starving foreground sync or repair reserves;
- RAM authority failure cases proving volatile receipts never satisfy durable
  POSIX barriers;
- cache and serving-trial failures proving non-authoritative hot copies never
  satisfy placement or durable ack receipts;
- prediction-accountability faults such as hint-only confidence accepted as
  authority movement, missing outcome evidence treated as success, failed
  payback retried without cooldown, one tenant manufacturing another tenant's
  movement confidence, and contradiction state ignored during admission;
- temporal faults such as unknown clock skew accepted as fresh, backwards time
  accepted as progress, stale clock-health samples accepted for RPO, sequence
  lag reported as wall-clock lag without conversion evidence, expired key or
  authorization windows accepted, crossed rollout deadlines ignored, and TTL
  expiry treated as reclaim authority without lifecycle/receipt evidence;
- stale cache, stale snapshot generation, geo-async lag, and degraded-read
  cases proving read-serving choices obey freshness and receipt evidence;
- recovery/degradation faults such as no-quorum success, stale source receipt
  accepted for repair, under-width EC reconstruction served as exact, corrupt
  repair source accepted, old epoch accepted after partition healing, fenced or
  draining peer counted as data, quarantined or wrong-domain repair source
  accepted, read repair without reserve, replacement receipt missing at
  old-receipt retirement, geo/archive lag exceeding policy, and degraded state
  hidden from caller/operator;
- transform and data-shape faults such as wrong key epoch, illegal dedup domain,
  malformed compression frame, digest-suite mismatch, EC under-width
  reconstruction, and mounted transform block/refusal state;
- allocator/layout faults such as stale mirror-only free-run evidence,
  wrong-generation segment evidence, pending-free reuse before fence,
  zone/write-pointer incompatibility, under-aligned block-volume placement, and
  ENOSPC or reserve exhaustion;
- capacity/admission faults such as quota exhaustion hidden as success, stale or
  expired allocation ticket, expired reserve escrow, dirty-window overcommit,
  protected sync/repair/evacuation floor borrowed by an optimizer, old-plus-new
  COW overlap omitted under snapshot pressure, relocation scratch under-reserve,
  geo backlog reserve overflow, and pending-free bytes counted before lifecycle
  and receipt safety;
- lifecycle/generation faults such as missing data-retaining snapshot or clone
  pins, bookmark-only receive bases, stale committed-root identity, orphan-held
  bytes reclaimed early, destroy/tombstone admission leaks, and omitted-content
  dependencies missing during receive or geo catch-up;
- relocation, defrag, rebake, rebuild, evacuation, and geo catch-up interrupted
  before and after replacement receipt publication;
- relocation anti-thrash cases proving cooldown, movement debt, and failed
  payback cannot hide reserve erosion or stale placement;
- policy rollout faults such as stale policy source accepted as active,
  publication transaction missing, conflicting override accepted, downgrade
  without authorization, active revision superseded during admission, in-flight
  fsync crossing a revision fence, relocation or receipt retirement crossing
  without re-entry, rollback receipt missing after partial stage, convergence
  frontier skipped, and mixed-revision state hidden from explanation.
- isolation faults such as unowned work admitted, wrong tenant charged,
  per-dataset memory budget bypassed, illegal burst borrowing from protected
  sync/repair reserve, background relocation destroying foreground p99,
  starvation override becoming unbounded, noisy-neighbor victim omitted,
  internet geo catch-up exceeding tenant egress budget, repair reserve exemption
  hidden, stale pressure evidence accepted, and throttle/refusal omitted from
  explanation.

Every row must name the requested policy revision, #915 service-objective
envelope, workload envelope, topology/media profile, temporal/timebase profile,
evidence-query snapshot and completeness verdict, fault schedule, earned receipt
set, post-recovery receipt obligations, and forbidden outcomes.
Forbidden outcomes include durable success without required receipt evidence,
hidden downgrade from durable to volatile or from `geo-intent` to `geo-async`,
split-brain receipt publication, old locator retirement before replacement
receipt publication, old receipts rewritten by policy change, hidden downgrade
during policy rollout, mixed-revision receipt sets reported as fully converged,
reserve/wear breach hidden behind successful relocation, budget-owner or
noisy-neighbor harm hidden behind aggregate throughput, isolation debt erased,
protected reserve borrowed without exemption, wall-clock freshness claimed from
unknown-skew or sequence-only evidence, stale or wrong-domain data-shape
evidence accepted as satisfied, allocator mirror evidence accepted as
authority, stale lifecycle evidence accepted as retained/reclaimable,
bookmark-only anchors treated as data-retaining, pending-free bytes reused too
early, false payback or adaptive confidence from refused attribution evidence,
comparator superiority from no-valid-baseline measurements, hard-gate,
performance, or claim success from a missing/stale/refused #913 snapshot,
mixed-policy evidence cut, or partial evidence cut treated as complete, result
success from missing/stale/refused #920 evidence, generic status replacing a
typed result/refusal, and explanations that omit degradation, lag/timebase,
volatility, trust-domain refusal, recovery obligation, replacement receipt blocker,
metadata namespace conflict, fsyncdir dependency, stale lookup/cache projection,
small-object shape blocker, metadata wear or reserve refusal,
transform block state, capacity/reserve refusal, policy rollout stage,
in-flight fence, convergence frontier, isolation scope, borrow/debt state,
lifecycle or layout blockers, evidence-query cut/refusal, attribution refusal,
result/refusal projection, retryability, delivery/index blocker, or refusal.

The validation matrix cross-links with #850 where a scenario also has latency,
tail, throughput, RPO, or wear/cost budgets. #850 measures whether TideFS is
fast enough under a declared envelope; #863 proves that the envelope remains
honest when the system is broken on purpose.

#875 owns the claim-registry boundary for these promises. Performance and fault
rows can generate evidence, but publishing-facing wording about fast durable
sync, WAN/internet geo behavior, RAM authority, flash-wear protection,
adaptive prediction/placement, or OpenZFS/Ceph/DRBD successor comparisons must
still map to stable planned, blocked, or validated claim ids before it can
become product language.

## Relationship To Existing Authority

This document composes existing authority surfaces:

- `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`: page cache is not durable truth;
  fsync may be satisfied only by committed storage, durable replayable intent,
  or a future equivalent receipt authority.
- `docs/INTENT_LOG_SYNC_WRITE_LATENCY_PC008.md`: bounded sync replies require
  durable replayable intent or full commit.
- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`: placement receipts are durable
  locator authority and must drive reads, rebuild, and reclaim.
- `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md`: pool-wide placement and
  failure-domain policy are receipt-backed.
- `docs/SCRUB_REPAIR_RESILVER_DESIGN.md`,
  `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`, and
  `docs/CROSS_REPLICA_SCRUB_COMPARISON_DESIGN.md`: scrub, repair, resilver,
  rebuild, anti-entropy, and movement material inform #900, but storage intent
  consumes typed recovery/degradation refs instead of originating a parallel
  repair or rebuild runtime.
- `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`: mounted
  device-level compression and encryption remain blocked until mounted content,
  scrub, repair, recovery, and raw-store paths use one transform-aware authority.
- `docs/BLAKE3_USAGE_POLICY.md`: BLAKE3 is the durable content-addressing and
  integrity digest, not a generic hot-path hash or duplicate transport checksum.
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`: checksum architecture remains
  historical target input unless live source, validation, and claims evidence
  prove a narrower current behavior.
- `docs/LOCAL_SNAPSHOTS_OW108.md` and `docs/SEND_RECEIVE_OW109.md`: scoped
  local snapshot and send/receive authority inform #881, including their
  still-open placement, reclaim, deadlist, distributed replication, and
  incremental-resume gaps.
- `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`,
  `docs/RECEIVE_STREAM_MERGE_POLICY.md`, and
  `docs/DATASET_LIFECYCLE_DESIGN.md`: deadlist, receive-base, and dataset
  lifecycle material inform #881, but historical or issue-scoped wording is not
  broad storage-intent lifecycle authority until live source, issue, and claim
  authority say so.
- `docs/SPACEMAP_ALLOCATOR_DESIGN.md`,
  `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`,
  `docs/LOCAL_STORAGE_ALLOCATOR_OW102.md`,
  `docs/ALLOCATOR_RECLAIM_FREE_SPACE_SCHEMA_FAMILY_P2-02.md`, and
  `docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md`: allocator, space accounting,
  segment, reclaim, and object-store material inform #880, but historical or
  unclassified design wording is not current storage-intent evidence until live
  source, issue, and claim authority say so.
- `docs/DEVICE_LAYOUT_POLICIES_DESIGN.md` and
  `docs/design/device-layout-policies-adaptive-segment-sizing.md`: media class
  and device segment sizing are placement inputs; storage intent owns the
  workload-facing record/extent/stripe shape policy that uses those inputs.
- Dataset property and mount-profile authorities are policy sources. Storage
  intent owns the compiled cross-source policy snapshot consumed by ack,
  placement, relocation, and explanation paths; it does not replace the
  source-specific property registries.
- #894 owns the storage-intent ordering-evidence slice for barrier scope,
  dependency closure, dirty epochs, replay idempotency, intent sequence, and
  publication boundary. It composes page-cache/writeback, intent-log, recovery,
  and distributed receipt evidence without replacing those runtime owners.
- #922 owns the storage-intent metadata/namespace evidence slice for metadata
  operation scope, VFS/namespace authority refs, namespace intent, fsyncdir,
  metadata locality, directory/xattr/ACL locality, small-object shape, metadata
  write amplification, and typed metadata refusal. It composes
  `docs/VFS_ENGINE_API_CONTRACT.md`, `docs/INODE_NAMESPACE_AUTHORITY.md`,
  #688 namespace revision work, #894 ordering, #842 ack receipts, #878 data
  shape, #920 result/refusal, and cost/wear evidence without replacing VFS
  semantics, inode identity authority, adapter caches, or response grammar.
- #750 owns the membership authority decision for epoch identity, quorum-write
  dispatch, witness-set role, join/drain lifecycle, and epoch/fence enforcement;
  storage intent consumes those evidence refs and must not originate a parallel
  membership authority.
- #897 owns the storage-intent trust/domain evidence slice for authenticated
  identity, admin/security/tenant domain, session-security posture, key epoch,
  authorization/audit refs, residency, sharing-domain compatibility, and
  compromise/quarantine refusal. It composes security, authz, transport, and
  transform evidence without replacing those owners.
- #900 owns the storage-intent recovery/degradation evidence slice for source
  receipts, reconstruction width, target health, repair/rebuild obligation,
  replacement receipt publication, old-receipt retirement, partition healing,
  RPO/RTO lag, and hidden-downgrade refusal. It composes placement receipt,
  scrub/repair/rebuild, membership, trust, ordering, capacity, layout, lifecycle,
  and data-shape evidence without replacing those owners.
- #901 owns the storage-intent policy-rollout evidence slice for source policy
  refs, compiled revision publication, change class, downgrade authorization,
  stage state, in-flight fences, convergence frontiers, rollback/re-entry,
  supersession, and typed rollout refusal. It composes #855 policy sources,
  authz/audit refs, operator runbook state, #874 satisfaction, and receipt
  evidence without replacing those owners.
- #902 owns the storage-intent tenant/budget/noisy-neighbor isolation evidence
  slice for budget-owner identity, isolation scope, fair-share windows, burst
  borrowing, debt, starvation, noisy-neighbor harm, reserve exemptions, and typed
  throttle/refusal state. It composes #897 trust/tenant-domain refs, #862 lane
  evidence, #893 per-dataset memory accounting, #856 cost, #898 capacity, #844
  wear, #846/#891 transport pressure, #850 performance, and #863 fault evidence
  without replacing those owners.
- #845 owns the workload/prediction evidence slice for bounded observations,
  confidence provenance, contradiction state, action classes, decision refs,
  outcome windows, payback verdicts, confidence updates, cooldowns, and
  anti-thrash state. It composes lifecycle, layout, path, wear, cost, scheduler,
  tenant, measurement-attribution, performance, and fault evidence without
  choosing placement, executing relocation, or publishing receipts.
- #903 owns the storage-intent temporal evidence slice for timebase identity,
  clock health, skew/uncertainty, evidence age, event/frontier stamps,
  lag/staleness, expiry/deadline, sequence-to-time conversion, and temporal
  refusal state. It composes membership, ordering, trust/key, rollout,
  lifecycle, prediction, transport, recovery, performance, and fault evidence
  without implementing clock synchronization, issuing leases, or replacing
  membership epochs.
- #904 owns the storage-intent media capability evidence slice for device and
  namespace identity, persistence domain, flush/FUA/barrier semantics,
  volatile-cache policy, atomicity/granularity, protocol/geometry capability,
  health/freshness, role eligibility, and media-capability refusal state. It
  composes local block/media facts, RAM/PMem authority, layout, wear, ack
  receipts, placement, recovery, performance, and fault evidence without
  probing devices, accounting wear, choosing placement, or emitting receipts.
- #905 owns the storage-intent decision-frontier evidence slice for decision
  identity, candidate sets, hard-gate results, score vectors, selected
  candidates, tie-breakers, reserve/admission refs, counterfactual baselines,
  payback/harm anchors, and refusal/defer state. It composes policy,
  service-objective, prediction, capacity, cost, wear, temporal,
  media-capability, layout, lifecycle, recovery, scheduling, placement,
  relocation, performance, fault, and explanation evidence without choosing
  placement or executing movement.
- #915 owns the storage-intent service-objective evidence slice for objective
  identity, policy/workload/operation scope, latency percentile and tail/jitter
  envelopes, throughput/burst/dwell/concurrency/queueing profiles,
  degradation/RPO/RTO ties, topology/media/environment scope, budget/cost/wear
  refs, comparator/claim refs, and typed objective refusal. It composes #845
  workload evidence, #862 admission, #902 isolation, #898 capacity, #904 media
  capability, #905 decision-frontier, #911 action-execution, #912 attribution,
  #913 query snapshots, #910 retention, #850 performance, #863 fault, and #875
  claims without running benchmarks, scheduling lanes, choosing placement, or
  deciding product language.
- #911 owns the storage-intent action-execution evidence slice for action
  identity, selected decision refs, admission refs, step state, idempotency and
  replay proof, source protection, target verification, publication/cutover,
  abort/rollback, outcome/budget accounting, and execution refusal state. It
  composes #905 decisions, #898 reserves, #902 isolation, #904 media capability,
  #900 recovery/degradation, #901 rollout, #910 retention, ordering receipts,
  read-serving, relocation, rebake, repair, performance, and fault evidence
  without choosing candidates, scheduling lanes, or implementing workers.
- #912 owns the storage-intent measurement-attribution evidence slice for
  measurement identity, subject scope, policy/workload/environment binding,
  sample windows, baseline/counterfactual lineage, decision/action/admission
  refs, metric/KPI/cost/wear vectors, confounder state, attribution verdicts,
  transfer scope, and allowed-use/refusal state. It composes #845 prediction,
  #905 decision-frontier, #911 action-execution, #915 service objectives, #850
  performance, #863 fault, #875 claims, #910 retention, and
  operator-explanation evidence without running benchmarks, training predictors,
  executing actions, or deciding claims.
- #910 owns the storage-intent evidence-retention slice for evidence identity,
  dependency graphs, retention classes, proof roots, compaction/summarization
  rules, safe purge frontiers, retention media/cost/privacy envelopes, and
  retention refusal state. It composes temporal, lifecycle, claims, recovery,
  rollout, prediction, decision-frontier, measurement-attribution, performance,
  fault, operator explanation, read-serving, relocation, and cleanup evidence
  without reclaiming stored data, expiring time, or deciding product claims.
- #913 owns the storage-intent evidence-query snapshot slice for query identity,
  consumer class, subject/policy scope, source-index generations, temporal and
  freshness frontiers, included evidence refs, completeness verdicts,
  replay/audit anchors, and query refusal state. It composes the underlying
  evidence producers plus #910 retention state without producing that evidence,
  choosing placement, executing actions, running measurements, explaining UI
  answers, validating faults, or deciding claims.
- #920 owns the storage-intent result/refusal evidence slice for caller-visible
  result identity, request/idempotency token, operation and surface class,
  policy/query/decision refs, earned receipt or failed hard-gate refs,
  degraded-visible state, response-registry projection, POSIX/block/API/trace
  compression, retryability, delivery/index refs, and retention/audit proof. It
  composes #842 ack receipts, #877 read serving, #862 scheduling, #843
  placement, #848 relocation, #911 actions, #915 service objectives, #913 query
  snapshots, #910 retention, and the current response/refusal runtime successor
  to the historical response-registry input without replacing adapters,
  inventing errno authority, or rendering a second response grammar.
- `docs/security/transport-security-boundary.md`: transport security is
  session-level. Storage intent may require and cite session-security evidence,
  but it must not reintroduce per-message crypto proof markers.
- `docs/security/pool-encryption-secret-handle-boundary.md`: key access flows
  through secret handles and time-bounded leases. Storage intent consumes key
  epoch and lifecycle refs for encrypted placement, repair, read serving, and
  rebake; it does not issue leases.
- `docs/security/operator-authz-boundary.md`: privileged remote and
  cross-domain operations remain behind the operator authorization/audit
  boundary. Storage intent consumes authorization/audit refs when policy
  requires them.
- `docs/security/unified-storage-encryption-threat-model.md`: security claims
  remain limited by their product-path evidence. Storage intent must preserve
  those non-claims when compiling remote, encrypted, or cross-domain policy.
- `docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md`: scoped current spec
  for deterministic quorum-set identity; it is input to #750 and storage-intent
  membership evidence, not a full membership service claim.
- `docs/MEMBERSHIP_SERVICE_DESIGN.md` and
  `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`: historical input
  for #750; useful for semantics, but not broad current authority by themselves.
- `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md` and
  `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`: scoped current specs for
  receipt-backed placement. Storage intent may consume their receipt refs but
  still needs #750 membership evidence for clustered quorum, fence, witness,
  and failure-domain freshness.
- `docs/RDMA_TRANSPORT_POSITION.md`: RDMA is optional acceleration; TCP-class
  transport remains the correctness baseline.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md`: transport owns session-local mechanics
  while membership/runtime own epoch, fencing, and roster decisions.
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md`: caches are not authority; RAM
  authority must be modeled explicitly.
- `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`: admission, dirty debt, transport
  queues, and memory budgets are hard gates for any optimizer.
- #893 and `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`: per-dataset memory
  partitioning and governor pressure are source evidence for #902 isolation, but
  storage intent owns the cross-resource policy question of whether an admitted
  action is fair, borrowed, throttled, or refused for the current receipt.
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`, `docs/SPACEMAP_ALLOCATOR_DESIGN.md`,
  `docs/LOCAL_STORAGE_ALLOCATOR_OW102.md`, and the claim/reserve ledger crates:
  quota, statfs, allocator, pending-free, allocation-ticket, claim, and reserve
  evidence inform #898, but storage intent consumes typed refs instead of
  originating a parallel capacity authority.
- `docs/design/unified-scheduling-classes-lane-priority-model.md`: storage
  intent maps onto the shared lane vocabulary for admission, dispatch,
  starvation prevention, and pressure throttling.
- `docs/design/background-service-framework-design.md`: relocation, repair,
  rebuild, scrub, compaction, and geo catch-up run as budgeted resumable work
  when they are not serving a foreground or critical policy risk.
- `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`,
  `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`, and
  `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`: policy publish,
  dataset/property mutation visibility, dry-run, stage, commit, verify, and
  rollback grammar are inputs to #855/#901; storage intent consumes their refs
  instead of inventing a second operator runbook engine.
- `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`: performance
  truth requires workload envelopes, service-objective contracts, KPIs, budgets,
  and receipts.
- `docs/FAULT_INJECTION_CHAOS_CORRUPTION_CAMPAIGNS_P10-02.md`: fault,
  corruption, partition, and recovery campaigns must name fault classes,
  legal outcomes, forbidden outcomes, recovery receipts, and gate artifacts.
- `docs/CLAIMS_GATE_POLICY.md`: publishing-facing storage-intent promises must
  stay behind registered claim ids, required evidence classes, and fail-closed
  validation.
- `docs/OPERATOR_UAPI_AUTHORITY.md`: operator surfaces must distinguish
  prototype, diagnostic, live-owner, and final UAPI claims.
- `docs/UNRELEASED_AUTHORITY_POLICY.md`: TideFS should choose the current
  storage-intent authority for unreleased policy formats instead of preserving
  stale pre-release compatibility paths by default.

## Incumbent Lessons

The point is not to imitate incumbent features.

- OpenZFS has strong consistency machinery, but `sync=disabled` exists as a
  dangerous escape hatch because synchronous write latency can be too costly
  for some deployments. TideFS should make the honest fast path better through
  sharded, media-aware, receipt-backed intent and placement rather than hiding
  the weaker guarantee.
- DRBD exposes useful A/B/C replication semantics, but they are a narrow
  acknowledgment ladder. TideFS needs named evidence across local intent,
  remote volatile receipt, quorum durable intent, full placement, geo RPO, and
  workload/media/cost dimensions.
- Ceph CRUSH models device classes, performance domains, and failure domains
  well, but transparent cache tiering has become a warning sign: moving data
  between fast and slow pools without a sufficiently precise workload,
  authority, and cost model can be slower and riskier than no tiering. TideFS
  must make movement explicit, receipt-backed, hysteresis-bound, and
  wear-budgeted.

Reference points for these lessons:

- OpenZFS `zfs(8)` documents `sync=standard|always|disabled` and warns that
  `sync=disabled` ignores synchronous transaction demands:
  <https://openzfs.github.io/openzfs-docs/man/v0.8/8/zfs.8.html>
- OpenZFS system administration documentation describes ZIL/SLOG, cache
  devices, and transaction-group durability context:
  <https://openzfs.org/wiki/System_Administration>
- LINBIT's DRBD 9 user guide describes Protocol B as memory-synchronous and
  Protocol C as synchronous after local and remote disk confirmation:
  <https://linbit.com/drbd-user-guide/drbd-guide-9_0-en/>
- Ceph CRUSH documentation describes failure-domain placement through CRUSH
  maps:
  <https://docs.ceph.com/en/reef/rados/operations/crush-map/>
- Red Hat Ceph documentation describes device/performance classes:
  <https://docs.redhat.com/en/documentation/red_hat_ceph_storage/5/html/storage_strategies_guide/crush_administration>
- Ceph cache-tiering documentation warns that cache tiering is deprecated and
  that the upstream community advises against new deployments:
  <https://docs.ceph.com/en/latest/rados/operations/cache-tiering/>

## Implementation Staircase

The child issues are a dependency ladder, not independent inventions of local
policy. Each stage may land narrow scaffolding, but it must name the temporary
adapter and the later issue that removes it. No runtime path may grow a second
storage-intent language beside the shared records and compiled policy snapshot.

| Stage | Graduation gate | Issues |
| --- | --- | --- |
| Records | Shared spellings and versioned records exist for policies, receipts, roles, ordering evidence, metadata/namespace evidence refs, proximity, membership evidence refs, trust/domain evidence refs, capacity/admission evidence refs, recovery/degradation evidence refs, policy-rollout evidence refs, tenant/isolation evidence refs, workload/prediction evidence refs, temporal evidence refs, media capability refs, decision-frontier refs, action-execution refs, service-objective refs, result/refusal refs, measurement-attribution refs, evidence-query refs, evidence-retention refs, media roles, data shape, layout evidence, lifecycle evidence, cost, wear, and relocation reasons. | #750, #841, #845, #878, #880, #881, #894, #897, #898, #900, #901, #902, #903, #904, #905, #910, #911, #912, #913, #915, #920, #922 |
| Policy compilation | Pool, dataset, mount, caller, and internal maintenance sources compile into immutable policy snapshots that consumers cite by id/revision. | #855 |
| Policy revision rollout | Compiled revisions publish, stage, roll back, supersede, and converge with explicit source provenance, publication transaction, downgrade authz, in-flight fences, old-receipt treatment, and convergence frontiers. | #901 |
| Evidence feeds | Local ack paths, ordering/replay refs, metadata/namespace refs, membership epoch/fence refs, trust/domain refs, capacity/admission refs, recovery/degradation refs, policy-rollout refs, tenant/isolation refs, temporal refs, media-capability refs, decision-frontier refs, action-execution refs, service-objective refs, result/refusal refs, measurement-attribution refs, evidence-query snapshots, evidence-retention refs, path evidence, media/wear cost, non-wear cost, workload vectors, prediction decision/outcome refs, data-shape evidence, layout/allocator evidence, and lifecycle evidence can publish read-only evidence without making final placement decisions. | #750, #842, #844, #845, #846, #856, #878, #880, #881, #894, #897, #898, #900, #901, #902, #903, #904, #905, #910, #911, #912, #913, #915, #920, #922 |
| Satisfaction reconciliation | Current receipts and evidence are reconciled through #913 query snapshots against the compiled policy as satisfied, converging, degraded-visible, blocked, refused, or unsafe/volatile, including metadata/namespace legality, policy rollout stage, mixed-revision obligations, tenant isolation state, media-capability refusal state, service-objective refusal state, action-execution state, result/refusal state, and evidence-retention blockers. | #874, #901, #902, #904, #910, #911, #913, #915, #920, #922 |
| Planning and admission | Hard constraints reject illegal candidates before scoring, including illegal ordering/replay state, metadata/namespace conflict state, membership/fence state, trust/domain state, temporal state, media-capability state, capacity/reserve state, recovery/degradation state, policy-rollout state, tenant/isolation state, service-objective state, prediction confidence/action state, measurement-attribution state, active action conflicts, data shapes, layout targets, and lifecycle states, then decision-frontier evidence records the #913 query snapshot, candidate sets, hard-gate results, score vectors, tie-breakers, selected plans, defer/refusal state, and #920 caller-result projection before admission/scheduling enforces the compiled policy. | #750, #843, #845, #862, #878, #880, #881, #894, #897, #898, #900, #901, #902, #903, #904, #905, #911, #912, #913, #915, #920, #922 |
| Read serving | Read source selection distinguishes cache, serving-trial, RAM authority, local/remote receipt, degraded reconstruction, snapshot, geo, archive, metadata-hot lookup or directory-index source, in-progress action source/target, and retained-root sources with #913 query snapshot, freshness, service objective, metadata/namespace evidence, epoch/fence, trust/domain, temporal/staleness, media-capability, decision-frontier, action-execution, evidence-retention, capacity-for-repair, recovery/degradation, policy revision, tenant isolation, receipt evidence, and #920 result projection. | #750, #877, #675, #881, #897, #898, #900, #901, #902, #903, #904, #905, #910, #911, #913, #915, #920, #922 |
| Authority extensions | RAM authority, data-shape rebake, allocator-aware defrag/compaction, metadata repack or directory-index compaction, lifecycle-aware reclaim, and relocation/rebuild/geo catch-up use the same receipt spine, service-objective envelopes, and #913 query snapshots, then publish replacement, ordering, metadata/namespace, trust/domain, temporal, media-capability, decision-frontier, action-execution, result/refusal, evidence-retention, capacity/admission, recovery/degradation, policy-rollout, tenant/isolation, and measurement-attribution evidence before source retirement or outcome learning as appropriate. | #750, #847, #848, #878, #880, #881, #894, #897, #898, #900, #901, #902, #903, #904, #905, #910, #911, #912, #913, #915, #920, #922 |
| Operator and gates | Operators can inspect the policy, rollout stage, receipt, service objective, evidence-query snapshot, result/refusal projection, lag/timebase, media capability, metadata/namespace state, decision frontier, action execution, measurement attribution, evidence retention, volatility, cost, trust/domain, capacity/reserve, recovery/degradation, isolation/throttle, prediction outcome, and refusal story, and every implementation claim maps to performance, fault, and claim-registry gates. | #845, #849, #850, #863, #875, #897, #898, #900, #901, #902, #903, #904, #905, #910, #911, #912, #913, #915, #920, #922 |

Interface gates between stages are explicit:

- Consumers take `StorageIntentPolicy` snapshots and receipt/evidence records,
  not raw caller hints, ad hoc dataset properties, or device labels.
- Consumers that see a policy source change must use #901 rollout evidence for
  publication, stage, in-flight fences, rollback, and convergence; they may not
  reinterpret old receipts by reading the newest mutable property value.
- Consumers may act on multi-family evidence only through #913 query snapshots
  or typed query refusals; unbounded live scans, stale indexes, UI-local caches,
  and mixed-policy evidence cuts are not storage-intent authority.
- Planners may score only candidates that already passed guarantee,
  service-objective, ordering/replay, membership/epoch/fence, trust/domain,
  failure-domain, media-capability, metadata/namespace, data-shape,
  layout/allocator,
  lifecycle/generation, capacity, recovery, policy-rollout, tenant/isolation,
  wear, transport, and degradation-law filters.
- Service-objective paths may call a result fast, low-latency, high-throughput,
  RAM-fast, WAN-safe, flash-friendly, or incumbent-superior only through #915
  objective evidence plus the required #912 attribution, #913 query snapshot,
  and #875 claim boundary.
- Result paths may return success, degraded-visible success, throttle, block,
  refusal, retry conflict, errno, block status, API status, or trace status only
  through #920 evidence plus response-registry projection; surface-local status
  strings are not storage-intent authority.
- Decision paths may claim a selected candidate, refused candidate set,
  tie-breaker, or optimizer payback only through #905 evidence; hidden
  winner-only state, unknown-cost-as-zero scoring, and discarded rejection
  reasons are not storage-intent authority.
- Action-execution paths may claim prepared, copied, verified, published,
  cut-over, aborted, rolled-back, completed, or refused state only through #911
  evidence; target writes, worker-local checkpoints, or successful transport
  transfers are not action completion.
- Metadata/namespace paths may claim fast fsyncdir, safe rename/link/unlink,
  stable lookup/readdir, metadata-hot serving, low-wear small-object shape, or
  metadata-local placement only through #922 evidence; VFS success, adapter
  cache hits, directory indexes, or small-file packing are not storage-intent
  authority by themselves.
- Evidence-retention paths may compact, summarize, redact, tombstone, or purge
  storage-intent proof only through #910 evidence; object reclaim, expired
  telemetry, or claim silence is not proof that receipts, decisions, outcomes,
  cooldowns, explanations, audits, or claims no longer depend on it.
- Evidence producers must publish retention class, dependency refs, proof-root
  refs, and evidence budget refs before other stages treat their records as
  receipt, decision, explanation, validation, or claim authority.
- Schedulers may delay, throttle, or refuse work, but they may not convert one
  acknowledgment class into another after admission.
- Ack receipt emitters may group, shard, coalesce, or pipeline work only when
  ordering evidence preserves the caller-visible barrier and replay contract.
- Media-capability paths may claim durable, PMem, FUA, ZNS/SMR, archive, or
  remote-target eligibility only through #904 evidence; device labels, path
  names, benchmark results, and stale probes are never role eligibility.
- Read-serving paths may accelerate through cache, trial, RAM, local, remote,
  degraded, snapshot, geo, or archive sources only when freshness, receipt,
  service-objective, metadata/namespace, membership epoch, fence, trust/domain,
  media-capability, action-execution, recovery/degradation, evidence-retention,
  and capacity predicates pass for the compiled policy.
- Data-shape and transform paths may change record size, compression,
  checksum/digest, dedup, encryption, EC, archive, or coalescing shape only
  through compiled policy and receipt/evidence records.
- Allocator and layout paths may use free-run, locality, zone, pending-free,
  reclaim, or fragmentation evidence only through authority records or marked
  non-authoritative mirrors.
- Lifecycle paths may use write-age, retention, snapshot, clone, receive-base,
  orphan, destroy, or reclaim-frontier evidence only through authority records
  or marked non-authoritative predictors.
- Capacity paths may use quota, statfs, pending-free, allocation-ticket,
  claim-ledger, reserve-ledger, dirty-window, and protected-floor evidence only
  through authority records; cost estimates, reclaim queues, and mirror
  projections do not satisfy admission by themselves.
- Recovery paths may use source receipts, reconstruction width, target health,
  repair/rebuild obligation, replacement receipt, retirement frontier, partition
  healing, and RPO/RTO lag only through authority records; reachable bytes,
  transfer success, or topology guesses do not satisfy recovery by themselves.
- Policy rollout paths may publish, stage, activate, roll back, supersede, or
  retire a revision only through #901 evidence; raw config updates, operator
  intent, or successful dry-run output do not activate a storage-intent policy.
- Tenant isolation paths may borrow, donate, throttle, defer, escalate, or
  refuse work only through #902 evidence; global idle resources, average
  throughput, or local lane state do not prove cross-tenant fairness by
  themselves.
- Prediction paths may raise confidence, admit an action class, declare
  payback, lower confidence, or clear cooldown only through #845 evidence plus
  #912 attribution verdicts; raw hints, one-off heat, hidden model state,
  confounded metrics, or missing outcome samples do not prove an
  authority-changing move is wise.
- Temporal paths may claim lag, age, freshness, expiry, deadline satisfaction,
  TTL, cooldown, or payback only through #903 evidence; raw timestamps,
  sequence counters without conversion, or local wall-clock reads do not prove
  cross-node freshness or wall-time RPO by themselves.
- Relocation workers may write speculative replacements, but they may not retire
  source receipts until replacement receipts, ordering evidence, and
  service-objective plus metadata/namespace plus trust/domain plus temporal plus
  media-capability plus action-execution plus evidence-retention plus
  capacity/admission plus recovery/degradation plus rollout plus isolation
  evidence satisfy the target policy.
- Validation rows and claim ids are not an afterthought: each stage must either
  add the relevant #850/#863 row binding and #875 claim boundary, or state
  which later issue owns that proof.

## Follow-Up Implementation Map

The follow-up issues should be non-overlapping slices. They should not edit
this document except to update the issue map after live tickets exist.

| Slice | Follow-up issue | Expected write set | Purpose |
| --- | --- | --- | --- |
| Membership epoch authority | #750 | `docs/MEMBERSHIP_AUTHORITY.md` | Decide epoch, quorum-write, witness-set, join/drain, fence, roster, and failure-domain authority, then expose typed refs storage-intent consumers can cite. |
| Storage intent core records | #841 | `crates/tidefs-storage-intent-core/`, workspace manifests | Define policy, ack class, receipt, ordering refs, metadata/namespace refs, membership evidence refs, trust/domain refs, temporal refs, capacity/admission refs, recovery/degradation refs, policy-rollout refs, tenant/isolation refs, workload/prediction refs, media-capability refs, decision-frontier refs, action-execution refs, service-objective refs, result/refusal refs, measurement-attribution refs, evidence-query refs, evidence-retention refs, media role, proximity, data-shape refs, layout refs, lifecycle refs, and cost records. |
| Ordering evidence authority | #894 | ordering evidence model surface or #841 core model | Expose barrier scope, dirty epoch, dependency closure, replay idempotency, intent sequence, publication boundary, and completion state for sync, quorum, relocation, repair, and receipt-retirement receipts. |
| Metadata/namespace evidence authority | #922 | storage-intent metadata/namespace records in #841 or `crates/tidefs-storage-intent-metadata-namespace/`, focused tests | Expose metadata subject, namespace operation, VFS/namespace authority refs, namespace-intent and fsyncdir receipts, metadata locality, small-object shape, metadata write amplification, decision/action/result refs, and typed metadata refusal state without replacing VFS or inode authority. |
| Trust/domain evidence authority | #897 | storage-intent trust/domain records in #841 or `crates/tidefs-storage-intent-trust/`, focused tests | Expose authenticated identity, admin/security/tenant domain, session-security posture, key epoch, authorization/audit refs, residency, sharing-domain compatibility, and quarantine/refusal state. |
| Capacity/admission evidence authority | #898 | storage-intent capacity/admission records in #841 or `crates/tidefs-storage-intent-capacity/`, focused tests | Expose logical/physical headroom, allocation tickets, claim/reserve receipts, dirty-window reserve, protected floors, pending-free frontiers, capacity amplification, typed ENOSPC/refusal state, and producer generation/freshness refs usable by #913 query snapshots. |
| Recovery/degradation evidence authority | #900 | storage-intent recovery/degradation records in #841 or `crates/tidefs-storage-intent-recovery/`, focused tests | Expose degraded state, source receipt set, reconstruction width, target health, repair/rebuild obligation, replacement receipt publication, old-receipt retirement, partition healing, RPO/RTO lag, typed recovery refusal state, and producer generation/freshness refs usable by #913 query snapshots. |
| Policy source and compilation | #855 | policy/config crate or `crates/tidefs-storage-intent-policy/` | Persist and compile pool, dataset, mount, caller, and internal maintenance policy into storage-intent records. |
| Policy revision rollout evidence authority | #901 | storage-intent policy-rollout records in #841 or `crates/tidefs-storage-intent-policy-rollout/`, focused tests | Expose source policy provenance, compiled revision publication, change class, downgrade authorization, stage state, in-flight fence, convergence frontier, rollback/re-entry, supersession, typed rollout refusal state, and producer generation/freshness refs usable by #913 query snapshots. |
| Tenant/isolation evidence authority | #902 | storage-intent tenant/isolation records in #841 or `crates/tidefs-storage-intent-isolation/`, focused tests | Expose budget owner, tenant/domain refs, isolation scope, resource-vector budgets, fair-share windows, burst/borrow/debt, starvation, noisy-neighbor harm, reserve exemptions, typed throttle/refusal state, and producer generation/freshness refs usable by #913 query snapshots. |
| Temporal evidence authority | #903 | storage-intent temporal records in #841 or `crates/tidefs-storage-intent-temporal/`, focused tests | Expose timebase identity, clock-health, skew/uncertainty, evidence age, event/frontier stamps, lag/staleness, expiry/deadline, sequence-to-time conversion, temporal refusal state, and producer generation/freshness refs usable by #913 query snapshots. |
| Media capability evidence authority | #904 | storage-intent media-capability records in #841 or `crates/tidefs-storage-intent-media-capability/`, focused tests | Expose device/media identity, persistence domain, flush/FUA/barrier semantics, volatile-cache policy, atomicity/granularity, protocol/geometry capability, health/freshness, role eligibility, media-capability refusal state, and producer generation/freshness refs usable by #913 query snapshots. |
| Decision-frontier evidence authority | #905 | storage-intent decision-frontier records in #841 or `crates/tidefs-storage-intent-decision/`, focused tests | Expose decision identity, evidence-query snapshot refs, candidate frontier, hard-gate results, score vector, selected candidate, tie-breaker, reserve/admission refs, counterfactual baseline, payback/harm anchors, and refusal/defer state. |
| Action-execution evidence authority | #911 | storage-intent action-execution records in #841 or `crates/tidefs-storage-intent-action-execution/`, focused tests | Expose action identity, selected decision/admission refs, #913 admission query snapshot refs, step state, idempotency/replay proof, source protection, target verification, publication/cutover boundary, abort/rollback state, outcome/budget accounting, and execution refusal state for idempotent actuation and source retirement. |
| Service-objective evidence authority | #915 | storage-intent service-objective records in #841 or `crates/tidefs-storage-intent-service-objective/`, focused tests | Expose objective identity, policy/workload/operation scope, latency percentile and tail/jitter envelope, throughput/burst/dwell/concurrency/queueing profile, degradation/RPO/RTO ties, topology/media/environment scope, isolation/cost/wear budget refs, decision/admission/action/query/attribution refs, comparator/claim refs, and objective refusal state. |
| Measurement-attribution evidence authority | #912 | storage-intent measurement-attribution records in #841 or `crates/tidefs-storage-intent-measurement-attribution/`, focused tests | Expose measurement identity, subject/policy/workload/environment binding, #913 intervention query snapshot refs, sample window, baseline/counterfactual lineage, decision/action/admission refs, metric/KPI/cost/wear vectors, confounder state, attribution verdict, transfer scope, and allowed-use/refusal state. |
| Evidence-retention authority | #910 | storage-intent evidence-retention records in #841 or `crates/tidefs-storage-intent-evidence-retention/`, focused tests | Expose evidence identity, dependency graph, retention class, proof root, query-snapshot dependencies, compaction/summarization rule, safe purge frontier, retention media/cost/privacy envelope, and retention refusal state for proof-safe evidence compaction. |
| Evidence-query snapshot authority | #913 | storage-intent evidence-query records in #841 or `crates/tidefs-storage-intent-evidence-query/`, focused tests | Expose bounded query snapshots with query id, consumer class, subject/policy scope, included evidence refs, source-index generations, freshness frontier, completeness verdict, retention/replay anchors, and typed query refusal state for consumers. |
| Local ack receipt emission | #842 | `crates/tidefs-local-filesystem/`, intent-log-adjacent code | Publish earned ack receipts for write, fsync, fdatasync, O_DSYNC, mmap sync, namespace intent, and fsyncdir paths with ordering, metadata/namespace, media-capability, capacity/admission refs, and #920 result/refusal refs for the ack floor. |
| Placement planner integration | #843 | `crates/tidefs-placement-planner/`, `crates/tidefs-replication-model/` | Consume #913 query snapshots over intent roles, metadata/namespace refs, membership/fence refs, trust/domain refs, media-capability refs, decision-frontier refs, capacity/admission refs, proximity domains, failure domains, media-role constraints, and #920 result/refusal blockers before scoring candidates. |
| Read-serving authority | #877 | read-serving model crate or `crates/tidefs-storage-intent-read-serving/`, focused tests | Define legal read source classes, #913 query snapshot use, freshness predicates, metadata-hot lookup and directory-index source law, epoch/fence law, trust/domain law, media-capability law, decision-frontier law, action-execution law, evidence-retention law, recovery/degradation law, geo stale-read boundaries, read-repair capacity evidence, and #920 result/refusal projection. |
| Data-shape authority | #878 | data-shape records/model module or `crates/tidefs-storage-intent-data-shape/`, focused tests | Bind record sizing, compression, checksum/digest, dedup, encryption, EC/archive, coalescing, small-object inline/packed/external shape, and rebake decisions to compiled policy, metadata/namespace refs, and evidence receipts. |
| Layout evidence authority | #880 | layout-evidence records/model module or `crates/tidefs-storage-intent-layout-evidence/`, focused tests | Expose allocator geometry, fragmentation, free-run pressure, alignment, zone/write-pointer state, directory/index locality, pending-free safety, and reclaim debt as policy evidence while consuming #904 capability refs for device semantics and #922 refs for metadata locality. |
| Lifecycle evidence authority | #881 | lifecycle-evidence records/model module or `crates/tidefs-storage-intent-lifecycle-evidence/`, focused tests | Expose write age, stability, snapshot/clone/receive-base retention, orphan/destroy state, metadata/small-object stability, and reclaim frontiers as policy evidence. |
| Media cost and wear ledger | #844 | `crates/tidefs-local-object-store/` | Track flash wear, WAF estimates, metadata and signal-persistence write amplification, media health, movement debt, payback evidence, and relocation write budgets while consuming #904 refs for media class, health, and capability freshness. |
| Non-wear cost ledger | #856 | cost-ledger crate or `crates/tidefs-storage-intent-cost/` | Account capacity, metadata amplification, network egress, retention, relocation, and operator-defined cost envelopes without replacing #898 admission evidence. |
| Workload and prediction evidence plane | #845 | `crates/tidefs-performance-contract/`, focused local signal producers | Materialize bounded workload vectors, signal-materialization and collection-cost refs, confidence classes, temporal refs, decision/outcome refs, payback verdicts, confidence updates, and anti-thrash state for planning, relocation, explanation, performance, and fault rows while linking authority-changing decisions to #905, objective scope to #915, execution/outcome to #911, attribution to #912, evidence cuts to #913, cost/wear budgets to #844/#856/#902, and retention/compaction to #910. |
| Satisfaction reconciler | #874 | satisfaction/reconciliation crate or `crates/tidefs-storage-intent-satisfaction/` | Reconcile compiled policy against #913 query snapshots as satisfied, converging, degraded, blocked, refused, or unsafe-visible, including #900 recovery/degradation, #901 rollout, #902 isolation, #904 media-capability, #922 metadata/namespace, #905 decision-frontier, #915 service-objective refusal, #911 action-execution, #920 result/refusal, and #910 retention state, without choosing placement. |
| Intent-aware admission and scheduling | #862 | scheduler/admission crate or `crates/tidefs-storage-intent-scheduler/` | Map compiled policy, #915 service-objective refs, #913 query snapshots, #898 reserve state, #902 isolation state, #904 media-capability refusal state, #922 metadata/namespace state, #905 decision-frontier refs, and #920 result/refusal refs to lanes, backpressure, QoS budgets, and observable scheduling evidence. |
| Transport path evidence | #846 | `crates/tidefs-transport/` | Expose measured path/proximity/carrier and temporal-sample evidence without making RDMA mandatory. |
| RAM authority design and implementation | #847 | docs first, then storage/runtime crates | Define volatile, replicated-volatile, intent-backed, and PMem-backed authority while consuming #904 evidence for PMem persistence-domain and flush/fence eligibility. |
| Relocation governor | #848 | new relocation/optimizer crate or existing background-service integration | Unify defrag, compaction, rebake, metadata repack, directory-index compaction, rebuild, evacuation, geo catch-up, wear movement, #915 service objectives, #913 query snapshots, media-capability gates, metadata/namespace gates, decision-frontier, action-execution, result/refusal, measurement-attribution, and evidence-retention evidence, reserve admission, recovery/degradation predicates, shadow evaluation, payback, and cooldown. |
| Result/refusal caller evidence | #920 | storage-intent core/result model, response-registry integration docs or code, adapter/result tests | Bind typed storage-intent outcomes to policy/query/decision/receipt refs, degraded-visible state, response-registry projection, errno/block/API/trace compression, retryability, delivery/index refs, and retention/audit proof. |
| Operator explanation UAPI | #849 | `apps/tidefsctl/`, operator docs | Explain policy, rollout stage, receipts, service objective, result/refusal projection, evidence-query snapshot, lag/timebase, media capability, metadata/namespace state, decision frontier, action execution, measurement attribution, evidence retention, volatility, placement, trust/domain state, capacity/reserve state, recovery/degradation state, isolation/throttle state, prediction outcome, and wear to operators. |
| Performance intent gates | #850 | `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`, `crates/tidefs-performance-contract/`, validation matrix | Add rows for ack latency, metadata storm, fsyncdir, lookup/readdir, small-object shape, throughput, tail, service-objective envelope consistency, result/refusal projection, evidence-query consistency, media-capability role legality, decision-frontier preservation, action-execution safety, measurement-attribution safety, evidence-retention safety, trust/domain changes, temporal freshness/lag, capacity admission, recovery/degradation, policy rollout, tenant isolation, prediction accuracy, signal-materialization overhead, wear, cost, RPO, and relocation. |
| Storage intent fault validation | #863 | `docs/FAULT_INJECTION_CHAOS_CORRUPTION_CAMPAIGNS_P10-02.md`, storage-intent validation matrix/config docs | Prove ack, placement, metadata/namespace, service-objective consistency, result/refusal preservation, evidence-query consistency, media capability, decision-frontier, action-execution, measurement-attribution, evidence-retention, trust/domain, temporal freshness/lag, capacity/reserve, recovery/degradation, policy rollout, tenant isolation, prediction accountability, signal-materialization safety, relocation, RAM, scheduler, and WAN promises under typed faults and forbidden-outcome checks. |
| Storage intent claims gate | #875 | `validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, focused claims-gate tests if needed | Register planned/blocked claim ids and evidence boundaries for storage-intent successor, performance, durability, metadata/namespace, service-objective envelope consistency, result/refusal preservation, evidence-query consistency, media-capability role eligibility, decision-frontier accountability, action-execution safety, measurement-attribution safety, evidence-retention safety, temporal lag/freshness, recovery/degradation, policy rollout, tenant isolation, adaptive prediction, RAM, WAN, and wear promises. |

## Validation For This Slice

The authority slice is documentation/design only. Validation is bounded to:

- source and documentation inspection;
- `git diff --check`.

Do not run local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, broad
xfstests, or heavy performance validation for this slice while the host is
below the TideFS heavy-work disk floor.
