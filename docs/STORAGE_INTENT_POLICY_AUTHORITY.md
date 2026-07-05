# Storage Intent Policy Authority

Issue: #839, #957, #968, #973, #975, #1588, #1762
Date: 2026-07-05
Status: current normative authority for storage-intent policy boundaries

This document defines the durable storage-intent contract that TideFS source,
validation, operator surfaces, and claim gates must preserve. It is the policy
and evidence language for write admission, fsync, placement, transport, media
choice, relocation, RAM pools, read serving, and operator explanation.

The core rule is:

> TideFS must not choose between fast and honest. Every successful
> acknowledgment must carry a named guarantee receipt, and the system must
> optimize only paths that earn that receipt.

This file is not a roadmap, proof packet, performance matrix, or product
admission artifact. Implementation gaps remain owned by source, tests,
validation artifacts, generated claim output, and live GitHub issues and pull
requests. Successor and comparator wording remains behind
`validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, and the claims
gate.

## Non-Claims

This document does not implement runtime behavior, change POSIX durability
semantics, add a production persistent WAL, prove RDMA, prove distributed
availability, enable mounted device-level compression or encryption, implement
deduplication or erasure coding, or claim performance superiority over
OpenZFS, Ceph, DRBD, local filesystems, or any other system.

Media names, cache tiers, RAM-fast paths, remote placement, prefetch success,
RDMA availability, latency rows, benchmark names, background reclaim state, and
source-model policy text do not upgrade an operation into a durability,
availability, freshness, production-readiness, release-readiness, or successor
claim.

Runtime and product claims require issue-scoped implementation, current
validation evidence, generated claim-registry admission, and claims-gate
closure for the exact scope being described.

## Authority Boundary

Storage intent is a cross-cutting contract, not a local tiering feature. The
compiled policy, evidence query, decision frontier, action execution record,
receipt, result/refusal projection, and operator explanation must all describe
the same authority shape.

The authority boundary has these laws:

1. Policy precedes placement. Placement, transport, caching, relocation, and
   rebake are implementations of intent, not the intent itself.
2. A receipt is earned evidence, not a label. Success is legal only when the
   receipt satisfies the requested policy predicate.
3. Prediction may optimize, but it may not weaken an acknowledgment floor or
   hide an unknown evidence state.
4. Caches accelerate. They do not become authority unless a compiled policy
   assigns an explicit volatile or durable authority class and the receipt
   names its loss boundary.
5. Background work may improve layout, cost, wear, or availability only after
   hard legality gates pass and source-retirement rules preserve old authority
   until replacement authority is published.
6. A caller-visible reply must project the earned receipt, degraded-visible
   state, or typed refusal. It must not translate missing evidence into generic
   success.
7. Evidence may be compacted only through a proof-retention rule that preserves
   every receipt, decision, fault, explanation, audit, and claim dependency
   that still requires it.

## Native Records

Source may split these records into Rust types, artifacts, indexes, or control
fields, but the contract below must remain expressible without inventing a
second policy dialect.

| Record | Normative role |
| --- | --- |
| `StorageIntentPolicy` | Requested and compiled behavior for a dataset, file, range, operation, planner epoch, or action class. |
| `StorageIntentPolicyId` and `StorageIntentPolicyRevision` | Stable identity for the policy snapshot used by an operation, evidence cut, receipt, or decision. |
| `StorageIntentReceipt` | Earned acknowledgment, placement, read-serving, relocation, or convergence evidence. |
| `StorageIntentEvidenceRef` | Reference to receipts, local intent records, membership, ordering, trust, media, capacity, scheduling, validation, or claim evidence. |
| `StorageIntentEvidenceQuerySnapshot` | A bounded, complete-for-purpose evidence cut with source-index generations, freshness frontier, completeness verdict, and refusal state. |
| `StorageIntentDecisionFrontier` | Hard-gate and score evidence for a planner, admission, read-serving, relocation, repair, geo, or receipt-retirement choice. |
| `StorageIntentActionExecution` | Idempotent action state, cutover/publication state, rollback or abort state, source-retirement blockers, and retry evidence. |
| `StorageIntentResultRefusal` | Caller-visible success, degraded-visible success, blocked, unknown, or refused outcome projection. |
| `StorageIntentRetentionProof` | Exact evidence, summary proof root, tombstone, redaction, audit hold, and replay depth required by remaining consumers. |

Every authority-changing record must name its subject scope, policy identity,
actor or producer identity, temporal or epoch evidence, and retention class.
Records that cannot provide those fields are telemetry or design input only.

## Policy Contract

`StorageIntentPolicy` must describe the requested floor rather than an
implementation preference. It must be able to carry:

- acknowledgment class and receipt-satisfaction predicate;
- read freshness profile and degraded-read law;
- placement, proximity, failure-domain, membership, and quorum constraints;
- service-objective envelope when latency, throughput, dwell, RPO, RTO, cost,
  isolation, or comparator terms are hard requirements;
- media-role, media-capability, and device-semantic requirements;
- data-shape requirements, including record size, compression, checksums,
  encryption boundary, dedup scope, erasure shape, coalescing, and rebake;
- allocation geometry, fragmentation, reclaim, zone, erase-block, and free-run
  constraints that decide whether placement or relocation is legal;
- lifecycle evidence requirements, including write age, overwrite/delete
  windows, snapshot and clone retention, receive-base dependencies,
  tombstones, and pending-free state;
- tenant, budget, noisy-neighbor, capacity, reserve, and ENOSPC rules;
- rollout, rollback, stage, preflight, shadow, and unsafe-mode rules;
- proof-retention requirements for receipts, decisions, outcomes,
  explanations, validation rows, and claims.

Policy compilation must preserve source provenance, inheritance, overrides,
publication transaction, downgrade authorization, and the active/staged/
rollback state. A stale or mixed policy revision is a refusal or unknown state,
not an implementation detail.

## Receipt Honesty

`StorageIntentReceipt` is the boundary between internal work and caller-visible
truth. A success receipt must name:

- operation, range, object, dataset, action, or convergence scope;
- policy id and revision;
- earned acknowledgment or authority class;
- placement, intent, read-source, or action evidence refs;
- ordering, replay, dirty-epoch, barrier, and publication evidence when the
  operation affects durability or namespace visibility;
- membership epoch, roster, quorum, witness/data role, failure-domain binding,
  drain, and fence evidence when remote or clustered state participates;
- trust, administrative domain, tenant domain, key epoch, authorization, audit,
  residency, and quarantine evidence when remote, shared, encrypted, repair, or
  geo state participates;
- capacity, reserve, admission, dirty-window, pending-free, isolation, and
  scheduler evidence when success consumes shared budget or makes future repair
  possible;
- digest, checksum, transform, erasure, rebake, and locator evidence when bytes
  or data shape are part of the guarantee;
- known remaining work, lag, degraded-visible state, repair obligation, or
  receipt-retirement dependency;
- retention and replay identity.

Receipt satisfaction is policy-specific. A receipt that satisfies one product
floor may be below, incomparable with, or irrelevant to another floor.

## Acknowledgment Classes

Acknowledgment classes are evidence labels, not a numeric dominance ladder.

| Ack class | Evidence required before success | Survives | Does not survive |
| --- | --- | --- | --- |
| `volatile-local` | Bytes or deltas accepted in local process or host RAM under policy budget. | Process-visible reads while alive. | Process crash, host crash, or power loss. |
| `volatile-replicated` | Bytes or deltas in RAM on enough fenced peers for the volatile policy. | Primary process or node loss while a fenced peer remains live. | Simultaneous power loss, peer loss before promotion, or missing durable replay. |
| `local-intent` | Replayable durable local intent with payload or range digest, metadata deltas, and flush evidence. | Local crash or power loss while intent media survives. | Loss of the only intent/data device. |
| `remote-volatile-plus-local` | `local-intent` plus remote fenced volatile receipt. | Primary node loss when remote peer stays live and local intent remains replayable. | Loss of local durable intent or simultaneous local and remote volatile loss. |
| `quorum-intent` | Replayable durable intents on a policy quorum of failure domains. | Minority device or node failure covered by the quorum. | Loss of quorum or malformed epoch/fence evidence. |
| `full-placement` | Policy-satisfying placement receipt for all required replicas or shards plus durable locator authority. | Failures inside the declared redundancy policy. | Failures beyond policy or receipt corruption without recovery. |
| `geo-async` | Local or quorum durable floor plus explicit remote lag and RPO receipt. | Local policy failures only; remote recovery inside the recorded RPO if catch-up succeeds. | Immediate remote-site recovery at acknowledgment time. |
| `geo-intent` | Durable replayable intent in another site or region with path, epoch, and trust evidence. | Site loss covered by the remote intent policy. | Region-wide failure beyond policy or freshness outside the requested floor. |
| `geo-full-placement` | Full placement receipts across required geographic domains. | Declared site or region failures. | Correlated failures beyond policy. |
| `archive-ec` | Durable erasure-coded or archive placement receipt with recovery width and rebuild policy. | Media failures inside archive policy. | Low-latency serving unless a serving role also exists. |

`remote-memory` by itself is not durable. It is a component of a larger
receipt and must say what happens if the primary node fails, if the remote
process crashes, and if power is lost.

## POSIX Sync And Unsafe Modes

A POSIX `fsync`, `fdatasync`, metadata barrier, FUA, or block completion may
report success only when the returned receipt satisfies the configured stable
storage floor for that surface. A lower class may be used for performance only
when the caller, dataset, mount, or control-plane policy explicitly selected an
unsafe or preview mode and the result projection exposes that weaker floor.

Unsafe modes must be named, auditable, revocable, and visible in receipts,
operator explanation, traces, and validation artifacts. They must not support
successor, production, release-readiness, POSIX-complete, distributed
availability, or crash-safety claims.

## Evidence Queries And Consistent Cuts

Planners, reconcilers, executors, read paths, explanation surfaces,
performance rows, fault rows, and claim gates must consume storage-intent state
through a bounded evidence query snapshot or return a typed refusal.

A valid snapshot records:

- query identity, consumer class, subject scope, policy id and revision;
- source-index generations, producer watermarks, compaction state, redaction
  state, and replay or audit anchor;
- included evidence refs across receipt, ordering, membership, trust,
  capacity, recovery, rollout, isolation, workload, temporal, media,
  decision, action, measurement, retention, data-shape, layout, lifecycle,
  transport, validation, and claim families;
- freshness frontier and invalidation frontier by evidence family;
- completeness verdict for the consumer: complete, partial-admissible,
  degraded-visible, unknown-evidence, blocked, refused, or unsafe-visible;
- query refusal reason when evidence is stale, contradictory, redacted,
  compacted beyond the consumer's proof need, unavailable, unauthorized, or
  unsupported.

An unbounded live scan, cache-local guess, dashboard sample, or mixed-policy
bundle is not storage-intent authority.

## Media Role Legality

Media role is authority only when policy and evidence assign a legal role.
Device type, transport speed, locality, or operator naming does not make a
device eligible.

| Role | Legal use |
| --- | --- |
| `intent-log` | Durable replay or barrier evidence for operations whose policy permits that medium and flush/fence semantics are proven. |
| `data-placement` | Durable data or shard placement with locator, checksum, lifecycle, and recovery evidence. |
| `metadata-placement` | Namespace, inode, xattr, ACL, or small-object authority with ordering and fsyncdir evidence where required. |
| `cache` | Non-authoritative acceleration with valid anchors, fences, and invalidation. |
| `volatile-authority` | Explicit RAM or remote-memory authority with visible loss boundary and membership/trust evidence. |
| `archive` | Durable cold or EC placement with recovery width, restore latency, and serving limits. |
| `repair-source` | Reconstruction or read-repair source with digest, freshness, and degraded-state evidence. |
| `scratch` | Temporary or rebuild workspace that cannot satisfy receipts unless promoted through a legal receipt path. |

Flash lifetime, erase-block or zone alignment, write amplification, foreground
latency, CPU amplification, rebuild cost, egress cost, and operator budget are
hard legality inputs when policy names them as constraints. Optimizers may not
spend protected sync, repair, evacuation, receipt-retirement, tenant, capacity,
or flash-wear reserves for optional movement.

## RAM And In-Memory Pools

RAM has two distinct meanings:

- cache, which is never authority;
- explicit volatile or persistent authority, which has named loss semantics.

Legal RAM authority classes:

| Class | Evidence | Use |
| --- | --- | --- |
| `ram-volatile-local` | Local volatile receipt. | Single-host scratch, tests, or throwaway intermediate data. |
| `ram-volatile-replicated` | Fenced data-peer volatile receipts with membership epoch and failure-domain evidence. | Ultra-low-latency clustered scratch that survives one live-node failure but not power loss. |
| `ram-intent-backed` | RAM serving plus durable local or quorum intent. | Low-latency service with replayable durability. |
| `pmem-durable` | Persistent-memory flush and fence evidence in the relevant persistence domain. | Durable low-latency intent or data role. |

A RAM pool must not be described as a cache when it is authority, and must not
be described as durable unless evidence survives the relevant crash or power
failure.

## Decision Frontier And Accountability

Decision-frontier evidence makes an optimizer's choice replayable. It must
record:

- action class, subject scope, policy id/revision, actor/component version,
  decision epoch, and temporal evidence;
- authority mode: live, shadow, trial, preflight, simulated, replay, or
  refused;
- evidence query snapshot used for hard gates and score inputs;
- bounded candidate set, deterministic ordering, candidate digest, and legal,
  illegal, unknown, deferred, or refused state for each candidate;
- hard-gate results for guarantee, service objective, ordering, membership,
  trust, temporal, media, data-shape, layout, lifecycle, capacity, recovery,
  rollout, isolation, prediction, transport, wear, and operator policy;
- score vector with units or typed unknown state for latency, tail, throughput,
  wear, CPU, read amplification, layout, reclaim, lifecycle churn, egress,
  congestion, recovery risk, foreground disruption, confidence, movement debt,
  payback, and operational complexity;
- selected candidate, tie-breaker, reserve/admission refs, rollback or
  no-cutover proof, and typed defer/refusal when no candidate may run;
- counterfactual baseline and retention requirement for learning, validation,
  operator explanation, and claims.

Illegal candidates may be observed and recorded, but they may not be scored.
A simulated or preflight frontier can guide later work, but it is not live
authority, a receipt, a placement update, or a claim artifact.

Measurement attribution must bind outcomes to the decision, action, and
evidence query that produced them. A metric that cannot show what evidence the
decision saw cannot prove payback, safety, or product claims.

## Action Execution And Source Retirement

Authority-changing action execution must be idempotent, replayable, and fenced
by the policy revision and evidence snapshot that admitted it. Before cutover,
execution must revalidate stale, superseded, contradicted, or expired evidence.

Source retirement is legal only after replacement authority exists and recovery
or rollback obligations are satisfied. Relocation, defrag, rebake, compaction,
repair, geo catch-up, receipt retirement, and retention compaction must publish
their action result, replacement receipt, old-source dependency, abort or
rollback state, and proof-retention state.

An action that cannot prove its cutover or source-retirement state is blocked
or refused. It is not allowed to leave callers, operators, or validation rows
to infer the state from background progress.

## Result, Refusal, And Caller Projection

The final response surface must carry the same truth as the storage-intent
authority records. A write, read, fsync, FUA, placement decision, relocation
action, operator request, retry, or validation row must project one of:

- success with an earned receipt;
- degraded-visible success with remaining work, lag, or repair obligations;
- unsafe-visible success when the caller explicitly selected that weaker floor;
- unknown evidence;
- blocked or deferred;
- refused with typed failed gates.

Result/refusal projection must name the result identity, policy revision,
evidence query snapshot, decision frontier, earned receipt if any, failed gate
refs, degraded visibility refs, admission/action state, response-registry or
caller projection, and retention class.

It is illegal to turn no quorum, stale evidence, degraded read, failed service
objective, missing source-retirement proof, or lower acknowledgment class into
generic success.

## Operator Explanation Boundary

Operators need a receipt explanation surface, not a hidden heuristic summary.
Operator-facing storage-intent explanations must be able to answer, within the
caller-authorized scope:

- what policy and revision apply;
- whether that revision is draft, staged, active, converging, rolled back,
  superseded, or refused;
- which evidence query snapshot backs the answer and whether any evidence is
  stale, redacted, compacted, unavailable, or refused;
- what receipt or degraded-visible state the last relevant operation earned;
- which placement, ordering, membership, trust, capacity, media, read-source,
  data-shape, layout, lifecycle, action, retention, and validation evidence
  made the state legal or illegal;
- which remote paths are behind and by what RPO/RTO or freshness envelope;
- which data is intentionally volatile;
- which work is pending relocation, rebake, repair, receipt retirement, geo
  catch-up, or proof compaction;
- which candidates were rejected and why;
- what the explanation may not be used to claim.

Explanation output is not itself runtime proof, product admission, or
successor/comparator evidence unless a claim gate explicitly consumes a current
artifact for that exact scope.

## Validation Classes

Storage-intent validation must preserve the distinction between authority text,
source-model checks, runtime evidence, and claim admission.

| Validation class | What it can prove | What it cannot prove alone |
| --- | --- | --- |
| Authority drift check | Referenced authority files, classifications, and generated docs remain aligned. | Runtime correctness, POSIX durability, performance, availability, or successor claims. |
| Source-model check | Types, state machines, static catalogs, policies, and generated artifacts preserve the contract. | Mounted behavior, crash durability, cluster availability, or production readiness. |
| Runtime row | A specific executable scenario observed the required receipt, refusal, recovery, or failure behavior. | Broader scopes, untested media, untested faults, or product-wide claims. |
| Performance/comparator row | A bounded workload, objective, baseline, and receipt set met the recorded gate. | General superiority, OpenZFS/Ceph parity, cost effectiveness, or successor wording outside the claim id. |
| Claims-gate review | Registered claim evidence classes and blockers match `validation/claims.toml` for the exact claim. | Unregistered product claims or unstated scopes. |

Fault validation must name fault class, injected or observed condition, policy
revision, expected legal outcomes, forbidden outcomes, receipt/result refs,
recovery refs, operator visibility, and artifact retention. A passing fault row
does not generalize beyond its declared scope.

## Successor And Comparator Guardrails

Storage-intent work may support future successor or comparator claims only by
feeding the registered claim ids and evidence classes. It does not grant
permission to use broad successor, replacement, superiority, parity, or
OpenZFS/Ceph-style wording.

The guardrails are:

1. Local and distributed successor truth remain split unless the generated
   claim registry validates a broader umbrella scope.
2. Comparator language must name the exact baseline, workload, topology,
   policy, receipt class, cost envelope, validation artifact, and claim id.
3. Incumbent lessons are design input only. They are not current TideFS proof.
4. Average throughput, single-row latency, media labels, RDMA availability,
   RAM speed, source-model validation, or old issue closure cannot prove
   superiority.
5. Operator explanation may expose limits and refusals, but explanation text is
   not a claim artifact unless the claim gate requires and validates it.
6. The absence of a refusal is not proof. Claim wording needs positive current
   evidence for the exact scope.

## Gap Ownership Boundary

This document keeps only the normative contract. Current implementation and
product-admission gaps remain outside this file:

- live product-admission umbrellas such as #1733 through #1745 own broad
  product proof boundaries;
- focused runtime and evidence owners, including #972 and the issue/PR lineage
  named by `validation/claims.toml`, own implementation closure where their
  scope applies;
- generated `docs/CLAIM_REGISTRY.md` records the current claim blockers and
  evidence classes;
- validation artifacts under `validation/artifacts/` and GitHub Actions runs
  carry executable evidence;
- source types, tests, and xtask checks carry implementation truth.

If future compression or implementation finds a still-real gap without a live
owner, record it in the owning GitHub issue or PR before expanding this file.

## Relationship To Existing Authority

Storage intent consumes, but does not replace, these authority surfaces:

- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` classifies this file as current
  spec and records its non-claim boundaries.
- `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, and generated
  `docs/CLAIM_REGISTRY.md` own publishing-facing claim guardrails.
- `docs/CONTROL_FORMAT_AND_JSON_POLICY.md` owns JSON and control-format
  boundaries for operator surfaces, durable records, and evidence artifacts.
- `docs/STORAGE_INTENT_SERVICE_OBJECTIVE_DESIGN.md` owns the focused
  service-objective envelope and typed refusal model.
- `docs/STORAGE_INTENT_RESULT_REFUSAL_EVIDENCE_DESIGN.md` owns the focused
  result/refusal evidence model.
- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` owns local and distributed
  receipt-authority boundaries where its scope applies.
- `docs/OPERATOR_UAPI_AUTHORITY.md`,
  `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`, and
  `docs/security/operator-authz-boundary.md` own operator surface and
  authorization constraints.
- Membership, timestamp, request, inode namespace, mounted transform, kernel
  residency, allocator, transport, cache, resource-governor, background-service
  framework, performance-gate, fault-catalog, and validation source modules
  own their source-backed mechanics.

When these surfaces conflict, source-backed runtime authority, generated claim
authority, and the more specific current spec govern the exact behavior. This
file governs only the storage-intent policy contract and honesty boundary.
