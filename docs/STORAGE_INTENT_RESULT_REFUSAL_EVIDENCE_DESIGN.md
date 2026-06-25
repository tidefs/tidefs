# Storage Intent Result/Refusal Evidence Design

Issue: #920
Date: 2026-06-25
Status: current design authority for storage-intent caller outcome evidence

This document defines the #920 storage-intent result/refusal evidence model.
It refines the compact #920 section in
`docs/STORAGE_INTENT_POLICY_AUTHORITY.md` into the caller-boundary record that
future model and runtime slices must encode.

The rule is:

> A storage-intent decision is not caller-visible truth until the result record
> names the policy, evidence cut, decision, receipt or blocker, response
> projection, retry law, and retention proof that made that answer legal.

TideFS must not turn no quorum, stale evidence, wrong trust domain, unsupported
media, reserve exhaustion, unsafe volatile cache, degraded-not-admitted state,
service-objective failure, rollout fence, action rollback, missing retention
proof, unsupported surface, or idempotent retry conflict into generic success,
generic timeout, generic `EIO`, or a hidden weaker acknowledgment.

## Non-Claims

This design does not implement runtime result projection, change POSIX errno
behavior, add a new response-registry runtime, or make storage-intent
architecture a validated product claim. It is a docs/design authority slice.

The older response-registry design remains classified as historical input in
`docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, and local refocus notes warn
against recreating response-registry scaffolding. #920 therefore composes the
current response-registry vocabulary already present in
`crates/tidefs-types-vfs-core/src/lib.rs`; it does not add policy-authority,
response-registry, truth-view, daemon, or parallel control-plane
infrastructure.

## Evidence Reviewed

- GitHub issue #920, including its gate disposition, acceptance criteria,
  expected write set, and validation tier.
- `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`, especially the media-native
  convergence gate, #913 query-snapshot law, #874 satisfaction loop, compact
  #920 result/refusal section, and implementation staircase.
- `crates/tidefs-storage-intent-core/src/lib.rs` for
  `StorageIntentEvidenceKind::ResultRefusalEvidence`,
  `StorageIntentEvidenceQuerySnapshot`, `StorageIntentReceipt`,
  decision-frontier records, action-execution records, and
  `StorageIntentRefusalReason`.
- `crates/tidefs-storage-intent-satisfaction/src/lib.rs` for #874
  satisfaction states and axes, including the `ResultRefusal` axis.
- `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md` and
  `crates/tidefs-types-vfs-core/src/lib.rs` for response-registry scope,
  truth-cut, render, refusal, retention, visible-answer, index, and recall
  vocabulary.
- `docs/STORAGE_INTENT_SERVICE_OBJECTIVE_DESIGN.md` for #915 objective state
  and refusal behavior.
- `docs/RAM_AUTHORITY_DESIGN.md`, `docs/MEMBERSHIP_AUTHORITY.md`,
  `docs/TRANSPORT_CLUSTER_AUTHORITY.md`, `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`,
  and `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` for neighbor laws that must
  reach callers through #920 instead of local status strings.
- `~/ai/docs/projects/tidefs/SCOPE_REFOCUS_2026-05-11.md`,
  `~/ai/docs/projects/tidefs/automation/WORKER_BRIEF.md`, and current TideFS
  workflow docs, which forbid new duplicated control-plane or
  response-registry scaffolding without a direct running-product need.

The required `~/ai/docs` searches found response-registry refocus material but
no separate active #920 process document beyond the TideFS/Nexus workflow
rules.

## Decision

`StorageIntentResultRefusalEvidence`, or an equivalent split model, is the
single storage-intent outcome record for caller-visible results. It is emitted
after policy, evidence-query, satisfaction, decision-frontier, admission,
action, service-objective, and receipt evidence have selected an outcome, and
before POSIX, block, control-plane, trace, operator, validation, or claim
surfaces compress that outcome.

The model owns these decisions:

- which storage-intent outcome class was selected;
- which policy revision, evidence cut, and decision frontier authorized that
  selection;
- which receipt was actually earned, or which hard gate/objective/action made
  success illegal;
- whether degraded-visible, cache-only, trial, staged, unsafe-visible, or
  blocked state can be shown;
- which response-registry scope, cut, render, refusal, retention, delivery,
  index, and recall refs the visible answer must use;
- what retry or idempotency class applies to the caller token;
- what retention and audit refs keep the proof replayable.

It does not own rendering. Response-registry materializes the canonical
envelope, render bundle, delivery commit, indexes, and recall bindings. #920
selects and cites the storage-intent truth that response-registry may render.

## Alternatives Considered

| Alternative | Decision |
| --- | --- |
| Adapter-local errno or completion status as authority | Rejected. It loses policy revision, evidence-cut, receipt, degraded state, and retry identity before traces or operators can inspect it. |
| Response-registry as the storage-intent policy engine | Rejected. Response-registry renders committed or refused truth; storage intent still owns policy/evidence outcome selection. |
| Receipt-only success/failure | Rejected. Receipts prove what was earned, but do not by themselves preserve stale-query refusals, scheduler defers, rollout holds, action rollback, unsupported-surface rendering, or retry conflicts. |
| Each consumer interprets #874 states locally | Rejected. `satisfied`, `converging`, `degraded-visible`, `unknown-evidence`, `blocked`, `refused`, and `unsafe-visible` must publish one shared result ref when they reach a caller or claim boundary. |
| A separate response-runtime crate for #920 | Rejected for this slice. Current refocus policy warns against duplicated response-registry scaffolding; the design composes existing docs and type vocabulary instead. |

## Record Shape

The record may land as one `StorageIntentResultRefusalEvidence` struct in
`tidefs-storage-intent-core`, as a focused result model crate selected by a
future implementation issue, or as equivalent records with the same required
field groups. The field groups below are the authority boundary.

| Field group | Required content |
| --- | --- |
| `result_identity` | Result id, request id, idempotency token, subject scope, operation class, caller/surface class, policy id/revision, rollout stage, result generation, temporal/frontier refs, and producer version. |
| `evidence_query` | #913 snapshot ref plus completeness, freshness, source-index generation, producer watermark, redaction generation, compaction generation, retention class, and query-refusal state used to derive the result. |
| `satisfaction_state` | #874 satisfaction/reconciliation ref, state, reason refs, satisfying receipt set, unknown or refused axes, and whether the state can be acted on by this caller class. |
| `decision_frontier` | #905 frontier ref, selected candidate, rejected candidates, unknown hard gates, score-vector refs, tie-breaker, defer/refusal reason, counterfactual baseline, and payback/harm anchors. |
| `receipt_outcome` | Earned `StorageIntentReceipt` when success or degraded-visible success is legal, including actual ack class, durability/RPO/RTO, placement width, volatility, lag, convergence, and pending work. |
| `failed_or_weakened_evidence` | Ordering, membership, trust/domain, capacity/reserve, recovery/degradation, rollout, isolation, temporal, media capability, service objective, action execution, attribution, retention, data-shape, layout, lifecycle, wear, cost, transport, metadata/namespace, RAM, prefetch/residency, and comparator blockers as applicable. |
| `degraded_visible` | #900/#874 degraded-visible state, source receipt set, reconstruction width, missing/corrupt/stale targets, no-quorum or partition state, RPO/RTO lag, repair obligation, visibility law, and whether the result may return bytes or ack completion. |
| `service_objective` | #915 objective ref and whether latency, tail, throughput, queue, RPO/RTO, wear, cost, isolation, or comparator objective was satisfied, degraded, blocked, refused, or not measured for this operation. |
| `admission_scheduler` | #862/#902/#898 lane, queue/admission result, throttle/defer state, budget owner, borrow/debt, reserve exemption, starvation or noisy-neighbor protection, and admission refusal. |
| `action_execution` | #911 action id, step state, idempotency/replay state, source protection, target verification, cutover/publication state, rollback/abort state, source-retirement blocker, and execution refusal. |
| `response_registry_projection` | `ResponseRegistryScopeClass`, `ResponseRegistryCutClass`, `ResponseRegistryRenderClass`, `ResponseRegistryRefusalClass` when any, `ResponseRegistryRetentionClass`, visible-answer ref, delivery commit ref, response index entry ref, recall binding ref, and delivery-conflict state. |
| `caller_projection` | POSIX errno/FUSE reply, block completion, control-plane JSON/API reply, trace result, operator explanation fieldset, validation row, claim-visible result, redaction mask, and backoff/retry hints where relevant. |
| `retryability` | One retry class from the table below, retry-after frontier or deadline when present, idempotent replay digest, delivery digest, duplicate/conflict refs, and unsafe-to-retry reason. |
| `retention_audit` | #910 proof-retention ref, response-registry retention/index refs, audit hold, replay depth, claim/performance/fault dependencies, compaction/redaction allowance, and safe purge frontier. |

### Outcome Classes

| Outcome class | Meaning |
| --- | --- |
| `receipt-success` | Requested floor was earned by the cited receipt and response-registry can render the selected cut. |
| `degraded-visible-success` | Weaker or partial state is legal only because policy, #900/#874, and #920 make degradation visible and preserve repair/lag obligations. |
| `cache-only-or-trial-success` | A cache, prefetch, staging, or trial result can be shown, but it is not durability, placement, source-retirement, or claim authority. |
| `deferred` | The operation waits for fresh evidence, capacity, rollout, repair, action progress, or scheduler admission without reporting success. |
| `blocked` | A repair, rollout, partition, stop ticket, unsafe surface, or action state prevents visible completion until external state changes. |
| `refused` | Policy or evidence says no legal result exists for this request as asked. |
| `unknown-evidence` | The cut is incomplete, stale, contradictory, redacted beyond use, compacted beyond authority, or unavailable for this caller class. |
| `unsafe-visible` | Policy explicitly admits a weaker/volatile mode, and the result must expose that weaker state without strengthening the receipt. |
| `delivery-conflict` | The same request or idempotency token would produce a different delivery or response digest. |

### Retry Classes

| Retry class | Caller meaning |
| --- | --- |
| `retry-safe` | Reissuing the same token redelivers the same digest or repeats only idempotent uncommitted work. |
| `retry-after-fresh-evidence` | Retry after the evidence-query frontier or named producer generation advances. |
| `retry-after-capacity` | Retry after capacity, reserve, budget, or queue pressure clears. |
| `retry-after-rollout` | Retry after policy publication, rollback, downgrade authorization, or convergence fence moves. |
| `retry-after-repair` | Retry after repair, rebuild, catch-up, source verification, or read-refresh obligation progresses. |
| `retry-conflict` | The token conflicts with an existing delivery, request shape, receipt, or replay digest. |
| `terminal-refusal` | Repeating the request cannot succeed without a different policy, surface, subject, or caller authority. |
| `unsafe-to-retry` | Repeating could duplicate non-idempotent side effects or weaken source protection. |

## Response-Registry Composition

#920 must store response-registry projection refs, not create a separate
rendering authority.

| Caller surface | Required response-registry projection |
| --- | --- |
| POSIX/FUSE read, write, fsync, fdatasync, mmap sync, lookup, or metadata operation | `CharterRead` or `CharterMutation` scope, `ReadAnchorExact`, `ReadAnchorDegraded`, `CommittedAuthority`, or `StopOrRefusal` cut, `PosixFilesystemAdapterWire` render, and a preserved typed refusal class before errno compression. |
| Block-volume write, flush, FUA, discard, or completion | `CharterMutation` scope, `CommittedAuthority` or `StopOrRefusal` cut, `BlockVolumeAdapterCompletion` render, and byte/status compression only after the #920 result exists. |
| Control-plane policy, admission, dry-run, status, or operator API | `ControlWrite`, `ControlRead`, or `RunbookStage` scope, JSON/API render, and explicit result/refusal fieldset refs. |
| Trace, explanation, truth view, performance row, fault row, or claim gate | `ExplanationQueryFieldset`, `TruthViewBundle`, `TestCampaignReport`, or refusal-only render with indexes and recall refs sufficient for replay. |
| Unsupported surface | `StopOrRefusal` cut, `UnsupportedCutOrSurface` refusal class, refusal-only render, and terminal or retry-after-surface-change hint. |

Response-registry cut selection is constrained:

1. `CommittedAuthority` requires a committed receipt, publication, or stage
   result. Prepared, staged, cache-only, or trial state cannot claim it.
2. `ReadAnchorExact` requires exact read anchors and freshness proof.
3. `ReadAnchorDegraded` requires #900/#874 degraded-visible proof and #920
   degraded visibility refs.
4. `StopOrRefusal` is mandatory for refused, blocked, unsafe-to-render, or
   delivery-conflict outcomes.
5. `RecallArchive` may project preserved artifacts, but may not rerun
   storage-intent authority or upgrade archived truth.

## Derivation Law

1. Start from one #913 evidence-query snapshot. If the snapshot lacks identity,
   policy revision, subject scope, freshness frontier, source replay anchor, or
   required family freshness for the caller class, the result is
   `unknown-evidence`, `deferred`, `blocked`, or `refused`; it is never generic
   success.
2. Consume #874 satisfaction state when the result projects policy
   satisfaction. Callers may not reinterpret `satisfied`, `converging`,
   `degraded-visible`, `unknown-evidence`, `blocked`, `refused`, or
   `unsafe-visible` from local subsystem facts.
3. Consume #905 decision-frontier records before any selected candidate can
   become success. Rejected or unknown hard gates remain cited in failure refs.
4. Success requires the exact earned `StorageIntentReceipt` for the result.
   A receipt weaker than the requested floor may only project as
   `degraded-visible-success`, `cache-only-or-trial-success`, or
   `unsafe-visible` when policy and visibility law permit.
5. #915 objective failure is a hard result input. Latency, tail, throughput,
   queue, RPO/RTO, wear, cost, isolation, or comparator failure cannot be
   hidden behind a receipt that only proves durability.
6. #862/#902/#898 admission and scheduler state determines whether a result is
   admitted, throttled, deferred, over budget, reserve-exempt, or refused.
7. #911 action state is part of the caller result whenever relocation, rebake,
   repair, catch-up, cutover, rollback, or source retirement affects what the
   caller sees.
8. #910 retention/index proof is part of completion for any result promised to
   traces, operators, validation rows, claims, audit, or idempotent replay.
9. Surface compression happens last. POSIX errno, block completion status, JSON
   reply shape, trace event, and operator fieldset must preserve a ref to the
   canonical result/refusal evidence.

## Consumer Contract

| Consumer | Required behavior |
| --- | --- |
| #842 ack receipts | Emit #920 refs for caller-visible write, fsync, fdatasync, O_DSYNC, FUA, namespace intent, and fsyncdir outcomes. A weaker receipt cannot masquerade as the requested floor. |
| #877 read serving | Return exact, degraded-visible, refreshed, blocked, refused, cache-only, or unknown outcomes through #920 instead of direct cache/store success. |
| #862 scheduling/admission | Publish throttle, defer, starvation, noisy-neighbor, reserve, and queue outcomes in a form #920 can cite. |
| #843 placement planner | Preserve illegal, unknown, rejected, selected, and counterfactual candidate refs when a placement decision reaches a caller-visible or claim-visible outcome. |
| #848 relocation governor | Preserve source receipts, target verification, payback/cost/wear, cooldown, and source-retirement blockers in #920-visible outcomes. |
| #911 action execution | Expose step, cutover, rollback, no-cutover, abort, verification, and idempotency state through #920 when a caller or operator can observe the action. |
| #912 attribution | Bind measurement outcomes to the #920 result when a performance row, prediction update, or claim-visible outcome depends on that operation. |
| #849 explanation | Render result id, outcome class, policy revision, evidence cut, receipt or blocker refs, degraded state, retry class, response projection, and retention proof. |
| #850 performance rows | Include result/refusal preservation rows so objective or performance evidence cannot pass while callers receive generic statuses. |
| #863 fault validation | Assert forbidden outcome collapse under stale evidence, no quorum, partition, wrong trust domain, unsupported media, capacity exhaustion, rollback, retention gaps, and retry conflicts. |
| #875 claims | Treat missing #920 refs as claim blockers for storage-intent durability, performance, service-objective, recovery, media-role, and successor wording. |
| #874 satisfaction | Publish states that #920 can consume; do not require each caller to reconstruct satisfaction from raw evidence families. |
| POSIX/block/control/traces | Compress only after the #920 evidence and response-registry refusal/render class exist, while preserving refs for operator and audit surfaces. |

## Validation Scenarios

Future implementation slices must include focused validation for at least these
scenarios. This docs slice records the expected proof shape.

| Scenario | Expected result/refusal proof |
| --- | --- |
| Stale evidence query | `unknown-evidence` or `retry-after-fresh-evidence`, #913 stale family refs, response `StopOrRefusal`, no success receipt. |
| No legal quorum | `refused` or `blocked`, membership/quorum/fence refs, failed hard gate, no generic `EIO`. |
| Partition or split-brain hold | `blocked`, stop/hazard response refusal, membership/fence refs, retry-after-repair or terminal refusal according to policy. |
| Wrong trust domain | `refused`, trust/domain and authorization refs, response auth/policy refusal, no remote durable success. |
| Unsupported or unsafe media role | `refused` or `unsafe-visible`, media-capability refs, cache/volatile/PMem refusal, no strengthened receipt. |
| Capacity or reserve exhaustion | `deferred`, `blocked`, or `refused`, capacity/admission and budget refs, response reserve/budget refusal. |
| Degraded read not admitted | `refused` or `blocked`, source receipts and recovery refs, `StopOrRefusal`, no bytes or exact-read claim. |
| Degraded read admitted with repair obligation | `degraded-visible-success`, source receipt set, reconstruction width, repair obligation, RPO/RTO lag, degraded read cut. |
| Service-objective failure | `deferred`, `blocked`, or `refused`, #915 objective state and failed metric/budget refs, no hidden success. |
| Scheduler throttle or defer | `deferred`, admission lane/queue/throttle refs, retry-after-capacity or retry-after-fresh-evidence hint. |
| Action rollback or no-cutover | `blocked` or `refused`, #911 rollback/no-cutover refs, source-retirement blocker, no committed-authority cut. |
| Missing retention or index proof | `blocked` or `refused`, #910 and response-registry delivery/index gap refs, no recall/audit claim. |
| Unsupported surface render | `refused`, unsupported-surface response refusal, refusal-only render, terminal or surface-change retry hint. |
| Idempotent retry conflict | `delivery-conflict` or `retry-conflict`, request token, previous digest, conflicting digest, response duplicate-delivery conflict. |
| POSIX errno compression | Linux-facing errno exists only after #920 and response-registry refusal class; trace/operator refs preserve the precise reason. |

## Follow-Up Mapping

This issue's design slice is satisfied by this document and the umbrella
authority cross-link. Implementation remains split across consumers that
already own non-overlapping behavior:

| Follow-up surface | Issue or owner | Expected work |
| --- | --- | --- |
| Result/refusal model record and predicates | #920 implementation follow-up or focused child issue if Nexus splits it | Add stable no-std record fields, outcome/retry enums, response projection refs, and fail-closed validation predicates. |
| Ack receipt caller projection | #842 | Attach result refs to local ack/fsync/FUA outcomes. |
| Read-serving projection | #877 | Route exact, stale, degraded, cache-only, and refused read outcomes through #920 refs. |
| Scheduler/admission projection | #862/#898/#902 | Emit admission/throttle/defer/budget refs consumable by #920. |
| Placement and relocation outcomes | #843/#848/#911 | Preserve decision/action/source-retirement refs when movement or placement reaches a caller or claim boundary. |
| Operator explanations and traces | #849 | Render the result fieldset without rediscovering policy truth. |
| Performance/fault/claim gates | #850/#863/#875 | Add forbidden-collapse checks and claim blockers for missing #920 evidence. |
| Response-registry integration | Existing response-registry vocabulary and any future running-product issue | Materialize envelope, render, delivery, index, and recall from #920-selected truth without adding duplicate scaffolding in this docs slice. |
