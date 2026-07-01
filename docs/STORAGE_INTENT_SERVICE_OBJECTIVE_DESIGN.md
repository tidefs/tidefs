# Storage Intent Service Objective Design

Issue: #915
Date: 2026-06-21
Status: current design authority for storage-intent service-objective evidence
Last updated: 2026-06-25 - model-projection gate slice

This document narrows the service-objective part of storage intent into an
implementation-ready contract. It defines the evidence that lets TideFS decide
whether a candidate write path, placement, RAM authority mode, relocation,
read-serving path, validation row, or product claim is allowed for the
declared workload and environment.

The rule is:

> A service objective is a hard evidence envelope. It is not a benchmark label,
> a tier name, or a score bonus.

TideFS can be fast only when it can say which workload, operation, medium,
topology, queue, durability floor, cost model, and failure state the speed
belongs to. A low p50 on local NVMe, a high streaming throughput number, or a
warm RAM read hit does not prove a small-sync WAL objective, a VM FUA
objective, a WAN geo objective, or a better-than-OpenZFS/Ceph/DRBD claim.

## Non-Claims

This document does not implement the service-objective record, placement
planner, scheduler, performance gate, measurement attribution path, operator
UAPI, or claim gate. It does not prove that current TideFS runtime code meets
any latency, tail, throughput, WAN, RAM, flash-wear, sync, or competitor
comparison objective.

It defines the evidence and refusal shape that follow-up source work must
encode. Runtime and product claims still require issue-scoped implementation,
focused validation, and claim evidence.

## Evidence Reviewed

- GitHub issue #915, including the requirement that service objectives bind
  workload, operation, topology/media, latency, throughput, queueing, RPO/RTO,
  isolation, cost, wear, comparator, and refusal state.
- `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`, especially the native media-role
  convergence gate and the service-objective envelope section.
- GitHub issue #841 / PR #959 for the storage-intent core record surface that
  should carry or reference the first implementation slice once it lands.
- GitHub issues #842, #843, #846, #847, #848, #849, #850, #862, #874, #875,
  #904, #905, #912, #913, #920, #926, #928, and #931 as direct consumers or
  required evidence neighbors.
- `docs/RAM_AUTHORITY_DESIGN.md`, because RAM-fast objectives must distinguish
  cache, volatile RAM authority, intent-backed RAM, and PMem durability.
- `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`, because durable POSIX barriers
  cannot be weakened by a latency objective.
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md`, because cache warmth is not
  authority.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md`, because WAN and replicated objectives
  must consume path, epoch, and fencing evidence instead of assuming RDMA.
- source-owned governor, scheduler, and admission paths, because queue, memory,
  CPU, and background-work budgets must be visible service-objective inputs.

The required `~/ai/docs` searches found no additional service-objective
process document beyond the general TideFS and Nexus workflow rules.

## Service Objective Versus Neighbor Evidence

Service objectives are not a replacement for other storage-intent evidence.
They are the compiled envelope those records must satisfy.

| Neighbor evidence | What it owns | What #915 owns |
| --- | --- | --- |
| #845 workload prediction | Observed and predicted access shape, confidence, decay, and signal cost. | The objective that says which workload envelope is policy-relevant and how much confidence is enough for each action class. |
| #904 media capability | Whether a target can legally play a media role. | Which media/topology profile is allowed for the objective and which missing capability makes the objective refused. |
| #905 decision frontier | Candidate set, hard gates, score vector, winner, counterfactuals, and tie-breakers. | Which objective gates the decision before scoring and which objective id the score claims to optimize. |
| #912 measurement attribution | Whether a measured delta belongs to a policy/action and scope. | Which objective the measurement may train, satisfy, cool down, or claim. |
| #850 performance rows | Validation artifacts and pass/fail rows. | The envelope each row is measuring; rows without an objective are telemetry, not storage-intent closure. |
| #875/#928/#931 claims | Product claim ids, comparator basis, and allowed wording. | The exact workload/environment envelope a claim may use. |

## Evidence Record Shape

`StorageIntentServiceObjectiveEvidence` or an equivalent record must bind the
following fields. If the first implementation splits the record across #841 and
a smaller model crate, these field groups remain the authority boundary.

| Field group | Required content |
| --- | --- |
| `objective_identity` | Objective id, producer id, policy id/revision, rollout/stage ref, subject scope, operation class, generation, and temporal refs. |
| `workload_scope` | Workload class, phase, request mix, subject/range/object cohort, tenant or budget owner, predictor refs, confidence/action class, observation window, and #913 query snapshot. |
| `operation_semantics` | Sync write, fsync, fdatasync, O_DSYNC, FUA/barrier, stable write, metadata op, fsyncdir, read, prefetch, mmap sync, direct I/O, repair, rebuild, relocation, rebake, geo catch-up, archive restore, RAM authority, or PMem durable role. |
| `ack_and_recovery_floor` | Required ack class, durable intent or full-placement floor, convergence debt, degraded-visible permission, RPO/RTO, stale-read law, partition/no-quorum behavior, and unsafe/volatile allowance if explicitly requested. |
| `latency_envelope` | p50/p95/p99 or stricter percentiles, max queue/admission time, max device/transport dwell, jitter/variance limits, tail-amplification limit, warmup/censoring law, and breach/refusal thresholds. |
| `throughput_envelope` | Minimum or maximum throughput, foreground/background class, burst window, dwell window, concurrency, queue depth, coalescing/batching profile, and backpressure law. |
| `topology_media_profile` | RAM/PMem/NVMe/SSD/ZNS/SMR/HDD/remote/object/archive eligibility, rack/DC/WAN/internet scope, RDMA-present or RDMA-absent path class, thermal/health state, trust/domain refs, and residency constraints. |
| `isolation_budget_refs` | #902 tenant/isolation refs, #862 scheduler/admission refs, fair-share, burst/borrow/debt, starvation state, noisy-neighbor harm, throttle/refusal state, and protected p99 owners. |
| `capacity_cost_wear_refs` | #898 capacity/reserve refs, #844 flash-wear/WAF refs, #856 egress/capacity/power/operator-money refs, movement debt, signal/write amplification, and reserve-exemption refs. |
| `decision_action_refs` | #905 decision-frontier refs, #911 action-execution refs, #926 preflight refs, #920 result/refusal refs, and #910 retention refs needed to replay why the objective was admitted, blocked, or refused. |
| `measurement_claim_refs` | #912 attribution refs, #850 performance row ids, #863 fault rows, #875 claim ids, #928 comparator-evidence refs, #931 legacy-claim audit refs, and allowed wording scope. |
| `objective_state` | `satisfied`, `converging`, `degraded-visible`, `cache-only`, `unknown-evidence`, `blocked`, `refused`, or `unsafe-visible`, with typed reason refs. |

## First Model Projection Contract

The first source implementation may live in `tidefs-storage-intent-core` or a
narrow #915 model crate, but the projection must behave as one compiled
contract. Splitting fields across helper structs is fine only when the public
record still carries enough identity, scope, evidence refs, and state to answer
"what exact envelope was admitted, measured, refused, or claimed?"

The model projection must encode these groups as typed values rather than free
text:

| Projection group | Required typed shape |
| --- | --- |
| Identity and scope | Objective id, policy id/revision, rollout/stage ref, producer, subject scope, generation, temporal ref, and evidence-query snapshot ref. |
| Workload binding | Workload class, phase, request mix, range/object cohort, action class, prediction/confidence refs, and allowed missing-evidence state. |
| Operation floor | Operation semantics, ack/durability floor, stable-write/FUA/barrier law, stale-read permission, RPO/RTO, partition/no-quorum treatment, and explicit volatile or unsafe-visible allowance when policy permits it. |
| Latency and tail | Percentile targets, max queue/admission time, max device/transport dwell, jitter/variance, tail amplification, warmup/censoring, and breach state. |
| Throughput and dwell | Floor, ceiling, foreground/background class, burst window, dwell window, batching/coalescing, dirty-window, and backpressure/refusal law. |
| Scheduler and isolation | Scheduler lane/admission refs, protected p99 owner, tenant/budget owner, fair-share, borrow/debt, starvation, noisy-neighbor, reserve-exemption, and throttle/defer state. |
| Environment | Media and topology profile, RAM/PMem/NVMe/SSD/HDD/object/archive class, rack/DC/WAN/internet scope, RDMA-present or RDMA-absent transport, thermal/health state, trust/domain refs, and media-capability refs. |
| Cost and movement | Capacity/reserve refs, write-amplification, flash-wear, movement debt, egress, power, capacity, operator-money, payback, cooldown, source-retirement, and retention refs. |
| Consumer refs | Decision-frontier, action-execution, result/refusal, performance-row, fault-row, measurement-attribution, comparator, claim, and evidence-retention refs. |
| State and reasons | Satisfaction/refusal class plus typed reason refs for unknown, stale, contradicted, out-of-cut, degraded-visible, cache-only, blocked, refused, or unsafe-visible state. |

Zero, absent, or unknown limits are not infinite limits. A missing p99 target,
throughput bound, queue cap, cost budget, or comparator baseline is usable only
when the objective state explicitly records that the dimension is
policy-unconstrained for this scope. Otherwise the record must be unknown,
blocked, degraded-visible, cache-only, unsafe-visible, or refused.

The first predicates should return typed state, not a lossy boolean:

| Predicate or query | Required meaning |
| --- | --- |
| `identity_is_bound` | Policy id/revision, objective id, subject scope, generation, and rollout/stage refs are all non-sentinel and internally consistent. |
| `scope_matches` | Workload, phase, operation, tenant/budget owner, media/topology, transport, ack shape, and failure state match the candidate, row, attribution verdict, or claim. |
| `has_required_evidence_cut` | The #913 snapshot contains complete-for-purpose fresh authority refs for every required field family and records typed state for missing or stale families. |
| `can_gate_candidate` | A planner, scheduler, read-serving, relocation, or prefetch/residency candidate either satisfies the required envelope before scoring or gets a rejected/degraded/refused state with reason refs. |
| `allows_performance_row` | A #850 row measures this objective id, workload/environment scope, operation semantics, and ack/degradation shape without inventing row-local semantics. |
| `allows_attribution_transfer` | A #912 verdict may train, satisfy, cool down, or claim this objective only within its recorded scope and evidence cut. |
| `allows_claim_wording` | A #875/#928/#931 claim may use successor, fast, low-latency, high-throughput, WAN, RAM, wear, or comparator wording only when objective, attribution, query, comparator, and claim refs all match. |

These predicates are hard-gate helpers. They must not score an average
throughput win, cache hit, fast local device, or incumbent-comparison row as a
partial substitute for an unmet required objective.

## Access Pattern Pass

The first design pass is the access pattern. TideFS must not optimize an
unidentified workload, and it must not carry a win from one pattern into
another pattern without #912 attribution and #913 query evidence.

| Pattern | Objective dimensions that matter | Common illegal shortcut |
| --- | --- | --- |
| Small sync WAL | fsync/O_DSYNC p99, durable-intent latency, replay ordering, queue dwell, foreground isolation, reserve headroom. | Treating aggregate write bandwidth or async batching as durable sync success. |
| VM image FUA | flush/FUA latency, ordered dirty window, block atomicity, capacity reserve, tail under concurrency. | Hiding volatile device cache or unsupported FUA behind a fast device label. |
| Metadata storm | create/unlink/rename/xattr/fsyncdir p99, metadata locality, namespace intent durability, directory hot-set behavior. | Letting bulk data or global commit work damage protected metadata p99. |
| Hot read serving | read p99, hit dwell, freshness, source authority, cache-only versus RAM authority, eviction law. | Treating cache warmth as placement authority or comparator evidence. |
| Read-mostly scan | sustained read throughput, prefetch budget, one-pass scan detection, cache pollution limit, device seek cost. | Promoting a one-pass scan into authority-changing hot placement. |
| Streaming ingest | throughput floor, coalescing shape, media write amplification, flash bypass or staging law, capacity admission. | Spending sync, repair, evacuation, or flash-wear reserves for bulk speed. |
| Mixed source tree | metadata/data coupling, small-file fanout, hot manifests, clone/layer reuse, dedup/compression value. | Moving only byte payloads while metadata p99 or namespace receipts fail. |
| Time-series/log aggregation | append locality, retention/TTL, compression value, cold-rollover shape, background compaction budget. | Rewriting flash repeatedly for short-lived data without payback proof. |
| Analytics/ML training | sequential throughput, repeated scan epochs, cache pollution, object/archive restore cost, WAN egress. | Treating high bandwidth as permission to evict hot sync or RAM-serving work. |
| Archive restore | restore RTO, request/egress cost, integrity refs, large-object shape, cold placement durability. | Calling object/archive storage durable POSIX or low-latency by label. |

## Prefetch And Residency Action Floors

#967 consumes service objectives but does not become authority here. The #915
record must still express the minimum objective state for prefetch, residency,
promotion, demotion, and source-retirement-adjacent decisions so #967 can fail
closed instead of inferring legality from a warm cache or a cheap medium.

| Action floor | Required #915 expression | Illegal shortcut |
| --- | --- | --- |
| No prefetch | Objective either has no latency/payback requirement for speculative fetch or policy refuses prefetch for this scope. | Treating absence of evidence as permission to cache or move data. |
| Bounded readahead | Read/scan phase, range cohort, p99 or throughput target, cache-pollution budget, and droppable speculative lane. | Promoting one-pass scans into durable hot placement. |
| Cache-only serving trial | Cache-only objective state, freshness law, hit dwell, eviction budget, and non-authority marker. | Claiming RAM/flash authority or comparator success from trial hits. |
| Staged restore | Archive/object restore phase, restore latency/RPO, integrity verification, egress/cost budget, and handoff/refusal state. | Serving staged bytes as POSIX durable authority before replacement receipts. |
| Persistent hot serving | Read-serving objective with authority/freshness refs, source media, target media, protected tenant budget, and dwell/cooldown law. | Letting another tenant's p99 pay for a hot-set promotion. |
| Authority-changing promotion | Durable authority requirement, source/target media capability, ack/recovery floor, capacity reserve, wear/cost/payback refs, and action-execution refs. | Treating cache residency or prediction confidence as receipt replacement. |
| Demotion | Coldness/payback objective, RPO/RTO and stale-read treatment, retention/lifecycle refs, and read-serving fallback state. | Moving data to slow/remote media while hiding foreground tail damage. |
| Source-retirement-affecting movement | Replacement receipt, old-receipt retirement frontier, recovery/degradation refs, action-execution success, retention refs, and refusal law. | Retiring the source because the target benchmarked faster or cheaper. |

## Media And Topology Pass

The second design pass is media and topology. An objective must say which
medium and distance profile it applies to and what evidence makes that profile
legal.

| Profile | Legal objective use | Required refusal when evidence is weak |
| --- | --- | --- |
| Volatile RAM | Unsafe/volatile work or explicitly volatile authority with loss semantics. | Durable sync, full placement, or source retirement must refuse without durable intent or placement receipts. |
| Intent-backed RAM | RAM-speed serving while durable local or quorum intent earns the barrier. | If ordering, replay, capacity, or durable-intent evidence is stale or missing, the objective is volatile/cache-only or refused. |
| PMem durable | Durable low-latency intent or placement when persistence-domain and flush/fence evidence are current. | PMem label, DAX mapping, or benchmark speed alone cannot satisfy durable objectives. |
| NVMe/SSD/flash | Low latency or hot serving when media capability and wear/WAF budgets allow it. | Unknown flush/FUA, unsafe cache, exhausted wear reserve, or missing WAF is not a zero-cost fast path. |
| ZNS/SMR | Sequential bulk, archive-like, or shape-aware placement when write-pointer and reset cost match the workload. | Random metadata-hot or sync objectives refuse without compatible layout evidence. |
| HDD | Full placement, cold data, sequential ingest, or defrag/locality objectives when seek/payback evidence holds. | Defrag or hot-sync claims refuse when p99 seek cost, rebuild risk, or locality payback is unproved. |
| Remote durable | Geo, backup, receive, or remote durable placement with commit semantics, trust, path, lag, and cost evidence. | Remote label or reachable endpoint cannot satisfy local sync latency or durable commit semantics. |
| WAN/internet | Correctness without RDMA; async, lagged, or geo objectives with visible RPO and cost. | RDMA absence is not correctness failure, but hidden lag, jitter, egress, or trust mismatch is objective refusal. |
| Object/archive | Cold/archive/restore objectives with integrity, retention, restore, and cost evidence. | POSIX FUA, hot metadata, low-latency sync, or block-device claims refuse. |

## Operation And Failure Pass

The third design pass is operation and failure. The objective remains legal
only while failures and degradation still match the envelope.

| Condition | Objective requirement |
| --- | --- |
| Crash or power loss | Durable objectives cite ordering, replay, media persistence, flush/fence, committed-root or durable-intent publication, and recovery evidence. |
| Device reset or namespace drift | Durable and placement objectives revalidate #904 generation, namespace identity, health, and stale-probe state before new receipts or source retirement. |
| Network jitter or loss | WAN and remote objectives carry #846 path evidence, #903 lag/freshness, #900 degradation, and visible RPO/refusal state. |
| Partition or fencing ambiguity | Quorum, replicated volatile RAM, remote durable, and geo objectives refuse stronger receipts until membership/fencing evidence is lawful. |
| Wear or cost pressure | Flash, relocation, preflight, signal persistence, and WAN objectives throttle, defer, or refuse when #844/#856/#902 budgets would be violated. |
| Noisy-neighbor pressure | Background ingest, rebuild, relocation, scan, and archive restore objectives yield before protected p99 or reserve owners are harmed. |
| Policy rollout | Objectives bind the policy revision used for admission and remain interpretable across rollback, supersession, mixed-revision convergence, and receipt retirement. |
| Measurement contradiction | Attribution conflicts, low sample mass, phase change, confounders, or comparator mismatch can cool down or diagnose, but cannot satisfy the objective. |

## Hard Laws

1. A required service objective is a hard gate before scoring. The planner or
   scheduler must reject, defer, degrade visibly, block, or refuse candidates
   that cannot meet the envelope.
2. Objective state is scoped. Evidence for one policy revision, workload phase,
   tenant, media profile, topology, transport, ack class, or failure state does
   not satisfy another objective without explicit attribution and query
   snapshot proof.
3. Throughput cannot buy hidden latency damage. Any borrowing from protected
   sync, repair, evacuation, wear, capacity, egress, or tenant-isolation budgets
   must cite budget evidence and expose throttle/defer/refusal state.
4. Objective failure never authorizes hidden `sync=disabled` semantics. Durable
   POSIX sync, FUA, RAM authority, and geo intent require the requested receipt
   or a typed refusal.
5. Cache-only success is not authority success. Cache, prewarm, and serving
   trials can satisfy cache objectives only when the objective state says
   `cache-only`.
6. RDMA is an accelerator, not a correctness requirement. WAN/internet
   objectives must state the RDMA-absent baseline when correctness or claims
   need to hold over ordinary transport.
7. Unknown cost, wear, path, freshness, media capability, trust, comparator, or
   attribution evidence is not zero. It is unknown, blocked, degraded-visible,
   or refused according to policy.
8. Defrag, compaction, rebake, relocation, rebuild, and geo catch-up objectives
   must preserve old receipts until replacement receipts, action-execution,
   recovery, cost, wear, and payback evidence permit source retirement.
9. Performance rows and claims must cite objective ids. A row or claim without
   a matching objective may be diagnostic, but it cannot prove storage-intent
   satisfaction or successor wording.

## Consumer Contract

| Consumer | Required behavior |
| --- | --- |
| #842 local ack receipts | Emit the earned receipt separately from objective satisfaction; a sync reply may earn durable intent while the service objective reports pending full placement or degraded-visible convergence. |
| #843 placement planner | Apply objective hard gates before score vectors, preserve rejected objective reasons, and keep low-confidence or unknown dimensions out of optimistic scoring. |
| #846 transport path evidence | Provide latency, bandwidth, loss, carrier, RDMA-present/RDMA-absent, and freshness evidence that objective envelopes can cite. |
| #847 RAM authority | Keep cache, volatile RAM authority, intent-backed RAM, and PMem durable objectives distinct all the way to receipt and explanation. |
| #848 relocation governor | Admit movement only when objective payback, foreground p99 protection, source-retirement safety, wear/cost budgets, and cooldown evidence all hold. |
| #849 operator UAPI | Render objective id, scope, state, missing evidence, degraded-visible state, refused reason, and the failures or costs the objective is protecting. |
| #850 performance gates | Require service-objective refs for storage-intent rows and prevent cross-workload or cross-topology row reuse without #912/#913 proof. |
| #862 scheduler | Map objective latency, queue, burst, dwell, isolation, and budget refs to lanes and backpressure, including refusal state. |
| #874 satisfaction reconciler | Publish objective satisfaction, convergence, degraded-visible, unknown, blocked, refused, cache-only, or unsafe-visible state from a coherent #913 cut. |
| #875/#928/#931 claims | Treat objective mismatch or missing comparator basis as a claim blocker, not weaker wording that can still imply superiority. |

## Runtime Follow-Up Boundaries

This design maps to existing implementation issues:

| Surface | Owner | Expected write set |
| --- | --- | --- |
| Core service-objective refs and enum vocabulary | #841 / #959 or #915 follow-up | `crates/tidefs-storage-intent-core/` or a narrow service-objective model crate |
| Objective evidence record and predicates | #915 | storage-intent model crate selected after #959 lands, focused tests |
| Workload/prediction input records | #845 | `crates/tidefs-performance-contract/` and bounded signal producers |
| Decision hard gates and score preservation | #905 / #843 | decision-frontier model plus placement planner integration |
| Scheduler/admission enforcement | #862 | scheduler/admission crate selected by that issue |
| Performance and fault validation rows | #850 / #863 | performance contract, validation matrices, and focused artifacts |
| Measurement attribution | #912 | attribution record/model crate or validation support selected by that issue |
| Operator explanation | #849 | `apps/tidefsctl/` and operator docs |
| Claim gate consumption | #875 / #928 / #931 | `validation/claims.toml`, generated claim registry, and claim-gate tests |

No implementation issue may treat a service objective as a benchmark label,
current media class, current queue priority, cache hit, or incumbent name. The
record must preserve objective scope, evidence refs, and typed refusal state.
