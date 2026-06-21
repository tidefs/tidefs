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
| `StorageIntentMembershipEvidence` | Reference projection of membership epoch, committed roster, quorum-set identity, witness/data role, failure-domain binding, drain/fence state, and split-brain hazard state owned by #750. |
| `StorageIntentOrderingEvidence` | Barrier, dependency, replay, dirty-epoch, intent-sequence, commit/root publication, and completion evidence owned by #894. |
| `StorageIntentTrustEvidence` | Security, administrative-domain, tenant-domain, key-epoch, authorization, audit, and compromise/quarantine evidence owned by #897 and sourced from the security, authz, transport, and transform authorities. |
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
- local, node, rack, datacenter, WAN, internet, and geo failure-domain
  dimensions;
- membership epoch, committed-roster, quorum-set, witness-role, fence/drain,
  and split-brain legality;
- trust/security-domain legality, including peer identity, admin/security
  domain, tenant/policy domain, key epoch, authorization, audit, compromise,
  quarantine, and regulatory/residency refusal state;
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
| `media_role_policy` | Which media classes may hold intent, metadata, serving data, cold data, read cache, or scratch data. |
| `workload_shape` | Workload envelope the planner should optimize for without changing hard guarantees. |
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
- the effective guarantee floor and failure-domain floor;
- the ordering, replay, barrier, dirty-epoch, and dependency requirements;
- the membership epoch, quorum, witness, drain/fence, and split-brain evidence
  requirements;
- the trust/security-domain, key-epoch, authorization, audit, compromise, and
  residency requirements;
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

### StorageIntentReceipt

Every successful acknowledgment returns or records a `StorageIntentReceipt`
projection. It names what was earned, not merely what was requested.

The receipt must bind:

- requested policy id and revision;
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
- failure domains represented in the receipt;
- media class and persistence semantics for each receipt participant;
- known missing work such as geo lag, archive conversion, or background
  full-placement completion;
- `lost_if` and `survives` summaries suitable for operator explanation.

Receipts are not marketing. They are the bridge between caller semantics,
crash recovery, placement, and operator UAPI.

## Satisfaction Reconciliation Loop

Storage intent is a closed control loop, not a one-shot planner output. #874
owns the read-only reconciler that compares one compiled policy revision with
the current evidence set and publishes the satisfaction state other subsystems
must act on.

The reconciler consumes policy snapshots, ack receipts, placement receipts,
transport path evidence, media-wear and non-wear cost ledgers, workload signal
snapshots, scheduler admission evidence, RAM authority receipts, relocation
state, and validation artifacts. It does not recompute policy, select new
placement, retire old receipts, emit ack receipts, or execute relocation. Its
job is to make the current truth machine-readable:

| State | Meaning |
| --- | --- |
| `satisfied` | Current receipts and evidence satisfy the compiled policy revision. |
| `converging` | The ack floor was earned, but full placement, geo, archive, or cost convergence remains pending and visible. |
| `degraded-visible` | The policy explicitly permits a weaker temporary state, and the weaker state is surfaced to callers/operators. |
| `unknown-evidence` | Required evidence is absent, stale, malformed, or contradictory, so satisfaction cannot be inferred. |
| `blocked` | Repair, relocation, geo catch-up, evidence refresh, or reserve recovery is required before success can be claimed. |
| `refused` | No legal receipt set can satisfy the policy under current media, topology, or cost constraints. |
| `unsafe-volatile` | The policy intentionally requested weaker volatile/unsafe behavior and the receipt truth exposes that weaker guarantee. |

Missing, stale, malformed, under-width, wrong-epoch, wrong-failure-domain,
wrong-lifecycle, unknown-cost, unknown-WAF, cache-only, or contradictory
evidence cannot satisfy a durable, geo, or low-latency floor by accident. They
must become an explicit unknown, blocked, degraded, refused, or unsafe-visible
state according to the compiled policy's degradation law.

This loop is what keeps the whole design native. A predictor may believe a
range is hot, a planner may propose a move, a scheduler may admit a lane, and a
relocation worker may publish replacement bytes, but TideFS only claims policy
satisfaction when the reconciler can cite the receipts and evidence that prove
it. Conversely, when evidence decays or policy strengthens, the reconciler is
the common trigger for visible convergence, repair, relocation, or refusal
instead of each subsystem inventing its own drift detector.

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

1. Observe request, subject, lifecycle, device, path, and policy signals.
2. Cite the compiled storage-intent policy revision for the operation or
   planning epoch.
3. Reconcile current receipts and evidence into a satisfaction state.
4. Compute a confidence-scored workload vector.
5. Generate candidate acknowledgment, serving, durable-placement, or
   relocation plans.
6. Reject candidates that do not meet hard guarantee, failure-domain, trust,
   lifecycle, capacity, wear, or operator-policy constraints.
7. Estimate latency, tail, throughput, write amplification, recovery risk, and
   money/egress cost for remaining candidates.
8. Reserve placement, transport, dirty-byte, and wear budgets.
9. Admit and dispatch the selected work through the scheduler/resource-governor
   lanes that match its action class.
10. Publish receipts before claiming stronger placement or retiring older
    locators.
11. Reconcile the new evidence back into a satisfaction state.
12. Feed observed result, payback, cooldown, and refusal evidence back into
    the predictor.

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

The scheduler consumes compiled policy, workload signals, resource-governor
pressure, media/cost ledgers, and transport evidence. It may delay,
backpressure, drop speculative work, or return typed refusals according to
policy. It may not weaken an acknowledgment receipt, hide volatile behavior, or
retire old placement receipts before replacement receipts exist.

Admission evidence must be observable:

- policy id and revision used for classification;
- action class and prediction confidence used for classification;
- selected lane and priority class;
- queue time and dispatch time;
- resource budget that throttled or refused the operation;
- starvation override or repair escalation reason;
- whether the work was dropped, deferred, admitted, or completed.

This is the mechanism that lets TideFS optimize both latency and throughput
without turning one tenant's bulk stream, rebuild, or geo catch-up into another
tenant's p99 failure.

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
- digest/checksum evidence for placement, degraded, or reconstructed bytes;
- transport/path evidence and lag evidence for remote or geo sources;
- stale, missing, or contradictory evidence reason when a candidate is rejected.

Cache-only or serving-trial hits may reduce latency while their anchors and
fences remain valid, but they do not satisfy durable placement, RAM authority,
geo, or successor claims by themselves. If an anchor is stale, the read must
invalidate, refresh, repair, degrade visibly, or refuse according to policy. It
must not fall through to a topology-only guess and call the result satisfied.

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

## Planner Scoring

Planning is a hard-constraint filter followed by multi-objective scoring.

Hard constraints include:

- requested guarantee floor;
- ordering, replay, barrier-scope, dirty-epoch, dependency, and publication
  legality;
- membership epoch, committed-roster, quorum-set, witness/data role, fence,
  drain, split-brain, and failure-domain legality;
- capacity and reservation availability;
- media role eligibility;
- data-shape compatibility and transform block state;
- allocator/layout compatibility, including alignment, free-space, pending-free,
  and zone/write-pointer state;
- lifecycle/generation compatibility, including retained roots, receive-base
  protection, orphan holds, destroy state, and reclaim-frontier safety;
- wear reserve availability;
- transport/path eligibility;
- operator policy and degradation law.

Only legal candidates reach scoring. The conceptual score is:

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

## Worked End-To-End Flows

### Small Sync WAL

1. The write arrives with `O_DSYNC`, small size, sequential offset, and high
   fsync density.
2. The predictor identifies a WAL-like vector but does not weaken the sync
   floor.
3. The planner selects sharded `sync-intent` roles on high-endurance low
   latency media, optionally quorum intent when the dataset policy asks for
   distributed sync.
4. Ordering evidence binds the dirty epoch, barrier scope, replay idempotency
   key, and dependency refs for the acknowledged range.
5. The ack receipt is `local-intent` or `quorum-intent`, not full cold
   placement.
6. Later convergence folds stable ranges into the file's durable placement.
7. Flash wear is one compact intent write per sync group, not a full-object
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
3. Flash is avoided except for metadata/intent required by the guarantee.
4. The receipt exposes full placement or the local/quorum ack plus pending
   convergence, depending on policy.
5. Readahead/cache admission avoids polluting hot read cache with one-pass
   data.

### Shape-Aware Rebake

1. A stable cold range has repeated evidence that compression or EC/archive
   shape would save flash writes, capacity, or internet egress.
2. The planner shadow-evaluates the rebake and records CPU, read amplification,
   degraded-read, rebuild, and restore-time costs.
3. The relocation governor admits the rebake only when payback, cooldown, wear,
   capacity, transport, and foreground budgets pass.
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
7. If the operator asks for `geo-intent`, the planner must pay the WAN latency
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
- What layout evidence applies: fragmentation, largest-run/free-run pressure,
  alignment, zone/write-pointer state, pending-free blockers, and reclaim debt?
- What lifecycle evidence applies: young/stable class, retained roots, snapshot
  or clone pins, receive-base dependencies, orphan/destroy state, and reclaim
  frontiers?
- How much flash endurance did this dataset consume?
- Which relocation jobs were skipped because the wear or foreground-latency
  budget was not worth spending?
- Which predictions are in shadow, serving-trial, admitted-move, cooldown, or
  failed-payback state?
- Which critical wear, capacity, or transport reserves are protecting sync,
  repair, evacuation, or geo catch-up work?
- Which guarantee would be lost if a device, node, rack, or site failed now?

This explanation must be based on receipts and current evidence, not on
topology recomputation alone.

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
- full-placement fsync latency;
- VM FUA/barrier tail latency;
- metadata storm p99 and fsyncdir latency;
- read-serving source latency and stale/refresh/refusal rate by source class;
- degraded read reconstruction latency and repair-on-read foreground cost;
- streaming ingest throughput without flash wear explosion;
- data-shape selection for record size, compression, checksum/digest, dedup,
  encryption, EC/archive shape, and coalescing under latency and cost floors;
- allocator/layout evidence for fragmentation, free-run scarcity, locality,
  alignment, zone/write-pointer constraints, pending-free safety, and reclaim
  debt;
- lifecycle-aware placement for young churn, stable-hot promotion,
  snapshot/clone/receive-base retention, orphan-held bytes, and dead-pending
  reclaim;
- one-pass scan cache behavior without persistent flash promotion;
- hot read promotion benefit/cost;
- serving-trial payback and cooldown behavior;
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
- reconciled satisfaction state before and after the measured action;
- ordering evidence for barrier scope, dirty epoch, dependency closure, replay
  idempotency, intent sequence, and publication boundary;
- membership epoch, quorum-set, participant-role, drain/fence, and
  failure-domain evidence where remote or clustered receipts participate;
- trust/security-domain, session-security, key-epoch, authorization/audit,
  residency, sharing-domain, and quarantine evidence where remote, shared,
  encrypted, repair, or geo receipts participate;
- workload envelope and prediction confidence/action class;
- environment/profile, including media and topology;
- p50/p95/p99 latency;
- throughput;
- foreground disruption;
- write amplification and flash wear;
- data-shape evidence, CPU cost, read amplification, and transform refusal state
  where relevant;
- allocator/layout evidence, fragmentation score, free-run pressure, alignment,
  pending-free safety, and reclaim debt where relevant;
- lifecycle evidence, retained-root refs, receive-base safety, orphan/destroy
  state, and reclaim-frontier refs where relevant;
- movement debt, payback window, cooldown state, and skipped-move reason where
  relevant;
- capacity and network cost where relevant;
- comparator set when making ZFS/Ceph/DRBD comparisons.

No performance claim should close merely because average throughput improved.

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
- RAM authority failure cases proving volatile receipts never satisfy durable
  POSIX barriers;
- cache and serving-trial failures proving non-authoritative hot copies never
  satisfy placement or durable ack receipts;
- stale cache, stale snapshot generation, geo-async lag, and degraded-read
  cases proving read-serving choices obey freshness and receipt evidence;
- transform and data-shape faults such as wrong key epoch, illegal dedup domain,
  malformed compression frame, digest-suite mismatch, EC under-width
  reconstruction, and mounted transform block/refusal state;
- allocator/layout faults such as stale mirror-only free-run evidence,
  wrong-generation segment evidence, pending-free reuse before fence,
  zone/write-pointer incompatibility, under-aligned block-volume placement, and
  ENOSPC or reserve exhaustion;
- lifecycle/generation faults such as missing data-retaining snapshot or clone
  pins, bookmark-only receive bases, stale committed-root identity, orphan-held
  bytes reclaimed early, destroy/tombstone admission leaks, and omitted-content
  dependencies missing during receive or geo catch-up;
- relocation, defrag, rebake, rebuild, evacuation, and geo catch-up interrupted
  before and after replacement receipt publication;
- relocation anti-thrash cases proving cooldown, movement debt, and failed
  payback cannot hide reserve erosion or stale placement;
- policy publish, rollback, or conflict while writes, relocation, and remote
  backlog are in flight.

Every row must name the requested policy revision, workload envelope,
topology/media profile, fault schedule, earned receipt set, post-recovery
receipt obligations, and forbidden outcomes. Forbidden outcomes include durable
success without required receipt evidence, hidden downgrade from durable to
volatile or from `geo-intent` to `geo-async`, split-brain receipt publication,
old locator retirement before replacement receipt publication, reserve/wear
breach hidden behind successful relocation, stale or wrong-domain data-shape
evidence accepted as satisfied, allocator mirror evidence accepted as authority,
stale lifecycle evidence accepted as retained/reclaimable, bookmark-only
anchors treated as data-retaining, pending-free bytes reused too early, and
explanations that omit degradation, lag, volatility, trust-domain refusal,
transform block state, lifecycle or layout blockers, or refusal.

The validation matrix cross-links with #850 where a scenario also has latency,
tail, throughput, RPO, or wear/cost budgets. #850 measures whether TideFS is
fast enough under a declared envelope; #863 proves that the envelope remains
honest when the system is broken on purpose.

#875 owns the claim-registry boundary for these promises. Performance and fault
rows can generate evidence, but publishing-facing wording about fast durable
sync, WAN/internet geo behavior, RAM authority, flash-wear protection, adaptive
placement, or OpenZFS/Ceph/DRBD successor comparisons must still map to stable
planned, blocked, or validated claim ids before it can become product language.

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
- #750 owns the membership authority decision for epoch identity, quorum-write
  dispatch, witness-set role, join/drain lifecycle, and epoch/fence enforcement;
  storage intent consumes those evidence refs and must not originate a parallel
  membership authority.
- #897 owns the storage-intent trust/domain evidence slice for authenticated
  identity, admin/security/tenant domain, session-security posture, key epoch,
  authorization/audit refs, residency, sharing-domain compatibility, and
  compromise/quarantine refusal. It composes security, authz, transport, and
  transform evidence without replacing those owners.
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
- `docs/design/unified-scheduling-classes-lane-priority-model.md`: storage
  intent maps onto the shared lane vocabulary for admission, dispatch,
  starvation prevention, and pressure throttling.
- `docs/design/background-service-framework-design.md`: relocation, repair,
  rebuild, scrub, compaction, and geo catch-up run as budgeted resumable work
  when they are not serving a foreground or critical policy risk.
- `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`: performance
  truth requires workload envelopes, KPIs, budgets, and receipts.
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
| Records | Shared spellings and versioned records exist for policies, receipts, roles, ordering evidence, proximity, membership evidence refs, trust/domain evidence refs, media, workload, data shape, layout evidence, lifecycle evidence, cost, wear, and relocation reasons. | #750, #841, #878, #880, #881, #894, #897 |
| Policy compilation | Pool, dataset, mount, caller, and internal maintenance sources compile into immutable policy snapshots that consumers cite by id/revision. | #855 |
| Evidence feeds | Local ack paths, ordering/replay refs, membership epoch/fence refs, trust/domain refs, path evidence, media/wear cost, non-wear cost, workload vectors, data-shape evidence, layout/allocator evidence, and lifecycle evidence can publish read-only evidence without making final placement decisions. | #750, #842, #844, #845, #846, #856, #878, #880, #881, #894, #897 |
| Satisfaction reconciliation | Current receipts and evidence are reconciled against the compiled policy as satisfied, converging, degraded-visible, blocked, refused, or unsafe/volatile. | #874 |
| Planning and admission | Hard constraints reject illegal candidates before scoring, including illegal ordering/replay state, membership/fence state, trust/domain state, data shapes, layout targets, and lifecycle states, and admission/scheduling enforces the compiled policy with typed delay, throttle, or refusal. | #750, #843, #862, #878, #880, #881, #894, #897 |
| Read serving | Read source selection distinguishes cache, serving-trial, RAM authority, local/remote receipt, degraded reconstruction, snapshot, geo, archive, and retained-root sources with freshness, epoch/fence, trust/domain, and receipt evidence. | #750, #877, #675, #881, #897 |
| Authority extensions | RAM authority, data-shape rebake, allocator-aware defrag/compaction, lifecycle-aware reclaim, and relocation/rebuild/geo catch-up use the same receipt spine and publish replacement, ordering, and trust/domain evidence before source retirement. | #750, #847, #848, #878, #880, #881, #894, #897 |
| Operator and gates | Operators can inspect the policy, receipt, lag, volatility, cost, trust/domain, and refusal story, and every implementation claim maps to performance, fault, and claim-registry gates. | #849, #850, #863, #875, #897 |

Interface gates between stages are explicit:

- Consumers take `StorageIntentPolicy` snapshots and receipt/evidence records,
  not raw caller hints, ad hoc dataset properties, or device labels.
- Planners may score only candidates that already passed guarantee,
  ordering/replay, membership/epoch/fence, trust/domain, failure-domain,
  data-shape, layout/allocator, lifecycle/generation, capacity, wear,
  transport, and degradation-law filters.
- Schedulers may delay, throttle, or refuse work, but they may not convert one
  acknowledgment class into another after admission.
- Ack receipt emitters may group, shard, coalesce, or pipeline work only when
  ordering evidence preserves the caller-visible barrier and replay contract.
- Read-serving paths may accelerate through cache, trial, RAM, local, remote,
  degraded, snapshot, geo, or archive sources only when freshness, receipt,
  membership epoch, fence, trust/domain, and degradation predicates pass for
  the compiled policy.
- Data-shape and transform paths may change record size, compression,
  checksum/digest, dedup, encryption, EC, archive, or coalescing shape only
  through compiled policy and receipt/evidence records.
- Allocator and layout paths may use free-run, locality, zone, pending-free,
  reclaim, or fragmentation evidence only through authority records or marked
  non-authoritative mirrors.
- Lifecycle paths may use write-age, retention, snapshot, clone, receive-base,
  orphan, destroy, or reclaim-frontier evidence only through authority records
  or marked non-authoritative predictors.
- Relocation workers may write speculative replacements, but they may not
  retire source receipts until replacement receipts, ordering evidence, and
  trust/domain evidence satisfy the target policy.
- Validation rows and claim ids are not an afterthought: each stage must either
  add the relevant #850/#863 row binding and #875 claim boundary, or state
  which later issue owns that proof.

## Follow-Up Implementation Map

The follow-up issues should be non-overlapping slices. They should not edit
this document except to update the issue map after live tickets exist.

| Slice | Follow-up issue | Expected write set | Purpose |
| --- | --- | --- | --- |
| Membership epoch authority | #750 | `docs/MEMBERSHIP_AUTHORITY.md` | Decide epoch, quorum-write, witness-set, join/drain, fence, roster, and failure-domain authority, then expose typed refs storage-intent consumers can cite. |
| Storage intent core records | #841 | `crates/tidefs-storage-intent-core/`, workspace manifests | Define policy, ack class, receipt, ordering refs, membership evidence refs, trust/domain refs, media role, proximity, workload, data-shape refs, layout refs, lifecycle refs, and cost records. |
| Ordering evidence authority | #894 | ordering evidence model surface or #841 core model | Expose barrier scope, dirty epoch, dependency closure, replay idempotency, intent sequence, publication boundary, and completion state for sync, quorum, relocation, repair, and receipt-retirement receipts. |
| Trust/domain evidence authority | #897 | storage-intent trust/domain records in #841 or `crates/tidefs-storage-intent-trust/`, focused tests | Expose authenticated identity, admin/security/tenant domain, session-security posture, key epoch, authorization/audit refs, residency, sharing-domain compatibility, and quarantine/refusal state. |
| Policy source and compilation | #855 | policy/config crate or `crates/tidefs-storage-intent-policy/` | Persist and compile pool, dataset, mount, caller, and internal maintenance policy into storage-intent records. |
| Local ack receipt emission | #842 | `crates/tidefs-local-filesystem/`, intent-log-adjacent code | Publish earned ack receipts for write, fsync, fdatasync, O_DSYNC, and mmap sync paths. |
| Placement planner integration | #843 | `crates/tidefs-placement-planner/`, `crates/tidefs-replication-model/` | Consume intent roles, membership/fence refs, trust/domain refs, proximity domains, failure domains, and media constraints. |
| Read-serving authority | #877 | read-serving model crate or `crates/tidefs-storage-intent-read-serving/`, focused tests | Define legal read source classes, freshness predicates, epoch/fence law, trust/domain law, degraded-read law, geo stale-read boundaries, and read-repair evidence. |
| Data-shape authority | #878 | data-shape records/model module or `crates/tidefs-storage-intent-data-shape/`, focused tests | Bind record sizing, compression, checksum/digest, dedup, encryption, EC/archive, coalescing, and rebake decisions to compiled policy and evidence receipts. |
| Layout evidence authority | #880 | layout-evidence records/model module or `crates/tidefs-storage-intent-layout-evidence/`, focused tests | Expose allocator geometry, fragmentation, free-run pressure, alignment, zone/write-pointer state, pending-free safety, and reclaim debt as policy evidence. |
| Lifecycle evidence authority | #881 | lifecycle-evidence records/model module or `crates/tidefs-storage-intent-lifecycle-evidence/`, focused tests | Expose write age, stability, snapshot/clone/receive-base retention, orphan/destroy state, and reclaim frontiers as policy evidence. |
| Media cost and wear ledger | #844 | `crates/tidefs-local-object-store/` | Track flash wear, WAF estimates, media health, movement debt, payback evidence, and relocation write budgets. |
| Non-wear cost ledger | #856 | cost-ledger crate or `crates/tidefs-storage-intent-cost/` | Account capacity, network egress, retention, relocation, and operator-defined cost envelopes. |
| Workload signal plane | #845 | `crates/tidefs-performance-contract/`, focused local signal producers | Materialize bounded workload vectors, confidence classes, and anti-thrash state for planning and performance rows. |
| Satisfaction reconciler | #874 | satisfaction/reconciliation crate or `crates/tidefs-storage-intent-satisfaction/` | Reconcile compiled policy against receipts and evidence as satisfied, converging, degraded, blocked, refused, or unsafe-visible without choosing placement. |
| Intent-aware admission and scheduling | #862 | scheduler/admission crate or `crates/tidefs-storage-intent-scheduler/` | Map compiled policy to lanes, backpressure, QoS budgets, and observable scheduling evidence. |
| Transport path evidence | #846 | `crates/tidefs-transport/` | Expose measured path/proximity/carrier evidence without making RDMA mandatory. |
| RAM authority design and implementation | #847 | docs first, then storage/runtime crates | Define volatile, replicated-volatile, intent-backed, and PMem-backed authority. |
| Relocation governor | #848 | new relocation/optimizer crate or existing background-service integration | Unify defrag, compaction, rebake, rebuild, evacuation, geo catch-up, wear movement, shadow evaluation, payback, and cooldown. |
| Operator explanation UAPI | #849 | `apps/tidefsctl/`, operator docs | Explain policy, receipts, lag, volatility, placement, trust/domain state, and wear to operators. |
| Performance intent gates | #850 | `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`, `crates/tidefs-performance-contract/`, validation matrix | Add rows for ack latency, throughput, tail, trust/domain changes, wear, cost, RPO, and relocation. |
| Storage intent fault validation | #863 | `docs/FAULT_INJECTION_CHAOS_CORRUPTION_CAMPAIGNS_P10-02.md`, storage-intent validation matrix/config docs | Prove ack, placement, media, trust/domain, relocation, RAM, scheduler, and WAN promises under typed faults and forbidden-outcome checks. |
| Storage intent claims gate | #875 | `validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, focused claims-gate tests if needed | Register planned/blocked claim ids and evidence boundaries for storage-intent successor, performance, durability, RAM, WAN, and wear promises. |

## Validation For This Slice

The authority slice is documentation/design only. Validation is bounded to:

- source and documentation inspection;
- `git diff --check`.

Do not run local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, broad
xfstests, or heavy performance validation for this slice while the host is
below the TideFS heavy-work disk floor.
