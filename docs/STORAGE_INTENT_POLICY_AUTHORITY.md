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

## Non-Claims

This document does not implement runtime behavior, change POSIX durability
semantics, add a production persistent WAL, prove RDMA, prove distributed
availability, or claim performance superiority over OpenZFS, Ceph, DRBD, or
any other system.

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
- local, node, rack, datacenter, WAN, internet, and geo failure-domain
  dimensions;
- volatile, durable-intent, full-placement, and RPO/lag dimensions;
- media-role legality, including cache versus RAM authority separation;
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
| `proximity_domain_set` | Allowed latency/topology domains for serving, intent, replica, and archive roles. |
| `media_role_policy` | Which media classes may hold intent, metadata, serving data, cold data, read cache, or scratch data. |
| `workload_shape` | Workload envelope the planner should optimize for without changing hard guarantees. |
| `cost_model` | Relative cost weights for latency, tail, throughput, media wear, capacity, power, network egress, and operator money. |
| `wear_budget` | Per-device or per-class write budget available for this policy and relocation class. |
| `relocation_policy` | When the system may rewrite, rebake, promote, demote, defrag, or evacuate data. |
| `degradation_policy` | Whether to refuse, block, serve stale-forbidden errors, or return explicit lower-class receipts under failure. |
| `explanation_scope` | Minimum operator-visible reason data that must be preserved. |

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
- intent-log receipt refs when replayable intent was used;
- placement receipt refs when durable placement was reached;
- transport/path evidence refs when remote receipt participated;
- membership/placement epoch and fencing context;
- failure domains represented in the receipt;
- media class and persistence semantics for each receipt participant;
- known missing work such as geo lag, archive conversion, or background
  full-placement completion;
- `lost_if` and `survives` summaries suitable for operator explanation.

Receipts are not marketing. They are the bridge between caller semantics,
crash recovery, placement, and operator UAPI.

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
| Append logs | sequential append, periodic fsync, high compressibility maybe | Coalesced extents, range intents, large sequential layout once stable | Tiny extents forever or forced random HDD placement |
| Large streaming ingest | large sequential writes, low reuse, low sync density | Direct HDD/EC/cold placement, large records, avoid flash unless policy asks | Flash writeback cache that doubles media writes |
| Sequential read/media | large sequential reads, low mutation | HDD/EC layout optimized for scan, optional prefetch, limited flash pinning | Hot-cache pollution from single-pass scans |
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

1. Observe request, subject, device, path, and policy signals.
2. Compute a confidence-scored workload vector.
3. Generate candidate placement or relocation plans.
4. Reject candidates that do not meet hard guarantee, failure-domain, capacity,
   wear, or operator-policy constraints.
5. Estimate latency, tail, throughput, write amplification, recovery risk, and
   money/egress cost for remaining candidates.
6. Reserve placement, transport, dirty-byte, and wear budgets.
7. Execute the selected plan.
8. Publish receipts.
9. Feed observed result back into the predictor.

Low-confidence predictions may tune queueing, prefetch, or shadow plans. They
must not trigger expensive relocation until hysteresis and benefit/cost gates
are satisfied.

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
| Speculative prefetch or hot-read promotion | speculative lane; droppable under pressure |
| Relocation/defrag/rebake/geo catch-up | background lane unless policy satisfaction or RPO risk escalates it |
| Repair/evacuation | background or critical escalation according to receipt risk and policy floor |

The scheduler consumes compiled policy, workload signals, resource-governor
pressure, media/cost ledgers, and transport evidence. It may delay,
backpressure, drop speculative work, or return typed refusals according to
policy. It may not weaken an acknowledgment receipt, hide volatile behavior, or
retire old placement receipts before replacement receipts exist.

Admission evidence must be observable:

- policy id and revision used for classification;
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

TideFS may expose an explicit non-POSIX or unsafe product profile for
operators who want maximum speed and accept loss. That profile must:

- have a name that exposes the weaker guarantee;
- return receipts naming the weaker ack class;
- be visible in `tidefsctl` and support bundles;
- be ineligible for claims that require POSIX durable sync behavior.

The goal is not to forbid fast unsafe products. The goal is to make them
honest and unnecessary for normal high-performance sync workloads.

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

## Flash Lifetime And Write Amplification

Flash endurance is an authority input, not an afterthought. Every flash-backed
device must expose a media cost ledger with at least:

- logical bytes written by TideFS class;
- estimated physical media bytes when available;
- write amplification estimate;
- erase-block or zone alignment quality;
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
4. Compress, checksum, deduplicate, and coalesce before writing to flash when
   the guarantee permits.
5. Treat high fsync density as a reason to optimize intent lanes, not as a
   reason to rewrite full data objects for every barrier.
6. Treat snapshot-pinned generations as stable candidates for cold placement,
   not as hot-write candidates.
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
- capacity consumed by replicated, erasure-coded, archive, remote, and
  snapshot-pinned data;
- transport bytes by proximity domain, carrier, peer/site, and reason;
- network egress/ingress cost classes for WAN and internet paths;
- rebuild, repair, evacuation, relocation, and geo catch-up bytes by reason;
- non-wear movement debt for recently relocated subjects, including capacity,
  network, recovery-bandwidth, and foreground-disruption debt;
- payback evidence for non-wear benefits such as capacity saved, RPO lag
  reduced, egress avoided, or rebuild risk reduced;
- retention cost for cold and snapshot-pinned generations;
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

Storage intent should treat data age and stability as first-class signals.
Most storage systems make poor cost decisions because they materialize bytes
too early into their final expensive form. TideFS should separate the lifecycle
of a write from the lifecycle of a durable object.

| Generation | Description | Typical action |
| --- | --- | --- |
| `young-dirty` | Newly accepted dirty bytes, not yet at the requested ack floor. | Admission, coalescing, intent reservation. |
| `young-acknowledged` | Bytes have earned an ack receipt but may not yet have full final placement. | Keep replayable intent, defer expensive shaping if policy allows. |
| `serving-trial` | A cache or serving copy exists because prediction says it may help, but durable authority has not changed. | Measure benefit, expire if payback is weak, preserve cache/authority distinction. |
| `stable-hot` | Bytes survived the short overwrite/delete window and are read often. | Add serving role on RAM/NVMe/SSD if benefit exceeds wear/cost. |
| `stable-warm` | Bytes are useful but not latency-critical. | Normal replicated or mixed-media placement. |
| `stable-cold` | Bytes are retained but rarely read or mutated. | HDD/EC/archive placement, large records, low relocation churn. |
| `snapshot-pinned` | Older generation cannot be reclaimed because a snapshot or receive base needs it. | Favor cold placement and avoid needless reshaping. |
| `dead-pending-reclaim` | Replacement receipt or namespace state says data is obsolete but reclaim is not yet safe. | Receipt-gated reclaim only. |

This lifecycle lets TideFS reduce write amplification without weakening
durability. A sync WAL write can earn a durable intent quickly, then be folded
into full placement once the short-lived overwrite/delete window has passed.
A backup stream can bypass flash full placement entirely. A temp-file burst can
die after intent/reclaim without ever consuming expensive serving media.

The `serving-trial` generation is deliberately not durable authority; it is how
TideFS can learn aggressively without letting a cache hit become a placement
claim.

## Planner Scoring

Planning is a hard-constraint filter followed by multi-objective scoring.

Hard constraints include:

- requested guarantee floor;
- failure-domain and membership epoch rules;
- capacity and reservation availability;
- media role eligibility;
- wear reserve availability;
- transport/path eligibility;
- operator policy and degradation law.

Only legal candidates reach scoring. The conceptual score is:

```text
score =
    latency_weight       * predicted_latency_cost
  + tail_weight          * predicted_tail_cost
  + throughput_weight    * throughput_shortfall_cost
  + wear_weight          * estimated_media_write_cost
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
that barely wins on latency while burning critical flash reserve should be
visible, reviewable, and reversible by policy.

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
4. The ack receipt is `local-intent` or `quorum-intent`, not full cold
   placement.
5. Later convergence folds stable ranges into the file's durable placement.
6. Flash wear is one compact intent write per sync group, not a full-object
   rewrite per barrier.

### Bulk Backup Ingest

1. The write stream is large, sequential, low-reuse, and low sync-density.
2. The planner chooses large records and direct HDD/EC/cold placement.
3. Flash is avoided except for metadata/intent required by the guarantee.
4. The receipt exposes full placement or the local/quorum ack plus pending
   convergence, depending on policy.
5. Readahead/cache admission avoids polluting hot read cache with one-pass
   data.

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
2. The dataset policy asks for local durable ack with remote RPO target.
3. The ack receipt is local/quorum durable plus `geo-async` lag, not
   `geo-intent`.
4. The geo catch-up lane batches, compresses, and prioritizes deltas under
   network cost and RPO budget.
5. If the operator asks for `geo-intent`, the planner must pay the WAN latency
   before success or return a refusal.

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
| `ram-volatile-replicated` | fenced peer volatile receipts with epoch | ultra-low-latency clustered scratch that survives one live-node failure but not power loss |
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
- What ack class did the last write/fsync receive?
- Which placement receipts currently satisfy policy?
- Which remote paths are behind, and by how much?
- Which data is intentionally volatile?
- Which data is pending relocation, rebake, repair, or geo catch-up?
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
- full-placement fsync latency;
- VM FUA/barrier tail latency;
- metadata storm p99 and fsyncdir latency;
- streaming ingest throughput without flash wear explosion;
- one-pass scan cache behavior without persistent flash promotion;
- hot read promotion benefit/cost;
- serving-trial payback and cooldown behavior;
- phase-changing sparse workload anti-thrash behavior;
- HDD defrag benefit under seek-heavy and scan-heavy workloads;
- SSD relocation write-amplification benefit/cost;
- rebuild/repair foreground protection;
- geo-async RPO lag under WAN and internet envelopes;
- geo-intent latency under the same path envelopes;
- RAM volatile and RAM intent-backed latency;
- media wear per TiB of logical writes.

Each row must bind:

- requested and earned ack classes;
- workload envelope and prediction confidence/action class;
- environment/profile, including media and topology;
- p50/p95/p99 latency;
- throughput;
- foreground disruption;
- write amplification and flash wear;
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
- transport partition, latency stretch, bandwidth clamp, packet loss, and
  RDMA-absent TCP/internet paths for quorum and geo modes;
- media corruption, flush omission, stale copy, truncation, bit flip, zeroed
  range, device loss, and endurance-reserve exhaustion;
- RAM authority failure cases proving volatile receipts never satisfy durable
  POSIX barriers;
- cache and serving-trial failures proving non-authoritative hot copies never
  satisfy placement or durable ack receipts;
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
breach hidden behind successful relocation, and explanations that omit
degradation, lag, volatility, or refusal.

The validation matrix cross-links with #850 where a scenario also has latency,
tail, throughput, RPO, or wear/cost budgets. #850 measures whether TideFS is
fast enough under a declared envelope; #863 proves that the envelope remains
honest when the system is broken on purpose.

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
- `docs/DEVICE_LAYOUT_POLICIES_DESIGN.md` and
  `docs/design/device-layout-policies-adaptive-segment-sizing.md`: media class
  and segment sizing are placement inputs, not full storage intent.
- Dataset property and mount-profile authorities are policy sources. Storage
  intent owns the compiled cross-source policy snapshot consumed by ack,
  placement, relocation, and explanation paths; it does not replace the
  source-specific property registries.
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
| Records | Shared spellings and versioned records exist for policies, receipts, roles, proximity, media, workload, cost, wear, and relocation reasons. | #841 |
| Policy compilation | Pool, dataset, mount, caller, and internal maintenance sources compile into immutable policy snapshots that consumers cite by id/revision. | #855 |
| Evidence feeds | Local ack paths, path evidence, media/wear cost, non-wear cost, and workload vectors can publish read-only evidence without making final placement decisions. | #842, #844, #845, #846, #856 |
| Planning and admission | Hard constraints reject illegal candidates before scoring, and admission/scheduling enforces the compiled policy with typed delay, throttle, or refusal. | #843, #862 |
| Authority extensions | RAM authority and relocation/defrag/rebake/rebuild/geo catch-up use the same receipt spine and publish replacement evidence before source retirement. | #847, #848 |
| Operator and gates | Operators can inspect the policy, receipt, lag, volatility, cost, and refusal story, and every implementation claim maps to performance and fault rows. | #849, #850, #863 |

Interface gates between stages are explicit:

- Consumers take `StorageIntentPolicy` snapshots and receipt/evidence records,
  not raw caller hints, ad hoc dataset properties, or device labels.
- Planners may score only candidates that already passed guarantee,
  failure-domain, capacity, wear, transport, and degradation-law filters.
- Schedulers may delay, throttle, or refuse work, but they may not convert one
  acknowledgment class into another after admission.
- Relocation workers may write speculative replacements, but they may not
  retire source receipts until replacement receipts satisfy the target policy.
- Validation rows are not an afterthought: each stage must either add the
  relevant #850/#863 row binding or state which later issue owns that proof.

## Follow-Up Implementation Map

The follow-up issues should be non-overlapping slices. They should not edit
this document except to update the issue map after live tickets exist.

| Slice | Follow-up issue | Expected write set | Purpose |
| --- | --- | --- | --- |
| Storage intent core records | #841 | `crates/tidefs-storage-intent-core/`, workspace manifests | Define policy, ack class, receipt, media role, proximity, workload, and cost records. |
| Policy source and compilation | #855 | policy/config crate or `crates/tidefs-storage-intent-policy/` | Persist and compile pool, dataset, mount, caller, and internal maintenance policy into storage-intent records. |
| Local ack receipt emission | #842 | `crates/tidefs-local-filesystem/`, intent-log-adjacent code | Publish earned ack receipts for write, fsync, fdatasync, O_DSYNC, and mmap sync paths. |
| Placement planner integration | #843 | `crates/tidefs-placement-planner/`, `crates/tidefs-replication-model/` | Consume intent roles, proximity domains, failure domains, and media constraints. |
| Media cost and wear ledger | #844 | `crates/tidefs-local-object-store/` | Track flash wear, WAF estimates, media health, movement debt, payback evidence, and relocation write budgets. |
| Non-wear cost ledger | #856 | cost-ledger crate or `crates/tidefs-storage-intent-cost/` | Account capacity, network egress, retention, relocation, and operator-defined cost envelopes. |
| Workload signal plane | #845 | `crates/tidefs-performance-contract/`, focused local signal producers | Materialize bounded workload vectors, confidence classes, and anti-thrash state for planning and performance rows. |
| Intent-aware admission and scheduling | #862 | scheduler/admission crate or `crates/tidefs-storage-intent-scheduler/` | Map compiled policy to lanes, backpressure, QoS budgets, and observable scheduling evidence. |
| Transport path evidence | #846 | `crates/tidefs-transport/` | Expose measured path/proximity/carrier evidence without making RDMA mandatory. |
| RAM authority design and implementation | #847 | docs first, then storage/runtime crates | Define volatile, replicated-volatile, intent-backed, and PMem-backed authority. |
| Relocation governor | #848 | new relocation/optimizer crate or existing background-service integration | Unify defrag, compaction, rebake, rebuild, evacuation, geo catch-up, wear movement, shadow evaluation, payback, and cooldown. |
| Operator explanation UAPI | #849 | `apps/tidefsctl/`, operator docs | Explain policy, receipts, lag, volatility, placement, and wear to operators. |
| Performance intent gates | #850 | `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`, `crates/tidefs-performance-contract/`, validation matrix | Add rows for ack latency, throughput, tail, wear, cost, RPO, and relocation. |
| Storage intent fault validation | #863 | `docs/FAULT_INJECTION_CHAOS_CORRUPTION_CAMPAIGNS_P10-02.md`, storage-intent validation matrix/config docs | Prove ack, placement, media, relocation, RAM, scheduler, and WAN promises under typed faults and forbidden-outcome checks. |

## Validation For This Slice

The authority slice is documentation/design only. Validation is bounded to:

- source and documentation inspection;
- `git diff --check`.

Do not run local Cargo, rustc, clippy, Nix, QEMU, FUSE, ublk, RDMA, broad
xfstests, or heavy performance validation for this slice while the host is
below the TideFS heavy-work disk floor.
