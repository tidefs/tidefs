# RAM Authority Design

Issue: #847
Date: 2026-06-21
Status: current design authority for RAM and persistent-memory authority
classes

This document defines when memory-speed storage in TideFS is authority and
when it is only cache. It narrows the RAM pool language from storage intent
policy into explicit receipt classes, failure behavior, promotion and demotion
rules, and operator explanation requirements.

The rule is simple: an authoritative RAM pool is a product authority with a
receipt. It is not an evictable cache entry with a stronger name.

## Non-Claims

This document does not implement a RAM pool, persistent-memory write path,
distributed volatile quorum, placement planner rule, operator command, or
performance gate. It does not prove that current TideFS runtime code satisfies
POSIX durability, cluster availability, PMem power-fail behavior, or replay
correctness.

PR #840 (the storage-intent authority document gate for this design) is now merged
into `origin/master`; `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` is the
canonical storage-intent authority on the default branch.

## Evidence Reviewed

- GitHub issue #847, including the docs-first write set and no-runtime-edit
  boundary.
- GitHub issue #839 and PR #840, especially the storage-intent receipt classes,
  POSIX sync honesty rule, RAM pool class list, and child issue map.
- GitHub issues #841, #842, and #846 for the intended storage-intent record,
  local acknowledgment receipt, and transport path evidence slices.
- GitHub issue #894 for storage-intent ordering and replay evidence: barrier
  scope, dirty epoch, dependency closure, replay idempotency, intent sequence,
  publication boundary, and completion state.
- GitHub issue #898 for storage-intent capacity/admission evidence around
  logical, physical, dirty-window, reserve, and ENOSPC legality.
- GitHub issue #901 for policy-revision rollout evidence, including
  publication, downgrade authorization, in-flight fences, and mixed-revision
  convergence state.
- GitHub issue #902 for tenant, budget, fair-share, noisy-neighbor,
  reserve-exemption, throttle, and refusal evidence.
- GitHub issue #903 for temporal evidence around timebase identity, clock
  health, staleness, expiry, lease, lag, and freshness claims.
- GitHub issue #904 for media-capability evidence covering persistence domain,
  flush/FUA/barrier semantics, atomicity, geometry, health, freshness, and role
  eligibility.
- GitHub issue #915 for compiled service-objective evidence binding latency
  percentile/tail, throughput floor/ceiling, concurrency/queue, burst/dwell,
  degradation/RPO/RTO, isolation, topology/media, cost, wear, attribution,
  query-snapshot, comparator/claim, and refusal state to a policy revision.
- GitHub issue #920 for storage-intent result/refusal evidence binding typed
  caller outcomes, including success, degraded-visible, blocked, refused,
  retryability, idempotency, and response-registry projection.
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md`: cache is not authority, every
  cache entry is evictable only under its cache law, and dirty state must drain
  through explicit state machines.
- `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`: page-cache bytes are mirrors, and
  successful durability barriers require committed storage, durable replayable
  intent, or an equivalent receipt authority.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md`: transport owns session-local mechanics
  and evidence, while membership/runtime own roster, epoch, and fencing
  decisions.
- source-owned governor and admission paths: daemon memory must be admitted and
  explained through one budget authority rather than hidden per-subsystem
  buffers.

The required `~/ai/docs` searches found no additional RAM-authority-specific
process document beyond the general TideFS and Nexus workflow rules.

## Scope

This design covers four RAM authority classes:

- `ram-volatile-local`
- `ram-volatile-replicated`
- `ram-intent-backed`
- `pmem-durable`

It also defines the refusal boundary between those classes and:

- clean read cache;
- dirty page-cache/writeback state;
- durable local or quorum intent;
- PMem/NVDIMM persistence;
- ordinary durable media placement.

This design does not authorize runtime edits outside docs. Runtime work must
use issue-scoped follow-ups with non-overlapping write sets.

## Authority Classes

| Class | Authority meaning | Receipt floor | POSIX durable barrier |
| --- | --- | --- | --- |
| `ram-volatile-local` | Bytes are authoritative only inside one local process or host RAM authority instance. | Local volatile receipt. | Never sufficient. |
| `ram-volatile-replicated` | Bytes are authoritative across a fenced volatile peer set for the current membership epoch. | Fenced volatile peer receipts. | Never sufficient. |
| `ram-intent-backed` | RAM serves hot bytes while durable local or quorum intent earns the configured barrier. | RAM serving receipt plus durable intent receipt. | Sufficient only when the durable intent and ordering/replay evidence satisfy the configured floor. |
| `pmem-durable` | Bytes are persisted in PMem/NVDIMM-class media with platform persistence-domain and flush/fence evidence. | Persistent-memory flush/fence receipt. | Sufficient only when metadata, ordering, and recovery evidence also satisfy the floor. |

### `ram-volatile-local`

`ram-volatile-local` is single-node volatile authority. It is legal only when
the compiled storage-intent policy names a volatile or unsafe profile whose
loss behavior is visible to the caller and operator.

Required receipt evidence:

- policy id and policy revision;
- object, range, or dataset scope covered by the RAM authority;
- authority instance id, process id or daemon instance id, and host id;
- byte length, generation, and optional digest or checksum when available;
- resource-governor admission ticket for authoritative RAM bytes;
- receipt time and local authority epoch;
- `lost_if` including process crash, daemon restart, host crash, and power
  loss;
- `survives` limited to reads by the same live authority instance unless the
  implementation records a stronger handoff.

Semantics:

- The authoritative byte is memory-resident. It may be served without durable
  media lookup while the authority instance remains live.
- It must not be stored as a cache entry or be evicted by cache policy.
- Memory pressure may refuse new writes, force explicit promotion, or abort a
  volatile product according to policy. It may not silently discard the only
  authoritative copy.
- A normal POSIX `fsync`, `fdatasync`, `msync(MS_SYNC)`, `O_DSYNC`, or FUA
  barrier cannot return success from this receipt unless the mount/product is
  explicitly non-POSIX and the weaker receipt is returned.

### `ram-volatile-replicated`

`ram-volatile-replicated` is volatile authority replicated across live peers.
It can survive one process or node failure only when the receipt proves enough
fenced peers remain to satisfy the volatile policy. It is not durable across a
power-loss event that removes all volatile peers.

Required receipt evidence:

- all `ram-volatile-local` evidence for the local authority;
- committed membership epoch and roster revision;
- membership/runtime fencing proof for every accepting peer;
- peer receipt list with peer id, authority instance id, epoch, generation,
  byte range, and acknowledgment time;
- required and observed peer count, or quorum formula, for the volatile class;
- transport path evidence from #846, including carrier, RTT or configured
  proximity, loss/error class, measurement age, and authentication/encryption
  context where available;
- partition handling rule for the receipt;
- `lost_if` including simultaneous peer loss, power loss across the volatile
  set, fencing ambiguity, or loss below the policy floor before promotion.

Peer-loss behavior:

- If peer loss leaves enough fenced volatile copies, the authority may keep
  serving under a degraded volatile receipt and schedule re-replication within
  the same policy.
- If peer loss drops below the volatile floor, new writes must be refused,
  blocked, or promoted according to policy. Reads must report degraded receipt
  state or refuse if freshness cannot be proven.
- A departed or drained peer cannot count toward a receipt after the committed
  membership epoch excludes it.
- Transport evidence supports the receipt but does not originate membership,
  quorum, or fencing truth.

Network partition behavior:

- The side that cannot prove the current committed epoch and fencing authority
  must stop issuing stronger volatile-replicated receipts.
- If both sides might believe they own the same bytes, the system must classify
  the range as fencing-ambiguous and refuse new authoritative writes until a
  runtime authority resolves the epoch.
- A stale transport session is never proof that a peer is still a legal
  authority holder.

### `ram-intent-backed`

`ram-intent-backed` serves bytes from RAM while durable intent earns the
configured barrier. This is the normal high-performance shape for workloads
that want memory-speed reads/writes without giving up recovery after crash.

Required receipt evidence:

- RAM authority instance, range, generation, and resource-governor admission;
- durable local intent receipt from #842, quorum intent receipt, or future
  equivalent durable intent evidence;
- intent payload or locator strong enough for replay to reconstruct the bytes;
- intent flush/fence evidence for the configured floor;
- ordering/replay evidence refs from #894 covering barrier scope, dirty epoch,
  dependency closure, replay idempotency key, intent sequence, publication
  boundary, and completion state;
- mapping from the RAM generation to the durable intent generation;
- replay order relative to committed roots, page-cache writeback, and subsequent
  placement receipts;
- `lost_if` for the RAM serving copy and `survives` for the durable intent
  boundary separately.

Semantics:

- A write may be read from RAM immediately according to freshness policy, but a
  durable POSIX barrier succeeds only after the durable intent receipt reaches
  the configured floor.
- On process crash, daemon restart, host crash, or power loss, RAM bytes are
  gone. Recovery uses the durable intent chain or durable placement receipts.
- If durable intent append, flush, or quorum receipt fails, the write may still
  have a volatile receipt, but the durable barrier must return an error,
  block, retry, or explicitly report the weaker unsafe receipt.
- Batching, sharding, coalescing, pipelining, or quorum fanout can optimize a
  durable RAM path only after the #894 ordering/replay gates prove the
  caller-visible barrier and replay contract.
- Subsequent full placement may retire the durable intent only after replacement
  placement receipts are published and replay no longer needs the intent.

### `pmem-durable`

`pmem-durable` is persistent-memory authority. It is not ordinary DRAM. It
requires evidence that the byte range resides in a platform persistence domain
and that CPU cache state, ordering, metadata, and recovery rules have reached
that domain.

Required receipt evidence:

- PMem namespace or NVDIMM device identity and health state;
- platform persistence-domain evidence, such as ADR/eADR or equivalent
  operator-accepted platform profile;
- byte range, generation, checksum or validation token, and metadata anchor;
- cache-line write-back or platform-equivalent flush evidence for modified
  bytes;
- store fence, drain, or ordering evidence before the receipt is issued;
- metadata persistence evidence for the locator that makes the bytes
  reachable after restart;
- ordering/replay evidence refs when PMem satisfies durable intent or a
  caller-visible barrier rather than only holding already-ordered data;
- recovery scanner or committed-root evidence that can distinguish complete,
  partial, stale, and poisoned PMem generations;
- `lost_if` for media failure, platform profile mismatch, incomplete flush,
  uncorrectable memory error, or metadata loss outside the PMem receipt.

Semantics:

- PMem can satisfy a durable barrier only for ranges whose bytes and recovery
  metadata are both persisted and ordered.
- Wrong-root, wrong-range, non-idempotent, unsealed, contradictory, or incomplete
  ordering evidence leaves the PMem receipt unknown, blocked, refused, or
  degraded-visible according to policy; it is not a successful durable barrier.
- A CPU cache store to a PMem mapping is not a receipt. Flush/fence evidence is
  required unless the platform profile proves that the persistence domain
  already includes the relevant caches.
- Ordinary DRAM with battery-backed system power is not `pmem-durable` unless
  the platform profile and recovery contract define the persistence domain and
  failure model.
- PMem can hold durable intent, durable data, or both. The receipt must say
  which role it satisfies.

## Failure Behavior

| Failure event | `ram-volatile-local` | `ram-volatile-replicated` | `ram-intent-backed` | `pmem-durable` |
| --- | --- | --- | --- | --- |
| Process crash | Lost. Any subsequent service must report absent volatile authority. | Survives only if enough fenced peers remain live and the new owner proves the epoch. | RAM copy lost; durable intent replays if the receipt was earned. | Survives if PMem flush/fence and metadata receipt were complete. |
| Daemon restart | Lost unless the same product has an explicit live handoff receipt. | Lost on the restarting daemon; surviving peers may rehydrate if epoch and quorum evidence remain valid. | Rehydrate from durable local or quorum intent, then publish a new RAM serving receipt. | Reopen by scanning validated PMem metadata and poisoning incomplete generations. |
| Host crash | Lost. | Survives only on peers outside the crashed host that still satisfy the volatile floor. | Host-local RAM lost; durable local intent survives only if it reached durable media, otherwise quorum intent may survive. | Survives if the platform persisted bytes and metadata before crash. |
| Power loss | Lost. | Lost if power loss covers all volatile peers; survives no better than remaining powered peers. | RAM lost; durable intent or placement decides recovery. | Survives only inside the documented persistence domain and media health model. |
| Peer loss | Not applicable. | Continue if remaining fenced peers satisfy policy; otherwise degrade, re-replicate, block, or refuse with a typed receipt. | Quorum intent may continue if remaining durable intent peers satisfy the floor. | Not peer-dependent unless PMem is used as a replicated role. |
| Network partition | Not applicable for single-host authority. | Cannot issue replicated volatile receipts unless current epoch and fencing are proven; ambiguous sides fail closed. | Durable local intent may still earn local floors; quorum or remote intent floors require partition-safe quorum evidence. | Local PMem durability unaffected, but replicated PMem roles still need epoch and quorum proof. |
| Fencing ambiguity | The local instance cannot upgrade to clustered authority. | Must stop new authoritative writes and classify affected ranges as fencing-ambiguous. | Durable barriers that rely on remote/quorum intent must refuse until fencing ambiguity is resolved. | Local PMem receipt may remain valid, but distributed placement claims must wait for fencing proof. |
| Replay after durable intent | No replay; bytes were intentionally volatile. | No replay unless a separate durable intent receipt exists. | Replay durable intent, reconstruct RAM serving state, and expose any missing volatile-only generations as lost. | Replay or scan PMem records, then join with durable intent or placement receipts as required by policy. |

Failure classification must be range- and generation-aware. A dataset may have
some bytes intentionally volatile, some bytes intent-backed, and some bytes
fully placed on durable media at the same time.

For `ram-intent-backed` and `pmem-durable`, replay after durable intent also
depends on #894 ordering evidence. Missing, stale, unsealed, wrong-root,
wrong-range, non-idempotent, partial-namespace, lost writeback-error,
under-quorum, or contradictory ordering evidence cannot be hidden by a RAM or
PMem receipt.

## Storage-Intent Consumption

The storage-intent core records from #841 should carry the RAM authority
decision without forcing runtime crates to reinterpret raw policy fields. The
record surface needs at least:

- `authority_class`: one of the four classes above, or a non-authoritative
  cache class;
- policy id and revision;
- range, object, generation, and dataset scope;
- requested guarantee floor and earned receipt class;
- `lost_if` and `survives` vectors for operator explanation;
- resource-governor budget category and admission receipt;
- local intent, quorum intent, ordering/replay, placement, PMem, transport,
  membership epoch, and fencing evidence refs when present;
- capacity/admission, policy-rollout, tenant-isolation, temporal, and
  media-capability evidence refs when RAM authority depends on reserve
  legality, policy-revision state, budget-owner protection, freshness or loss
  windows, PMem persistence domain, or flush/FUA/barrier semantics;
- downgrade/refusal reason when the requested floor could not be earned.

The local ack receipt work in #842 should emit or consume these records at
write, `fsync`, `fdatasync`, `O_DSYNC`, FUA, and shared mmap sync boundaries.
The transport evidence work in #846 should supply path and carrier evidence
for volatile peer receipts, but membership/runtime authority must still supply
epoch and fencing proof.

Issue #894 owns the shared ordering-evidence model that RAM authority consumes
when it emits, interprets, reconciles, plans, schedules, explains, validates,
or claims durable intent receipts. RAM authority may serve bytes fast, but it
may not weaken barrier scope, dependency closure, replay idempotency, intent
sequence, publication boundary, or completion state.

Issues #898, #901, #902, #903, and #904 own the capacity/admission,
policy-rollout, tenant-isolation, temporal, and media-capability evidence that
RAM authority consumes. A RAM receipt may cite those refs, but this document
does not define their record layouts or runtime producers. Missing, stale,
expired, contradictory, over-budget, unsafe-downgrade, unknown-timebase,
unknown-persistence-domain, or unsupported-flush/FUA evidence must become a
typed unknown, blocked, throttled, refused, failed, or degraded-visible state
according to policy; it is not a silent weaker RAM authority success.

## Resource-Governor Boundary

Authoritative RAM bytes must be budgeted separately from evictable cache. The
resource governor may expose the exact category names in a future slice, but
the contract is fixed:

- `ram-volatile-local` and `ram-volatile-replicated` bytes are protected
  authority or authority-adjacent memory, not `data_cache`.
- `ram-intent-backed` needs separate accounting for the RAM serving copy,
  dirty or replayable intent coverage, and any cluster queue bytes used for
  quorum intent.
- `pmem-durable` mappings must account for host virtual-memory pressure,
  pinned mappings, and flush work, even when the persistent bytes live outside
  ordinary DRAM.
- Memory pressure may throttle, refuse, or force an explicit policy
  transition. It may not silently demote authoritative RAM into cache or drop
  volatile authority without the product's declared loss event.
- Operator pressure reports must distinguish evictable cache, dirty writeback
  debt, volatile authority, RAM serving copies backed by durable intent, PMem
  durable ranges, and transport queue memory.

Capacity, budget-owner, and temporal evidence remain separate from the local
memory counter. `ram-intent-backed` and `pmem-durable` roles must preserve #898
reserve/admission refs when dirty windows, intent media, PMem mappings, repair
reserve, or receipt retirement need protected headroom. Shared RAM authority,
transport queues, and replay work must preserve #902 budget-owner and
fair-share refs rather than hiding one tenant's p99 harm behind aggregate
throughput. Any loss window, lease, expiry, cooldown, or freshness claim must
cite #903 temporal refs or degrade to unknown/refused according to policy.

## Promotion And Demotion Rules

Promotion or demotion changes the receipt class. It must be explicit,
auditable, and monotonic with respect to already-issued guarantees.

| Transition | Legal only when | Must refuse when |
| --- | --- | --- |
| Cache -> `ram-volatile-local` | A compiled policy requests volatile authority and a resource-governor authority budget is admitted. | The caller only asked for read cache or the system would create the only authoritative copy from an evictable entry. |
| `ram-volatile-local` -> `ram-volatile-replicated` | Fenced peers acknowledge the same generation under the committed epoch. | Peer receipts, epoch, or fencing evidence are missing or stale. |
| Volatile RAM -> `ram-intent-backed` | Durable local or quorum intent and #894 ordering evidence cover the same generation before any durable barrier success is reported. | Intent append/flush/quorum or ordering/replay evidence fails or does not cover the bytes strongly enough for replay. |
| `ram-intent-backed` -> durable media placement | Replacement placement receipts are published and recovery no longer needs the intent for those bytes. | Placement is incomplete, stale, below policy, or would retire intent before replay and ordering evidence are safe. |
| `ram-intent-backed` -> `pmem-durable` | PMem flush/fence plus metadata persistence, #904 media-capability refs, and ordering evidence cover the same generation and role. | Platform persistence-domain, flush/fence, media health, metadata, media-capability, or ordering evidence is missing. |
| `pmem-durable` -> ordinary durable media | New durable placement receipts satisfy policy before PMem receipt retirement. | The move would lose the only durable authority or leave recovery metadata behind. |
| Any durable class -> volatile RAM | Operator explicitly weakens policy for future writes and existing durable receipts remain historically true. | Existing bytes would be reclassified weaker without a policy revision and operator-visible consent. |
| Any authority -> cache | Replacement authority exists, the old receipt is retired, or the product declares the volatile-loss event. | The bytes would remain reachable only through evictable cache. |

Policy transitions must fail closed when they cannot preserve the requested
floor. Silent weakening is forbidden. In particular:

- a clean cache hit cannot become a durable or volatile authority receipt;
- a volatile receipt cannot satisfy a durable POSIX barrier;
- a PMem mapping without flush/fence evidence cannot be upgraded to durable;
- a replicated volatile receipt without current fencing evidence cannot be
  treated as clustered authority;
- memory pressure cannot convert authority into cache.

Promotion and demotion also consume #898, #901, #902, #903, and #904 when the
transition depends on reserve headroom, policy-revision rollout, budget
ownership, freshness or expiry, or media eligibility. When a transition can affect
latency, throughput, tail, queue, burst, dwell, isolation, or cost envelopes, it
must also consume #915 service-objective refs to avoid hiding degraded p99 or
weaker throughput under a stale envelope claim. A caller-visible transition,
refusal, or degraded result must consume #920 result/refusal refs instead of
collapsing to generic success, timeout, EIO, or silent weaker guarantee. A
policy revision cannot
reinterpret old RAM receipts without #901 convergence or downgrade evidence.
Capacity pressure cannot borrow protected sync, repair, evacuation, or
receipt-retirement reserve without #898 evidence. PMem cannot satisfy a
durable role from a media label alone; it needs #904 persistence-domain and
flush/FUA/barrier evidence.

## Operator Explanation Requirements

Future `tidefsctl` and support bundles must be able to report, for a dataset,
file, range, or pool:

- which bytes are intentionally volatile;
- the exact authority class for each reported range or generation;
- which policy revision requested that class;
- the last earned receipt and the evidence refs behind it;
- ordering/replay evidence state for durable intent, PMem, and receipt
  retirement;
- what failures would lose the bytes;
- what failures the bytes are expected to survive;
- whether a durable intent replay is pending, complete, failed, or not
  applicable;
- which peers currently hold volatile copies and under which membership epoch;
- whether any peer, path, or fencing evidence is stale;
- which PMem ranges are durable, poisoned, incomplete, or pending flush;
- resource-governor budget pressure for volatile authority, RAM serving,
  dirty intent, PMem mappings, and cluster queues;
- capacity/admission, reserve, and ENOSPC state from #898 when RAM intent or
  PMem durability depends on protected headroom;
- policy rollout and mixed-revision state from #901 when a RAM authority class
  changes or old receipts remain under an earlier policy;
- tenant, budget-owner, fair-share, noisy-neighbor, and throttle state from
  #902 when RAM or PMem pressure can harm another protected scope;
- temporal evidence from #903 for loss-window, lease, expiry, freshness, lag,
  RPO, or replay-age claims;
- media-capability state from #904 for PMem persistence domain, flush/FUA,
  atomicity, geometry, health, freshness, and role eligibility;
- compiled service-objective state from #915 when RAM or PMem authority
  affects latency, throughput, tail, queue, burst, dwell, isolation, cost,
  wear, or comparator claims;
- result/refusal state from #920 for any caller-visible RAM authority outcome,
  including success, degraded-visible, blocked, refused, retryability, and
  idempotency classification;
- any requested policy transition that was refused to avoid weakening
  guarantees.

The explanation must be receipt-backed. It must not infer durability or
volatility only from current topology, cache warmth, or device names.

## Runtime Follow-Up Boundaries

This docs slice maps to existing and future implementation work as follows:

| Surface | Issue or owner | Expected write set |
| --- | --- | --- |
| Storage-intent RAM class records and receipt spellings | #841 | `crates/tidefs-storage-intent-core/`, workspace manifests |
| Local durable intent receipt emission | #842 | `crates/tidefs-local-filesystem/src/` and local intent-log/writeback-adjacent modules |
| Storage-intent ordering and replay evidence | #894 | model surface selected by #894, with runtime paths excluded until that issue expands its write set |
| Capacity/admission evidence for RAM intent and PMem roles | #898 | storage-intent capacity/admission record or model crate selected by #898 |
| Policy-revision rollout evidence for RAM authority changes | #901 | storage-intent rollout record or model crate selected by #901 |
| Tenant and budget isolation evidence for shared RAM authority | #902 | storage-intent isolation record or model crate selected by #902 |
| Temporal evidence for loss windows, leases, expiry, and freshness | #903 | storage-intent temporal record or model crate selected by #903 |
| Media-capability evidence for PMem persistence and flush/FUA roles | #904 | storage-intent media-capability record or model crate selected by #904 |
| Compiled service-objective evidence for RAM authority latency, throughput, tail, isolation, and cost envelopes | #915 | storage-intent service-objective record or model crate selected by #915 |
| Result/refusal evidence for caller-visible RAM authority outcomes and retryability | #920 | storage-intent result/refusal record or model crate selected by #920 |
| Transport path evidence for volatile peer receipts | #846 | `crates/tidefs-transport/src/` |
| Intent-aware admission and memory/QoS scheduling | #862 | scheduler or admission crate named by that issue |
| Operator explanation of volatility and receipts | #849 | `apps/tidefsctl/` and operator docs |
| Runtime RAM pool implementation | future issue before code edits | storage/runtime crate paths selected by that issue |
| PMem/NVDIMM runtime implementation | future issue before code edits | PMem media, flush/fence, recovery, and validation paths selected by that issue |

No implementation issue may represent authoritative RAM as an evictable cache
entry, bypass the resource governor, or claim durable POSIX sync success from
volatile evidence.
