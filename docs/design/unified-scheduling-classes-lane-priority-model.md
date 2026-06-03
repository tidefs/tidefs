# Unified Scheduling Classes and Lane Priority Model

**Issue**: [#1617](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1617) (closes [#1241](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1241))
**Status**: design-spec (design-only; Rust implementation deferred to wire-up issues)
**Priority**: P2
**Lane**: storage-core
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8-11)
**Depends on**: existing `LaneClass` enum and `TransportLaneBudgetRecord` in `tidefs-types-transport-session`

## Abstract

tidefs classifies work into five canonical scheduling classes — CONTROL, METADATA, DEMAND,
SPECULATIVE, BACKGROUND — with strict priority ordering, per-lane budget caps, starvation
prevention timeouts, and preemption. The `LaneClass` enum already exists in
`tidefs-types-transport-session`; this design specifies the unified `LaneConfig` struct,
resource-agnostic lane scheduler, resource-specific configurations, per-lane starvation
prevention, preemption contract, memory-pressure response policy, and unified observability.

The lane model spans every resource that processes multi-class work: cluster transport
(#1210), device IO scheduling, FUSE request admission, background service ticks (#1179),
cache admission (#1237), and memory pressure response (#1211). Today each subsystem
defines its own priority/budget model. This design unifies them under a single
`LaneConfig` struct and lane scheduler so that starvation prevention, budget enforcement,
and preemption are consistent across all resources.

---

## 1. Five canonical scheduling classes

The `LaneClass` enum already exists in `crates/tidefs-types-transport-session/src/lib.rs`
with five variants and priority ordering. This design formalizes the semantics of each
class beyond transport into a system-wide contract.

| Class | Priority | Starvation Risk | Budget Cap Type | Preemptible? | Examples |
|---|---|---|---|---|---|
| `Metadata` | 1 (high) | Tolerable within bounds | Cap + backpressure | No | readdir, lookup, getattr, mkdir, unlink |
| `Demand` | 2 (normal) | Tolerable within bounds | Cap + backpressure | No | User reads/writes, fsync, state transfer foreground |
| `Background` | 4 (lowest) | Starvable, resumable | Strict cap, droppable + resumable | Yes | Cleaning, GC, compaction, rebake, bulk transfer (#1229) |

### 1.1 Invariants

1. **Strict priority**: CONTROL always runs before METADATA, METADATA before DEMAND, etc.
2. **Starvation prevention**: If a lower-priority lane has not been serviced for
   `starvation_timeout_ms`, at least one op from that lane MUST run next, even if a
   higher-priority lane has pending work. CONTROL and METADATA are exempt from starvation
   (their timeouts are zero, meaning they always run when ready).
3. **Budget caps**: Each lane has `max_inflight_bytes` and `max_inflight_ops`. Exceeding
   either triggers backpressure on that lane's producers.
4. **Preemption**: CONTROL can preempt any lower-priority lane mid-operation where safe
   (not during a transaction commit). SPECULATIVE and BACKGROUND ops can be dropped on
   preemption and resumed later.
5. **Memory pressure**: When memory pressure rises, lower-priority lanes are throttled
   first: SPECULATIVE → BACKGROUND → DEMAND → METADATA → CONTROL never throttled.

---

## 2. Unified `LaneConfig` struct

Every resource that processes work from multiple scheduling classes uses the same
`LaneConfig` struct. This replaces ad-hoc per-resource budget definitions.

### 2.1 Core struct

```rust
/// Unified lane configuration for any resource that processes multi-class work.
///
/// One `LaneConfig` exists per `(resource_id, LaneClass)` pair. The lane scheduler
/// reads these configs to enforce priority, budgets, starvation prevention, and
/// preemption across all lanes of a resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneConfig {
    /// Which scheduling class this config applies to.
    pub lane_class: LaneClass,

    /// Hard cap on bytes in-flight for this lane.
    /// When in-flight bytes exceed this, producers must back off.
    pub max_inflight_bytes: u64,

    /// Hard cap on operations in-flight for this lane.
    /// When in-flight ops exceed this, producers must back off.
    pub max_inflight_ops: u64,

    /// Maximum time (ms) this lane can wait without being serviced.
    /// After this duration, at least one op from this lane MUST be
    /// processed next, regardless of higher-priority pending work.
    /// Set to 0 for CONTROL and METADATA (always serviced when ready).
    pub starvation_timeout_ms: u64,

    /// Whether CONTROL can preempt an in-flight operation on this lane.
    /// Only SPECULATIVE and BACKGROUND are preemptible.
    pub preemptible: bool,

    /// Whether in-flight operations on this lane can be dropped entirely
    /// under extreme memory pressure (true for SPECULATIVE, BACKGROUND).
    pub droppable: bool,

    /// Whether dropped operations can be resumed later (true for BACKGROUND,
    /// false for SPECULATIVE which must be re-requested).
    pub resumable: bool,

    /// The priority band for pressure-driven throttling.
    /// Lower values are throttled first when memory pressure rises.
    pub pressure_throttle_order: u8,

    /// Reference name for the latency budget policy (e.g., "latency.tight",
    /// "latency.normal", "latency.loose"). Mirrors
    /// `TransportLaneBudgetRecord::latency_budget_ref`.
    pub latency_budget_ref: &'static str,

    /// Reference name for the drop/reorder policy (e.g., "drop.oldest",
    /// "drop.none"). Mirrors `TransportLaneBudgetRecord::drop_or_reorder_policy_ref`.
    pub drop_or_reorder_policy_ref: &'static str,
}
```

### 2.2 Default configurations per lane

```rust
impl LaneConfig {
    /// Default lane configuration for CONTROL class.
    pub const fn control(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Control,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 0,    // never starved
            preemptible: false,
            droppable: false,
            resumable: false,
            pressure_throttle_order: 4,  // throttled last
            latency_budget_ref: "latency.tight",
            drop_or_reorder_policy_ref: "none",
        }
    }

    /// Default lane configuration for METADATA class.
    pub const fn metadata(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Metadata,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 0,    // not starvable
            preemptible: false,
            droppable: false,
            resumable: false,
            pressure_throttle_order: 3,
            latency_budget_ref: "latency.tight",
            drop_or_reorder_policy_ref: "none",
        }
    }

    /// Default lane configuration for DEMAND class.
    pub const fn demand(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Demand,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 5000, // 5s max wait
            preemptible: false,
            droppable: false,
            resumable: false,
            pressure_throttle_order: 2,
            latency_budget_ref: "latency.normal",
            drop_or_reorder_policy_ref: "none",
        }
    }

    /// Default lane configuration for SPECULATIVE class.
    pub const fn speculative(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Speculative,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 30000, // 30s max wait
            preemptible: true,
            droppable: true,
            resumable: false,
            pressure_throttle_order: 1,   // throttled first
            latency_budget_ref: "latency.loose",
            drop_or_reorder_policy_ref: "drop.oldest",
        }
    }

    /// Default lane configuration for BACKGROUND class.
    pub const fn background(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Background,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 60000, // 60s max wait
            preemptible: true,
            droppable: true,
            resumable: true,
            pressure_throttle_order: 0,   // throttled very first
            latency_budget_ref: "latency.loose",
            drop_or_reorder_policy_ref: "drop.oldest",
        }
    }
}
```

### 2.3 Relationship to existing `TransportLaneBudgetRecord`

The existing `TransportLaneBudgetRecord` in `tidefs-types-transport-session` already
carries `lane_class_ref`, `priority_class`, `max_inflight_bytes`, `latency_budget_ref`,
`drop_or_reorder_policy_ref`, and `backpressure_state_class`. `LaneConfig` is the
**unified superset** that adds starvation timeout, preemption, and droppable/resumable
semantics.

`TransportLaneBudgetRecord` continues to serve as the transport-layer record (it is
serializable and digest-bearing). `LaneConfig` is the in-memory runtime configuration
used by the lane scheduler. A conversion function bridges the two:

```rust
impl From<&TransportLaneBudgetRecord> for LaneConfig {
    fn from(rec: &TransportLaneBudgetRecord) -> Self {
        let base = match rec.lane_class_ref {
            LaneClass::Control => Self::control(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Metadata => Self::metadata(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Demand => Self::demand(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Speculative => Self::speculative(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Background => Self::background(rec.max_inflight_bytes, u64::MAX),
        };
        Self {
            latency_budget_ref: rec.latency_budget_ref,
            drop_or_reorder_policy_ref: rec.drop_or_reorder_policy_ref,
            ..base
        }
    }
}
```

---

### 2.4 Mapping to the public `LaneState` enum

The existing `LaneState` enum (`Open` / `CreditLimited` / `Backpressured` /
`Draining` / `Sealed`) in `tidefs-types-transport-session` describes the
backpressure state exposed to transport producers. The lane scheduler maps
these states to admission rules:

| `LaneState`      | Scheduler behavior |
|------------------|--------------------|
| `Open`           | Full admission; budget caps enforced normally. |
| `CreditLimited`  | Admission allowed but `max_inflight_bytes` reduced to 50% of configured. |
| `Backpressured`  | New ops queued but not dispatched until pressure eases. Starvation timeout still fires. |
| `Draining`       | Existing inflight ops complete; no new admissions. Starvation timeout suspended. |
| `Sealed`         | Terminal; all inflight ops dropped; no admissions; lane removed from scheduling. |

When `TransportLaneBudgetRecord` has `backpressure_state_class == LaneState::Backpressured`,
the `LaneConfig` budget caps remain unchanged, but the lane scheduler applies the
admission rule above. This allows the transport layer to signal backpressure without
changing the declared lane budget, which is an authoritative record.
## 3. Unified lane scheduler

### 3.1 `LaneScheduler` struct

The lane scheduler is the runtime component that selects which lane's work to process
next. It is resource-agnostic: transport, FUSE admission, device IO, and background
ticks all instantiate their own `LaneScheduler` with resource-specific `LaneConfig`
values.

```rust
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Operation queued on a specific lane.
pub struct LaneOp<T> {
    /// The work item.
    pub item: T,
    /// When the operation was enqueued.
    pub enqueued_at: Instant,
    /// Estimated byte cost (for budget tracking).
    pub byte_cost: u64,
}

/// Per-lane runtime state maintained by the scheduler.
///
/// Note: this is distinct from the public `LaneState` enum in
/// `tidefs-types-transport-session` (Open / CreditLimited / Backpressured /
/// Draining / Sealed), which describes the backpressure state exposed to
/// transport producers. This struct tracks the scheduler-internal bookkeeping
/// for queue depth, starvation, and preemption counters.
struct LaneRuntime {
    config: LaneConfig,
    /// Pending operations, FIFO.
    queue: VecDeque<LaneOp<Box<dyn Send + 'static>>>,
    /// Current in-flight bytes across all ops in queue + in-progress.
    inflight_bytes: u64,
    /// Current in-flight operation count.
    inflight_ops: u64,
    /// Timestamp of the oldest unserviced op in queue (if any).
    oldest_enqueue: Option<Instant>,
    /// How many times this lane has been preempted.
    preemption_count: u64,
    /// Total time this lane has spent starved (unserviced with pending work).
    total_starved: Duration,
    /// When the last op from this lane started processing.
    last_serviced: Option<Instant>,
}

/// The unified lane scheduler.
///
/// One instance per resource. All methods are &mut self to encourage
/// single-threaded ownership with explicit synchronization points.
pub struct LaneScheduler {
    /// Per-lane state, indexed by `LaneClass` discriminant.
    lanes: [LaneRuntime; 5],
    /// Resource name for observability.
    resource_name: &'static str,
    /// Global memory pressure level (0-100).
    memory_pressure: u8,
}
```

### 3.2 Core algorithm: `select_next()`

The scheduler's primary entry point is `select_next()`, which returns the lane class
whose work should be processed next, or `None` if nothing is pending.

```
Algorithm select_next():
  1. For each lane in priority order (CONTROL → BACKGROUND):
     a. If the lane has inflight_bytes < max_inflight_bytes
        AND inflight_ops < max_inflight_ops
        AND queue is non-empty:
        → return this lane immediately

  2. If all lanes are at budget cap, check starvation:
     For each starvable lane (DEMAND, SPECULATIVE, BACKGROUND)
     in priority order:
       If queue is non-empty
       AND oldest_enqueue elapsed > starvation_timeout_ms:
         → return this lane (override budget cap for one op)

  3. If CONTROL has pending work and any lower lane is running
     a preemptible op:
       → signal preemption of current op, return CONTROL

  4. Return None (nothing can proceed)
```

### 3.3 Starvation prevention details

Starvation prevention is a **lane-level** guarantee, not an op-level guarantee. The
contract is: within `starvation_timeout_ms` of the oldest op being enqueued, at least
one op from that lane will be dispatched.

- When step 2 fires, exactly one op is admitted (the budget cap is overridden for
  that single op). After the op completes, normal budget enforcement resumes.
- The starvation clock resets when an op from that lane is *dispatched*, not when
  it completes.
- CONTROL and METADATA have `starvation_timeout_ms = 0`, meaning their starvation
  check is never triggered — they are always processed when ready and under budget.
- DEMAND has a 5-second starvation timeout. Under normal load, DEMAND is served
  naturally through step 1. The timeout protects against pathological cases where
  a flood of CONTROL+METADATA messages indefinitely blocks user reads.

### 3.4 Preemption contract

Preemption allows CONTROL to interrupt a lower-priority operation mid-flight.
Preemption is only safe when:

1. The currently-running lower-priority op is on a `preemptible` lane (SPECULATIVE
   or BACKGROUND).
2. The op has not entered a transactional commit phase.
3. The resource supports mid-op interruption (transport frames can be paused at
   chunk boundaries; background ticks can yield between batch entries).

When preemption occurs:
- **Droppable + non-resumable** (SPECULATIVE): The op is discarded. A new request
  must be issued if the data is still needed.
- **Droppable + resumable** (BACKGROUND): The op saves its cursor/resume state
  and re-enqueues at the front of the BACKGROUND queue.
- **Non-droppable** (DEMAND, METADATA): The op is not preempted. CONTROL waits
  until it completes or yields naturally.

### 3.5 Memory pressure integration

When `memory_pressure` rises, the scheduler throttles lanes in order of
`pressure_throttle_order` (lowest first):

| Pressure Level | Action |
|---|---|
| 0-40 (normal) | All lanes at full budget |
| 41-60 (elevated) | SPECULATIVE: reduce `max_inflight_bytes` to 25% of configured |
| 61-80 (high) | SPECULATIVE: drain all inflight, stop admitting; BACKGROUND: reduce to 25% |
| 81-95 (critical) | SPECULATIVE: sealed; BACKGROUND: drain; DEMAND: reduce to 50% |
| 96-100 (emergency) | Only CONTROL and METADATA admit new work; all others drain and seal |

The `memory_pressure` value is updated by the unified resource governor (#1237).
The lane scheduler reads it atomically (or via `&mut self`) on each `select_next()`
call.

---

## 4. Resource-specific lane configurations

### 4.1 Cluster transport (#1210)

The transport layer is the first resource to adopt the unified lane model. The
existing `TransportLaneBudgetRecord` and `MessageFamily::primary_lane_class()`
already classify transport work; this design adds starvation prevention and
preemption.

| Lane | `max_inflight_bytes` | `max_inflight_ops` | `starvation_timeout_ms` | `preemptible` |
|---|---|---|---|---|
| CONTROL | 1 MiB | 64 | 0 | false |
| METADATA | 16 MiB | 256 | 0 | false |
| DEMAND | 64 MiB | 512 | 5000 | false |
| SPECULATIVE | 8 MiB | 64 | 30000 | true |
| BACKGROUND | 256 MiB | 1024 | 60000 | true |

The transport scheduler operates at frame granularity: each `select_next()` call
returns the lane whose next frame should be serialized onto the wire. Frame
multiplexing across lanes is already supported via the `LaneClass` field in
`TransportEnvelopeRecord`.

**Preemption on transport**: CONTROL frames can be injected between chunk boundaries
of a BACKGROUND bulk transfer (#1229). The BACKGROUND transfer's chunk shipper
saves its cursor and the remaining chunks re-enqueue.

### 4.2 Device IO scheduler (design-only)

The device IO scheduler is a future resource; this design specifies its lane config
for forward compatibility.

| Lane | `max_inflight_bytes` | `max_inflight_ops` | `starvation_timeout_ms` |
|---|---|---|---|
| CONTROL | 256 KiB | 8 | 0 |
| DEMAND | 64 MiB | 256 | 50 |
| BACKGROUND | 256 MiB | 512 | 2000 |

Note: METADATA and SPECULATIVE are not present in the device IO scheduler because
IO is classified as either demand (user reads/writes) or background (cleaning, scrub).
CONTROL IO handles superblock updates, pool label writes, and other admin IO.

**Tradeoff**: collapsing METADATA into DEMAND at the IO layer means that metadata
IO (e.g., extent map updates during commit_group sync) competes directly with user reads.
However, the commit_group sync itself runs in the CONTROL or METADATA lane at the FUSE layer,
so metadata IO during commit_group sync is already prioritized. At the device layer, the
distinction between "metadata block" and "data block" is blurred because ZFS-style
copy-on-write turns all writes into new allocations.

### 4.3 FUSE request admission

FUSE request admission controls how many concurrent FUSE requests of each class
are admitted into the tidefs daemon.

| Lane | Max Concurrent Ops | Admission Policy |
|---|---|---|
| METADATA | 128 | FIFO admit, never drop |
| DEMAND | 64 | FIFO admit, never drop |
| SPECULATIVE | 8 | Admit only if memory_pressure < 60 |

CONTROL is not present in FUSE admission because CONTROL messages originate from
cluster membership, not from user FUSE requests. BACKGROUND is not present because
background services are internally ticked, not FUSE-driven.

When `memory_pressure >= 60`, SPECULATIVE FUSE requests (prefetch hints,
readahead) are rejected at admission with `ENOMEM` or silently dropped (the
kernel will retry or skip prefetch).

### 4.4 Background service ticks (#1179)

Each background service (cleaner, GC, compaction, rebake) runs on a per-tick budget
within the BACKGROUND lane. CONTROL can interrupt a background tick to handle
lease/admin messages.

```rust
/// Per-tick budget for a background service.
pub struct BackgroundTickBudget {
    /// Maximum bytes processed per tick.
    pub max_bytes_per_tick: u64,
    /// Maximum operations per tick.
    pub max_ops_per_tick: u64,
    /// Maximum wall-clock time per tick.
    pub max_time_per_tick: Duration,
    /// Whether CONTROL can preempt this tick mid-batch.
    pub preemptible: bool,
    /// Cursor for resumable ticks.
    pub resume_cursor: Option<Vec<u8>>,
}
```

Background services check their tick budget after each batch (e.g., after processing
256 reclaim entries). If the budget is exhausted, they yield. If CONTROL preempts,
they save their cursor and re-enqueue.

---

## 5. Interaction with related subsystems

### 5.1 Cache admission (#1237)

The unified resource governor classifies cache fills by lane class:

- **DEMAND fills**: cache misses from user reads. Admitted unconditionally (subject
  to cache capacity).
- **SPECULATIVE fills**: prefetch, readahead. Admitted only when cache pressure is low
  and SPECULATIVE lane is not backpressured.
- **BACKGROUND fills**: bulk data ingest during rebuild/scrub. Admitted only when
  BACKGROUND lane is not backpressured and cache free space > 20%.

### 5.2 Memory budget (#1211)

When memory pressure rises, the lane scheduler reduces budgets in order:

1. SPECULATIVE: evict speculative cache entries first, stop admitting new speculative
   cache fills, reduce transport inflight.
2. BACKGROUND: reduce background tick budgets, reduce BACKGROUND transport inflight.
3. DEMAND: increase backpressure latency but never starve. DEMAND's starvation timeout
   prevents indefinite blocking.
4. CONTROL: unaffected. Must always run to maintain cluster membership.

### 5.3 Writeback / commit_group (#1190)

CommitGroup sync operations are classified as CONTROL or METADATA lane. The commit_group commit
itself (steps 1-7 from #1267) is non-preemptible once started, but the sync trigger
decision respects lane priority.

### 5.4 BULK plane (#1229)

BULK traffic (state transfer, replica transfer) runs in BACKGROUND lane by default.
When a BULK transfer is demand-driven (e.g., a user read that requires catching up
a stale replica), it can be upgraded to DEMAND lane via `MessageFamily::secondary_lane_class()`.


They are small, latency-critical, and must never be delayed by bulk traffic.

---

## 6. Unified observability

### 6.1 `tidefsctl lanes` command

A unified observability view across all resources:

```text
$ tidefsctl lanes
RESOURCE        LANE          INFLIGHT(B)  CAP(B)    OPS  CAP(OPS)  STARVED(s)  PREEMPTED
transport       CONTROL              512    1 MiB      2       64         0.0          0
transport       METADATA           12 Mi   16 MiB     48      256         0.0          0
transport       DEMAND             48 Mi   64 MiB    312      512         0.0          0
transport       SPECULATIVE        2 Mi    8 MiB      12       64         0.8         89
transport       BACKGROUND         80 Mi  256 MiB    256     1024         1.2        340
fuse            METADATA                -        -      3      128           -          -
fuse            DEMAND                  -        -     45       64           -          -
fuse            SPECULATIVE             -        -      0        8           -          -
bg_services     BACKGROUND              -        -      1        -           -          2
```

The command reads from shared atomic counters and per-scheduler state, aggregated
by a `LaneObservability` collector.

### 6.2 Per-lane metrics

Each lane exposes the following metrics via the `LaneScheduler`:

| Metric | Type | Description |
|---|---|---|
| `inflight_bytes` | `AtomicU64` | Current bytes in-flight |
| `inflight_ops` | `AtomicU64` | Current operations in-flight |
| `total_starved` | `AtomicU64` (micros) | Total time ops waited beyond `starvation_timeout_ms` |
| `preemption_count` | `AtomicU64` | How many times ops on this lane were preempted |
| `backpressure_count` | `AtomicU64` | How many times producers were backpressured |
| `dropped_count` | `AtomicU64` | How many ops were dropped (SPECULATIVE/BACKGROUND only) |
| `lane_state` | `AtomicU8` | Current `LaneState` (Open, CreditLimited, Backpressured, Draining, Sealed) |

### 6.3 Integration with existing `LaneState`

The existing `LaneState` enum already has the states needed for observability:

- `Open`: normal operation
- `CreditLimited`: budget cap reached, producers throttled
- `Backpressured`: memory pressure has reduced available budget
- `Draining`: lane is being drained (e.g., during shutdown or pressure escalation)
- `Sealed`: no new ops admitted (emergency pressure or shutdown)

---

## 7. Tradeoffs and design rationale

### 7.1 Why five lanes, not three or seven?

- **Three lanes** (control, normal, background) is too coarse: it cannot distinguish
  between demand reads and speculative prefetch at the admission layer, nor between
  metadata and bulk data on the transport.
- **Seven lanes** adds complexity without clear benefit. The ZFS I/O scheduler has
  six priority levels, but several are rarely used in practice.
- **Five lanes** maps cleanly to the existing `MessageFamily` classification and
  the transport session model. It provides enough granularity for backpressure and
  starvation prevention without excessive state space.

### 7.2 Starvation timeout vs. weighted fair queueing

Weighted fair queueing (WFQ) is the alternative to starvation timeouts. WFQ assigns
each lane a weight and ensures proportional service. However:

- WFQ requires per-op overhead to track virtual time, which is expensive at high
  throughput.
- WFQ cannot express "CONTROL always wins" — weights are relative, not absolute.
- Starvation timeout with strict priority is simpler, cheaper, and matches the
  real-world requirement: CONTROL must never wait, BACKGROUND can wait up to 60s.

**Rationale**: strict priority + starvation timeout gives us the best of both
worlds: CONTROL is never delayed, and BACKGROUND is guaranteed progress within
a bounded time window.

### 7.3 Preemption vs. cooperative yielding

Full preemption (interrupting an op mid-flight) is complex and error-prone. The
alternative is cooperative yielding: each op checks a "should I yield?" flag at
safe points. However:

- CONTROL messages are small (lease renewals are ~100 bytes) and latency-critical
  (< 1ms). Cooperative yielding at chunk boundaries (64 KiB) could add up to 1ms
  of delay on a saturated link.
- BACKGROUND ops (256 MiB bulk transfer) can hold the wire for seconds without
  natural yield points.

**Rationale**: preemption at chunk boundaries for SPECULATIVE/BACKGROUND gives
CONTROL sub-millisecond dispatch latency. DEMAND and METADATA ops are small enough
that cooperative yielding at natural boundaries (frame boundaries for transport,
batch boundaries for background ticks) is sufficient.

### 7.4 Per-resource vs. global scheduler

A single global scheduler that dispatches across all resources (transport, IO,
FUSE, background) would provide the most unified view. However:

- Resources have fundamentally different op types (frames vs. IO blocks vs.
  FUSE requests vs. tick batches).
- A global scheduler would couple unrelated subsystems and create a bottleneck.
- Per-resource schedulers with shared `LaneConfig` and consistent
  starvation/preemption semantics give us unification at the *contract* level
  without coupling at the *execution* level.

**Rationale**: per-resource schedulers with the unified `LaneConfig`. The
observability layer aggregates across resources.

### 7.5 Memory pressure as a global signal

Memory pressure is a single integer (0-100) shared across all resources. An
alternative is per-resource pressure (transport buffer pressure, cache pressure,
IO queue depth). However:

- A single global signal is simpler to reason about and tune.
- Memory is the primary shared resource across all subsystems.
- Per-resource pressure can be added later as a refinement within each
  resource's scheduler, using the global signal as a ceiling.

---

## 8. Implementation plan

### Phase 1: `LaneConfig` and `LaneScheduler` (this design)

1. Add `LaneConfig` struct to `tidefs-types-transport-session` (or a new
   `tidefs-lane-scheduler` crate).
2. Implement `LaneScheduler` with the `select_next()` algorithm.
3. Add starvation prevention and preemption support.
4. Add `From<TransportLaneBudgetRecord>` conversion.
5. Unit tests for scheduler ordering, starvation, preemption, and pressure
   throttling.

### Phase 2: Transport adoption (#1210)

1. Replace ad-hoc transport lane logic with `LaneScheduler`.
2. Wire `LaneConfig` to existing `TransportLaneBudgetRecord` values.
3. Add frame-level preemption for BACKGROUND bulk transfers.
4. Integration test: CONTROL frames delivered within 1ms under BACKGROUND
   saturation.

### Phase 3: FUSE admission and background ticks

1. Implement FUSE request admission with per-class concurrency caps.
2. Add `BackgroundTickBudget` and per-tick lane checks to background services.
3. Wire CONTROL preemption into background tick loop.

### Phase 4: Observability

1. Add per-lane atomic counters.
2. Implement `tidefsctl lanes` command.
3. Add lane metrics to existing diagnostic output.

---

## 9. References

- `crates/tidefs-types-transport-session/src/lib.rs` — existing `LaneClass`, `LaneState`, `TransportLaneBudgetRecord`
- #1210 — transport boundedness (per-lane frame delivery)
- #1179 — background service framework (tick budgets)
- #1237 — unified resource governor (cache admission policy)
- #1211 — memory budget (pressure response per lane)
- #1229 — BULK plane (BACKGROUND lane traffic)
- #1267 — commit_group state machine (CONTROL/METADATA lane commit_group sync)
- ZFS I/O scheduler: six priority levels, `zio_priority_table`, weighted round-robin
