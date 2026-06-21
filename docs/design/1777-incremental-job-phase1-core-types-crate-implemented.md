# IncrementalJob Phase 1 — Core Types Crate Implemented (#1385)

**Issue**: [#1777](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1777)
**Prior art**: [#1385](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1385) (original implementation),
[#1239](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1239) (universal incremental cursor framework)
**Canonical design**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md)
**Coordination seal**: [#1930](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1930)
**Maturity**: **design-spec** — data-plane types and `IncrementalJob` trait frozen;
Rust subsystem wire-up deferred to wire-up issues
**Lane**: storage-core (universal incremental cursor framework)
**Kind**: design

---

## Design Spec Statement

This document is the **design-spec** for the Phase 1 `IncrementalJob` core types
crate (`tidefs-types-incremental-job-core`) originally implemented in #1385.
All data-plane types (`WorkBudget`, `CursorState`, `JobProgress`, `Checkpoint`,
`StepResult`, `JobId`, `JobKind`, `JobError`) and the `IncrementalJob`
control-plane trait are **frozen**. No further design changes to the types crate
or the `IncrementalJob` trait are permitted without a new design issue.

**Rust implementation of subsystem wire-up is deferred.** The types crate
(`tidefs-types-incremental-job-core`, ~1625 lines, ~65 tests) and the trait +
codec crate (`tidefs-incremental-job-core`, ~992 lines, ~32 tests) are
implemented. The 14 background maintenance subsystems that implement
`IncrementalJob` are each deferred to dedicated wire-up issues.

---

## 1. Architecture

### 1.1 Three-Phase Layering

The universal incremental cursor framework (#1239) is structured in three phases:

| Phase | Crate | Scope | Status |
|---|---|---|---|
| **Phase 1** | `tidefs-types-incremental-job-core` | Data-plane types + `IncrementalJob` trait | **implemented-source** (~1625 lines, ~65 tests) |
| **Phase 2** | `tidefs-incremental-job-core` | `CheckpointCodec` binary serialization + trait re-exports | **implemented-source** (~992 lines, ~32 tests) |
| **Phase 3** | `tidefs-background-scheduler` | Scheduling loop, budget allocation, job lifecycle | **implemented-source** (~1410 lines) |
| **Wire-up** | 14 subsystem crates | Each subsystem implements `IncrementalJob` | **deferred** |

### 1.2 Dependency Graph

```
tidefs-types-incremental-job-core   ← Phase 1, zero tidefs dependencies
    ↑ depends on (only core, optional alloc/serde)
tidefs-incremental-job-core        ← Phase 2, depends only on Phase 1 crate
    ↑ implements trait
[14 subsystem crates]              ← each implements IncrementalJob
    ↑ scheduled by
tidefs-background-scheduler        ← Phase 3, scheduling loop
```

The split between the types crate (Phase 1) and the trait/codec crate (Phase 2)
avoids a dependency tangle: admin tools and protocol serializers can depend on
`tidefs-types-incremental-job-core` for `WorkBudget`, `JobError`, `JobId`, and
`JobKind` without pulling in the `IncrementalJob` trait and its `Send` bound.

### 1.3 Crate Layout

```
crates/tidefs-types-incremental-job-core/
├── Cargo.toml      — Zero mandatory deps, optional serde, alloc by default
└── src/
    └── lib.rs      — ~1625 lines, ~65 unit tests, single-file

crates/tidefs-incremental-job-core/
├── Cargo.toml      — Depends only on types crate
└── src/
    └── lib.rs      — ~992 lines, ~32 unit tests, single-file
```

Both crates are single-file `lib.rs`, `no_std`-first, `forbid(unsafe_code)`,
with feature flags `alloc` (default on) and `serde` (optional).

### 1.4 Feature Flags

| Feature | Default | Effect |
|---|---|---|
| `alloc` | **yes** | Enables `CursorState`, `Checkpoint`, `StepResult`, `IncrementalJob` trait, and `JobError::Other(String)`. Gated types use `extern crate alloc` for `Vec<u8>`, `String`. |
| `serde` | no | Derives `Serialize`/`Deserialize` on all types. Implies `alloc`. |

With `alloc` disabled, the types crate provides a ~500-line no-heap core:
`WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and fixed-message `JobError`

---

## 2. Data Structures

### 2.1 `WorkBudget` — Three-Dimensional Resource Bound

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBudget {
    pub max_items: u64,  // 0 = unbounded
    pub max_bytes: u64,  // 0 = unbounded
    pub max_ms: u64,     // 0 = unbounded (soft limit)
}
```

Every `step()` call receives a `WorkBudget`. Implementations MUST NOT exceed any
active limit. A limit of `0` means unbounded in that dimension. At least one
limit SHOULD be non-zero for forward-progress boundedness.

| Constant | Items | Bytes | Time | Use |
|---|---|---|---|---|
| `DEFAULT_TICK` | 1024 | 64 MiB | 100 ms | Normal operations |
| `MAINTENANCE_TICK` | 256 | 16 MiB | 50 ms | Idle cluster background |
| `UNBOUNDED` | 0 | 0 | 0 | Admin-initiated jobs, tests |
| `PAUSED` | 0 | 0 | 0 | Suspended job (all zeros) |

Key methods: `is_bounded()`, `is_unbounded()`, `items_within_budget()`,
`bytes_within_budget()`. Budget enforcement is the implementor's
responsibility — the framework does not preempt.

### 2.2 `CursorState` — Opaque Cursor Blob (`alloc`-gated)

```rust
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CursorState(pub Vec<u8>);
```

Opaque serialized cursor private to each `IncrementalJob` implementation.
The format and interpretation are entirely the subsystem's responsibility.
The framework treats cursors as black boxes for persistence and crash recovery.

Methods: `empty()`, `is_empty()`, `len()`, `as_bytes()`. Round-trip via
`From<Vec<u8>>`.

### 2.3 `JobProgress` — Aggregate Progress Counters

```rust
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct JobProgress {
    pub items_processed: u64,
    pub items_total_estimate: u64,   // 0 = unknown
    pub bytes_processed: u64,
    pub bytes_total_estimate: u64,   // 0 = unknown
    pub elapsed_ms: u64,
}
```

`completion_permille()` returns the job's completion estimate in permille
(0–1000). If `items_total_estimate > 0`, uses item ratio; otherwise falls back
to `bytes_total_estimate` ratio; returns 0 if neither estimate is known.

### 2.4 `Checkpoint` — Crash-Resumable Progress Marker (`alloc`-gated)

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub job_id: JobId,
    pub job_kind: JobKind,
    pub epoch: u64,          // monotonically incremented on daemon restart
    pub cursor_state: CursorState,  // opaque cursor position
    pub progress: JobProgress,      // aggregate progress since job creation
}
```

Persisted atomically in the dataset-scoped checkpoint area. The `epoch` counter
enables the admin to distinguish "fresh run" from "crash recovery".

### 2.5 `StepResult` — Outcome of One `step()` Call (`alloc`-gated)

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepResult {
    pub checkpoint: Checkpoint,
    pub is_complete: bool,
}
```

Constructors: `StepResult::in_progress(checkpoint)` and
`StepResult::complete(checkpoint)`. After every `step()` returning `Ok(result)`,
the caller must persist `result.checkpoint` before the next `step()`.

### 2.6 `JobId` — Unique Job Identifier

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct JobId(pub u64);
```

Newtype over `u64`. `JobId::NONE = JobId(0)` is the sentinel for "no job".
Displays as `"job-<id>"`.

### 2.7 `JobKind` — Background Operation Discriminant

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JobKind {
    DeferredCleanup,    // refcount-delta cleanup queues
    SnapshotDestroy,    // snapshot teardown (deadlist processing)
    GCMark,             // GC reachability marking
    BtreeCompaction,    // B+tree page compaction/merging
    Rebake,             // ingest journal → base shard conversion
    JournalCleaning,    // intent-log segment reclamation
    DatasetDestroy,     // admin-initiated dataset teardown
    Scrub,              // lightweight integrity check
    DeepScrub,          // full data checksum verification
    Resilver,           // device replacement data rebuild
    Rebalance,          // rebalance planner
    Reclaim,            // space reclaim job
    AdminJob,           // generic admin operation
    OrphanRecovery,     // orphan index recovery
    Other(u8),          // forward-compatibility extension
}
```

14 named variants + 1 forward-compatibility slot. `Other(u8)` ensures the
discriminant can represent future job kinds without breaking existing
serialized state. `size_of::<JobKind>()` is 2 bytes (niche-optimized).

### 2.8 `JobError` — Structured Error Type

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobError {
    CheckpointCorrupted { job_id: JobId, detail: &'static str },
    InvalidCursor { job_id: JobId, detail: &'static str },
    BudgetExceeded { job_id: JobId, limit: &'static str, actual: u64 },
    JobAlreadyComplete { job_id: JobId },
    IoError { job_id: JobId, detail: &'static str },
    #[cfg(feature = "alloc")]
    Other(String),
}
```

Five fixed-message variants (no allocation required) plus one `alloc`-gated
`Other(String)` for subsystem-specific error messages. All variants carry
`job_id` for admin correlation.

---

## 3. Algorithms

### 3.1 `IncrementalJob` Lifecycle State Machine

Every `IncrementalJob` instance moves through a small set of states:

```text
  resume(None) ──→ step(budget) ──→ persist_checkpoint ──→ step(budget) ──→ … ──→ complete()
                     │                                                           │
                     └── crash ──→ resume(Some(cp)) ──→ step(budget) ──→ … ──────┘
```

**States**:

| State | Entry condition | Exit condition |
|---|---|---|
| **New** | `resume(None)` succeeds | First `step()` call |
| **Active** | After `step()` → `Ok(StepResult { is_complete: false, … })` | Next `step()` or crash |
| **Completed** | `step()` → `Ok(StepResult { is_complete: true, … })` | `complete()` called |
| **Crashed** | Any point before `complete()` | `resume(Some(cp))` restores Active |

### 3.2 Step Dispatch Algorithm

The background scheduler (#1179) dispatches steps with the following algorithm:

1. **Select job**: Pick the highest-priority active `IncrementalJob` from the
   scheduler's run queue. Priority is scheduler-owned, not part of the trait.
2. **Allocate budget**: Compute a per-job `WorkBudget` from the global tick
   budget and the job's scheduling class weight.
3. **Call `step(budget)`**: Dispatch the bounded work unit.
4. **Persist checkpoint**: On `Ok(result)`, call `persist_checkpoint()` and
   write the checkpoint to stable storage atomically within the current commit_group.
5. **Check completion**: If `result.is_complete`, invoke `complete()` and remove
   the job from the active set.
6. **Handle error**: On `Err(e)`, the scheduler logs the error, optionally
   retries, and escalates to the admin event stream if retries are exhausted.

### 3.3 Crash Recovery Algorithm

Crash recovery is the implementor's responsibility via `resume(Some(cp))`:

1. On daemon restart, the scheduler scans the dataset checkpoint area for all
   persisted `Checkpoint` records.
2. For each checkpoint, the scheduler determines the owning subsystem from
   `checkpoint.job_kind`.
3. The subsystem calls `MyJob::resume(Some(checkpoint))` which:
   - Deserializes `checkpoint.cursor_state` into the subsystem's internal cursor
   - Repositions the internal iterator to the exact pre-crash position
   - Returns a fully initialized job ready for `step()`
4. The scheduler resumes normal step dispatch from the recovered position.
5. **Idempotency guarantee**: Calling `step()` from the recovered cursor
   position produces no duplicate side effects — the checkpoint is the
   linearization point.

### 3.4 CheckpointCodec Binary Format

The `CheckpointCodec` trait (Phase 2, `tidefs-incremental-job-core`) provides
a length-delimited binary format:

```text
+----------------+----------------+------------------+-------------------+
| magic (8 bytes)| version (4 B)  | payload_len (4 B)| payload (variable)|
+----------------+----------------+------------------+-------------------+
```

- **magic**: `b"TFSCHKPT"` (8 bytes) — identifies a tidefs checkpoint record
- **version**: `u32` LE — schema version (currently 1)
- **payload_len**: `u32` LE — total payload byte length
- **payload**: concatenation of `job_id` (8 B LE), `job_kind` (2 B LE),
  `epoch` (8 B LE), `items_processed` (8 B LE), `bytes_processed` (8 B LE),
  `elapsed_ms` (8 B LE), and `cursor_state` (variable-length blob)

Total header size: 16 bytes. Maximum checkpoint size: ~4 GiB (u32 payload_len).
Typical checkpoint size in practice: 64–256 bytes for most subsystems.

### 3.5 Budget Compliance Enforcement

gate (`tidefs-xtask check-incremental-cursor`) tests compliance:

1. **Deterministic trace**: Record every `step()` call with input budget and
   output `StepResult`.
2. **Budget baseline**: For each subsystem, measure max items/bytes/time
   consumed per step across 10,000 random workloads.
3. **Assertion**: No step exceeds its input `WorkBudget` in any dimension.
4. **Crash injection**: Inject crashes at every step boundary in the trace and
   verify that `resume(checkpoint)` + `step()` produces identical aggregate
   output to the non-crashed run.

---

## 4. Tradeoffs

### 4.1 Opaque `CursorState` vs. Typed Cursor

**Decision**: `CursorState(Vec<u8>)` — opaque blob.

**Rationale**: Different subsystems have fundamentally different cursor shapes
(B+tree position stacks, extent offsets, object IDs). Forcing a common typed
cursor would require either a massive enum or dynamic dispatch. The opaque
approach lets each implementation define its own format while the framework
treats cursors as black boxes. The `CheckpointCodec` trait (Phase 2) handles
serialization boundaries.

**Cost**: Admin tools cannot introspect cursors without subsystem-specific
knowledge. Mitigated by `JobProgress` aggregate counters for admin display
and the `epoch` field for crash detection.

### 4.2 Two-Crate Split vs. Monolithic Crate

**Decision**: Split into `tidefs-types-incremental-job-core` (Phase 1) and
`tidefs-incremental-job-core` (Phase 2).

**Rationale**: Admin tools, protocol serializers, and embedded firmware can
depend on the types crate without pulling in the `IncrementalJob` trait and its
`Send` bound. The core crate depends only on the types crate and is the single
dependency for all subsystem implementations.

**Cost**: Two `Cargo.toml` files, two import paths. Mitigated by the Phase 2
crate re-exporting all types from Phase 1.

### 4.3 `no_std` + `alloc` Feature Gate

**Decision**: `#![cfg_attr(not(test), no_std)]` with `alloc` feature enabled
by default.

**Rationale**: The 99% case (all tidefs daemons) runs with a heap, so `alloc`
default keeps the crate ergonomic. The no-heap core (~500 lines) provides
`WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and fixed-message `JobError`

**Cost**: Feature-gated types require `#[cfg(feature = "alloc")]` guards on
`CursorState`, `Checkpoint`, `StepResult`, and `IncrementalJob`. Acceptable
for a crate with a single `lib.rs`.

### 4.4 `forbid(unsafe_code)`

**Decision**: Zero unsafe code in both crates.

**Rationale**: These are type-definition and trait-definition crates with no FFI,
no direct memory manipulation, and no performance-critical paths. Unsafe code
would increase audit surface without benefit. All unsafe code belongs in
subsystem implementations.

### 4.5 Binary Checkpoint Format vs. Serde-Only

**Decision**: Both `CheckpointCodec` (binary) and optional `serde` support.

**Rationale**: The binary format is ~2× more compact than JSON and works without

**Cost**: Two serialization paths to maintain. The binary format is intentionally
simple (16-byte header + flat field encoding) to keep both paths trivial.

### 4.6 Single-File Crate Layout

**Decision**: Both Phase 1 and Phase 2 crates are single-file (`lib.rs` only).

**Rationale**: All types are tightly coupled — they appear together in every
`StepResult`, `Checkpoint`, and `IncrementalJob` implementation. Splitting into
modules would create import friction without meaningful separation of concerns.
Revisit if either crate exceeds ~3000 lines.

### 4.7 Error Model: Fixed Variants vs. Dynamic

**Decision**: Five fixed-message variants + one `alloc`-gated `Other(String)`.

**Rationale**: The five fixed variants cover the most common error categories
without requiring allocation. The `Other` variant provides an escape hatch for
subsystem-specific error messages when `alloc` is available. This balances
`no_std` compatibility with practical error reporting.

**Cost**: `Other(String)` is opaque to error-matching logic. Acceptable since
subsystem-specific errors are not actionable by the scheduler — they are
escalated to the admin event stream for human intervention.

---

## 5. Subsystem Wire-Up Catalog (Deferred)

Each of the 14 subsystems below must implement `IncrementalJob` in its own
wire-up issue. The types crate provides the shared vocabulary; each subsystem
defines its own cursor format, budget semantics, and completion criteria.

| # | Subsystem | Crate | Key challenge |
|---|---|---|---|
| 1 | Deferred cleanup | `tidefs-cleanup-job-core` | Refcount-delta extent iteration |
| 2 | Snapshot destroy | `tidefs-cluster-snapshot` | Deadlist B+tree traversal |
| 3 | GC mark | `tidefs-cluster-gc` | Metadata reachability graph walk |
| 4 | B+tree compaction | `tidefs-btree` | Sorted key/value leaf-page rewrite |
| 5 | Rebake | `tidefs-rebake-planner` | Ingest journal → base shard conversion |
| 6 | Journal cleaning | `tidefs-reclaim` | Intent-log segment reclamation |
| 7 | Dataset destroy | `tidefs-dataset-lifecycle` | Admin-initiated teardown |
| 8 | Scrub | `tidefs-online-verifier` | Lightweight integrity check pass |
| 9 | Deep scrub | `tidefs-online-verifier` | Full data checksum verification |
| 10 | Resilver | `tidefs-rebuild-planner` | Device replacement data rebuild |
| 11 | Rebalance | `tidefs-rebalance-planner` | Capacity rebalancing |
| 12 | Admin jobs | `tidefs-authority-publication-core` | Generic long-running operations |
| 13 | Reclaim | `tidefs-reclaim-job-core` | Space reclaim job |
| 14 | Orphan recovery | `tidefs-orphan-recovery-job-core` | Orphan index recovery |

---

## 6. ZFS and Ceph design-input comparison

This table is a design-input summary for the Phase 1 type contract. It does
not validate deployed TideFS background-job reliability, performance, or safety
relative to ZFS or Ceph.

| Dimension | TideFS (this design) | ZFS | Ceph |
|---|---|---|---|
| **Shared type vocabulary** | Yes — 8 types, 1 trait, all subsystems | No — each subsystem defines its own types | No — per-PG types |
| **Unified budget model** | `WorkBudget` with 3 dimensions (items, bytes, time) | `zfs_scan_legacy` (bytes only) | `osd_recovery_max_active` (ops only) |
| **Crash-resumable checkpoints** | `Checkpoint` with opaque cursor + epoch | Ad-hoc (`dsl_scan_phys_t`, ZAP objects) | In-memory only |
| **Error classification** | 6 structured variants + catch-all | Per-subsystem error codes | Per-PG error counters |
| **Forward compatibility** | `JobKind::Other(u8)` | N/A | Versioned OSDMap |
| **No-alloc support** | Yes — feature-gated | No | No |
| **Unsafe code** | Zero | Ubiquitous | Some |
| **Cursor framework** | Single `IncrementalJob` trait | `dsl_scan_t` (read-only), `spa_sync` passes (ad-hoc), `device_rebuild` (bitmaps) | Per-PG state machines (recovery, backfill, scrub) |

---


```bash
cargo test -p tidefs-types-incremental-job-core
cargo test -p tidefs-incremental-job-core
cargo clippy -p tidefs-types-incremental-job-core -- -D warnings
cargo clippy -p tidefs-incremental-job-core -- -D warnings
cargo check --workspace
```

The full xtask gate: `tidefs-xtask check-incremental-cursor` verifies
integration with the background scheduler and the deterministic crash
injection harness (#1230).

---

## 8. References

- **Universal incremental cursor framework**: [`docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md`](../UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md)
- **Canonical design spec**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md)
- **Seal document**: [`docs/design/incremental-job-core-types-crate-design-sealed.md`](./incremental-job-core-types-crate-design-sealed.md)
- **Phase 1 design spec (#1855)**: [`docs/design/1855-incremental-job-phase1-design-spec.md`](./1855-incremental-job-phase1-design-spec.md)
- **Phase 2 trait + codec**: [`docs/design/incremental-job-core-trait-checkpoint-codec-design.md`](./incremental-job-core-trait-checkpoint-codec-design.md)
- **Background service framework**: [`docs/design/background-service-framework-design.md`](./background-service-framework-design.md)
- **Implemented design-spec (#2026)**: [`docs/design/phase1-incremental-job-core-types-implemented.md`](./phase1-incremental-job-core-types-implemented.md)
- **Coordination seal (#1930)**: [`docs/design/incremental-job-core-wire-up-deferred-design.md`](./incremental-job-core-wire-up-deferred-design.md)
- **Crate source**: `crates/tidefs-types-incremental-job-core/src/lib.rs`
- **Phase 2 crate**: `crates/tidefs-incremental-job-core/src/lib.rs`
- **Issue #1385**: Original Phase 1 crate implementation

---

## 9. Revision History

| Date | Change | Issue |
|---|---|---|
| 2026-05-02 | Initial crate implementation (~1625 lines, ~65 tests) | #1385 |
| 2026-05-04 | Design document formalized | #1588 |
| 2026-05-04 | Coordination seal confirmed; design frozen | #1930 |
| 2026-05-04 | Formal seal document; wire-up deferred | #1985 |
| 2026-05-04 | Consolidated design-spec document | #1855 |
| 2026-05-05 | Design-spec document for #1385 implementation context | #1777 |
