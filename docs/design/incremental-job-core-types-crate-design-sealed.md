# IncrementalJob Core Types Crate Design — Sealed

**Issue**: [#1985](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1985)
**Canonical design**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md) (comprehensive design spec)
**Prior coordination**: [#1930](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1930) (coordination seal)
**Status**: **sealed** — no further design changes permitted without a new design issue
**Maturity**: **design-spec** — Phase 1 data-plane types and `IncrementalJob` trait are frozen
**Lane**: storage-core (universal incremental cursor framework, #1239)
**Kind**: design

## Seal Statement

This document formally seals the design of `crates/tidefs-types-incremental-job-core/`.
The crate architecture, type designs, the `IncrementalJob` trait contract, feature
flags (`alloc`, `serde`), `no_std` posture, `forbid(unsafe_code)`, and dependency
graph position are **frozen**. No further design changes are permitted without a
new design issue.

**All subsystem wire-up is deferred to dedicated wire-up issues.** The types crate
provides the shared vocabulary; individual subsystems (cleanup, GC mark, B+tree
compaction, rebake, journal cleaning, dataset destroy, scrub, deep scrub, resilver,
rebalance, admin jobs, reclaim, orphan recovery) implement `IncrementalJob` in
their own crates.

## 1. Architecture Overview

### 1.1 Crate Identity

```
crates/tidefs-types-incremental-job-core/
├── Cargo.toml      — Zero mandatory deps, optional serde, alloc by default
└── src/
    └── lib.rs      — ~1625 lines, ~65 unit tests, single-file
```

The crate is the **authority crate** for all shared types in the universal
incremental cursor framework (#1239). It is dependency-minimal, `no_std`-first,
and free of unsafe code. It serves as the single shared type foundation for the
14 background maintenance subsystems.

### 1.2 Dependency Graph Position

```
tidefs-types-incremental-job-core   ← this crate (Phase 1, leaf)
    ↑ depends on
tidefs-incremental-job-core        ← trait + CheckpointCodec (Phase 2, #1620)
    ↑ implements
[cleanup, snap-destroy, gc-mark,   ← subsystem crates (Phase 4–6, wire-up)
 compact, rebake, clean, …]
    ↑ schedules
tidefs-background-scheduler        ← scheduling loop (Phase 3, #1673)
```

`tidefs-types-incremental-job-core` is the lowest leaf — zero tidefs crate
dependencies. It only depends on `core` (and optionally `alloc`, `serde`).

### 1.3 Feature Flags

| Feature | Default | Effect |
|---|---|---|
| `alloc` | **yes** | Enables `CursorState`, `Checkpoint`, `StepResult`, `IncrementalJob` trait, and `JobError::Other`. Gated types use `extern crate alloc` for `Vec<u8>`, `String`. |
| `serde` | no | Derives `Serialize`/`Deserialize` on all types. Implies `alloc`. |

**Rationale**: The `alloc` default keeps the crate ergonomic for the 99% case
(all tidefs daemons run with a heap). Disabling `alloc` produces a ~500-line core
with only `WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and fixed-message
shims that cannot allocate.

## 2. Data-Plane Types

### 2.1 `WorkBudget` — Three-Dimensional Resource Bound

```rust
pub struct WorkBudget {
    pub max_items: u64,  // records/entries/items per step (0 = unbounded)
    pub max_bytes: u64,  // bytes per step (0 = unbounded)
    pub max_ms: u64,     // wall-clock milliseconds per step (0 = unbounded)
}
```

| Constant | Items | Bytes | Time | Use |
|---|---|---|---|---|
| `DEFAULT_TICK` | 1024 | 64 MiB | 100 ms | Normal operations |
| `MAINTENANCE_TICK` | 256 | 16 MiB | 50 ms | Idle cluster background |
| `UNBOUNDED` | 0 | 0 | 0 | Unrestricted (tests, urgent ops) |
| `PAUSED` | 0 | 0 | 0 | Suspended job (all zeros = no work) |

**Design invariants**:
- Every `step()` call receives a `WorkBudget` and MUST NOT exceed any active limit.
- At least one limit SHOULD be non-zero to guarantee forward-progress boundedness.
- Budget enforcement is the implementor's responsibility (no preemption).
- `is_paused()` — all limits are zero (semantically distinct from unbounded).
- `is_bounded()` — at least one limit is non-zero.

### 2.2 `JobId` — Unique Job Identifier

```rust
pub struct JobId(u64);
```

- Newtype over `u64` with `Copy, Clone, Eq, Hash, Ord`.
- `JobId::NONE` = `JobId(0)` — sentinel for "no job."
- Serializes as u64 in JSON (via `serde`); displays as `"job-<id>"`.

### 2.3 `JobKind` — Background Operation Discriminant

Flat enum with 14 variants covering all background maintenance and admin
operations:

```rust
pub enum JobKind {
    DeferredCleanup,    // refcount-delta cleanup queues
    SnapshotDestroy,    // snapshot teardown
    GCMark,             // GC reachability marking
    BtreeCompaction,    // B+tree page compaction
    Rebake,             // ingest journal → base shard conversion
    JournalCleaning,    // intent log truncation
    DatasetDestroy,     // dataset destruction
    Scrub,              // online lightweight integrity check
    DeepScrub,          // full data integrity verification
    Resilver,           // redundancy rebuild after device failure
    Rebalance,          // data rebalancing across devices
    AdminJob,           // administrator-initiated operations
    Reclaim,            // free-space reclaim
    OrphanRecovery,     // orphaned object recovery
    Other(u8),          // forward-compatible extension slot
}
```

**Design invariants**:
- Flat enum (not nested) to keep `size_of::<JobKind>()` at 2 bytes (1-byte tag + 1-byte payload).
- `Other(u8)` provides forward compatibility — new job kinds enter as `Other(N)` before getting a named variant.
- `label()` returns a `&'static str` for display/logging.
- `is_integrity_check()` groups scrub, deep scrub, and orphan recovery.

### 2.4 `JobProgress` — Aggregate Progress Counters

```rust
pub struct JobProgress {
    pub items_processed: u64,   // cumulative items handled since job creation
    pub bytes_processed: u64,   // cumulative bytes handled
    pub items_total_estimate: u64,  // estimated total items (0 = unknown)
    pub bytes_total_estimate: u64,  // estimated total bytes (0 = unknown)
}
```

- All counters are saturating (never wrap).
- `completion_permille()` computes progress as permille (0–1000) using items
  first, falling back to bytes when items estimate is unknown.
- `checked_add()` and `saturating_add()` for safe accumulation.

### 2.5 `CursorState` — Opaque Serialized Cursor

```rust
#[cfg(feature = "alloc")]
pub struct CursorState(pub Vec<u8>);
```

- Opaque blob representing the implementation-specific cursor position.
- The framework treats it as a black box — only the job implementation
  knows the internal format.
- Gated on `alloc` feature (requires `Vec<u8>`).
- `is_empty()` for fresh-start detection.

### 2.6 `Checkpoint` — Persisted Progress Marker

```rust
#[cfg(feature = "alloc")]
pub struct Checkpoint {
    pub job_id: JobId,
    pub job_kind: JobKind,
    pub epoch: u64,               // monotonic checkpoint generation counter
    pub cursor_state: CursorState, // opaque position blob
    pub progress: JobProgress,    // aggregate counters
}
```

- `epoch` increments atomically on each `persist_checkpoint()` call.
- `new_initial()` creates a fresh checkpoint for a new job (empty cursor, zero progress, epoch 0).
- `is_fresh()` — true when epoch is 0 and cursor is empty (never persisted).
- Serialization via `CheckpointCodec` trait (Phase 2, #1620) for on-disk persistence.

### 2.7 `StepResult` — Outcome of One `step()` Call

```rust
#[cfg(feature = "alloc")]
pub struct StepResult {
    pub is_complete: bool,
    pub checkpoint: Checkpoint,
}
```

- `in_progress(checkpoint)` — job has more work (common case).
- `complete(checkpoint)` — job is finished.
- The scheduler uses `is_complete` to decide whether to reschedule or retire.

### 2.8 `JobError` — Structured Error Type

```rust
pub enum JobError {
    CursorStateInvalid { job_id: JobId, detail: &'static str },
    CheckpointCorrupted { job_id: JobId, reason: &'static str },
    BudgetExceeded { job_id: JobId, dimension: &'static str },
    IoError { job_id: JobId, detail: &'static str },
    Fatal { job_id: JobId, message: &'static str },
    #[cfg(feature = "alloc")]
    Other { job_id: JobId, message: alloc::string::String },
}
```

- Six variants: five fixed-message (no-alloc compatible) plus one alloc-gated catch-all.
- Every variant carries `job_id` for scheduler correlation.
- Implements `Display` and `Debug`.

## 3. The `IncrementalJob` Trait

```rust
#[cfg(feature = "alloc")]
pub trait IncrementalJob {
    /// Resume a job from a previously persisted checkpoint.
    /// Returns `JobError::CursorStateInvalid` if the cursor blob is corrupt.
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError>
    where
        Self: Sized;

    /// Execute one tick of work within the given budget.
    fn step(&mut self, budget: WorkBudget) -> StepResult;

    /// Produce a serializable checkpoint of the current position.
    fn persist_checkpoint(&self) -> Checkpoint;

    /// Mark the job as complete and release resources.
    fn complete(self);

    /// Return the job's unique identifier.
    fn job_id(&self) -> JobId;

    /// Return the job's operation kind.
    fn job_kind(&self) -> JobKind;
}
```

**Lifecycle contract**:
1. Scheduler calls `resume(checkpoint)` to create or restore a job.
2. Each tick, scheduler calls `step(budget)` until `is_complete` or budget exhausted.
3. After each `step()`, scheduler calls `persist_checkpoint()` and writes to stable storage.
4. On completion, scheduler calls `complete()` to release job resources.

**Design invariants**:
- `step()` MUST respect the budget in all three dimensions.
- `persist_checkpoint()` MUST increment `epoch` on every call.
- `complete()` is idempotent and safe to call multiple times.
- `job_id()` and `job_kind()` are pure accessors with no side effects.

## 4. Implementation Status (May 2026)

| Component | Status | Crate / Doc |
|---|---|---|
| Phase 1 core types (`WorkBudget`, `JobId`, `JobKind`, etc.) | **implemented-source** | `tidefs-types-incremental-job-core` (1619 lines, 65 tests) |
| Phase 2 trait + `CheckpointCodec` | **implemented-source** | `tidefs-incremental-job-core` (992 lines, 32 tests) |
| Phase 3 background scheduler | **implemented-source** | `tidefs-background-scheduler` (1410 lines) |
| Subsystem wire-up (cleanup, scrub, etc.) | **deferred** | Wire-up issues pending |

## 5. Deferred Wire-Up Subsystems

The following subsystems require dedicated wire-up issues to implement
`IncrementalJob` and integrate with the background scheduler:

| Subsystem | JobKind | Wire-up scope |
|---|---|---|
| Deferred cleanup | `DeferredCleanup` | Refcount-delta cleanup queue iteration |
| Snapshot destroy | `SnapshotDestroy` | Deadlist traversal + block freeing |
| GC mark | `GCMark` | Reachability marking pass |
| B+tree compaction | `BtreeCompaction` | Page merge/split cursor |
| Rebake | `Rebake` | Ingest journal → base shard conversion |
| Journal cleaning | `JournalCleaning` | Intent log truncation |
| Dataset destroy | `DatasetDestroy` | Recursive dataset teardown |
| Scrub | `Scrub` | Lightweight checksum verification |
| Deep scrub | `DeepScrub` | Full data integrity verification |
| Resilver | `Resilver` | Redundancy rebuild |
| Rebalance | `Rebalance` | Data redistribution |
| Admin jobs | `AdminJob` | Operator-initiated operations |
| Reclaim | `Reclaim` | Free-space reclamation |
| Orphan recovery | `OrphanRecovery` | Orphaned object recovery |

Each wire-up issue must:
- Implement `IncrementalJob` in the subsystem's crate.
- Provide a `CheckpointCodec` implementation for cursor serialization.
- Register the job kind with the background scheduler.

## 6. Design Rationale and Tradeoffs

### 6.1 Single-file crate vs. multi-module

**Decision**: Single `lib.rs` with all types and the trait co-located.

**Rationale**: Types are tightly coupled — `Checkpoint` contains `CursorState`,
`StepResult` contains `Checkpoint`, `JobProgress` is embedded in `Checkpoint`.
Splitting into sub-modules would create circular visibility or require
re-exports. At ~1625 lines, the file remains manageable. If the crate grows
beyond 3000 lines, introduce sub-modules.

### 6.2 Flat `JobKind` enum vs. hierarchical

**Decision**: Flat enum with `Other(u8)` extension slot.

**Rationale**: Keeps `size_of::<JobKind>()` at 2 bytes (niche-optimized).
A two-level hierarchy (category + sub-kind) would add complexity for the
scheduler without clear benefit until variant count exceeds 32 (one byte
discriminant limit). Revisit if variant count approaches 32.

### 6.3 Opaque `CursorState` vs. typed cursor

**Decision**: `CursorState(Vec<u8>)` — opaque blob.

**Rationale**: Different subsystems have fundamentally different cursor shapes
(B+tree position stacks, extent offsets, object IDs). Forcing a common typed
cursor would require either a massive enum or dynamic dispatch. The opaque
approach lets each implementation define its own format while the framework
treats cursors as black boxes. The `CheckpointCodec` trait (Phase 2) handles
serialization boundaries.

### 6.4 `no_std` posture

**Decision**: `#![cfg_attr(not(test), no_std)]` with `alloc` feature enabled by default.

**Rationale**: The 99% case (all tidefs daemons) runs with a heap, so `alloc`
default keeps the crate ergonomic. The `no_std` core (without `alloc`) provides
This covers all known use cases without over-engineering.

### 6.5 `forbid(unsafe_code)`

**Decision**: Zero unsafe code.

**Rationale**: This is a type-definition crate with no FFI, no direct memory
manipulation, and no performance-critical paths. Unsafe code would provide
no benefit and would increase audit surface. All unsafe code belongs in
subsystem implementations, not in shared type definitions.

### 6.6 Error model: fixed variants vs. dynamic

**Decision**: Five fixed-message variants + one alloc-gated `Other(String)`.

**Rationale**: The five fixed variants cover the most common error categories
without requiring allocation. The `Other` variant provides an escape hatch for
subsystem-specific error messages when `alloc` is available. This balances
`no_std` compatibility with practical error reporting.

## 7. Testing Strategy

The crate includes ~65 unit tests covering:

| Category | Count | Key invariants tested |
|---|---|---|
| `WorkBudget` | 12 | Default/MAINTENANCE tick values, boundedness, paused detection, within-budget checks |
| `CursorState` | 6 | Empty detection, clone/eq, vec round-trip |
| `JobProgress` | 10 | Default zero, permille calculation, items/bytes fallback, saturating accumulation |
| `Checkpoint` | 8 | Initial creation, freshness, serde roundtrip |
| `StepResult` | 4 | In-progress/complete constructors |
| `JobId` | 5 | None sentinel, display format |
| `JobKind` | 7 | Label strings, integrity check grouping, Other roundtrip |
| `JobError` | 6 | Display messages, job_id accessor |
| Serde roundtrip | 5 | JSON roundtrip for WorkBudget, Checkpoint |
| Trait lifecycle | 10 | Resume, step, persist, complete, resume-from-checkpoint, invalid-cursor error |

```bash
cargo test -p tidefs-types-incremental-job-core
cargo clippy -p tidefs-types-incremental-job-core -- -D warnings
cargo check --workspace
```

## 8. ZFS / Ceph design-input comparison

This sealed comparison records why the type vocabulary was shaped this way. It
is not validation evidence for deployed TideFS background-job behavior, and it
does not make a product-facing claim against ZFS or Ceph.

| Dimension | tidefs types crate | ZFS | Ceph |
|---|---|---|---|
| **Shared type vocabulary** | Yes — 8 types, 1 trait, all subsystems | No — each subsystem defines its own types | No — per-PG types |
| **Unified budget model** | `WorkBudget` with 3 dimensions | `zfs_scan_legacy` (bytes only) | `osd_recovery_max_active` (ops only) |
| **Crash-resumable checkpoint** | `Checkpoint` with opaque cursor + epoch | Ad-hoc per-subsystem (scrub_progress ZAP) | In-memory only |
| **Error classification** | 6 structured variants + catch-all | Per-subsystem error codes | Per-PG error counters |
| **Forward compatibility** | `JobKind::Other(u8)` | N/A | Versioned OSDMap |
| **No-alloc support** | Yes — feature-gated | No | No |
| **Unsafe code** | Zero | Ubiquitous | Some |

## 9. Revision History

| Date | Change | Issue |
|---|---|---|
| 2026-05-02 | Initial crate implementation (1619 lines, 65 tests) | #1385 |
| 2026-05-04 | Design document formalized | #1588 |
| 2026-05-04 | Design document updated; closed via #1701 | #1701 |
| 2026-05-04 | Coordination seal confirmed; design frozen | #1930 |
| 2026-05-04 | Formal seal document; wire-up deferred | #1985 |

## 10. References

- **Canonical design spec**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md)
- **Phase 2 trait + CheckpointCodec**: [`docs/design/incremental-job-core-trait-checkpoint-codec-design.md`](./incremental-job-core-trait-checkpoint-codec-design.md)
- **Universal incremental cursor framework**: [`docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md`](../UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md)
- **Background service framework**: [`docs/design/background-service-framework-design.md`](./background-service-framework-design.md)
- **Crate source**: `crates/tidefs-types-incremental-job-core/src/lib.rs`
- **Phase 2 crate**: `crates/tidefs-incremental-job-core/src/lib.rs`
