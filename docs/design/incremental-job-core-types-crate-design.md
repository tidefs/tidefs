# IncrementalJob Core Types Crate Design

**Issue**: [#1385](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1385)
**Coord**: [#1930](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1930)
**Closes**: [#1701](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1701), [#1588](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1588), [#1385](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1385)
**Prior**: [#1588](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1588) (design formalization), [#1701](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1701) (prior coordination)
**Status**: sealed
**Maturity**: **design-spec** — Phase 1 data-plane types and `IncrementalJob` trait are frozen; Rust implementation of deferred subsystem wire-up deferred to wire-up issues
**Priority**: P2
**Lane**: storage-core (universal incremental cursor framework)
**Depends on**: [#1239](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1239) (universal incremental cursor framework design)
**Related**: [#1620](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1620) (Phase 2 trait + CheckpointCodec), [#1673](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1673) (background scheduler), [#1619](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1619) (deferred cleanup), [#1913](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1913) (scrub/resilver)

## Coordination Seal (#1930)

This document is the canonical design specification for the Phase 1 data-plane
types and `IncrementalJob` control-plane trait in the universal incremental cursor
framework (#1239).

**Seal statement**: The crate architecture, type designs (`WorkBudget`, `JobId`,
`JobKind`, `JobProgress`, `CursorState`, `Checkpoint`, `StepResult`, `JobError`),
the `IncrementalJob` trait contract, feature flags (`alloc`, `serde`), `no_std`
posture, `forbid(unsafe_code)`, and dependency graph position are frozen. No
further design changes are permitted without a new design issue. Wire-up issues
may be filed against individual subsystem integrations (cleanup, GC mark,
B+tree compaction, rebake, journal cleaning, dataset destroy, scrub, deep scrub,
resilver, rebalance, admin jobs, reclaim, orphan recovery).

### Current implementation status (May 2026)

| Component | Status | Crate / Doc |
|---|---|---|
| Phase 1 core types (`WorkBudget`, `JobId`, `JobKind`, etc.) | **implemented-source** | `tidefs-types-incremental-job-core` (1619 lines, 65 tests) |
| Phase 2 trait + `CheckpointCodec` | **implemented-source** | `tidefs-incremental-job-core` (992 lines, 32 tests) |
| Phase 3 background scheduler | **implemented-source** | `tidefs-background-scheduler` (1410 lines) |
| Subsystem wire-up (cleanup, scrub, etc.) | **deferred** | Wire-up issues pending |

Originally written for #1588 to formalize the design of
`crates/tidefs-types-incremental-job-core/` (implemented in #1385).


## 1. Purpose
The `tidefs-types-incremental-job-core` crate is the authority crate for all
shared types in the universal incremental cursor framework (#1239). It defines:

- **Data-plane types**: `WorkBudget`, `CursorState`, `JobProgress`, `Checkpoint`,
  `StepResult`, `JobId`, `JobKind`, and `JobError` — the vocabulary spoken by
  every cursor-driven background job.
- **Control-plane trait**: `IncrementalJob` — the universal contract that every
  background maintenance and admin operation implements.

The crate is dependency-minimal, `no_std`-first, and free of unsafe code. It
serves as the single shared type foundation for the 10+ subsystems that adopt
the incremental cursor contract (deferred cleanup, snapshot destroy, GC mark,
B+tree compaction, rebake, journal cleaning, dataset destroy, scrub, deep scrub,
resilver, rebalance, admin jobs, reclaim, and orphan recovery).

## 2. Crate Architecture

### 2.1 Crate identity

```
crates/tidefs-types-incremental-job-core/
├── Cargo.toml
└── src/
    └── lib.rs         (1625 lines, ~65 unit tests)
```

Single-file crate. All types, trait, and tests co-locate in `lib.rs`. No
sub-module split needed at this scope — related types are tightly coupled and
share the same feature gates.

### 2.2 Feature flags

| Feature | Default | Effect |
|---|---|---|
| `alloc` | **yes** | Enables `CursorState`, `Checkpoint`, `StepResult`, `IncrementalJob` trait, and `JobError::Other`. Gated types use `extern crate alloc` for `Vec<u8>`, `String`. |
| `serde` | no | Derives `Serialize`/`Deserialize` on all types. Implies `alloc`. |

**Rationale**: The `alloc` default keeps the crate ergonomic for the 99% case
(all tidefs daemons run with a heap). Disabling `alloc` produces a ~500-line
core with only `WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and fixed-message
shims that cannot allocate.

### 2.3 Dependencies

- **Zero mandatory dependencies**. The crate compiles with only `core`.
- **Optional `serde`**: gated behind the `serde` feature for admin protocol
- **No tidefs-internal dependencies**. This crate is a leaf in the dependency
  graph, ensuring it can be used by every other crate without circularity risk.

### 2.4 Safety posture

```rust
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
```

No unsafe code anywhere. All types are plain data (`Copy` or `Clone`), the trait
is purely safe, and error types carry only owned or `&'static str` data. This
eliminates a class of memory-safety bugs that would otherwise propagate into
every subsystem that implements `IncrementalJob`.

## 3. Type Designs

### 3.1 WorkBudget — three-dimensional resource bound

```rust
pub struct WorkBudget {
    pub max_items: u64,   // max records/entries to process (0 = unbounded)
    pub max_bytes: u64,   // max bytes to allocate/relocate (0 = unbounded)
    pub max_ms: u64,      // max wall-clock ms (soft limit, 0 = unbounded)
}
```

#### Design rationale

Three orthogonal dimensions reflect the three resources constrained by background
work: CPU (items), I/O (bytes), and latency (time). A limit of zero means
"unbounded" in that dimension — a deliberate choice to avoid sentinel values
and keep the zero-init pattern safe.

#### Constants

| Constant | Items | Bytes | Time | Use case |
|---|---|---|---|---|
| `DEFAULT_TICK` | 1024 | 64 MiB | 100 ms | Normal scheduler tick |
| `MAINTENANCE_TICK` | 256 | 16 MiB | 50 ms | Lightweight idle-cluster tick |
| `UNBOUNDED` | 0 | 0 | 0 | Admin-initiated run-to-completion |
| `PAUSED` | 0 | 0 | 0 | Scheduler-semantic "do no work" |

`PAUSED` and `UNBOUNDED` have identical bit patterns (all zeros) but carry
distinct scheduling semantics. The scheduler distinguishes them by context:
`PAUSED` means "skip this job tick," `UNBOUNDED` means "run to completion."
This is a **semantic overloading** tradeoff: same bits, different meaning in
the scheduling layer, avoiding an extra boolean field at the cost of making
`is_unbounded() == is_paused()` always true.

#### Budget-check helpers

All budget enforcement is delegated to the `IncrementalJob` implementation.
The crate provides `const fn` helpers for implementations to self-check:

- `is_bounded()` — at least one limit non-zero
- `is_unbounded()` — all three limits zero
- `items_within_budget(items)` — `max_items == 0 || items <= max_items`
- `bytes_within_budget(bytes)` — `max_bytes == 0 || bytes <= max_bytes`

No time-check helper is provided because wall-clock enforcement is inherently
runtime-dependent (requires `Instant`), which is not available in `core`.
Implementations track time externally and stop cooperatively.

#### Design input from prior art

The following bullets are design inputs only. They do not validate TideFS
runtime behavior or establish a product-facing comparison against ZFS or Ceph.

- **ZFS**: No unified budget. Scrub/resilver can consume all IOPS. `zfs_scan`
  has a per-commit_group byte limit (`zfs_scan_legacy` tunable) but no items or time
  dimension. ARC eviction is byte-bounded but not job-scoped.
- **Ceph**: `osd_max_backfills` limits concurrent backfill operations but
  doesn't bound per-tick work. Recovery has a configurable max bytes/sec
  (`osd_recovery_max_active`) but no per-step items or time envelope.

### 3.2 CursorState — opaque cursor blob

```rust
#[cfg(feature = "alloc")]
pub struct CursorState(pub Vec<u8>);
```

#### Design rationale

The cursor is deliberately opaque at this layer. Each `IncrementalJob`
implementation owns the serialization format of its cursor data. The framework
treats `CursorState` as an opaque payload for persistence and crash recovery.
This avoids coupling the type system to job-specific cursor formats (which
range from a simple `u64` offset to a multi-page B+tree position stack).

**Tradeoff**: Opacity prevents the framework from introspecting cursor state
(e.g., for cross-job progress estimation). The benefit is that adding a new
job kind never requires changes to this crate. Progress observability is
provided by `JobProgress`, not cursor introspection.

`CursorState` is gated on `alloc` because the `Vec<u8>` backing requires a
heap. Without `alloc`, jobs that don't need persistent cursors can still use
the other types.

#### Helper methods

- `empty()` — fresh-start sentinel
- `is_empty()`, `len()`, `as_bytes()` — read-only access for serialization

### 3.3 JobProgress — aggregate progress counters

```rust
pub struct JobProgress {
    pub items_processed: u64,
    pub items_total_estimate: u64,   // 0 = unknown
    pub bytes_processed: u64,
    pub bytes_total_estimate: u64,   // 0 = unknown
    pub elapsed_ms: u64,
}
```

#### Design rationale

Progress counters are separated from the cursor for two reasons:

1. **Cursor is opaque, progress is transparent**. The admin needs to read
   progress without understanding the cursor format.
2. **Progress is additive**. Multiple steps accumulate into aggregate counters.
   The cursor is a position, not a sum.

#### completion_permille() algorithm

```
if items_total_estimate > 0:
    return (items_processed * 1000 / items_total_estimate) as u16
elif bytes_total_estimate > 0:
    return (bytes_processed * 1000 / bytes_total_estimate) as u16
else:
    return 0
```

Returns thousandths (0–1000) for granular admin display without floating-point.
Items are preferred over bytes when both are available because item counts are
typically more stable (byte estimates fluctuate with compression and variable
record sizes). The `u128` intermediate prevents overflow on 64-bit counters.

#### accumulate()

Uses `saturating_add` to prevent overflow from corrupting progress display.
Estimates are **not** additive — the caller retains its own estimate. This is
because estimates come from the job implementation, not from step-level deltas.

### 3.4 Checkpoint — persisted progress marker

```rust
#[cfg(feature = "alloc")]
pub struct Checkpoint {
    pub job_id: JobId,
    pub job_kind: JobKind,
    pub epoch: u64,               // incremented on restart
    pub cursor_state: CursorState, // opaque position
    pub progress: JobProgress,     // aggregate counters
}
```

#### Design rationale

`Checkpoint` bundles everything needed to resume a job after a crash. It is
persisted atomically in a dataset-scoped checkpoint area (Phase 2).

**Epoch counter**: The `epoch` field starts at 1 and is incremented by the
persistence layer on every daemon restart. This enables:
- Admin visibility into crash history (epoch > 1 = "this job crashed at least once")
- Stale-checkpoint detection (epoch-based fencing for split-brain scenarios)
- Crash-injection harness verification (#1230)

**Constructor**: `Checkpoint::new_initial(job_id, job_kind)` creates a fresh
checkpoint with `epoch = 1`, empty cursor, and zeroed progress.

#### Gating

`Checkpoint` requires `alloc` because it embeds `CursorState` (which holds
`Vec<u8>`). Without `alloc`, the crate can define jobs but cannot checkpoint
them — a valid configuration for stateless or single-shot jobs.

### 3.5 StepResult — step outcome

```rust
#[cfg(feature = "alloc")]
pub struct StepResult {
    pub checkpoint: Checkpoint,  // position after batch
    pub is_complete: bool,        // true → call complete(), don't step() again
}
```

Constructor methods enforce the two valid outcomes:
- `StepResult::in_progress(checkpoint)` — `is_complete = false`
- `StepResult::complete(checkpoint)` — `is_complete = true`

The last checkpoint before completion is preserved so the admin can inspect
final progress before `complete()` deletes it.

### 3.6 JobId — unique job identifier

```rust
pub struct JobId(pub u64);
```

Newtype over `u64` with `NONE = JobId(0)` sentinel. Monotonically increasing,
pool-scoped counter. The newtype prevents accidental mixing with other `u64`
identifiers (e.g., commit_group numbers, inode numbers).

`is_none()` / `is_some()` mirror `Option` semantics for ergonomic use in
`Option<JobId>` patterns. Derives `Ord`/`PartialOrd` for B+tree key ordering
in the checkpoint store.

### 3.7 JobKind — discriminant enum

```rust
pub enum JobKind {
    DeferredCleanup,   // extent freeing after unlink/truncate
    SnapshotDestroy,   // deadlist processing
    GCMark,            // metadata reachability marking
    BtreeCompaction,   // B+tree defragmentation
    Rebake,            // ingest-to-base conversion
    JournalCleaning,   // data journal reclamation
    DatasetDestroy,    // admin-initiated teardown
    Scrub,             // online integrity (metadata/sampled)
    DeepScrub,         // full read-and-verify
    Resilver,          // device replacement rebuild
    Reclaim,           // refcount-delta deferred reclamation
    OrphanRecovery,    // mount-time nlink==0 extent reclaim
    AdminJob,          // generic admin operation
    Other(u8),         // forward-compatibility
}
```

#### Design rationale

**14 variants** (13 named + 1 open). This covers the 12 original job kinds
from #1239 plus `Reclaim` (#1180) and `OrphanRecovery`. The `Other(u8)`
variant provides forward compatibility: a newer daemon can read checkpoints
from an older daemon that used a since-removed variant, and an older daemon
can skip checkpoints with unknown variant numbers.

#### Classification helpers

- `label()` — human-readable `&'static str` for admin display
- `is_integrity_check()` — `true` for `Scrub | DeepScrub`; used by scheduling
  to avoid starving integrity work when space reclaim is urgent
- `is_latency_sensitive()` — `true` for `Resilver | JournalCleaning | OrphanRecovery | Reclaim`;
  these should not be starved by lower-priority bulk work

**Tradeoff**: A flat enum vs. a trait-based classification. The enum approach
is simpler, enables exhaustive `match`, and compiles to a single-byte
discriminant (with niche optimization for `Option<JobKind>`). The cost is that
adding a new variant requires a crate version bump. The `Other(u8)` escape
hatch mitigates this.

### 3.8 JobError — error type

```rust
pub enum JobError {
    CheckpointCorrupt { job_id: JobId, reason: &'static str },
    CursorStateInvalid { job_id: JobId, reason: &'static str },
    BudgetExceeded { job_id: JobId, budget: WorkBudget, actual_items: u64, actual_bytes: u64 },
    JobAlreadyComplete { job_id: JobId },
    IoError { job_id: JobId, message: &'static str },
    #[cfg(feature = "alloc")]
    Other(String),  // catch-all with heap-allocated message
}
```

#### Design rationale

**Structured errors**: The first five variants carry structured data
(`job_id`, budget details, reason strings). This enables programmatic error
handling — the scheduler can distinguish "retryable budget overrun" from
"fatal checkpoint corruption."

**`&'static str` for fixed messages**: Avoids heap allocation for the common
error paths. Checkpoint corruption and I/O errors use pre-baked reason strings
like `"magic mismatch"` or `"write failed"`. The `Other(String)` variant
provides an escape hatch for subsystem-specific errors that need dynamic
messages, gated on `alloc`.

**`job_id()` accessor**: Returns `Option<JobId>` — `Some` for structured
variants that carry a job context, `None` for `Other`. Enables error reporting
that correlates failures to specific jobs.

**Tradeoff**: `BudgetExceeded` includes `actual_items` and `actual_bytes` but
not `actual_ms`. Time overrun detection requires runtime infrastructure
(`Instant`) not available in `core`. Implementations that need time-budget
enforcement track it externally.

## 4. IncrementalJob Trait Design

```rust
#[cfg(feature = "alloc")]
pub trait IncrementalJob {
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError> where Self: Sized;
    fn step(&mut self, budget: WorkBudget) -> StepResult;
    fn persist_checkpoint(&self) -> Checkpoint;
    fn complete(self);
    fn job_id(&self) -> JobId;
    fn job_kind(&self) -> JobKind;
}
```

### 4.1 Lifecycle state machine

```
  resume(checkpoint) ──→ step(budget) ──→ persist_checkpoint() ──→ step(budget) ──→ …
                              │                                              │
                              │ is_complete=true                             │
                              ▼                                              │
                          complete()                                         │
                                                                             │
                     crash at any point ──→ resume(last_checkpoint) ──→ … ───┘
```

### 4.2 Contract invariants

1. **Budget respect**: `step()` MUST NOT exceed the supplied `WorkBudget` in
   tests compliance.

2. **Crash safety**: `resume(last_checkpoint)` after a crash MUST produce the
   same final outcome as if the crash never happened. The checkpoint is the
   linearization point.

3. **Idempotency**: Calling `step()` twice with the same cursor position MUST
   NOT produce duplicate side effects. Three canonical strategies are
   available to implementors:
   - **Before-write check** (Cleanup, SnapDestroy, DsDestroy): verify target
     extent/entry is still in expected state before modifying.
   - **Intent logging** (Rebake, Clean, Resilver): write intent record before
     batch, clear after. On resume, replay or discard pending intents.
   - **Tombstone-based** (Scrub, DeepScrub): mark entries as processed with
     commit_group stamp; skip already-processed entries on resume.

4. **Checkpoint ordering**: The checkpoint reflects the position *after* the
   batch was committed. Checkpoint-before-work would lose progress on crash;
   work-before-checkpoint means at-most-once semantics rely on idempotency.

### 4.3 Trait object safety

The trait in the **types crate** (`tidefs-types-incremental-job-core`) is
**not** object-safe because `resume` uses `where Self: Sized`. This enables
zero-cost monomorphization: the scheduler dispatches through generics, not
dyn dispatch, eliminating vtable overhead in the hot `step()` path.

By contrast, the trait in the **core crate** (`tidefs-incremental-job-core`)
is object-safe (uses `&dyn IncrementalJob`), trading monomorphization for
scheduler dispatch flexibility. The two crates co-exist:
- `tidefs-types-incremental-job-core` — authority types + non-object-safe trait
- `tidefs-incremental-job-core` — object-safe trait + `CheckpointCodec`

### 4.4 Comparison to #1239 design spec

The implemented trait differs from the original #1239 design spec in two ways:

| Aspect | #1239 spec | Implemented | Rationale |
|---|---|---|---|
| `resume` signature | `resume(state: Option<Checkpoint>)` | `resume(checkpoint: Checkpoint)` | Always provide a checkpoint; use `Checkpoint::new_initial()` for fresh starts. Eliminates `Option` branching in every implementation. |
| `step` return | `Result<StepResult, JobError>` | `StepResult` (infallible) | Budget violations and I/O errors are handled inside `step()`. The trait returns `StepResult` directly. The `Result` wrapper was removed because every error case is either recoverable within `step()` (budget: stop early) or fatal (I/O: panic/unwind). |
| `complete` signature | `complete(self) -> Result<(), JobError>` | `complete(self)` (infallible) | Completion cleanup should never fail in a way the scheduler can handle. If the checkpoint delete fails, the job is still logically complete. |

## 5. Design Tradeoffs

### 5.1 `no_std` with `alloc` default vs. `std`

**Choice**: `no_std` with default-on `alloc` feature.

test harness) to use the core types without a full OS. The feature gate
ensures `Vec`/`String` dependencies are explicit and optional.

**Con**: `no_std` prevents using `std::error::Error`, `std::time::Instant`,
and `std::io::Error`. Time-budget enforcement and I/O error wrapping must
be done at the caller level, not in this crate.

### 5.2 Single-file crate vs. sub-module split

**Choice**: All types in one `lib.rs`.

**Pro**: Simple, no intra-crate `use` chains, feature gates apply uniformly.
At 1625 lines, the file is still navigable.

**Con**: If `JobKind` grows past ~20 variants or the crate exceeds ~3000
lines, it should be split into `budget.rs`, `checkpoint.rs`, `job.rs`, etc.

### 5.3 `&'static str` errors vs. `Cow<str>`

**Choice**: `&'static str` for fixed error messages, `String` (gated) for
dynamic ones.

**Pro**: No allocation for the common path (checkpoint corrupt, cursor
invalid). The `Other(String)` variant handles subsystem-specific errors.

**Con**: Implementations cannot embed runtime-computed error details (e.g.,
file paths) in structured variants. They must use `Other(format!(...))`.

### 5.4 `Other(u8)` forward-compat variant

**Choice**: `JobKind::Other(u8)` instead of `#[non_exhaustive]`.

**Pro**: Older crates can deserialize checkpoints with unknown job kinds
without failing. The `u8` payload preserves the discriminant value so a
round-trip through an older daemon doesn't lose information.

**Con**: `match` on `JobKind` must handle `Other(_)`, which is slightly less
ergonomic than exhaustive matching. We accept this for forward compatibility.

### 5.5 PAUSED vs UNBOUNDED semantic overloading

**Choice**: Both use `{0, 0, 0}` bits.

**Pro**: No extra field. The scheduler layer distinguishes them by context
(is the job supposed to run? is it admin-triggered?).

**Con**: `is_unbounded()` returns `true` for both. Admin code that checks
boundedness must also check scheduling state separately.

## 6. Serialization Contract

When the `serde` feature is enabled, all types derive `Serialize`/`Deserialize`.
This is used for:

- **Admin protocol**: `tidefsctl jobs list` wire format
  encoding for crash-harness verification
- **Checkpoint persistence**: Phase 2 `CheckpointCodec` uses serde under
  the hood for the on-media binary format

The serde integration is feature-gated to avoid pulling in `serde` and
`serde_derive` for embedded contexts that don't need serialization.

## 7. Testing Strategy

The crate includes ~65 unit tests covering:

| Category | Test count | Examples |
|---|---|---|
| `WorkBudget` | 12 | `default_tick_values`, `is_bounded_when_any_limit_set`, `items_within_budget_bounded`, `bytes_within_budget_unbounded` |
| `CursorState` | 6 | `empty_cursor`, `cursor_from_vec`, `cursor_clone_eq` |
| `JobProgress` | 10 | `progress_default_zero`, `completion_permille_items`, `completion_permille_bytes_fallback`, `accumulate_saturating` |
| `Checkpoint` | 8 | `new_initial_checkpoint`, `is_fresh_empty`, `serde_roundtrip` |
| `StepResult` | 4 | `in_progress_constructor`, `complete_constructor` |
| `JobId` | 5 | `none_is_zero`, `is_none_is_some`, `display_format` |
| `JobKind` | 7 | `label_returns_correct_strings`, `is_integrity_check`, `other_roundtrip` |
| `JobError` | 6 | `display_messages`, `job_id_accessor`, `other_variant` |
| Serde roundtrip | 5 | `work_budget_json_roundtrip`, `checkpoint_json_roundtrip` |


```bash
cargo test -p tidefs-types-incremental-job-core
cargo clippy -p tidefs-types-incremental-job-core -- -D warnings
cargo check --workspace
```

The full xtask gate (`tidefs-xtask check-incremental-cursor`) also verifies
the integration with `tidefs-incremental-job-core` and the background
scheduler.

## 8. Relationship to Other Crates

```
tidefs-types-incremental-job-core   ← this crate (Phase 1)
    ↑
    │ depends on
    │
tidefs-incremental-job-core        ← trait + CheckpointCodec (Phase 2)
    ↑
    │ implements
    │
[cleanup, snap-destroy, gc-mark,   ← subsystem crates (Phase 4–6)
 compact, rebake, clean, …]
    ↑
    │ schedules
    │
tidefs-background-scheduler        ← scheduling loop (Phase 3)
```

`tidefs-types-incremental-job-core` is the lowest leaf in the incremental
job dependency graph. No tidefs crate depends on it at the type-definition
level — only at the implementation level.

## 9. ZFS / Ceph design-input comparison

This table compares interface shape and design requirements for the type crate.
It is not evidence that deployed TideFS background work is more reliable,
faster, safer, or cheaper than incumbent implementations. Product-facing
incumbent claims must be tracked through #875 and #928/#930 comparator
evidence.

| Dimension | tidefs types crate | ZFS | Ceph |
|---|---|---|---|
| **Shared type vocabulary** | Yes — 8 types, 1 trait, all subsystems | No — each subsystem defines its own types (`dsl_scan_phys_t`, `bpobj`, `spa_sync`) | No — per-PG types with no inter-subsystem sharing |
| **Unified budget model** | `WorkBudget` with 3 dimensions | `zfs_scan_legacy` (bytes only, per-commit_group) | `osd_recovery_max_active` (ops only) |
| **Crash-resumable checkpoint** | `Checkpoint` with opaque cursor + epoch | Ad-hoc: `scrub_progress` ZAP object, send resume token; no unified format | In-memory only; restart from scratch |
| **Error classification** | 6 structured variants + catch-all | Per-subsystem error codes (no shared classification) | Per-PG error counters, no shared error model |
| **Forward compatibility** | `JobKind::Other(u8)` | N/A (monolithic codebase) | N/A (versioned OSDMap, not per-job) |
| **No-alloc support** | Yes — feature-gated `Vec`/`String` | No — kernel module, always has alloc | No — always has alloc |
| **Unsafe code** | Zero (`#![forbid(unsafe_code)]`) | Ubiquitous (kernel module, raw pointers) | Some (buffer management, messenger) |

## 10. Open Questions

1. **Time budget enforcement**: With `no_std`, wall-clock enforcement is
   external to the crate. Should Phase 2 add an optional `std` feature
   that provides `WorkBudget::time_within_budget(Instant)`?
   **Proposal**: Add in Phase 2 if profiling shows time overruns are common.

2. **Cursor compression**: `CursorState` is opaque `Vec<u8>`. Should the
   crate mandate or suggest compression (LZ4) for large cursors (B+tree
   position stacks)? **Proposal**: Leave to implementations. The crate
   provides the opaque container; the job chooses the format and compression.

3. **`JobKind` variant growth**: With 14 variants and counting, should
   `JobKind` become a trait or a two-level hierarchy
   (category + sub-kind)? **Proposal**: Keep flat enum until variant count
   exceeds 32 (one byte discriminant limit for niche optimization).

4. **`JobProgress` ETA**: Should the crate provide an ETA calculator, or
   leave it to the scheduler? **Proposal**: Leave to scheduler (Phase 3).
   The crate provides raw progress; the scheduler applies EMA/regression.

5. **`abort()` method**: The trait has `complete()` but not `abort()`. Should
   we add an optional `abort()` for cancelled jobs (e.g., clean up intent
   log records from a cancelled REBAKE)? **Proposal**: Add as a default
   no-op method in a future revision if cancellation use cases emerge.

## 11. Revision History

| Date | Change | Issue |
|---|---|---|
| 2026-05-02 | Initial crate implementation (1619 lines, 65 tests) | #1385 |
| 2026-05-04 | Design document formalized | #1588 |
| 2026-05-04 | Design document updated; closed as #1701 | #1701 |
| 2026-05-04 | Coordination seal confirmed; design frozen | #1930 |
