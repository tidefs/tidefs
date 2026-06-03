# IncrementalJob Phase 1 Design Spec — #1855

**Issue**: [#1855](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1855)
**Canonical design**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md)
**Coordination seal**: [#1930](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1930)
**Maturity**: **design-spec** — Phase 1 data-plane types and `IncrementalJob` trait are frozen; Rust subsystem wire-up deferred to wire-up issues
**Lane**: storage-core (universal incremental cursor framework, #1239)
**Kind**: design
**Prior art**: [#1385](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1385) (original implementation), [#1588](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1588) (design formalization)

## Design Spec Statement

This document is the **design-spec** for the Phase 1 data-plane types and
control-plane contract of the universal incremental cursor framework (#1239).
All data-plane types (`WorkBudget`, `CursorState`, `JobProgress`, `Checkpoint`,
`StepResult`, `JobId`, `JobKind`, `JobError`) and the `IncrementalJob`
control-plane trait are **frozen**. No further design changes to the types crate
or the `IncrementalJob` trait are permitted without a new design issue.

**Rust implementation of subsystem wire-up is deferred.** The types crate
(`tidefs-types-incremental-job-core`) and the trait + codec crate
(`tidefs-incremental-job-core`) are implemented. The 14 background maintenance
subsystems that implement `IncrementalJob` are each deferred to dedicated
wire-up issues.

---

## 1. Architecture

### 1.1 Three-Phase Layering

The universal incremental cursor framework is structured in three phases:

| Phase | Crate | Scope | Status |
|---|---|---|---|
| **Phase 1** | `tidefs-types-incremental-job-core` | Data-plane types + definitions | **implemented-source** (~1625 lines, ~65 tests) |
| **Phase 2** | `tidefs-incremental-job-core` | `IncrementalJob` trait + `CheckpointCodec` binary serialization | **implemented-source** (~992 lines, ~32 tests) |
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

### 1.3 Crate Identity

```
crates/tidefs-types-incremental-job-core/
├── Cargo.toml      — Zero mandatory deps, optional serde, alloc default
└── src/
    └── lib.rs      — ~1625 lines, ~65 unit tests, single-file
```

Single-file crate layout. All types and tests co-locate in `lib.rs`.
No sub-module split is needed at this scope — the types are tightly coupled
and share the same feature gates.

### 1.4 Feature Flags

| Feature | Default | Effect |
|---|---|---|
| `alloc` | **yes** | Enables `CursorState`, `Checkpoint`, `StepResult`, and `JobError::Other(String)`. Gated types use `Vec<u8>`, `String`. |
| `serde` | no | Derives `Serialize`/`Deserialize` on all types. Implies `alloc`. |

With `alloc` disabled, the types crate provides a ~500-line no-heap core:
`WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and fixed-message `JobError`

### 1.5 Safety Posture

```rust
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
```

Zero unsafe code in both crates. These are type-definition and trait-definition
crates with no FFI, no direct memory manipulation, and no performance-critical
paths. All unsafe code belongs in subsystem implementations.

---

## 2. Data Structures

### 2.1 `WorkBudget` — Three-Dimensional Resource Bound

```rust
pub struct WorkBudget {
    pub max_items: u64,  // 0 = unbounded
    pub max_bytes: u64,  // 0 = unbounded
    pub max_ms: u64,     // 0 = unbounded (soft limit)
}
```

| Constant | Items | Bytes | Time | Use |
|---|---|---|---|---|
| `DEFAULT_TICK` | 1024 | 64 MiB | 100 ms | Normal operations |
| `MAINTENANCE_TICK` | 256 | 16 MiB | 50 ms | Idle cluster background |
| `UNBOUNDED` | 0 | 0 | 0 | Admin-initiated jobs, tests |
| `PAUSED` | 0 | 0 | 0 | Suspended job |

**Key methods**: `is_bounded()`, `is_unbounded()`, `items_within_budget(n)`,
`bytes_within_budget(n)`, `is_paused()`.

**Invariants**:
- Every `step()` call receives a `WorkBudget`. Implementations MUST NOT exceed any active limit.
- Budget enforcement is the implementor's responsibility — the framework does not preempt.
- `is_paused()` is semantically distinct from `is_unbounded()`: both have all-zero fields, but `PAUSED` signals the job should not run.

### 2.2 `CursorState` — Opaque Cursor Blob (`alloc`-gated)

```rust
pub struct CursorState(pub Vec<u8>);
```

Opaque serialized cursor private to each `IncrementalJob` implementation.
The format and interpretation are entirely the subsystem's responsibility.
The framework treats cursors as black boxes for persistence and crash recovery.

Methods: `empty()`, `is_empty()`, `len()`, `as_bytes()`. Round-trip via
`From<Vec<u8>>`.

### 2.3 `JobProgress` — Aggregate Progress Counters

```rust
pub struct JobProgress {
    pub items_processed: u64,
    pub items_total_estimate: u64,   // 0 = unknown
    pub bytes_processed: u64,
    pub bytes_total_estimate: u64,   // 0 = unknown
    pub elapsed_ms: u64,
}
```

`completion_permille()` returns 0–1000 using `items_total_estimate` (preferred)
or `bytes_total_estimate` as fallback. Returns 0 when neither estimate is known.
`accumulate()` uses saturating addition — estimates are not additive.

### 2.4 `Checkpoint` — Crash-Resumable Progress Marker (`alloc`-gated)

```rust
pub struct Checkpoint {
    pub job_id: JobId,
    pub job_kind: JobKind,
    pub epoch: u64,            // monotonic, incremented on daemon restart
    pub cursor_state: CursorState,
    pub progress: JobProgress,
}
```

The checkpoint is the **linearization point** for crash safety. After every
`step()` call, `persist_checkpoint()` must atomically persist the checkpoint
to stable storage before the next `step()`. On daemon restart, the epoch
counter is incremented so the admin can distinguish "fresh run" from
"continuing."

Factory: `new_initial(job_id, job_kind)` creates epoch-1, empty-cursor,
zero-progress checkpoint for brand-new jobs.

### 2.5 `StepResult` — Outcome of One Step (`alloc`-gated)

```rust
pub struct StepResult {
    pub checkpoint: Checkpoint,     // updated cursor + progress
    pub is_complete: bool,          // true = job finished
}
```

Constructors: `in_progress(checkpoint)` sets `is_complete: false`.
`complete(checkpoint)` sets `is_complete: true`. The scheduler reads `is_complete()`
to decide whether to call `step()` again or `complete()`.

### 2.6 `JobId` — Unique Job Identifier

```rust
pub struct JobId(pub u64);
```

Newtype over `u64`. `Copy, Clone, Eq, Hash, Ord`. `JobId::NONE` = `JobId(0)` is
the sentinel. Displays as `"job-<id>"`. Monotonically increasing, pool-scoped
counter. The newtype prevents accidental mixing with other `u64` identifiers.

### 2.7 `JobKind` — Background Operation Discriminant

Flat enum with 14 variants:

```rust
pub enum JobKind {
    DeferredCleanup,     // refcount-delta cleanup queues
    SnapshotDestroy,     // snapshot teardown
    GCMark,              // GC reachability marking
    BtreeCompaction,     // B+tree page compaction
    Rebake,              // ingest journal to base shard conversion
    JournalCleaning,     // intent-log segment reclamation
    DatasetDestroy,      // admin-initiated dataset teardown
    Scrub,               // metadata integrity verification
    DeepScrub,           // data integrity verification
    Resilver,            // device replacement data rebuild
    Rebalance,           // space redistribution
    AdminJob,            // admin-initiated generic operations
    Reclaim,             // reclaim queue processing
    OrphanRecovery,      // orphan index cleanup
    Other(u8),           // forward-compatible extension slot
}
```

`size_of::<JobKind>()` = 2 bytes (niche-optimized `Other(u8)` discriminant).
`label()` returns human-readable names. `is_integrity_check()` is true for
`Scrub | DeepScrub`. `is_space_reclaim()` groups cleanup-like variants.

### 2.8 `JobError` — Structured Error Type

Six variants:

| Variant | Arity | Alloc-free | Use |
|---|---|---|---|
| `CheckpointCorrupt` | unit | yes | Recovered checkpoint failed decode |
| `BudgetViolated` | unit | yes | `step()` exceeded WorkBudget |
| `IoError` | unit | yes | I/O failure |
| `NotSupported` | unit | yes | Job kind not supported in this context |
| `Internal` | unit | yes | Unexpected internal invariant violation |
| `Other(String)` | String | no (`alloc`) | Subsystem-specific messages |

`job_id(&self)` accessor returns the associated `JobId`. All fixed variants
are allocation-free; `Other` requires the `alloc` feature.

---

## 3. Algorithms

### 3.1 IncrementalJob Lifecycle State Machine

```
                    ┌─────────────────────────────┐
                    │       resume(None)           │
                    │  (fresh start, epoch=1)      │
                    └─────────────┬───────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
          ┌────────│         step(budget)          │◄────────┐
          │        └─────────────┬───────────────┘         │
          │                      │                          │
          │                      ▼                          │
          │        ┌─────────────────────────────┐         │
          │        │  persist_checkpoint(cp)      │         │
          │        └─────────────┬───────────────┘         │
          │                      │                          │
          │              ┌───────┴───────┐                  │
          │              │               │                  │
          │              ▼               ▼                  │
          │   StepResult::InProgress  StepResult::Done      │
          │              │               │                  │
          └──────────────┘               ▼                  │
                              ┌─────────────────────────┐   │
                              │     complete(self)       │   │
                              └─────────────────────────┘   │
```

### 3.2 Crash-Resume Guarantee

The framework provides **idempotent resumption**: after a crash and daemon
restart, `resume(Some(cp))` must produce the same final state as uninterrupted
execution. This is enforced by:

1. **Epoch increment on restart**: The persistence layer bumps the epoch
   counter on every daemon restart. This enables stale-checkpoint detection
   and split-brain fencing.
2. **Atomic checkpoint persistence**: `persist_checkpoint()` must use `fsync`
   or equivalent before returning. The on-media checkpoint is the single
   source of truth for crash recovery.
3. **Idempotent step boundary**: Calling `step()` twice with the same cursor
   position MUST NOT produce duplicate side effects. This is the implementor's
   responsibility.

### 3.3 Budget Enforcement Algorithm

Budget enforcement is **cooperative**, not preemptive. Each `step()`
implementation is responsible for checking the budget before each unit of work:

```
fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
    let mut items = 0;
    let mut bytes = 0;
    while !self.is_done() {
        // Check all three dimensions before each unit of work
        if budget.is_bounded() {
            if items >= budget.max_items { break; }
            if bytes >= budget.max_bytes { break; }
            // Self-time to respect max_ms (soft limit)
            if elapsed_ms >= budget.max_ms { break; }
        }
        // Process one unit of work
        let work_item = self.next()?;
        items += 1;
        bytes += work_item.byte_cost();
        self.apply(work_item)?;
    }
    Ok(StepResult::in_progress(self.checkpoint()))
}
```

The framework does not preempt or enforce the budget; it trusts the
implementation. A `BudgetViolated` error is defined for implementations that

### 3.4 Completion Detection

When a job has no more work, `step()` returns `StepResult::complete(cp)`.
The scheduler then:
1. Calls `complete(self)` exactly once — the job struct is consumed.
2. Never calls `step()` again on this job.
3. Removes the job's checkpoint from stable storage.

### 3.5 Progress Estimation

`JobProgress::completion_permille()` implements the following priority order:

- If `items_total_estimate > 0`: return `clamp((items_processed * 1000) / items_total_estimate, 0, 1000)`
- Else if `bytes_total_estimate > 0`: return `clamp((bytes_processed * 1000) / bytes_total_estimate, 0, 1000)`
- Else: return 0 (unknown total, cannot estimate)

Uses `u128` intermediate to prevent overflow. Items are preferred over bytes
because item counts are typically more stable (byte estimates fluctuate with
compression and variable record sizes). Returns thousandths (0–1000) for
granular admin display without floating-point.

---

## 4. Tradeoffs

### 4.1 Opaque `CursorState(Vec<u8>)` vs. Typed Cursor Enum

**Decision**: Opaque byte blob.

**Rationale**: Different subsystems have fundamentally different cursor shapes
(B+tree position stacks, extent offsets, object ID ranges). A common typed
cursor would require a massive enum (~14 variants times N sub-variants) or dynamic
dispatch. The opaque approach lets each implementation define its own format
while the framework treats cursors as black boxes. The `CheckpointCodec` trait
handles serialization boundaries.

### 4.2 Flat `JobKind` Enum vs. Hierarchical Category + Sub-Kind

**Decision**: Flat enum with `Other(u8)` extension slot.

**Rationale**: 14 variants at 2 bytes (`size_of`) with niche optimization.
A two-level hierarchy (category + sub-kind) adds complexity without clear
benefit until variant count exceeds 32 (single-byte discriminant limit).
Revisit if variant count approaches 32.

### 4.3 `complete()` Consumes `self`

**Decision**: Ownership transfer on completion.

**Rationale**: Prevents accidental reuse after completion. The scheduler must
move the job out of its handle (e.g., `Option::take`) before calling `complete()`.
Rejected alternative: `&mut self` with a `completed: bool` flag, because that
pushes the safety burden onto every `step()` implementation instead of
centralizing it in the type system.

### 4.4 Two-Crate Split (Types vs. Trait + Codec)

**Decision**: `tidefs-types-incremental-job-core` (Phase 1) and
`tidefs-incremental-job-core` (Phase 2).

**Rationale**: The types crate is a true leaf with zero tidefs dependencies.
Admin tools, protocol serializers, and embedded probe firmware can depend on
the types crate without pulling in the `IncrementalJob` trait and its `Send`
bound. The core crate depends only on the types crate and is the single
dependency for all subsystem implementations.

### 4.5 `no_std` + `alloc` Feature Gate

**Decision**: `#![cfg_attr(not(test), no_std)]` with `alloc` feature enabled
by default.

**Rationale**: The 99% case (all tidefs daemons) runs with a heap, so `alloc`
default keeps the crate ergonomic. The no-heap core (~500 lines) provides
`WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and fixed-message `JobError`

### 4.6 `forbid(unsafe_code)`

**Decision**: Zero unsafe code in both crates.

**Rationale**: These are type-definition and trait-definition crates with no
FFI, no direct memory manipulation, and no performance-critical paths. Unsafe
code would increase audit surface without benefit. All unsafe code belongs in
subsystem implementations.

### 4.7 Binary Checkpoint Format vs. Serde-Only

**Decision**: Both `CheckpointCodec` (binary) and optional `serde` support.

**Rationale**: The binary format (4-byte magic `0x56_49_43_4A` = "VICJ",
2-byte version, length-delimited payload fields) is roughly 2x more compact than JSON
matters.

### 4.8 Single-File Crate Layout

**Decision**: Both Phase 1 and Phase 2 crates are single-file (`lib.rs` only).

**Rationale**: All types are tightly coupled — they appear together in every
`StepResult`, `Checkpoint`, and `IncrementalJob` implementation. Splitting into
modules would create import friction without meaningful separation of concerns.
Revisit if either crate exceeds ~3000 lines.

---

## 5. Subsystem Wire-Up Catalog (Deferred)

The following 14 subsystems are each deferred to dedicated wire-up issues.
Each wire-up issue must:

1. Add `tidefs-incremental-job-core` as a dependency to the subsystem crate.
2. Implement `IncrementalJob` for the subsystem's job struct.
3. Implement `CheckpointCodec` for the subsystem's cursor format.
4. Add a factory method to the background scheduler.
   harness (#1230).

| # | Subsystem | JobKind Variant | Crate | Cursor Format | Unique Concerns |
|---|---|---|---|---|---|
| 1 | Deferred Cleanup | `DeferredCleanup` | `tidefs-cleanup-job-core` | Extent list offset + refcount delta pointer | Refcount atomicity across COMMIT_GROUP boundaries |
| 2 | Snapshot Destroy | `SnapshotDestroy` | `tidefs-reclaim-job-core` | Deadlist block pointer + offset | Must hold dataset destroy lock throughout |
| 3 | GC Mark | `GCMark` | `tidefs-cluster-gc` | Object ID + B+tree traversal stack | Distributed reachability; cross-node coordination |
| 4 | B+tree Compaction | `BtreeCompaction` | `tidefs-btree` | Path stack (page ID, level, slot) | Rebalancing may split/merge parent nodes |
| 5 | Rebake | `Rebake` | `tidefs-rebake-planner` | Journal segment ID + record offset | Must not rebake records with active COMMIT_GROUP readers |
| 6 | Journal Cleaning | `JournalCleaning` | `tidefs-cleanup-queue-core` | Segment ID + block offset | Must ensure no live references remain |
| 7 | Dataset Destroy | `DatasetDestroy` | `tidefs-dataset-lifecycle` | Object ID iterator | Requires admin authorization; must free all space |
| 8 | Scrub | `Scrub` | `tidefs-verification-engine` | Metadata block address + checksum state | Read-only; must not modify data |
| 9 | Deep Scrub | `DeepScrub` | `tidefs-verification-engine` | Data block address + checksum state | Read-only; full data verification |
| 10 | Resilver | `Resilver` | `tidefs-rebuild-planner` | Device + block offset | Writes to replacement device; must track redundancy |
| 11 | Rebalance | `Rebalance` | `tidefs-rebalance-planner` | Extent ID + destination device list | Multi-device atomic relocation |
| 12 | Admin Job | `AdminJob` | `tidefs-admin-service` | Task-specific opaque blob | Varied semantics; admin-tool UX required |
| 13 | Reclaim | `Reclaim` | `tidefs-reclaim` | Queue position + extent map cursor | Space pressure triggered; must respect priority |
| 14 | Orphan Recovery | `OrphanRecovery` | `tidefs-orphan-recovery-job-core` | Orphan index position | Must reconcile with active namespace catalog |

---

## 6. Comparison to ZFS and Ceph

| Dimension | TideFS (this design) | ZFS | Ceph |
|---|---|---|---|
| Shared type vocabulary | 8 types, 1 trait, all subsystems | Ad-hoc per subsystem | Per-PG types |
| Unified budget | `WorkBudget` (items, bytes, time) | `zfs_scan_legacy` (bytes only) | `osd_recovery_max_active` (ops only) |
| Crash-resumable checkpoints | `Checkpoint` with opaque cursor + epoch | Ad-hoc (`dsl_scan_phys_t`, ZAP objects) | In-memory only |
| Error classification | 6 structured variants | Per-subsystem error codes | Per-PG error counters |
| Forward compatibility | `JobKind::Other(u8)` | N/A | Versioned OSDMap |
| No-alloc support | Yes (feature-gated) | No | No |
| Unsafe code | Zero | Ubiquitous | Some |

---

## 7. Open Questions

1. **`abort()` method**: Should `IncrementalJob` include an optional `abort()`
   for cancelled jobs that may need to undo partial work? **Proposal**: Add as
   default no-op in a future revision if cancellation use cases emerge.

2. **Scheduling priority**: Should `JobKind` carry priority, or should the
   scheduler own the priority table? **Decision**: The scheduler owns the
   priority table. Adding priority to the trait would couple the types crate
   to scheduling policy.

3. **Checkpoint compression**: Large cursors (deep B+tree position stacks)
   may benefit from LZ4 compression. **Proposal**: Add optional compression
   flag (version bit 31) if profiling shows cursors exceeding 4 KiB.

4. **Multiple active checkpoints per job**: Jobs like journal cleaning may
   benefit from multiple independent cursors. **Proposal**: The job manages
   multiple cursors internally; the trait sees one opaque `cursor_state`.

5. **Step timeout preemption**: The crate's `max_ms` is a soft hint. Should
   the scheduler preempt? **Proposal**: The scheduler wraps `step()` in a
   timeout (Phase 3). The trait does not need mid-step cancellation support.

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

## 9. References

- **Universal incremental cursor framework**: `docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md`
- **Canonical design**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md)
- **Seal document**: [`docs/design/incremental-job-core-types-crate-design-sealed.md`](./incremental-job-core-types-crate-design-sealed.md)
- **Phase 2 trait + codec**: [`docs/design/incremental-job-core-trait-checkpoint-codec-design.md`](./incremental-job-core-trait-checkpoint-codec-design.md)
- **Background service framework**: [`docs/design/background-service-framework-design.md`](./background-service-framework-design.md)
- **Issue #1385**: Original crate implementation
- **Issue #1930**: Coordination seal
- **Issue #1985**: Formal seal document

---

## 10. Revision History

| Date | Change | Issue |
|---|---|---|
| 2026-05-05 | Design-spec document created; Phase 1 frozen; wire-up catalog deferred | #1855 |
