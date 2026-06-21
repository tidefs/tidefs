# IncrementalJob Core Trait and CheckpointCodec Design (#1620)

Maturity: **design-spec** for the Phase 2 control-plane trait, checkpoint
serialization contract, and binary on-media checkpoint format of the universal
incremental cursor framework.

This document closes Forgejo issue #1620 and formalizes the design of
`crates/tidefs-incremental-job-core/` (implemented alongside #1385).

## 1. Purpose

The `tidefs-incremental-job-core` crate defines the **control-plane contract**
for the universal incremental cursor framework (#1239). It builds on the
data-plane types from `tidefs-types-incremental-job-core` (Phase 1, #1385) and
adds two layers:

- **`IncrementalJob` trait**: The universal contract that every cursor-driven
  background job must implement. It defines the lifecycle methods `resume()`,
  `step()`, `persist_checkpoint()`, `complete()`, and the identity accessors
  `job_id()` and `job_kind()`.
- **`CheckpointCodec` trait**: A binary serialization contract for persisting
  `Checkpoint` values to stable storage with forward-compatible framing
  (magic bytes, version number, length-delimited payloads).

Together, these two traits form the **enforcement layer** above the data-plane
types: the types crate defines *what* is spoken, the core crate defines *how*
the contract is implemented and *how* checkpoints survive crashes.

### 1.1 Relationship to Phase 1

| Layer | Crate | Scope | Lines | Tests |
|---|---|---|---|---|
| Data-plane types | `tidefs-types-incremental-job-core` | WorkBudget, Checkpoint, StepResult, JobId, JobKind, JobProgress, JobError | 1625 | ~65 |
| Control-plane trait + codec | `tidefs-incremental-job-core` | IncrementalJob trait, CheckpointCodec trait, binary format | 992 | ~32 |

Both crates are `no_std`-first, `forbid(unsafe_code)`, and feature-gated with
`alloc` (default on) and `serde` (off by default). The core crate depends on
the types crate as its sole tidefs-internal dependency.

### 1.2 Why two crates?

Splitting types from the trait/codec layer avoids a dependency tangle:

- **Types crate**: A true leaf. Zero tidefs dependencies. Can be used by
  serialization without pulling in the trait contract.
- **Core crate**: Depends only on the types crate. Subsystem crates (cleanup,
  scrub, rebake, etc.) depend on the core crate to implement `IncrementalJob`.
  The background scheduler depends on the core crate to dispatch `step()` calls.

Without the split, every crate that wants `WorkBudget` or `JobError` would
also pull in the `IncrementalJob` trait and its `Send` bound — an unnecessary
coupling for admin tools and protocol serializers.

## 2. The IncrementalJob Trait

### 2.1 Full trait definition

```rust
pub trait IncrementalJob: Send {
    /// Resume from a previous checkpoint, or start fresh.
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized;

    /// Execute one bounded batch of work.
    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError>;

    /// Persist the checkpoint to stable storage.
    fn persist_checkpoint(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<(), JobError>;

    /// Finalize the completed job.
    fn complete(self) -> Result<(), JobError>;

    /// Return the job's stable identity.
    fn job_id(&self) -> JobId;

    /// Return the job's classification.
    fn job_kind(&self) -> JobKind;
}
```

### 2.2 Lifecycle state machine

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
          │        │    persist_checkpoint(cp)    │         │
          │        └─────────────┬───────────────┘         │
          │                      │                          │
          │                      ├── StepResult::InProgress ─┘
          │                      │
          │                      ├── StepResult::Complete
          │                      │
          │                      ▼
          │        ┌─────────────────────────────┐
          │        │        complete()            │
          │        └─────────────────────────────┘
          │
          │   ─ ─ ─ CRASH ─ ─ ─
          │
          ▼
┌─────────────────────────────┐
│   resume(Some(checkpoint))  │
│   (crash recovery, epoch++) │
└─────────────┬───────────────┘
              │
              └── continues from saved cursor position
```

### 2.3 `resume()` — the constructor

`resume()` is an **associated function** (not a method), making it the
canonical constructor for every `IncrementalJob` implementor. This is
unusual for Rust traits (most use `new()` as an inherent method), but
necessary because:

1. **Crash recovery needs the checkpoint**: After a crash, the scheduler
   reads the last persisted `Checkpoint` from stable storage and passes it
   to `resume(Some(cp))`. The job reconstructs its internal cursor position
   from `cp.cursor_state`.
2. **Type-level contract**: Making `resume()` part of the trait ensures the
   scheduler can construct any `IncrementalJob` implementation through the
   same generic interface without knowing the concrete type at dispatch time
   (via `Box<dyn IncrementalJob>` or equivalent type-erased handle).
3. **Epoch tracking**: The scheduler increments `Checkpoint::epoch` on each
   resume to distinguish fresh starts (epoch=1) from crash recoveries
   (epoch≥2). This enables crash-frequency monitoring and stuck-job detection.

When `resume(Some(cp))` is called, the implementation MUST verify that
`cp.job_id` matches the expected job and that `cp.job_kind` is compatible.
A mismatch produces `JobError::InvalidCheckpoint`.

### 2.4 `step()` — the bounded work unit

Every `step()` call MUST:

| Requirement | Enforcement |
|---|---|
| Allocate/relocate at most `budget.max_bytes` bytes | Implementation responsibility |
| Return within ~`budget.max_ms` (soft) | External enforcement by scheduler's timeout wrapper |
| Return `StepResult::InProgress(checkpoint)` on partial completion | Trait contract |
| Return `StepResult::Complete(checkpoint)` when done | Trait contract |
| Return `JobError::JobAlreadyComplete` if called after completion | Implementation responsibility |

**Idempotency guarantee**: Calling `step()` twice with the same internal cursor
position (because the intervening `persist_checkpoint` failed or the scheduler
crashed) MUST NOT produce duplicate side effects. The checkpoint is the
linearization point: all side effects up to the cursor position recorded in
the checkpoint are durable; no side effects beyond that position have occurred.

In practice, implementations achieve idempotency through:
- **Intent logging**: Write an intent record (e.g., "free extents [A..B]")
  before the step, commit it atomically with the checkpoint in the same commit_group,
  then perform the actual freeing. On resume, skip extents already covered by
  committed intents.
- **Tombstone-based**: Mark records as processed with a monotonic generation
  counter. On resume, skip records whose generation ≤ the checkpoint's epoch.
- **Before-write check**: Before mutating any record, check that it hasn't
  already been mutated (e.g., refcount already 0 for a free operation).

The idempotency strategy is the implementor's choice; the trait does not
mandate a specific approach.

### 2.5 `persist_checkpoint()` — the durability barrier

Called after every successful `step()` that returns a non-error `StepResult`.
The implementation writes the checkpoint to **stable storage** (not just the
page cache) in a manner that survives a crash.

**Atomicity requirement**: The checkpoint write MUST be atomic with respect
to the current transaction group (commit_group). If the commit_group commits, the checkpoint
is durable. If the commit_group aborts (crash before commit), the checkpoint is
discarded along with any partial step side effects.

**On-media location**: Each dataset has a reserved checkpoint area
(`DatasetMetadataV1.incremental_job_checkpoints`) — a small fixed-size region
(typically 4 KiB per job kind) that stores the most recent checkpoint for
each active job. The checkpoint area uses a **write-twice** pattern: write to
a staging slot, then atomically update a generation counter to make the new
checkpoint visible. This prevents torn writes from producing a corrupt
checkpoint that survives a crash.

### 2.6 `complete()` — the finalizer

Called exactly once when `StepResult::is_complete` is true. The implementation:

1. Clears the persistent checkpoint from the dataset's checkpoint area
2. Releases any resources held by the job (iterators, locks, memory)
3. Optionally emits a completion event to the admin event stream
4. Consumes `self` (takes ownership), preventing accidental reuse

After `complete()` returns, the job no longer exists. The scheduler removes
it from the active job table.

### 2.7 `Send` bound

The trait requires `Send` because background jobs execute on dedicated
scheduler threads. Every implementation must be safe to transfer between
threads. This is enforced at compile time: any non-`Send` type in an
implementation causes a compilation error.

### 2.8 Trait object compatibility

The trait is **object-safe** — all methods take `&self` or `&mut self`
(except `resume()` which is an associated function and `complete()` which
takes `self`). The scheduler can type-erase implementations via
`Box<dyn IncrementalJob>` and dispatch `step()`, `persist_checkpoint()`,
`job_id()`, and `job_kind()` through the vtable.

`resume()` and `complete()` are called at well-defined lifecycle boundaries
where the concrete type is known, avoiding the need for object-safe
constructors or consuming finalizers.

## 3. The CheckpointCodec Trait

### 3.1 Trait definition

```rust
pub trait CheckpointCodec {
    /// Encode a checkpoint to a binary buffer.
    fn encode(checkpoint: &Checkpoint, buf: &mut [u8])
        -> Result<usize, JobError>;

    /// Decode a checkpoint from a binary buffer.
    fn decode(buf: &[u8]) -> Result<Checkpoint, JobError>;

    /// Return the maximum encoded size for a given checkpoint.
    fn encoded_size(checkpoint: &Checkpoint) -> usize;
}
```

### 3.2 Binary checkpoint format

The default `CheckpointCodec` implementation produces a length-delimited
binary format with forward-compatible framing:

```
┌──────────────────────────────────────────────────────┐
│  Byte offset  │ Size   │ Field                        │
├───────────────┼────────┼──────────────────────────────┤
│  0            │ 8      │ Magic: "VFSCHKPT" (0x54… )   │
│  8            │ 4      │ Version (u32 LE, currently 1) │
│  12           │ 4      │ Total length (u32 LE)         │
│  16           │ 8      │ job_id (u64 LE = JobId.0)     │
│  24           │ 2      │ job_kind discriminant (u16 LE) │
│  26           │ 2      │ job_kind Other payload (u16 LE, 0 if not Other) │
│  28           │ 8      │ epoch (u64 LE)                │
│  36           │ 4      │ cursor_state length (u32 LE)  │
│  40           │ N      │ cursor_state (opaque bytes)   │
│  40+N         │ 8      │ items_processed (u64 LE)      │
│  48+N         │ 8      │ bytes_processed (u64 LE)      │
│  56+N         │ 8      │ total_items (u64 LE)          │
│  64+N         │ 8      │ total_bytes (u64 LE)          │
│  72+N         │ 8      │ completion_permille (u32 LE)  │
│  76+N         │ 4      │ reserved padding              │
└──────────────────────────────────────────────────────┘
```

**Fixed header**: 16 bytes (magic + version + total length).
**Variable payload**: 64 + N bytes, where N = cursor_state length (0..65535).
**Total maximum**: 80 + 65535 bytes ≈ 65.6 KiB.

### 3.3 Design rationale

| Decision | Rationale |
|---|---|
| **Magic bytes** | Prevents accidental interpretation of non-checkpoint data. The 8-byte magic `VFSCHKPT` is unlikely to appear in random data (1 in 2^64). |
| **Version number** | Enables forward-compatible format evolution. A reader encountering version 2 can reject or upgrade. |
| **Total length prefix** | Allows readers to skip unknown future fields. A reader that knows version 1 reads 64+N bytes; if the total length is larger, the extra bytes are a future extension. |
| **Little-endian** | Consistent with tidefs's on-media format conventions; matches x86 and ARM native byte order (no swap on deployment targets). |
| **Separate cursor_state length** | The opaque cursor can be any size (0 for fresh start, up to 64 KiB). The length prefix avoids scanning for terminators. |
| **Completion fields** | `total_items`, `total_bytes`, and `completion_permille` are informational (computed from `items_processed / total_items`) and enable the scheduler to display progress without decoding the opaque cursor. |

### 3.4 Forward compatibility

Version 1 readers encountering a version 2+ checkpoint:
1. Read the header (magic + version + total length).
2. If version > 1, check if the total length includes at least the known fields
3. If yes, decode the known fields and skip the unknown suffix.
4. If no, return `JobError::InvalidCheckpoint`.

Future versions can add fields after byte 80 without breaking v1 readers, as
long as the fixed portion (bytes 0-79) remains backward-compatible.

## 4. The MockCountingJob Test Harness

The crate includes a `MockCountingJob` that serves as both a **test harness**
and a **reference implementation**. It simulates a simple scanning job that
counts from 0 to a target, processing at most `budget.max_items` per step.

### 4.1 Cursor format

The mock encodes its cursor as an 8-byte little-endian counter (the next item
to process). On resume, it decodes the counter and resumes from that position.
Fresh starts begin at 0.

### 4.2 Test coverage

|---|---|
| `counting_job_full_lifecycle` | Fresh start → step loop → complete. Verifies 100 items at 10/step = 10 steps. |
| `counting_job_resume_from_checkpoint` | Run 5 steps, capture checkpoint, resume, complete remaining. Verifies idempotent resumption. |
| `counting_job_budget_respected` | Tight budget (max_items=3). Verifies step() doesn't exceed the budget. |
| `counting_job_step_after_complete_errors` | Step after complete returns `JobAlreadyComplete`. |
| `checkpoint_codec_roundtrip` | Encode a checkpoint, decode it, verify equality. Tests all fields. |
| `checkpoint_codec_version_rejection` | Decoding unknown version returns appropriate error. |
| `checkpoint_codec_truncated_buffer` | Decoding a buffer shorter than header size returns error. |
| `checkpoint_codec_cursor_truncation` | Decoding a buffer where the cursor is shorter than stated returns error. |
| `checkpoint_codec_empty_cursor` | Roundtrip a checkpoint with zero-length cursor. |
| `job_id_identity_preserved` | `job_id()` returns the same `JobId` from `resume()` through `complete()`. |
| `job_kind_identity_preserved` | `job_kind()` returns the same `JobKind` throughout lifecycle. |
| `epoch_increments_on_resume` | `resume(Some(cp))` produces a checkpoint with epoch = old_epoch + 1. |
| `trait_is_send` | Compile-time check that `IncrementalJob: Send`. |
| `trait_object_dispatch` | Runtime dispatch through `&mut dyn IncrementalJob`. |

### 4.3 Push constants

```rust
pub const CHECKPOINT_MAGIC: &[u8; 8] = b"VFSCHKPT";
pub const CHECKPOINT_HEADER_SIZE: usize = 16;
pub const CHECKPOINT_VERSION: u32 = 1;
```

These are public constants so other crates (the background scheduler, the
the full `CheckpointCodec` trait.

## 5. Integration Architecture

### 5.1 Dependency graph

```
tidefs-types-incremental-job-core     ← Phase 1: data-plane types
    ↑
    │ depends on
    │
tidefs-incremental-job-core          ← Phase 2: trait + codec (THIS CRATE)
    ↑
    ├── tidefs-deferred-cleanup      ← implements IncrementalJob
    ├── tidefs-snapshot-destroy      ← implements IncrementalJob
    ├── tidefs-gc-mark               ← implements IncrementalJob
    ├── tidefs-btree-compaction      ← implements IncrementalJob
    ├── tidefs-rebake                ← implements IncrementalJob
    ├── tidefs-journal-cleaner       ← implements IncrementalJob
    ├── tidefs-dataset-destroy       ← implements IncrementalJob
    ├── tidefs-scrub                 ← implements IncrementalJob
    ├── tidefs-resilver              ← implements IncrementalJob
    ├── tidefs-admin-job             ← implements IncrementalJob
    ├── tidefs-reclaim               ← implements IncrementalJob
    ├── tidefs-orphan-recovery       ← implements IncrementalJob
    ↑
    │ schedules
    │
tidefs-background-scheduler          ← Phase 3: scheduling loop
```

### 5.2 Scheduler integration

The background scheduler (#1179) interacts with `IncrementalJob` through a
type-erased handle:

```rust
// Pseudocode — not in this crate, but in the scheduler
struct JobHandle {
    inner: Box<dyn IncrementalJob>,
    last_checkpoint: Option<Checkpoint>,
    consecutive_errors: u32,
    total_steps: u64,
}

impl JobHandle {
    fn tick(&mut self, budget: WorkBudget) -> Result<TickOutcome, JobError> {
        let result = self.inner.step(budget)?;
        self.inner.persist_checkpoint(&result.checkpoint)?;
        self.last_checkpoint = Some(result.checkpoint);
        self.total_steps += 1;
        if result.is_complete {
            self.inner.complete()?; // consumes self.inner via take/swap
            Ok(TickOutcome::Completed)
        } else {
            Ok(TickOutcome::InProgress)
        }
    }
}
```

The scheduler calls `tick()` once per scheduling round for each active job,
allocating a `WorkBudget` derived from the job's priority class and the
cluster's current resource pressure.

### 5.3 Priority-driven budget allocation

| JobKind | Default priority | Budget multiplier | Pressure boost |
|---|---|---|---|
| `DataCleanup` | HIGH | 2.0× | ENOSPC → TIME_CRITICAL |
| `SnapshotDestroy` | NORMAL | 1.0× | — |
| `GCMark` | NORMAL | 1.0× | Memory pressure → HIGH |
| `BTreeCompact` | LOW | 0.5× | Fragmentation > 50% → NORMAL |
| `Rebake` | NORMAL | 1.0× | Ingest journal > 80% → HIGH |
| `JournalClean` | HIGH | 1.5× | ENOSPC → TIME_CRITICAL |
| `DatasetDestroy` | ADMIN | ∞ (UNBOUNDED) | — |
| `Scrub` | LOW | 0.25× | — |
| `DeepScrub` | LOW | 0.1× | — |
| `Resilver` | TIME_CRITICAL | 4.0× | — |
| `Reclaim` | HIGH | 1.0× | ENOSPC → TIME_CRITICAL |
| `OrphanRecovery` | HIGH | 1.0× | — |
| `AdminJob` | ADMIN | configurable | — |

The multiplier is applied to `DEFAULT_TICK` to produce the per-tick budget.
The scheduler sums all multipliers across active jobs and caps the total at
100% of the background IO budget to prevent starvation of foreground workloads.

## 6. ZFS / Ceph design-input comparison

This section treats ZFS and Ceph as design inputs for a shared trait and
checkpoint codec. It is not a measured claim that TideFS already provides
better crash resumption, latency, or operator visibility. Such statements
remain blocked behind #875 and #928/#930 comparator evidence.

| Dimension | tidefs (this crate) | ZFS | Ceph |
|---|---|---|---|
| **Shared trait** | Yes — `IncrementalJob`, all 12+ subsystems | No — `dsl_scan_phys_t` for scrub, `bpobj` for deferred free, `device_rebuild` bitmaps for resilver; each uses different types | No — per-PG state machines (`pg_scrubber`, `pg_recovery`, `pg_backfill`) with no shared Rust-compatible contract |
| **Unified constructor** | `resume(Option<Checkpoint>)` — fresh or crash | Ad-hoc: `dsl_scan_init()`, `bpobj_open()`, `device_rebuild_init()` — each has different signatures | Per-state-machine `start()` methods with different signatures |
| **Checkpoint persistence** | `persist_checkpoint()` + `CheckpointCodec` binary format with magic, version, length framing | ZAP objects for scrub progress (key-value store, ad-hoc schema); `spa_sync` for commit_group-based checkpoint; no unified format | In-memory only; restart from scratch on OSD restart or PG migration |
| **Forward-compatible format** | Versioned binary with length-delimited framing | ZAP objects are extensible but not schema-versioned; breakage on incompatible changes | PG state is versioned via OSDMap epoch but not per-job |
| **Budget enforcement** | `WorkBudget` enforced per-step; trait contract mandates respect | `zfs_scan_legacy` (bytes only, per-commit_group); no per-step enforcement | `osd_recovery_max_active` (ops only); no per-step enforcement |
| **`Send` safety** | Compile-time `Send` bound on trait | N/A (C, no thread-safety type system) | N/A (C++, no trait-bound `Send` equivalent) |
| **Trait object dispatch** | `Box<dyn IncrementalJob>` through vtable | N/A | N/A (virtual dispatch not used for PG operations) |
| **Unsafe code** | `#![forbid(unsafe_code)]` | Ubiquitous (kernel module, raw pointers, assembly) | Some (buffer management, messenger, async messenger) |

### 6.1 ZFS design risks this contract targets

1. **Scrub crash restart**: the design target is to avoid restart-from-beginning
   background jobs by persisting checkpoints after bounded steps. This document
   does not quantify saved time on real pools.

2. **Deferred free fragmentation**: ZFS's `bpobj` (block pointer object) for
   deferred frees is used here as the design input for requiring per-step work
   budgets. The target `WorkBudget` values describe TideFS contract shape, not
   measured per-commit_group latency against ZFS.

3. **Admin fragmentation**: ZFS has `zpool scrub`, `zpool resilver`,
   `zfs destroy`, and `zpool initialize` — each with different progress
   reporting. TideFS targets unified progress via `JobProgress` and a single
   jobs command; current operator-visible superiority remains unclaimed here.

## 7. Testing Strategy

### 7.1 Unit tests (~32 tests)

All tests live in `crates/tidefs-incremental-job-core/src/lib.rs` using
`#[cfg(test)]` and `MockCountingJob`.

### 7.2 Integration tests (future)

When subsystem crates implement `IncrementalJob`, each should include:

- **Full lifecycle test**: Fresh start → step → complete
- **Crash-resume test**: Run N steps, capture checkpoint, resume, complete
- **Budget respect test**: Verify `step()` doesn't exceed budget dimensions
- **Double-step idempotency test**: Call `step()` twice with same cursor,
  verify no duplicate side effects
- **Codec roundtrip**: Encode → decode → verify equality for every checkpoint
  the subsystem produces


```bash
cargo test -p tidefs-incremental-job-core
cargo clippy -p tidefs-incremental-job-core -- -D warnings
cargo check --workspace
```

The full xtask gate (`tidefs-xtask check-incremental-cursor`) also verifies
the integration with the background scheduler and the deterministic crash
injection harness (#1230).

## 8. Tradeoffs and Design Decisions

### 8.1 `resume()` as associated function vs. inherent method

**Decision**: `resume()` is part of the trait as an associated function.

**Tradeoff**: Unlike Rust conventions where constructors are inherent `new()`
methods, making `resume()` part of the trait enables the scheduler to
construct any `IncrementalJob` through a type-erased factory.

**Downside**: Callers cannot write `MyJob::resume(checkpoint)` without
importing the trait (`use tidefs_incremental_job_core::IncrementalJob`).

### 8.2 `complete()` consumes `self`

**Decision**: `complete(self)` takes ownership.

**Tradeoff**: Prevents accidental reuse of a completed job. The scheduler
must move the job out of its handle (e.g., via `Option::take`) before
calling `complete()`.

**Alternative considered**: `&mut self` with a `completed: bool` flag.
Rejected because it allows `step()` to be called after `complete()`, which
would require every `step()` implementation to check a flag — pushing the
safety burden onto every implementor instead of centralizing it in the
type system.

### 8.3 Binary format vs. serde-only

**Decision**: Provide both a fixed binary format (via `CheckpointCodec`) and
optional serde support (via the `serde` feature on the types crate).

**Tradeoff**: The binary format is ~2× more compact than JSON and doesn't
require `serde` at runtime (useful for `no_std` without alloc). Serde

### 8.4 `no_std` + `alloc` feature gate

**Decision**: Default feature `alloc` enables `Vec<u8>` and `String` in the
types crate; the core crate gates `CheckpointCodec` behind `alloc`.

**Tradeoff**: With `alloc` disabled, `CheckpointCodec` is unavailable because
it requires `Vec<u8>`. This is acceptable because the codec is used in
persistence paths that always have a heap. The types-only path (WorkBudget,
JobId, JobKind) works without alloc for embedded probe contexts.

### 8.5 Single-file crate

**Decision**: Both the types crate and the core crate are single-file
(`lib.rs` only).

**Tradeoff**: A 1600-line or 1000-line `lib.rs` is large for a single file.
However, all types are tightly coupled (they appear together in every
`StepResult`, `Checkpoint`, and trait implementation), so splitting into
modules would create import friction without meaningful separation of
concerns. This can be revisited if the crate grows beyond 3000 lines.

## 9. Open Questions

1. **`abort()` method**: Should the trait include an optional `abort()` for
   cancelled jobs? Some jobs (rebake, journal clean) may need to undo partial
   work if cancelled mid-operation. **Proposal**: Add as a default no-op
   method in a future revision if cancellation use cases emerge.

2. **`priority()` method**: Should `JobKind` carry scheduling priority, or
   should the scheduler own the priority table? **Proposal**: The scheduler
   owns the priority table (Section 5.3). Adding priority to the trait
   would couple the crate to scheduling policy, which should be configurable
   by the operator.

3. **Checkpoint compression**: Large cursors (B+tree position stacks for
   deep trees) may benefit from compression (LZ4) in the binary format.
   **Proposal**: Add an optional compression flag to the version field
   (version bit 31 = compressed) if profiling shows cursors exceeding 4 KiB.

4. **Multiple active checkpoints per job**: Some jobs (journal clean) may
   benefit from multiple independent cursors (one per journal segment).
   **Proposal**: The job manages multiple cursors internally; the trait
   only sees a single opaque `cursor_state`. The job can encode multiple
   sub-cursors into the opaque bytes using its own framing.

5. **`step()` timeout**: The crate does not enforce `max_ms` — it's a soft
   hint. Should the scheduler preempt a `step()` that exceeds its time budget?
   **Proposal**: The scheduler wraps `step()` in a timeout (Phase 3). The
   trait does not need to support cancellation mid-step because all steps
   are bounded by design.

## 10. Revision History

| Date | Change | Issue |
|---|---|---|
| 2026-05-02 | Phase 2 crate implemented (992 lines, ~32 tests) | #1385 |
| 2026-05-04 | Design document formalized | #1620 |
