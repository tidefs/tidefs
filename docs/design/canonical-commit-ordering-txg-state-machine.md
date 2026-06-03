# canonical commit ordering and multi-phase commit_group state machine

**Issue**: [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267)
**Status**: design-draft
**Maturity**: spec-draft for the Rust implementation; based on v0.262 Python reference slice-0 commit_group + ZFS commit_group model
**Lane**: storage-core
**Hard-gate**: yes

## 1. Problem statement

Without explicit commit ordering rules, the write path can violate crash safety in subtle
ways: metadata records pointing to unflushed data payloads, checkpoint pointers
preceding journal writes, torn commits leaving the pool in an unrecoverable state.
ZFS solves this with its ZIL+commit_group machinery; tidefs needs its own explicit contract
that is simpler and narrower but equally rigorous.

The v0.262 Python reference implements what it calls "slice-0 commit_group batching": a pool-side
mechanism that stages metadata roots in memory and commits them when thresholds are
met. It does **not** implement data-before-metadata flush ordering, a quiesce phase,
or checkpoint-pointer durability. Those are the gap this design fills.

## 2. Scope and non-scope

### In scope

- Canonical seven-step commit ordering with the invariant "a pointer is never persisted
  before what it points to"
- Multi-phase commit_group state machine: OPEN -> QUIESCE -> SYNC -> OPEN
- Three durability trigger classes: metadata-only, data+metadata, forced (fsync/O_DSYNC)
- Four auto-sync triggers with a strict evaluation hierarchy
- Back-pressure throttling when dirty bytes exceed `commit_group_dirty_max_bytes`
- Deterministic clock injection for time-based trigger testing
- Maintenance tick for timer-driven sync without user mutations

### Explicitly out of scope

- Intent log / LOG_DEVICE for low-latency sync writes (tracked in #1252)
- Torn-commit recovery via journal scanning (tracked in #1224)
- Crash injection harness (tracked in #1230)
- CommitGroup sync scheduling in the CONTROL lane (tracked in #1241)
- Distributed commit_group commit protocol (the cluster commit_group is tracked in the v0.262 reference
  and deferred to a separate distributed-commit_group design)
- Production Reed-Solomon / erasure-coded commit_group (deferred)

## 3. Canonical seven-step commit ordering

Every committed transaction group follows a fixed seven-step pipeline. Steps are
numbered 1 through 7 and must execute in order. Each step must complete before the
next step begins.

```
STEP 1 -- APPEND data records (extent payloads, shard bodies)
    |
STEP 2 -- FLUSH data journal (fsync/fdatasync on data SegmentStore)
    |
STEP 3 -- APPEND metadata updates (extent maps, inodes, directories, catalogs)
    |
STEP 4 -- APPEND commit record (METADATA_COMMIT_V1 or POOLMAP_COMMIT_V1)
    |
STEP 5 -- FLUSH metadata journal (fsync on metadata SegmentStore)
    |
STEP 6 -- UPDATE checkpoint pointer copies in system area (slice-0)
    |
STEP 7 -- FLUSH system area writes (fsync on poolmap SegmentStore)
```

### 3.1 Invariant

> A pointer is never persisted before what it points to.

- **Steps 1-2** ensure data payloads are durable on storage media before metadata
  records reference them. If a crash occurs after step 3 but before step 5, the
  metadata references may be lost but the data blocks are harmless orphaned records
  (reclaimable by the segment cleaner).

- **Steps 3-4** ensure the commit record that binds all metadata updates together is
  itself durable. The commit record is the atomic unit of metadata mutation.

- **Steps 5-7** ensure the commit record is durable before the checkpoint pointer
  makes it reachable on next mount. A torn checkpoint pointer (step 6 partial write)
  is detected by the recovery contract (section 8) and triggers journal fallback.

- **Steps 6-7** ensure the checkpoint pointer is durable before any reader trusts it.
  The system area (slice-0) is the single source of truth for "which commit is current."

### 3.2 Durability trigger classes

Not every commit requires all seven steps. The design recognizes three classes,
selected based on what is dirty at commit_group-sync time.

| Class | Dirty state | Steps executed |
|---|---|---|
| **Metadata-only commit** | Only inode/directory/catalog records are dirty; no data payloads | 3-7 |
| **Data + metadata commit** | Both data extents and metadata records are dirty | 1-7 (full pipeline) |
| **Forced durability** (fsync/O_DSYNC) | Specific file/directory forced through pipeline | 1-7 for the target file(s), or 3-7 if no data extents are dirty for that scope |

The class is determined at the start of the SYNC phase by inspecting the dirty-state
tracking (section 5.1). A metadata-only commit skips the data-journal append and flush
(steps 1-2), which is the common fast path for namespace operations (mkdir, rename,
unlink, setxattr).

### 3.3 Relationship to the v0.262 Python reference

The Python reference `pool_commit_group_io.py` implements a simplified model where a commit_group sync
calls `_commit_new_root_immediate()`, which performs a single metadata-commit write
without the seven-step pipeline. The data-before-metadata ordering is absent because
the Python reference does not separate data and metadata SegmentStores with distinct
flush points. The Rust implementation will need to:

1. Track which SegmentStore families (data, metadata_journal, pool_map_journal) have
   been written to during the current commit_group.
2. Issue per-store flush/fsync at the correct step boundary.
3. Write the checkpoint pointer as a separate record after the metadata commit.

## 4. Multi-phase commit_group state machine

### 4.1 States

```
                    +--------------------------------------+
                    |                                      |
                    v                                      |
    +------+  quiesce   +----------+  sync_start   +------+--+
    | OPEN | -------->  | QUIESCE  | ------------> |  SYNC   |
    +------+            +----------+               +-----+---+
         ^                                              |
         |            sync_complete                     |
         +----------------------------------------------+
```

**OPEN phase:**
- Accept new writes into the current commit_group.
- Accumulate dirty bytes (coarse accounting via SegmentStore write hooks).
- Track dirty inodes, dirty extent maps, and dirty directory entries.
- Reads consult staged metadata roots (in-memory) for uncommitted mutations.
- New writes that arrive during OPEN are immediately staged.

**QUIESCE phase** (triggered by: any sync trigger firing):
- Stop accepting new writes into **this** commit_group.
- New writes arriving during quiesce are directed to the **next** commit_group (a new OPEN).
- Wait for all in-flight write I/O to complete (drain the write pipeline).
- In-flight means: SegmentStore `append_record()` calls that have returned to the
  caller but whose fsync has not yet been issued. The quiesce barrier ensures every
  byte to be committed has reached the kernel page cache.

**SYNC phase:**
- Execute the seven-step ordering (section 3) for all dirty state accumulated during OPEN.
- Append the commit record and checkpoint pointer.
- Publish the new metadata root as the pool's committed state.
- Dirty buffers become clean; the commit_group object is recycled (or dropped).

**After SYNC completes:**
- If there is a pending next commit_group (because writes arrived during QUIESCE/SYNC),
  it transitions from OPEN to become the current commit_group.
- If there is no pending commit_group, the pool returns to an idle state with no active commit_group
  (the next mutation will create a new OPEN).

### 4.2 State invariants

| State | Accepts new writes? | Has dirty state? | In-flight I/O? |
|---|---|---|---|
| **OPEN** | yes | maybe | yes |
| **QUIESCE** | no (redirected to next commit_group) | yes | yes (being drained) |
| **SYNC** | no (redirected to next commit_group) | yes (being committed) | no (drained before SYNC begins) |
| **(idle)** | no commit_group exists | -- | -- |

### 4.3 Concurrent commit_group existence

At most **two** commit_group objects can exist simultaneously:

- **Current commit_group**: the one that is OPEN (accepting writes) or transitioning through
  QUIESCE/SYNC.
- **Next commit_group**: created when a write arrives during QUIESCE or SYNC. It starts in
  OPEN state and is "queued" behind the current commit_group.

This is a deliberate simplification of ZFS's three-commit_group pipeline (open/quiescing/
syncing). Two commit_groups are sufficient for the userspace preview because:

- The SYNC phase runs synchronously on the calling thread (no background sync
  thread). While SYNC is executing, new writes must go somewhere -- they go to the
  next commit_group.
- A third commit_group would only be needed if SYNC were asynchronous and could overlap
  with a subsequent QUIESCE, which is not planned for the userspace path.

## 5. Dirty-state tracking

### 5.1 Per-commit_group dirty sets

Each commit_group object maintains:

```rust
struct CommitGroupDirtyState {
    /// Inodes modified during this commit_group (keyed by inode_id).
    dirty_inodes: BTreeSet<InodeId>,

    /// Extent maps modified during this commit_group (keyed by inode_id).
    dirty_extent_maps: BTreeSet<InodeId>,

    /// Directory entries added/removed/renamed (keyed by dir_inode_id).
    dirty_dirs: BTreeSet<InodeId>,

    /// Coarse byte accounting, broken down by SegmentStore family.
    bytes_poolmap: u64,
    bytes_metadata: u64,
    bytes_data: u64,

    /// True if any data extents were appended during this commit_group.
    has_data_dirty: bool,

    /// True if any metadata was modified during this commit_group.
    has_metadata_dirty: bool,
}
```

The boolean flags `has_data_dirty` and `has_metadata_dirty` drive the durability
trigger class selection (section 3.2).

### 5.2 Coarse byte accounting

The v0.262 Python reference uses SegmentStore write hooks
(`after_record_append(store, total_padded_bytes)`) for coarse dirty-byte accounting.
This design adopts the same mechanism:

- Each SegmentStore family (poolmap, metadata, data) calls back into the commit_group
  manager after every record append.
- The commit_group manager adds the padded record bytes to the appropriate bucket.
- This accounting is intentionally coarse: it counts padded record bytes, not
  logical dirty bytes. It is sufficient for back-pressure thresholds (section 7).

The write hooks are **suspended** during the SYNC phase (steps 3-7 and steps 1-7)
to prevent the commit's own record appends from being mis-attributed to the next commit_group.

### 5.3 Relationship to the transaction model

The commit_group state machine sits **above** the explicit transaction model (#1190). When
commit_group batching is enabled:

- `begin_transaction()` / `commit_transaction()` operate within the current OPEN commit_group.
  The transaction's mutations are staged to the commit_group's dirty sets but are not
  individually committed to storage.
- The commit_group's SYNC phase commits all accumulated transaction work as one atomic unit.
- Explicit transactions are rejected when no commit_group is active and commit_group batching is
  enabled (matching the Python reference behavior: `TransactionActiveError`).

## 6. Auto-sync trigger hierarchy

### 6.1 Trigger evaluation order

Triggers are evaluated in a strict priority order at mutation boundaries (after
each pool operation) and at maintenance-tick boundaries:

| Priority | Trigger | Config key | Effect |
|---|---|---|---|
| 1 (highest) | **Hard cap** | `commit_group_dirty_max_bytes` | Forces QUIESCE immediately; writers are throttled until the QUIESCE completes |
| 2 | **Op count** | `commit_group_target_ops` | Fires QUIESCE when staged ops >= threshold |
| 3 | **Time** | `commit_group_target_seconds` | Fires QUIESCE when elapsed >= threshold (best-effort; checked at boundaries) |
| 4 (lowest) | **Soft bytes** | `commit_group_target_bytes` | Fires QUIESCE when dirty bytes >= threshold (best-effort) |

The ordering is intentional: the hard cap prevents unbounded memory growth regardless
of other settings. Op count is a precise trigger; time and bytes are best-effort
heuristics that supplement it.

### 6.2 Default values and safety bounds

| Config key | Default | Min | Max | Unit |
|---|---|---|---|---|
| `commit_group_target_ops` | 64 | 1 | 1,000,000 | staged operations |
| `commit_group_target_seconds` | 0.0 (disabled) | 0.0 | 3600.0 | seconds |
| `commit_group_target_bytes` | 0 (disabled) | 0 | 2^60 | padded record bytes |
| `commit_group_dirty_max_bytes` | 0 (disabled) | 0 | 2^60 | padded record bytes |

A value of 0 disables the trigger. The maintenance tick (section 9) is the only way to drive
time-based syncs without user mutations when `commit_group_target_seconds > 0`.

### 6.3 Auto-sync decision algorithm

```rust
fn should_quiesce(commit_group: &CommitGroupState, cfg: &CommitGroupConfig, clock: &dyn CommitGroupClock) -> Option<QuiesceReason> {
    if !commit_group.dirty_state.has_metadata_dirty && !commit_group.dirty_state.has_data_dirty {
        return None;
    }

    // 1. Hard cap: prevent unbounded growth.
    if let Some(max_bytes) = cfg.dirty_max_bytes {
        if commit_group.dirty_state.total_bytes() >= max_bytes {
            return Some(QuiesceReason::DirtyMaxBytes);
        }
    }

    // 2. Op-count threshold.
    if commit_group.ops_staged >= cfg.target_ops {
        return Some(QuiesceReason::TargetOps);
    }

    // 3. Time threshold.
    if let Some(target_s) = cfg.target_seconds {
        if clock.now() - commit_group.start_time >= target_s {
            return Some(QuiesceReason::TargetSeconds);
        }
    }

    // 4. Soft dirty-bytes threshold.
    if let Some(target_bytes) = cfg.target_bytes {
        if commit_group.dirty_state.total_bytes() >= target_bytes {
            return Some(QuiesceReason::TargetBytes);
        }
    }

    None
}
```

### 6.4 Explicit sync

In addition to auto-sync, the operator (or fsync/O_DSYNC path) can call
`commit_group_sync()` to force an immediate QUIESCE -> SYNC transition regardless of
thresholds. This is the mechanism behind `fsync()` and `O_DSYNC` durability
guarantees.

## 7. Back-pressure

### 7.1 Hard-cap back-pressure

When `commit_group_dirty_max_bytes > 0` and dirty bytes reach or exceed the threshold
during the OPEN phase:

1. The commit_group is immediately forced into QUIESCE (even if other triggers haven't fired).
2. Writers that attempt to append new records are throttled: the write path blocks
   (or returns `EWOULDBLOCK` for non-blocking paths) until the QUIESCE completes
   and the next commit_group enters OPEN.
3. The back-pressure is coarse: it applies to all writers, not just the ones that
   pushed the total over the threshold. This is acceptable for the userspace preview
   and matches ZFS behavior.

### 7.2 Throttle semantics

The throttle is advisory for the FUSE write path: a write that would exceed
`commit_group_dirty_max_bytes` blocks with a timeout. If the timeout expires before the
SYNC phase completes, the write returns `EAGAIN` (FUSE: the userspace daemon can
retry).

For the block-volume path, the throttle is hard: writes are queued in the block
adapter and held until capacity opens.

### 7.3 Relation to allocator ENOSPC

Back-pressure on dirty bytes is independent of allocator ENOSPC. A pool can have
plenty of free space but still throttle writers because the commit_group has accumulated
too many uncommitted dirty bytes in memory. Conversely, a pool near ENOSPC may
still accept writes if the dirty-byte budget is available.

## 8. Recovery contract


On pool open:

1. Read the checkpoint pointer from the system area (slice-0 on each device).
2. If multiple devices are present, select the newest valid checkpoint pointer
   (highest `commit_seq` with a valid checksum).
   location, verify its integrity (BLAKE3-256 checksum, record framing).
4. If the checkpoint pointer is valid: load the committed state directly.
   This is the fast path.
5. If the checkpoint pointer is torn/corrupt/invalid: fall back to journal
   scanning. Scan the metadata journal SegmentStore for the newest valid
   `METADATA_COMMIT_V1` record and use that as the recovery point.

### 8.2 Crash-at-each-step analysis

The design must survive a crash at any of the seven steps:

| Crash after step | What is on disk | Recovery outcome |
|---|---|---|
| 1 (data append partial) | Partial data extent records; no metadata reference | Orphaned data records; metadata state unchanged; no data loss; orphaned records reclaimable by segment cleaner |
| 2 (data fsync done) | Durable data extents; no metadata reference | Same as step 1: orphans, no loss |
| 3 (metadata append partial) | Durable data + partial metadata; no commit record | Metadata rollback to previous commit; data orphans; no directory-visible loss |
| 4 (commit record appended) | Durable data + metadata + commit record; old checkpoint pointer | Commit is durable but unreachable (old checkpoint pointer still points to previous commit); on next mount, checkpoint pointer is stale, so recovery falls back to journal scan, which finds the newer commit record |
| 5 (metadata fsync done) | Same as step 4 but metadata journal is fsynced | Same outcome: commit exists but is unreachable until journal scan |
| 7 (checkpoint fsync done) | Everything durable; current checkpoint pointer | Clean recovery: mount at the new commit |

The key property: **at no point can the pool reach an inconsistent state where
metadata references data that was never made durable**. The data-before-metadata
ordering (step 2 before step 3) guarantees this.

### 8.3 Torn-commit detection

A commit record that was partially written (crash during step 4) is detected by
the record's own integrity check (BLAKE3-256 trailer). The journal scan skips
records whose trailer doesn't verify and continues scanning backward for the
next valid commit.

## 9. Maintenance tick

### 9.1 Purpose

The maintenance tick (`commit_group_tick()`) services timer-based sync triggers without
requiring user mutations. It is called by the pool's background service loop
at a regular cadence.

### 9.2 Algorithm

```rust
fn commit_group_tick(&mut self) -> CommitGroupTickOutcome {
    if self.current_commit_group.is_none() {
        return CommitGroupTickOutcome::NoCommitGroup;
    }
    if self.current_commit_group_phase != CommitGroupPhase::Open {
        return CommitGroupTickOutcome::NotOpen;
    }
    match self.should_quiesce() {
        Some(reason) => {
            self.quiesce_and_sync();
            CommitGroupTickOutcome::Synced { reason }
        }
        None => CommitGroupTickOutcome::NoTrigger,
    }
}
```

### 9.3 Integration with service_background

The pool's `service_background()` implementation calls `commit_group_tick()` as one of
its maintenance tasks. In the v0.262 Python reference, this is done inside
`service_background()` with `max_tasks` controlling non-commit_group work. The Rust
implementation follows the same pattern.

## 10. Deterministic clock injection

### 10.1 Clock trait

```rust
pub trait CommitGroupClock: Send + Sync {
    fn now(&self) -> f64;
}

pub struct MonotonicClock;
impl CommitGroupClock for MonotonicClock {
    fn now(&self) -> f64 {
        // std::time::Instant or clock_gettime(CLOCK_MONOTONIC) as seconds
    }
}

pub struct TestClock {
    now: AtomicF64,  // or Mutex<f64>
}
```

The `TestClock` allows tests to advance time deterministically without `sleep()`.
This matches the Python reference's `commit_group_clock` callable.

### 10.2 Test coverage

All four trigger types must be testable with deterministic clock injection:

- `test_auto_sync_on_op_threshold`: `commit_group_target_ops=2`, two mutations -> auto-sync
- `test_auto_sync_on_time_threshold`: `commit_group_target_seconds=10.0`, advance clock
  past threshold on next mutation -> auto-sync
- `test_auto_sync_on_byte_threshold`: `commit_group_target_bytes=1` -> immediate auto-sync
- `test_backpressure_hard_cap`: `commit_group_dirty_max_bytes=4096`, exceed -> QUIESCE
- `test_time_threshold_syncs_without_mutation_via_tick`: advance clock past
  threshold, call `commit_group_tick()` -> auto-sync
- `test_crash_at_each_step`: crash simulation at each of the 7 steps, verify
  recovery outcome per section 8.2 table
- `test_close_flushes_commit_group`: open pool, mutate, close without explicit sync ->
  verify data survives reopen

## 11. Configuration and tuning

### 11.1 Pool creation parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `commit_group_enabled` | `bool` | `true` | Enable commit_group batching. When `false`, every mutation immediately commits (prior-generation mode). |
| `commit_group_target_ops` | `u32` | 64 | Staged operation count that triggers auto-quiesce. |
| `commit_group_target_seconds` | `f64` | 0.0 | Elapsed time in seconds that triggers auto-quiesce. 0.0 disables. |
| `commit_group_target_bytes` | `u64` | 0 | Dirty padded bytes that trigger auto-quiesce. 0 disables. |
| `commit_group_dirty_max_bytes` | `u64` | 0 | Hard cap on dirty bytes before back-pressure. 0 disables. |
| `commit_group_clock` | `Option<Box<dyn CommitGroupClock>>` | `None` (use `MonotonicClock`) | Clock source for time-based triggers. Test hook. |

### 11.2 Tuning guidance

| Workload | Recommended settings |
|---|---|
| **Metadata-heavy** (many small files, renames) | `commit_group_target_ops=256`, `commit_group_target_seconds=5.0` |
| **Data-heavy** (large sequential writes) | `commit_group_target_bytes=134_217_728` (128 MiB), `commit_group_target_seconds=30.0` |
| **Low-latency** (fsync-heavy databases) | `commit_group_target_seconds=0.0`, rely on explicit `commit_group_sync()` calls driven by fsync |
| **Memory-constrained** | `commit_group_dirty_max_bytes=67_108_864` (64 MiB) to bound in-memory dirty state |

## 12. Rust implementation plan

### 12.1 Crate layout

The commit_group state machine belongs in the existing `tidefs-local-object-store` crate as
part of the `Pool` type. A new module `pool::commit_group` will contain:

```
crates/tidefs-local-object-store/src/pool/
  mod.rs          (existing Pool type, gains CommitGroupManager field)
  commit_group.rs          (NEW: CommitGroupManager, CommitGroupState, CommitGroupPhase, CommitGroupDirtyState, etc.)
```

### 12.2 Key types

```rust
// crates/tidefs-local-object-store/src/pool/commit_group.rs

/// The three phases of a commit_group lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitGroupPhase {
    Open,
    Quiesce,
    Sync,
}

/// Reason a commit_group was quiesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceReason {
    ExplicitSync,
    TargetOps,
    TargetSeconds,
    TargetBytes,
    DirtyMaxBytes,
}

/// Dirty state accumulated during a commit_group's OPEN phase.
#[derive(Debug, Default)]
pub struct CommitGroupDirtyState {
    pub dirty_inodes: BTreeSet<InodeId>,
    pub dirty_extent_maps: BTreeSet<InodeId>,
    pub dirty_dirs: BTreeSet<InodeId>,
    pub bytes_poolmap: u64,
    pub bytes_metadata: u64,
    pub bytes_data: u64,
    pub has_data_dirty: bool,
    pub has_metadata_dirty: bool,
}

impl CommitGroupDirtyState {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_poolmap + self.bytes_metadata + self.bytes_data
    }
}

/// A commit_group object representing one transaction group.
pub struct CommitGroupState {
    pub commit_group_id: u64,
    pub phase: CommitGroupPhase,
    pub start_time: f64,
    pub ops_staged: u64,
    pub dirty_state: CommitGroupDirtyState,
    /// Staged metadata roots (in-memory).
    pub staged_roots: Option<StagedRoots>,
}

/// Configuration knobs for the commit_group manager.
#[derive(Debug, Clone)]
pub struct CommitGroupConfig {
    pub enabled: bool,
    pub target_ops: u32,
    pub target_seconds: Option<f64>,
    pub target_bytes: Option<u64>,
    pub dirty_max_bytes: Option<u64>,
}

/// Outcome of a commit_group tick.
#[derive(Debug)]
pub enum CommitGroupTickOutcome {
    NoCommitGroup,
    NotOpen,
    NoTrigger,
    Synced { reason: QuiesceReason },
}

/// Top-level commit_group manager embedded in Pool.
pub struct CommitGroupManager {
    config: CommitGroupConfig,
    clock: Box<dyn CommitGroupClock>,
    current: Option<CommitGroupState>,
    next: Option<CommitGroupState>,
    write_hooks_suspended: bool,
}
```

### 12.3 CommitGroupManager public API

```rust
impl CommitGroupManager {
    pub fn new(config: CommitGroupConfig, clock: Box<dyn CommitGroupClock>) -> Self;

    /// Called by pool mutating operations before staging a mutation.
    /// Opens a new commit_group if none is active. Returns the current commit_group (or next commit_group
    /// if the current is in QUIESCE/SYNC).
    pub fn begin_or_get_commit_group(&mut self) -> &mut CommitGroupState;

    /// Stage a metadata root update within the current commit_group.
    pub fn stage_roots(&mut self, roots: StagedRoots);

    /// Record padded bytes appended to a SegmentStore family.
    pub fn record_bytes(&mut self, family: SegmentStoreFamily, bytes: u64);

    /// Evaluate auto-sync triggers. If any fire, initiate QUIESCE -> SYNC.
    /// Called after each pool mutation.
    pub fn auto_sync_if_needed(&mut self);

    /// Explicit sync: force QUIESCE -> SYNC regardless of thresholds.
    /// Returns true if a commit was published.
    pub fn sync(&mut self) -> Result<bool, CommitGroupError>;

    /// Maintenance tick for timer-driven sync.
    pub fn tick(&mut self) -> CommitGroupTickOutcome;

    /// Suspend write hooks during SYNC to avoid mis-attribution.
    pub fn suspend_write_hooks(&mut self);
    pub fn resume_write_hooks(&mut self);

    /// Abort the current commit_group (drop staged state without committing).
    pub fn abort(&mut self);

    /// Whether the commit_group is dirty (has uncommitted mutations).
    pub fn is_dirty(&self) -> bool;

    /// Whether a commit_group is currently open.
    pub fn is_open(&self) -> bool;
}
```

### 12.4 Commit pipeline (SYNC phase)

The SYNC phase is implemented as a single method that calls the seven steps
sequentially. Each step returns a `Result`; failure at any step aborts the
sync (the pool remains at the previous committed state).

```rust
fn execute_sync_phase(
    &mut self,
    commit_group: &mut CommitGroupState,
    stores: &mut SegmentStoreSet,
    system_area: &mut SystemArea,
) -> Result<(), SyncError> {
    let class = commit_group.commit_class();

    match class {
        CommitClass::DataAndMetadata | CommitClass::ForcedDurability => {
            // Step 1: all data records are already appended during OPEN.
            // Step 2: flush data journal.
            stores.data.fsync()?;
        }
        CommitClass::MetadataOnly => {
            // Skip steps 1-2.
        }
    }

    // Step 3: metadata records are already appended during OPEN.
    // Step 4: append the METADATA_COMMIT_V1 record.
    let commit_ptr = stores.metadata.append_commit_record(&commit_group.staged_roots)?;

    // Step 5: flush metadata journal.
    stores.metadata.fsync()?;

    // Step 6: update checkpoint pointer in system area.
    system_area.write_checkpoint_pointer(commit_ptr, commit_group.commit_group_id)?;

    // Step 7: flush system area.
    system_area.fsync()?;

    Ok(())
}
```

### 12.5 Integration points

The CommitGroupManager integrates with existing Pool subsystems:

| Subsystem | Integration |
|---|---|
| **SegmentStore** | Write hooks: after every `append_record()`, call `commit_group_mgr.record_bytes()`. Check `commit_group_mgr.write_hooks_suspended` before calling. |
| **Commit path** (`_commit_new_root`) | When commit_group is enabled, call `commit_group_mgr.stage_roots()` instead of writing the commit immediately. |
| **Read path** | Consult `commit_group_mgr.current().staged_roots` for uncommitted metadata. If no commit_group is active, read from committed state directly. |
| **Pool close** | If a dirty commit_group is open, call `commit_group_mgr.sync()` to flush before closing. |
| **fsync/O_DSYNC** | Call `commit_group_mgr.sync()` to force immediate durability. |
| **service_background** | Call `commit_group_mgr.tick()` as part of maintenance loop. |

### 12.6 Write hook suspension contract

The write-hook suspension is critical for correctness. During the SYNC phase,
`execute_sync_phase()` appends commit records and writes checkpoint pointers.
These append operations must NOT be counted as dirty bytes for the next commit_group.

The contract:

1. `CommitGroupManager::sync()` sets `write_hooks_suspended = true` before calling
   `execute_sync_phase()`.
2. `SegmentStore::append_record()` checks `commit_group_mgr.write_hooks_suspended` before
   calling `commit_group_mgr.record_bytes()`. If suspended, skip the hook.
3. `CommitGroupManager::sync()` clears `write_hooks_suspended = false` after
   `execute_sync_phase()` returns.
4. If `execute_sync_phase()` returns an error, the suspension is cleared in the
   error path to prevent a permanent suspension leak.


### 13.1 Required tests

|---|---|
| `test_commit_group_stages_until_sync` | Mutations are invisible on-disk until `commit_group_sync()` |
| `test_close_flushes_commit_group` | `Pool::close()` syncs a dirty commit_group |
| `test_auto_sync_on_op_threshold` | Op-count trigger fires at the right boundary |
| `test_auto_sync_on_time_threshold` | Time trigger fires with deterministic clock |
| `test_auto_sync_on_byte_threshold` | Byte trigger fires immediately when threshold is low |
| `test_backpressure_hard_cap` | `commit_group_dirty_max_bytes` forces QUIESCE and throttles writers |
| `test_tick_syncs_without_mutation` | `commit_group_tick()` fires time trigger without new mutations |
| `test_explicit_sync_during_open_commit_group` | `commit_group_sync()` commits all staged work |
| `test_crash_at_step_*` (x7) | Crash at each of the 7 steps, verify recovery outcome |
| `test_torn_commit_detection` | Partial commit record is detected and skipped |
| `test_torn_checkpoint_detection` | Torn checkpoint pointer triggers journal fallback |
| `test_commit_group_abort` | `commit_group_abort()` drops staged state without committing |
| `test_concurrent_commit_group` | Writes during QUIESCE go to next commit_group |
| `test_write_hook_suspension` | Commit records are not mis-attributed to next commit_group |
| `test_fsync_forces_sync` | `fsync()` triggers `commit_group_sync()` |

### 13.2 Gate command

```
tidefs-xtask check-commit_group-commit-ordering
```

This xtask will:

1. Run the unit test suite for the commit_group module.
2. Run crash-simulation tests (7 crash points).
3. Verify the recovery contract for each crash point.

## 14. References

- v0.262 Python reference: `tidefs_io/pool_commit_group_io.py` (pool-side commit_group batching)
- v0.262 Python reference: `tidefs_core/cluster_commit_group.py` (cluster commit_group)
- v0.262 Python reference tests: `tests/test_commit_group.py`
- ZFS commit_group model: `SPA` syncing context, `dsl_pool_sync_context`, `commit_group_list`
- Issue #1267: Canonical commit ordering and multi-phase commit_group state machine
- #1190: G2 transaction model (durability contract)
- #1252: Intent log / LOG_DEVICE for sync writes
- #1224: Torn-commit recovery
- #1230: Crash injection harness
- #1241: CommitGroup sync scheduling in CONTROL lane
- `docs/IMPLEMENTATION_IMPLICATIONS.md` for general implementation constraints
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` for flow classes and
  distributed write ordering
