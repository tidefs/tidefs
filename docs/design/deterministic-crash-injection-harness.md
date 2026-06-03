# Deterministic Crash/Fault Injection Harness — Design Specification

**Issue**: [#1230](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1230)
**Status**: design-spec
**Priority**: P2
**Depends on**: #1267 (commit_group state machine), #1174 (trace oracle), #1175 (cluster simnet)

## Abstract

The crash injection harness provides deterministic, repeatable fault injection
trigger a controlled crash at precise points in the write path — across commit_group
lifecycle boundaries, filesystem operations, and background services. After
each crash, the daemon restarts, runs mount-time recovery, and asserts that all
invariants hold.

This design extends the existing `CrashInjectionBoundary` infrastructure (11
object-pipeline boundaries, currently in `types.rs`) with three new hook
families mapped to the seven-step canonical commit ordering (#1267) and the
multi-phase commit_group state machine.

---

## 1. Architecture Overview

### 1.1 Three-layer hook taxonomy

```
Layer 1: COMMIT_GROUP Lifecycle — phase transitions + 7-step commit boundaries
Layer 2: Operation — per-POSIX-op injection (rename, unlink, write, fsync, etc.)
Layer 3: Background Service — cleaner, GC, snap destroy, job progress
```

### 1.2 Relationship to existing infrastructure

The existing `CrashInjectionBoundary` enum (11 variants) covers object-level
boundaries in the persistence pipeline: content objects, transaction inodes,
directories, superblock, root commit write, and root commit sync. This design
preserves those boundaries and adds hooks at semantic levels above them — commit_group
phase transitions, individual operations, and background service checkpoints.

The existing `inject_next_sync_failure_after_boundary()` mechanism in
`persistence.rs` injects faults at `FilesystemCommitBoundary` points. The new
harness extends this with named hook registration, counting for deterministic
trigger ordering, and replay integration with the trace oracle.

---

## 2. Named Injection Hooks

### 2.1 COMMIT_GROUP Lifecycle Hooks

Mapped to the seven-step canonical commit ordering from #1267 and the commit_group state
machine's Open/Quiesce/Sync phases.

| Hook ID | Trigger Point | Phase | Step |
|---|---|---|---|
| `COMMIT_GROUP_BEFORE_OPEN` | Before entering new Open phase | Open→Open | — |
| `COMMIT_GROUP_AFTER_RECORD_WRITE` | After `record_write()` accumulates bytes | Open | ~1 |
| `COMMIT_GROUP_BEFORE_QUIESCE` | Before `begin_quiesce()` — writes rejected for current commit_group | Open→Quiesce | — |
| `COMMIT_GROUP_AFTER_QUIESCE` | After inflight writes drained | Quiesce | — |
| `COMMIT_GROUP_BEFORE_SYNC` | Before `begin_sync()` | Quiesce→Sync | 1 done |
| `COMMIT_GROUP_AFTER_DATA_FLUSH` | After data journal flush (step 2) | Sync | 2 |
| `COMMIT_GROUP_AFTER_METADATA_APPEND` | After metadata appended (step 3) | Sync | 3 |
| `COMMIT_GROUP_AFTER_COMMIT_RECORD` | After commit record appended (step 4) | Sync | 4 |
| `COMMIT_GROUP_AFTER_METADATA_FLUSH` | After metadata journal flush (step 5) | Sync | 5 |
| `COMMIT_GROUP_AFTER_CHECKPOINT` | After checkpoint pointer copies (step 6) | Sync | 6 |
| `COMMIT_GROUP_AFTER_SYSTEM_FLUSH` | After system area flush (step 7) | Sync | 7 |
| `COMMIT_GROUP_AFTER_COMPLETE` | After `complete_sync()`, phase back to Open | Sync→Open | — |

### 2.2 Operation Hooks

| Hook ID | Trigger Point | Operation |
|---|---|---|
| `OP_RENAME_BEFORE_COMMIT` | After dir entries updated, before commit | rename(2) |
| `OP_RENAME_AFTER_SRC_UNLINK` | After src dentry removed (EXCHANGE) | EXCHANGE |
| `OP_UNLINK_BEFORE_FINALIZE` | After nlink→0, before deferred cleanup | unlink(2) |
| `OP_UNLINK_BEFORE_DENTRY_REMOVE` | Before directory entry removed | unlink(2) |
| `OP_WRITE_BEFORE_EXTENT_UPDATE` | After data written, before extent map | write(2) |
| `OP_WRITE_AFTER_EXTENT_UPDATE` | After extent map, before dirty mark | write(2) |
| `OP_FSYNC_BEFORE_FLUSH` | Before flush barrier | fsync(2) |
| `OP_FSYNC_AFTER_DATA_SYNC` | After data sync, before metadata sync | fsync(2) |
| `OP_TRUNCATE_BEFORE_FREE` | Before freeing truncated extents | truncate(2) |
| `OP_CREATE_BEFORE_INODE` | After name reserved, before inode alloc | creat(2) |
| `OP_CREATE_AFTER_INODE` | After inode allocated, before dir entry | creat(2) |
| `OP_LINK_BEFORE_COMMIT` | After dir entry, before mutation commit | link(2) |
| `OP_SNAPSHOT_BEFORE_COMMIT` | After catalog entry, before root commit | snapshot |
| `OP_SNAPSHOT_AFTER_COMMIT` | After root commit, before return | snapshot |

### 2.3 Background Service Hooks

| Hook ID | Trigger Point | Service |
|---|---|---|
| `CLEANER_BEFORE_RELOCATE` | Before relocating live record | Cleaner |
| `CLEANER_AFTER_RELOCATE` | After relocation, before locator update | Cleaner |
| `CLEANER_BEFORE_DEALLOCATE` | Before deallocating old segment | Cleaner |
| `SNAP_DESTROY_BEFORE_DEADLIST` | Before deadlist move | Snap destroy |
| `SNAP_DESTROY_AFTER_DEADLIST` | After deadlist move, before free | Snap destroy |
| `JOB_PROGRESS_BEFORE_PERSIST` | Before persisting job cursor | All jobs |
| `JOB_PROGRESS_AFTER_PERSIST` | After cursor persisted | All jobs |
| `GC_BEFORE_MARK` | Before mark phase | Metadata GC |
| `GC_AFTER_MARK` | After mark, before sweep | Metadata GC |
| `GC_BEFORE_SWEEP` | Before sweeping unreferenced objs | Metadata GC |
| `GC_AFTER_SWEEP` | After sweep, before cursor update | Metadata GC |

---

## 3. Crash-Consistency Invariants

After any controlled crash at any hook, the following invariants must hold:

1. **Atomic rename**: After crash, either old name exists OR new name exists,
   never both (RENAME_NOREPLACE). Target never partially overwritten.

2. **Atomic unlink**: Directory entry is either removed OR still present. Never
   a dangling dentry pointing to a freed inode. nlink matches directory entry
   count for every inode.

3. **nlink consistency**: `st_nlink` equals the actual directory entry count
   for every inode reachable from the root. Zero nlink inodes are either
   absent from the namespace or pending deferred cleanup with a valid job
   cursor.

4. **Fsync contract**: After fsync returns successfully, data written up to
   that point survives the crash. Before fsync completion, data up to the last
   committed commit_group is present (no torn writes for committed commit_groups).

5. **No negative space accounting**: All space counters are non-negative and
   transactionally consistent. Claim ledger tracks allocations against the
   correct commit_group; freed space is either not yet returned or fully accounted.

6. **Job resumability**: Deferred cleanup jobs resume from the last persisted
   cursor position. No work is silently lost; a job may repeat a small amount
   of work (cursor granularity) but must not skip work.

7. **Checkpoint integrity**: Either the previous checkpoint is intact and
   bootable OR the new checkpoint is fully committed — never a torn checkpoint
   with partial metadata and stale pointers.

---

## 4. Harness Design

### 4.1 Hook registration and counting

Hooks are registered at test startup via a `CrashTestConfig` that lists which
hook IDs are armed and, for each, which occurrence (1st, 2nd, …, Nth) triggers
the crash. This allows testing the Nth time a hook is hit within a workload
rather than only the first time.

```rust
pub struct CrashTestConfig {
    /// Armed hooks: map of hook_id → occurrence number to crash on.
    pub armed_hooks: BTreeMap<CrashHookId, u64>,
    /// Whether to SIGKILL (default: true) or simulate power loss.
    pub crash_mode: CrashMode,
    /// Seed for deterministic workload replay.
    pub seed: u64,
}

pub enum CrashMode {
    /// SIGKILL the process.
    Sigkill,
    /// Simulate power loss: exit with special code, discard in-memory state.
    PowerLoss,
}
```

### 4.2 Controlled crash protocol

1. **Hook fires**: The daemon reaches a registered hook point and decrements
   the occurrence counter. When counter reaches zero, the crash triggers.

2. **Crash**: Depending on `CrashMode`, the daemon either receives SIGKILL
   (process vanishes) or performs an immediate, ungraceful exit that discards
   all in-flight buffers and pending writes (simulating power loss).

3. **Restart**: The test harness restarts the daemon. Mount-time recovery runs:
   root-slot scanning selects the latest valid committed root, intent log
   replay applies acknowledged but uncommitted writes, and the filesystem
   reaches a consistent state.

4. **Verification**: The harness asserts every crash-consistency invariant
   against the recovered filesystem state.

5. **Repeatability**: Same hook + same seed + same workload → same recovery
   outcome. The harness records the result (pass/fail, observed root, observed
   errors) in a structured report.

### 4.3 Determinism and integration with trace oracle

The harness uses a fixed random seed for workload generation, a fixed clock
(via `FixedClock` from commit_group.rs), and hook counters that advance strictly. This
ensures deterministic replay.

Integration with the trace oracle (#1174) means each crash test emits a JSONL
trace of all VfsEngine-boundary calls and their results. The trace can be
replayed against an alternative implementation (different OS, different

### 4.4 Rust implementation sketch

```rust
// In crates/tidefs-local-filesystem/src/crash_hooks.rs (new)

use std::collections::BTreeMap;

/// Stable string identifier for every hook point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrashHookId {
    // COMMIT_GROUP lifecycle
    CommitGroupBeforeOpen,
    CommitGroupAfterRecordWrite,
    CommitGroupBeforeQuiesce,
    CommitGroupAfterQuiesce,
    CommitGroupBeforeSync,
    CommitGroupAfterDataFlush,
    CommitGroupAfterMetadataAppend,
    CommitGroupAfterCommitRecord,
    CommitGroupAfterMetadataFlush,
    CommitGroupAfterCheckpoint,
    CommitGroupAfterSystemFlush,
    CommitGroupAfterComplete,
    // Operation
    OpRenameBeforeCommit,
    OpRenameAfterSrcUnlink,
    OpUnlinkBeforeFinalize,
    OpUnlinkBeforeDentryRemove,
    OpWriteBeforeExtentUpdate,
    OpWriteAfterExtentUpdate,
    OpFsyncBeforeFlush,
    OpFsyncAfterDataSync,
    OpTruncateBeforeFree,
    OpCreateBeforeInode,
    OpCreateAfterInode,
    OpLinkBeforeCommit,
    OpSnapshotBeforeCommit,
    OpSnapshotAfterCommit,
    // Background service
    CleanerBeforeRelocate,
    CleanerAfterRelocate,
    CleanerBeforeDeallocate,
    SnapDestroyBeforeDeadlist,
    SnapDestroyAfterDeadlist,
    JobProgressBeforePersist,
    JobProgressAfterPersist,
    GcBeforeMark,
    GcAfterMark,
    GcBeforeSweep,
    GcAfterSweep,
}

impl CrashHookId {
    pub fn stable_id(self) -> &'static str {
        match self {
            // COMMIT_GROUP
            Self::CommitGroupBeforeOpen => "commit_group-before-open",
            Self::CommitGroupAfterRecordWrite => "commit_group-after-record-write",
            Self::CommitGroupBeforeQuiesce => "commit_group-before-quiesce",
            Self::CommitGroupAfterQuiesce => "commit_group-after-quiesce",
            Self::CommitGroupBeforeSync => "commit_group-before-sync",
            Self::CommitGroupAfterDataFlush => "commit_group-after-data-flush",
            Self::CommitGroupAfterMetadataAppend => "commit_group-after-metadata-append",
            Self::CommitGroupAfterCommitRecord => "commit_group-after-commit-record",
            Self::CommitGroupAfterMetadataFlush => "commit_group-after-metadata-flush",
            Self::CommitGroupAfterCheckpoint => "commit_group-after-checkpoint",
            Self::CommitGroupAfterSystemFlush => "commit_group-after-system-flush",
            Self::CommitGroupAfterComplete => "commit_group-after-complete",
            // Operation
            Self::OpRenameBeforeCommit => "op-rename-before-commit",
            Self::OpRenameAfterSrcUnlink => "op-rename-after-src-unlink",
            Self::OpUnlinkBeforeFinalize => "op-unlink-before-finalize",
            Self::OpUnlinkBeforeDentryRemove => "op-unlink-before-dentry-remove",
            Self::OpWriteBeforeExtentUpdate => "op-write-before-extent-update",
            Self::OpWriteAfterExtentUpdate => "op-write-after-extent-update",
            Self::OpFsyncBeforeFlush => "op-fsync-before-flush",
            Self::OpFsyncAfterDataSync => "op-fsync-after-data-sync",
            Self::OpTruncateBeforeFree => "op-truncate-before-free",
            Self::OpCreateBeforeInode => "op-create-before-inode",
            Self::OpCreateAfterInode => "op-create-after-inode",
            Self::OpLinkBeforeCommit => "op-link-before-commit",
            Self::OpSnapshotBeforeCommit => "op-snapshot-before-commit",
            Self::OpSnapshotAfterCommit => "op-snapshot-after-commit",
            // Background
            Self::CleanerBeforeRelocate => "cleaner-before-relocate",
            Self::CleanerAfterRelocate => "cleaner-after-relocate",
            Self::CleanerBeforeDeallocate => "cleaner-before-deallocate",
            Self::SnapDestroyBeforeDeadlist => "snap-destroy-before-deadlist",
            Self::SnapDestroyAfterDeadlist => "snap-destroy-after-deadlist",
            Self::JobProgressBeforePersist => "job-progress-before-persist",
            Self::JobProgressAfterPersist => "job-progress-after-persist",
            Self::GcBeforeMark => "gc-before-mark",
            Self::GcAfterMark => "gc-after-mark",
            Self::GcBeforeSweep => "gc-before-sweep",
            Self::GcAfterSweep => "gc-after-sweep",
        }
    }
}

thread_local! {
    static CRASH_HOOK_STATE: std::cell::RefCell<Option<CrashHookState>> =
        const { std::cell::RefCell::new(None) };
}

struct CrashHookState {
    armed: BTreeMap<CrashHookId, u64>,
    crash_mode: CrashMode,
    fired_any: bool,
}

pub fn arm_crash_hooks(config: CrashTestConfig) {
    CRASH_HOOK_STATE.with(|state| {
        *state.borrow_mut() = Some(CrashHookState {
            armed: config.armed_hooks,
            crash_mode: config.crash_mode,
            fired_any: false,
        });
    });
}

/// Call at each hook point. Returns normally unless the hook fires,
/// in which case the process is terminated or the crash is triggered.
pub fn check_crash_hook(hook: CrashHookId) {
    CRASH_HOOK_STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(ref mut s) = *state {
            if let Some(count) = s.armed.get_mut(&hook) {
                if *count == 0 {
                    return;
                }
                *count -= 1;
                if *count == 0 {
                    s.fired_any = true;
                    match s.crash_mode {
                        CrashMode::Sigkill => {
                            // SIGKILL self: process vanishes immediately.
                            unsafe { libc::kill(libc::getpid(), libc::SIGKILL); }
                            std::process::abort();
                        }
                        CrashMode::PowerLoss => {
                            // Exit with a distinctive code so the harness
                            // knows this was a controlled crash.
                            std::process::exit(99);
                        }
                    }
                }
            }
        }
    });
}
```

---

## 5. Crash Test Matrix (Minimum V1 Coverage)

Each scenario tests a crash at a specific hook after a deterministic workload.
After restart and recovery, invariants 1-7 from §3 are asserted.

| # | Scenario | Hook | Workload | Key Invariants |
|---|---|---|---|---|
| 1 | Write commit_group crash at each step | All 12 COMMIT_GROUP hooks | Write 64 KiB file, fsync | 4, 5, 7 |
| 2 | Rename atomicity | `OP_RENAME_BEFORE_COMMIT`, `OP_RENAME_AFTER_SRC_UNLINK` | RENAME_NOREPLACE + EXCHANGE | 1, 3 |
| 3 | Unlink with deferred cleanup | `OP_UNLINK_BEFORE_FINALIZE` | Unlink open file, crash, reopen | 2, 3, 6 |
| 4 | Fsync durability | `OP_FSYNC_BEFORE_FLUSH`, `OP_FSYNC_AFTER_DATA_SYNC` | Write, fsync, crash | 4, 5 |
| 5 | Snapshot creation crash | `OP_SNAPSHOT_BEFORE_COMMIT` | Create snapshot mid-write | 5, 7 |
| 6 | Snapshot destroy crash | `SNAP_DESTROY_BEFORE_DEADLIST`, `SNAP_DESTROY_AFTER_DEADLIST` | Destroy snapshot, crash mid-job | 5, 6 |
| 7 | Cleaner relocation crash | `CLEANER_BEFORE_RELOCATE`, `CLEANER_AFTER_RELOCATE`, `CLEANER_BEFORE_DEALLOCATE` | Fill segment, trigger cleaner | 5, 6, 7 |
| 8 | Metadata GC crash | `GC_BEFORE_MARK`, `GC_AFTER_MARK`, `GC_BEFORE_SWEEP` | Create + delete many files, trigger GC | 3, 5, 6 |

---

## 6. Integration With Existing Issues

- **#1267 (commit_group state machine)**: Hooks are placed at every phase transition and
  and back-pressure all survive crashes.
- **#1224 (torn-commit recovery)**: The crash at `COMMIT_GROUP_AFTER_COMMIT_RECORD`
  (step 4) directly tests the journal scanning fallback. Crash at
  `COMMIT_GROUP_AFTER_CHECKPOINT` tests root-slot recovery.
  intent-log-durable writes survive and are correctly replayed on restart.
  that orphan tracking survives and deferred cleanup resumes correctly.
- **#1215 (space accounting)**: Invariant #5 (no negative space) is asserted
  after every crash. Space counters are re-derived from live state.
- **#1174 (trace oracle)**: Each crash test emits a JSONL trace. Cross-
- **#1175 (cluster simnet)**: The deterministic crash harness design mirrors
  simnet's philosophy: seed-driven workloads, fixed clocks, repeatable outcomes.
  transaction model's crash durability contract.

---

## 7. Implementation Ordering

### Phase 1: Core hook infrastructure
- Define `CrashHookId` enum and `CrashTestConfig` in a new module
  `crates/tidefs-local-filesystem/src/crash_hooks.rs`
- Implement `arm_crash_hooks()` and `check_crash_hook()` with
  `thread_local!` state
- Wire hook check calls into commit_group phase transitions in `commit_group.rs`
  (`begin_quiesce`, `begin_sync`, `complete_sync`, etc.)

### Phase 2: Operation hooks
- Wire hook checks into individual filesystem operations in `lib.rs`:
  `rename`, `unlink`, `write_file`, `fsync_file`, `truncate_file`,
  `create_file`, `link`, `create_snapshot`

### Phase 3: Background service hooks
- Wire into cleaner, GC, snapshot destroy, and job progress code paths

### Phase 4: Crash test matrix
- Implement the 8 crash test scenarios as integration tests in
  `tests/crash_injection_tests.rs`
- Each test: arm hooks, run workload, crash, restart, verify invariants

### Phase 5: Trace oracle integration
- Emit JSONL trace records at hook boundaries
- Add cross-implementation replay to the oracle test suite

---

## 8. Open Questions

1. **SIGKILL vs. power loss**: SIGKILL leaves the OS page cache and write-back
   buffers intact (the OS eventually flushes them). True power loss testing
   requires `sync_file_range(SYNC_FILE_RANGE_WAIT_BEFORE)` barriers and
   O_DIRECT verification. For V1, the harness uses SIGKILL with post-crash
   `sync()` to flush any residual kernel buffers.

2. **Cluster crash injection**: This design addresses single-node crashes.
   Multi-node crash injection (e.g., crashing a node mid-replication) is
   tracked in the distributed-commit_group design and cluster simnet (#1175).

3. **Hook granularity vs. performance**: Checking a hook on every write
   operation is acceptable in test mode but must be zero-cost in production.
   The `thread_local!` approach with `Option` ensures hooks are checked only
   when armed (test mode).

4. **Interaction with `CrashInjectionBoundary`**: The existing 11
   `CrashInjectionBoundary` variants operate at the object persistence level
   and use `inject_next_sync_failure_after_boundary`. The new `CrashHookId`
   system operates at the semantic level. Both systems coexist: object-level
   filesystem contract.

---

## Appendix A: Full Hook ID Reference

```
COMMIT_GROUP_BEFORE_OPEN                    COMMIT_GROUP_AFTER_RECORD_WRITE
COMMIT_GROUP_BEFORE_QUIESCE                 COMMIT_GROUP_AFTER_QUIESCE
COMMIT_GROUP_BEFORE_SYNC                    COMMIT_GROUP_AFTER_DATA_FLUSH
COMMIT_GROUP_AFTER_METADATA_APPEND          COMMIT_GROUP_AFTER_COMMIT_RECORD
COMMIT_GROUP_AFTER_METADATA_FLUSH           COMMIT_GROUP_AFTER_CHECKPOINT
COMMIT_GROUP_AFTER_SYSTEM_FLUSH             COMMIT_GROUP_AFTER_COMPLETE

OP_RENAME_BEFORE_COMMIT            OP_RENAME_AFTER_SRC_UNLINK
OP_UNLINK_BEFORE_FINALIZE          OP_UNLINK_BEFORE_DENTRY_REMOVE
OP_WRITE_BEFORE_EXTENT_UPDATE      OP_WRITE_AFTER_EXTENT_UPDATE
OP_FSYNC_BEFORE_FLUSH              OP_FSYNC_AFTER_DATA_SYNC
OP_TRUNCATE_BEFORE_FREE            OP_CREATE_BEFORE_INODE
OP_CREATE_AFTER_INODE              OP_LINK_BEFORE_COMMIT
OP_SNAPSHOT_BEFORE_COMMIT          OP_SNAPSHOT_AFTER_COMMIT

CLEANER_BEFORE_RELOCATE            CLEANER_AFTER_RELOCATE
CLEANER_BEFORE_DEALLOCATE          SNAP_DESTROY_BEFORE_DEADLIST
SNAP_DESTROY_AFTER_DEADLIST        JOB_PROGRESS_BEFORE_PERSIST
JOB_PROGRESS_AFTER_PERSIST         GC_BEFORE_MARK
GC_AFTER_MARK                      GC_BEFORE_SWEEP
GC_AFTER_SWEEP
```

## Appendix B: Relationship to CrashInjectionBoundary

```
CrashInjectionBoundary (existing, 11 variants)
  BeforeContentObjects
  AfterContentObjects
  AfterTransactionInodes
  AfterTransactionDirectories
  AfterTransactionSuperblock
  AfterTransactionObjectsSynced
  AfterMalformedRootCommit
  AfterRootCommitMissingTransaction
  AfterRootCommitWritten
  AfterRootCommitSynced
  NoCrash

CrashHookId (new, 36 variants)
  └── COMMIT_GROUP lifecycle: 12 hooks
  └── Operation: 14 hooks
  └── Background service: 10 hooks
```
