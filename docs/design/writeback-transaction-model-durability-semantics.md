# writeback, transaction model, and durability semantics

**Issue**: [#1190](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1190)
**Status**: spec-draft
**Maturity**: formal design — defines the layer between user-visible I/O and the commit_group commit pipeline
**Lane**: storage-core
**Hard-gate**: yes
**Depends on**: #1267 (commit_group state machine), #1252 (intent log + LOG_DEVICE), #1224 (torn-commit recovery)

## 1. Problem statement

The commit_group state machine (#1267) defines the commit pipeline but does not define what feeds
it. Without an explicit writeback model, dirty pages accumulate without accounting,
fsync/O_DSYNC semantics are undefined, and the intent log (#1252) has no prescribed
integration point. ZFS solves this with its object_store_tx + ZIL architecture; tidefs needs its
own contract that is narrower, explicit, and directly composable with the existing
commit_group state machine.

The v0.262 Python reference (`pool_transactions_io.py`, `pool_durability_io.py`,
`pool_commit_group_io.py`) implements slice-0 transaction grouping and durability ack levels
but defers the full writeback pipeline (G2 in `REALITY_CHECK.md`). This design fills
that gap.

## 2. Scope

### In scope

- Dirty buffer lifecycle: tracking, accounting, and lifecycle of in-memory dirty state
  across inodes, directories, extent maps, and catalog records
- Transaction model: explicit begin/commit/abort with staged-root isolation
- fsync/O_DSYNC/O_SYNC semantics: per-file, per-directory, and data-only durability
  guarantees mapped to intent-log and commit_group-commit paths
- Intent log role: how the intent log (#1252) provides low-latency sync-write
  acknowledgement before bulk commit_group commit
- Durability contract: what each I/O path guarantees, when data is safe, and what
  the crash recovery contract (#1224) requires
- Wire-up diagram: how the four subsystems (writeback, transaction, intent log, commit_group)
  compose at runtime

### Out of scope

- Distributed (cluster) commit_group commit (separate distributed-commit_group design)
- Torn-commit recovery specifics (covered by #1224)
- log device format / on-media layout (covered by #1252)
- Checksum architecture (covered by #1287)
- mmap writeback coherency (covered by #1259)

## 3. Architecture overview

Four subsystems compose the full write path:

```
 user write(2) / fsync(2) / O_DSYNC
           │
           ▼
   ┌──────────────────┐
   │  Writeback Layer  │  ← dirty-byte accounting, buffer lifecycle
   │  (this design)    │
   └────────┬─────────┘
            │
     ┌──────┴──────┐
     │             │
     ▼             ▼
┌──────────┐  ┌──────────────┐
│Intent Log│  │Transaction   │
│(#1252)   │  │Model (explicit│
│sync-write│  │begin/commit/  │
│fast path │  │abort)         │
└────┬─────┘  └──────┬───────┘
     │               │
     └───────┬───────┘
             ▼
   ┌──────────────────┐
   │  CommitGroup State Machine│  ← OPEN/QUIESCE/SYNC, 7-step commit pipeline
   │  (#1267)          │
   └──────────────────┘
```

The writeback layer is the single source of truth for "what is dirty." It tracks dirty
state at per-inode granularity and accounts dirty bytes across data extents, metadata
records, and catalog mutations. The commit_group state machine (#1267) reads dirty accounting
from the writeback layer when evaluating auto-sync triggers. The intent log (#1252)
provides a low-latency sync-write path for fsync/O_DSYNC: the log entry is written and
acknowledged immediately, while the bulk data+metadata lands in the next commit_group commit.

## 4. Dirty buffer lifecycle

### 4.1 Dirty-state taxonomy

Every mutation to a filesystem object falls into exactly one of three dirty categories:

| Category | Examples | Accounting unit |
|---|---|---|
| **Data** | write(2) to a regular file, truncate that changes extent map | bytes written to data SegmentStore |
| **Metadata** | inode attribute updates, directory entry insert/remove, snapshot create/delete | count of dirty inodes + dirty directory entries |
| **Catalog** | derived-catalog rebuild, pool-map update | flag: catalog-dirty (binary) |

Categories are tracked separately because they drive different durability paths:
- **Data-only dirty**: triggers data+metadata commit (steps 1-7)
- **Metadata-only dirty**: triggers metadata-only commit (steps 3-7)
- **Catalog dirty**: always forces pool-map commit with metadata commit
- **None dirty**: no-op — `do_commit()` returns immediately (unless intent log is
  non-empty)

### 4.2 Per-inode dirty tracking

Each inode in the in-memory `FileSystemState` carries dirty-state flags:

```rust
// Conceptual — not the actual struct definition
struct InodeDirtyState {
    /// Set when write(2) or truncate(2) modifies data extents.
    data_dirty: bool,
    /// Set when attributes change (mode, owner, timestamps, size from truncate).
    attr_dirty: bool,
    /// Set when xattrs are modified.
    xattr_dirty: bool,
    /// Set when the inode is newly created and not yet committed.
    is_new: bool,
    /// Cumulative dirty byte count since last commit (padded record bytes).
    dirty_bytes: u64,
}

struct DirectoryDirtyState {
    /// Set when entries are added, removed, or renamed.
    entries_dirty: bool,
    /// Number of entry mutations since last commit.
    dirty_entry_count: u64,
}
```

The writeback layer maintains a dirty-set index:

```rust
struct DirtySet {
    dirty_inodes: BTreeSet<InodeId>,       // inodes with any dirty flags
    dirty_dirs: BTreeSet<InodeId>,          // directories with dirty entries
    dirty_bytes_data: u64,                  // total data dirty bytes
    dirty_bytes_metadata: u64,              // estimated metadata dirty bytes
    catalog_dirty: bool,                    // catalog needs pool-map commit
    dirty_op_count: u64,                    // total mutation count
}
```

### 4.3 Dirty accounting on write

When `write(2)` is called:

1. Allocate/update extent records in the data SegmentStore (step 1 of commit pipeline,
   but done eagerly during write — see §6 "Intent log role")
2. Increment `dirty_bytes_data` by the padded record size
3. Set `data_dirty = true` on the inode
4. Add inode to `dirty_inodes`
5. Increment `dirty_op_count`

When `mkdir(2)` / `rename(2)` / `unlink(2)` is called:

1. Modify in-memory directory state
2. Set `entries_dirty = true` on the parent directory
3. Add parent directory to `dirty_dirs`
4. Create/modify the target inode (for mkdir), set `is_new = true` or `attr_dirty = true`
5. Increment `dirty_op_count`

When attributes are changed (chmod, chown, utimes):

1. Modify in-memory inode
2. Set `attr_dirty = true`
3. Add inode to `dirty_inodes`
4. Increment `dirty_op_count`

### 4.4 Dirty clearing

Dirty state is cleared only after a successful SYNC phase completes. The commit_group state
machine's `complete_sync()` resets the dirty-set index to empty state. Between writes
and the next commit_group sync, dirty state accumulates monotonically.

### 4.5 Dirty-state read visibility

While a commit_group is OPEN or in QUIESCE, reads must see the latest dirty state. This is
already the case in the current architecture — `FileSystemState` holds the
authoritative in-memory state and is mutated in place. Reads consult `self.state`
directly. The commit_group sync phase writes a snapshot of the current state; reads during
SYNC continue to see the in-memory state (the snapshot is for persistence, not
isolation).

## 5. Transaction model

### 5.1 Explicit transactions (user-facing)

TideFS supports explicit transactions — a sequence of mutations grouped into an
atomic unit. This is the analogue of ZFS's "transaction group" at the application
layer, distinct from the internal commit_group commit group.

```rust
// Conceptual API
impl LocalFileSystem {
    /// Begin an explicit transaction.
    /// Captures the current committed generation as the baseline.
    /// Returns an error if a transaction is already active.
    pub fn begin_transaction(&mut self) -> Result<()>;

    /// Commit the transaction: publish all staged mutations as a single commit_group commit.
    /// This forces an immediate commit_group sync (quiesce → sync → complete).
    pub fn commit_transaction(&mut self) -> Result<()>;

    /// Abort the transaction: discard all mutations made since begin_transaction.
    /// Restores state to the pre-transaction snapshot.
    pub fn abort_transaction(&mut self) -> Result<()>;
}
```

### 5.2 Transaction isolation

During a transaction:

1. **Mutations are staged in the in-memory state** — they are not published to the
   commit_group sync pipeline until commit.
2. **Reads within the transaction see the staged state** — the transaction provides
   read-your-writes visibility.
3. **External readers (other file descriptors, other processes) see the
   pre-transaction state** — this is the natural COW property: the checkpoint
   pointer still points to the pre-transaction committed root.
4. **No auto-sync triggers fire during a transaction** — the commit_group state machine's
   `should_quiesce()` check is suppressed. The caller controls when durability
   happens.
5. **Intent log entries accumulated during a transaction are held** — they are
   flushed as part of the transaction commit.

### 5.3 Transaction commit path

```
begin_transaction()
    snapshot = current committed generation
    self.in_transaction = true

    ... mutations accumulate in self.state ...

commit_transaction()
    1. self.in_transaction = false
    2. Flush intent log entries accumulated during transaction
    3. Force commit_group quiesce (skip trigger evaluation)
    4. Force commit_group sync (full 7-step pipeline)
    5. Publish new checkpoint pointer
    6. Clear dirty-set index
    7. Return

abort_transaction()
    1. self.in_transaction = false
    2. Restore self.state from pre-transaction snapshot
    3. Discard intent log entries accumulated during transaction
    4. Clear dirty-set index
    5. Return
```

### 5.4 Interaction with auto-sync commit_group

When no explicit transaction is active, the system operates in **auto-sync mode**:
the commit_group state machine's trigger hierarchy drives commit timing. Writes are grouped
implicitly by the auto-sync thresholds (op count, byte count, time). This is the
normal operating mode for most workloads and is equivalent to ZFS's default commit_group
syncing.

## 6. fsync / O_DSYNC / O_SYNC semantics

### 6.1 Durability levels

Three durability levels map to POSIX fsync family semantics:

| Level | POSIX call | Guarantee |
|---|---|---|
| **Full sync** | `fsync(fd)` | File data + metadata durable |
| **Data-only sync** | `fdatasync(fd)` | File data durable; metadata only if needed for retrieval |
| **Directory sync** | `fsync(dirfd)` | Directory entry durable (new file name visible after crash) |

### 6.2 Intent log fast path

For low-latency sync writes, the intent log (#1252) provides a fast path:

```
user calls fsync(fd)
    │
    ▼
writeback layer identifies dirty inode(s) for this fd
    │
    ▼
intent_log.append(SyncWriteRange { inode_id, offset, len, data_digest })
    │
    ▼
intent_log.flush_and_sync()       ← fsync to LOG_DEVICE if configured, else to main store
    │
    ▼
return to user (acknowledged)
    │
    │  ... time passes ...
    ▼
next commit_group sync: intent log entries replayed against committed state
    │
    ▼
checkpoint pointer updated
```

The key property: the user's fsync returns as soon as the intent log entry is
durable, without waiting for the full commit_group commit pipeline. The actual data and
metadata land in the commit_group commit asynchronously. On crash recovery, the intent log
is replayed before any new writes are accepted.

### 6.3 Intent log entry types

Per #1252, the intent log supports these entry types relevant to sync semantics:

| Entry kind | Triggered by | Contents |
|---|---|---|
| `SyncWriteRange` | `fsync(fd)` / `fdatasync(fd)` with dirty data | `inode_id`, byte range, data checksum, data payload ref |
| `OdsyncDataRange` | `write(2)` with `O_DSYNC` | Same as `SyncWriteRange` |
| `SharedMmapMsync` | `msync(2)` on shared mapping | `inode_id`, page-aligned range |
| `NamespaceSyncIntent` | `fsync(dirfd)` on directory | `parent_inode_id`, entry name, operation (add/remove/rename) |

### 6.4 fsync without intent log

If the intent log is disabled or the log device is not configured, fsync falls
back to the **forced commit_group sync path**:

```
fsync(fd) without intent log:
    1. Mark target inode(s) as requiring forced durability
    2. Force quiesce the current commit_group
    3. Execute full 7-step commit pipeline (DurabilityClass::ForcedDurability)
    4. Return to user after checkpoint pointer update
```

This is higher latency but provides identical durability guarantees. ZFS calls
this the "ZIL bypass" path and uses it when the ZIL is on the same device as the
main pool.

### 6.5 File-descriptor scope for fsync

`fsync(fd)` must be scoped to the specific file, not the entire pool. The
implementation:

1. Collect all dirty inodes reachable from `fd`
2. For data extents: write only the extents belonging to this inode (step 1 of
   commit pipeline), flush only the data SegmentStore (step 2)
3. For metadata: write only this inode's metadata record and any dirty parent
   directory entries (step 3)
4. Steps 4-7 proceed normally (commit record + checkpoint pointer)

This is a **scoped sync** — it does not force unrelated dirty state through the
pipeline. Other dirty inodes remain in the current commit_group for the next auto-sync.

### 6.6 Rename atomicity and fsync

Per POSIX (and issue #1205), `rename(2)` is atomic with respect to crashes: after
a crash, either the old name or the new name exists, never both, never neither.
For fsync-after-rename:

1. `fsync(new_parent_dirfd)` must ensure the rename entry is durable
2. If the renamed file had dirty data, `fsync(fd)` on the renamed file must ensure
   that data is durable under the new name
3. The intent log's `NamespaceSyncIntent` captures the rename atomically

## 7. Intent log integration (§6 of full contract)

### 7.1 Intent log lifecycle in the commit_group pipeline

The intent log participates in the commit_group commit pipeline at three points:

**During OPEN phase (write admission):**
- Sync-write entries are appended to the intent log immediately
- `intent_log.flush_and_sync()` is called for each sync write
- The commit_group state machine's `dirty_bytes` and `dirty_ops` are NOT incremented for
  intent-log-only writes (the intent log is the source of truth, not the dirty-set
  index)

**At QUIESCE boundary:**
- `intent_log.flush_if_needed()` drains any pending entries
- In-flight intent log entries are counted toward the quiesce decision
  (`inflight_writes` in the commit_group state machine)

**During SYNC phase:**
- Intent log entries are replayed against the committed state before the commit
  record is written (step 3 of the metadata pipeline)
- After successful replay, intent log entries are cleared from the log
- The cleared entries' data is now committed via the normal commit_group path

**On crash recovery (mount):**
- Intent log is loaded from the log device (or main store if no LOG_DEVICE)
- `intent_log.replay_entries_against_state()` applies all durable entries
- If replay succeeds, the intent log is cleared and mount proceeds
- If replay fails (missing data payload), mount is refused — the intent log is the
  authoritative record of acknowledged writes

### 7.2 Intent log flush triggers

The intent log flushes to durable storage at these boundaries:

| Trigger | What flushes | Latency |
|---|---|---|
| `fsync(fd)` / `fdatasync(fd)` | All entries for this fd | Low (LOG_DEVICE) or Medium (main store) |
| `sync_all()` | All pending entries | Medium |
| `O_DSYNC` write completion | This write's entry | Lowest |
| Adaptive flush interval (100ms default) | All pending entries | Background |
| Pending entry count >= `max_pending_entries` (64 default) | All pending entries | Background |
| Transaction commit | All entries in transaction scope | Medium |

### 7.3 log device selection

Per #1252, the log device is an optional separate fast device (NVMe, Optane, or
battery-backed DRAM). When configured:

- Intent log entries are written to the log device first (with fsync)
- Entries are acknowledged to the caller after LOG_DEVICE fsync
- A background task replicates entries from LOG_DEVICE to the main object store
- On crash recovery, log device is the authoritative source; main-store copies are

When not configured, intent log entries are written directly to the main object
store's metadata SegmentStore.

## 8. Durability contract

### 8.1 What "durable" means

A mutation is **durable** when it survives an OS crash (kernel panic, power loss)
and is visible after the filesystem remounts. "Durable" explicitly does NOT mean:

- Surviving media failure (that's the replication/erasure-coding layer — #1286, #1249)
- Surviving filesystem bugs (that's the verification layer — #1287, #1288)
- Being visible to other nodes in a cluster (that's the distributed-commit_group contract)

### 8.2 Durability guarantees by operation

| Operation | Durability path | When acknowledged | Crash recovery guarantee |
|---|---|---|---|
| `write(2)` (normal) | Auto-sync commit_group | After next commit_group sync completes | Writes since last commit_group sync may be lost |
| `write(2)` + `O_DSYNC` | Intent log fast path | After intent log entry flushed | Replayed from intent log on mount |
| `write(2)` + `fsync(fd)` | Intent log fast path (or forced commit_group if no intent log) | After intent log entry flushed | Replayed from intent log on mount |
| `fdatasync(fd)` | Intent log fast path (data only) | After data intent log entry flushed | Data replayed; metadata from last commit_group |
| `mkdir(2)` | Auto-sync commit_group | After next commit_group sync | Lost if crash before sync |
| `mkdir(2)` + `fsync(parent)` | Intent log `NamespaceSyncIntent` (or forced commit_group) | After intent log entry flushed | Replayed from intent log |
| `rename(2)` | Auto-sync commit_group | After next commit_group sync | Atomic: old or new name, never both |
| `rename(2)` + `fsync(parent)` | Intent log `NamespaceSyncIntent` | After intent log entry flushed | Replayed from intent log |
| `unlink(2)` | Auto-sync commit_group | After next commit_group sync | Lost if crash before sync |
| `truncate(2)` | Auto-sync commit_group | After next commit_group sync | Lost if crash before sync |
| `sync_all()` | Forced commit_group sync | After full 7-step pipeline + checkpoint update | Everything durable |

### 8.3 Durability ack levels (per-dataset, from Python reference)

The Python reference defines per-dataset durability ack levels (`pool_durability_io.py`
`set_dataset_durability`). These control the replication factor for extent writes:

| Ack level | Meaning | When adopted in Rust |
|---|---|---|
| 3 (prior-generation) | Extent-data records, no replication | Immediate |
| 4 | Replicated ingest records (EXTENT_INGEST_V1) | After per-dataset replication design |
| 5 | Base redundancy satisfied at commit (EXTENT_BASE_SHARD_V1) | After erasure-coding design (#1249) |

For the initial Rust implementation, all datasets operate at ack level 3 (prior-generation).
Level 4 and 5 are gated on the distributed replication and erasure coding designs
respectively.

## 9. Recovery contract

### 9.1 Mount-time state resolution

On mount, the filesystem resolves its state in this order (already implemented in
`load_latest_committed_state`):

1. Read the newest valid checkpoint pointer from the system area (slice-0)
3. Load the metadata root (inodes, directories, catalogs)
4. Load the intent log
5. Replay intent log entries against the loaded state
6. If replay produces a consistent state, clear the intent log and proceed
7. If replay fails or the checkpoint pointer is corrupt, fall back to journal
   scanning (torn-commit recovery, per #1224)

### 9.2 Crash-at-each-step analysis

The commit_group state machine design (#1267, §8) already includes a crash-at-each-step
analysis for the 7-step commit pipeline. The writeback and intent-log layers add
two new crash points:

**Crash during intent log append (before flush):**
- Intent log entry is in memory only → lost
- Caller receives I/O error (write failed)
- No recovery needed — the entry was never acknowledged

**Crash after intent log flush but before commit_group sync:**
- Intent log entry is durable on LOG_DEVICE/main store
- CommitGroup state (dirty inodes, extent maps) may be lost
- Recovery: intent log replay reconstructs the missing state
- If replay succeeds, mount proceeds with the reconstructed state
- If replay fails (e.g., LOG_DEVICE corruption, missing data payload), mount is refused

**Crash during intent log replay on mount:**
- Partial replay: some entries applied, some not
- The intent log's replay is idempotent — entries carry enough context to detect
  already-applied state
- If a replayed entry's checksum doesn't match the stored data, the entry is
  skipped and the event is logged
- If any entry fails irrecoverably, mount is refused

## 10. Implementation plan (Rust)

### 10.1 New crate/module layout

```
crates/tidefs-local-filesystem/src/
    commit_group.rs              ← already implemented (#1267)
    intent_log.rs       ← already implemented (#1252)
    writeback.rs        ← NEW: DirtySet, InodeDirtyState, writeback accounting
    transaction.rs      ← NEW: TransactionGuard, begin/commit/abort
    sync.rs             ← NEW: fsync/fdatasync/O_DSYNC dispatch
```

### 10.2 Key types (type sketches)

```rust
// writeback.rs

pub(crate) struct DirtySet {
    pub data_bytes: u64,
    pub metadata_ops: u64,
    pub dirty_inodes: BTreeSet<InodeId>,
    pub dirty_dirs: BTreeSet<InodeId>,
    pub catalog_dirty: bool,
}

impl DirtySet {
    pub fn is_clean(&self) -> bool { ... }
    pub fn clear(&mut self) { ... }
    pub fn durability_class(&self) -> DurabilityClass { ... }
}

// transaction.rs

pub struct TransactionGuard<'fs> {
    fs: &'fs mut LocalFileSystem,
    committed: bool,
}

impl<'fs> TransactionGuard<'fs> {
    pub fn commit(self) -> Result<()> { ... }
    pub fn abort(self) -> Result<()> { ... }
}

impl<'fs> Drop for TransactionGuard<'fs> {
    fn drop(&mut self) {
        if !self.committed {
            // Auto-abort on drop without explicit commit
            let _ = self.abort_inner();
        }
    }
}

// sync.rs

pub(crate) enum SyncScope {
    File(InodeId),
    Directory(InodeId),
    All,
    DataOnly(InodeId),
}

impl LocalFileSystem {
    pub fn fsync_file(&mut self, path: &str) -> Result<()>;
    pub fn fsync_data_only(&mut self, path: &str) -> Result<()>;
    pub fn fsync_directory(&mut self, path: &str) -> Result<()>;
    pub fn sync_all(&mut self) -> Result<()>;
}
```

### 10.3 Integration points with existing code

1. **`LocalFileSystem::do_commit()`** — already wired to `CommitGroupStateMachine`. Add
   `DirtySet` check at entry: if clean and intent log empty, return immediately.
2. **`LocalFileSystem::write_file()` / `create_file()` / etc.** — add calls to
   `DirtySet::record_data_write()` / `DirtySet::record_metadata_op()`.
3. **`LocalFileSystem::fsync_file()`** — new method, dispatches to intent log fast
   path or forced commit_group sync per §6.
4. **`LocalFileSystem::begin_transaction()` / `commit_transaction()` /
   `abort_transaction()`** — new methods implementing §5.
5. **`load_latest_committed_state()`** — already replays intent log. No changes
   needed for this design.

### 10.4 Test plan

1. **Dirty accounting unit tests**: verify byte counts, op counts, dirty flags
   after write/mkdir/unlink/rename operations
2. **Transaction isolation tests**: verify that reads within a transaction see
   staged changes, external reads see pre-transaction state, abort restores
   correctly
3. **fsync semantics tests**: verify that fsync-after-write survives simulated
   crash (kill -9), verify that data written without fsync may be lost
4. **O_DSYNC write tests**: verify that each O_DSYNC write is durable
   independently
5. **Intent log replay tests**: corrupt LOG_DEVICE entries, verify mount refusal;
   truncate LOG_DEVICE, verify partial replay
6. **Auto-sync integration tests**: write N bytes, wait for auto-sync trigger,
   verify durability without explicit fsync

## 11. References

- Python reference: `tidefs_io/pool_commit_group_io.py` (549 lines), `tidefs_io/pool_transactions_io.py`,
  `tidefs_io/pool_durability_io.py`
- Issue #1267: Canonical commit ordering and commit_group state machine (design + implementation)
- Issue #1252: Intent log and log device design spec
- Issue #1224: Torn-commit recovery contract
- Issue #1205: Rename atomicity spec
- Issue #1259: mmap cluster coherency (for msync semantics)
- POSIX: `fsync(2)`, `fdatasync(2)`, `open(2)` O_DSYNC/O_SYNC
- ZFS: ZIL (ZFS Intent Log), commit_group commit, object_store_tx
