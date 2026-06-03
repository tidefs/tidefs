# metadata engine parallelism: multi-core metadata path, lock sharding, optimistic concurrency, and per-core transaction accumulation

**Issue**: [#1278](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1278)
**Status**: design-draft
**Maturity**: spec-draft — defines the concurrency architecture for metadata operations across the four-level parallelism taxonomy
**Lane**: storage-core
**Depends on**: #1206 (lock service architecture), #1267 (canonical commit_group state machine), #1219 (dataset lifecycle), #1127/#1145 (FUSE daemon), #1179 (background scheduler)
**Related**: #1248 (cluster distributed lock service), #1257 (btree CoW persistence), #1276 (cross-dataset reflink)

## 1. Problem statement

Filesystem metadata throughput is the bottleneck that determines interactive responsiveness
for shell workloads (`ls`, `find`, `tar`, `cp -r`, `rm -rf`, `git status`). The
dominant open-source filesystems handle metadata parallelism poorly:

- **Ceph MDS**: Effectively single-threaded for namespace operations within a subtree.
  Static multi-MDS partitioning is brittle and requires manual balancing. Achieves
  ~10-50K metadata ops/sec regardless of core count.
- **ZFS ZPL**: Serial commit_group sync. Single-threaded metadata write path per dataset. Reads
  can be concurrent but writes serialize on the commit_group sync thread.

TideFS must design for metadata multi-core scaling from day one. Retrofitting
parallelism after the metadata path solidifies around a single-threaded assumption
is a known failure mode (Ceph's multi-MDS journey took a decade and still doesn't
reach linear scaling).

## 2. Scope and non-scope

### In scope

- Four-level parallelism taxonomy defining the lock granularity hierarchy
- Lock architecture extending #1206: Pool → Dataset → Directory-inode → Extent
- CommitGroup integration: concurrent OPEN phase, ordered QUIESCE drain, optimistic commit
- Per-worker transaction accumulator design
- CoW B+tree per-thread dirty-node isolation
- Conflict detection protocol: same-directory + same-name → EEXIST at commit
- Lock ordering enforcement to prevent deadlocks
- Integration contracts with commit_group state machine (#1267), lock service (#1206/#1248),
  and FUSE daemon (#1127/#1145)
- Anti-anti-patterns: explicit design decisions that avoid Ceph/ZFS bottlenecks

### Explicitly out of scope

- Data-path parallelism implementation (Level 4 is spec'd here; implementation is
  deferred to extent-map parallelism)
- Cluster-wide distributed lock integration (tracked in #1248; this design defines
  local-node concurrency only)
- Per-core metadata journals (deferred to successor; this design uses a single
  SegmentStore append as the serialization point)
- NUMA-aware thread pinning (deferred to scheduler profile)
- FUSE multiqueue integration (tracked in #1145)
  implementation gate)

## 3. Anti-patterns catalog

These are the known-bad paths this design explicitly avoids.

| Anti-pattern | Source | Why it fails | TideFS alternative |
|---|---|---|---|
| Global namespace lock | Ceph MDS journal | Single-threaded for all namespace ops | Per-directory-inode locks (§4.2) |
| Static subtree partitioning | Ceph multi-MDS | Brittle, manual balancing, hotspot migration | Dynamic lock acquisition per operation |
| Single commit_group sync thread | ZFS ZPL | Metadata writes serialize on one thread | Per-core accumulation + concurrent OPEN (§5) |
| Per-file locking for namespace ops | Naive design | Wrong granularity — creates false contention between create(/a/x) and create(/a/y) | Directory-inode lock + optimistic intra-directory (§4.3) |
| Pre-commit conflict detection | Pessimistic locking | Forces serialization of commutative ops | Optimistic detection at commit_group commit (§6.3) |
| Dataset-scoped exclusive writer lease (as bottleneck) | Phase 1 tidefs | Single writer per dataset; all others read-only | Sharded leases per #1248 + intra-dataset parallelism |

## 4. Four-level parallelism taxonomy

```
Level 1 ─── Per-dataset (zero-cost)
             Different datasets are fully independent.
             Zero shared locks. Zero shared state.

Level 2 ─── Intra-dataset namespace
             Different directories proceed in parallel.
             Directory inode lock is the serialization point.

Level 3 ─── Intra-directory (optimistic)
             Commutative operations in the same directory
             commit in the same commit_group.

Level 4 ─── Data path
             Extent-level locking, never blocked by metadata.
             Metadata ops never block data IO.
```

### 4.1 Level 1 — Per-dataset parallelism

**Zero-cost baseline.** Datasets are fully independent namespaces rooted in separate
dataset roots. Two datasets share no inode space, no directory hierarchy, no lock
domain. Operations on dataset A and dataset B proceed with zero coordination.

This is already the TideFS architecture: each dataset carries its own inode table,
directory tree, and extent map. The lock hierarchy starts at the Dataset level
explicitly to allow this independence.

Concrete example:

```
Thread 0: create(/pool/ds_a/home/user/file.txt)  ─┐
Thread 1: create(/pool/ds_b/projects/README.md)    │  zero shared locks
Thread 2: readdir(/pool/ds_c/archive/)             ─┘
```

All three proceed in parallel with no lock acquisition beyond their respective
dataset handles.

### 4.2 Level 2 — Intra-dataset namespace parallelism

**Directory-inode lock as serialization point.** Within a single dataset, different
directories proceed in parallel. The lock is on the **directory inode itself**, not
on a global namespace lock.

Lock acquisition order within a dataset:

```
Dataset::open(ds_id)
  └── acquire Dataset read lock (shared, for metadata ops)
        └── acquire DirectoryInode lock on parent dir
              └── mutate directory index (create, unlink, rename source/target)
```

Concrete example:

```
Thread 0: create(/pool/ds/a/x.txt)   →  lock directory inode of /pool/ds/a
Thread 1: create(/pool/ds/b/y.txt)   →  lock directory inode of /pool/ds/b
Thread 2: unlink(/pool/ds/c/z.txt)   →  lock directory inode of /pool/ds/c
```

All three proceed in parallel — different directories, no lock conflict.

```
Thread 0: create(/pool/ds/a/x.txt)   →  lock directory inode of /pool/ds/a
Thread 1: create(/pool/ds/a/y.txt)   →  wait on directory inode of /pool/ds/a
```

Thread 1 is serialized behind Thread 0 because they operate on the same parent
directory `/pool/ds/a`. This is correct: the directory index is a single data
structure that must be mutated consistently.

### 4.3 Level 3 — Intra-directory optimistic concurrency

**Commutative same-directory operations commit in the same commit_group.** Within a single
directory, operations that do not conflict on name can commit together. Conflict
detection is optimistic: operations proceed in parallel during the commit_group OPEN phase
using per-thread dirty state, and conflicts are detected at commit_group commit time.

Concrete examples:

```
// Commutative — commit in same commit_group
Thread 0: create(/pool/ds/dir/x.txt)  →  per-thread accumulator A
Thread 1: create(/pool/ds/dir/y.txt)  →  per-thread accumulator B
// At commit: x.txt and y.txt both appear in commit_group N. No conflict.

// Conflicting — detected at commit
Thread 0: create(/pool/ds/dir/x.txt)  →  per-thread accumulator A
Thread 1: create(/pool/ds/dir/x.txt)  →  per-thread accumulator B
// At commit: both try to insert "x.txt". Thread 1 gets EEXIST.

// Read/write parallelism
Thread 0: readdir(/pool/ds/dir/)      →  reads committed snapshot (commit_group N-1)
Thread 1: create(/pool/ds/dir/z.txt)  →  writes to next commit_group (commit_group N)
// No conflict: reads see committed state; writes go to next commit_group.
```

This is the key innovation: TideFS does not pessimistically serialize all operations
on a single directory. Instead, it lets them run in parallel and resolves conflicts
at the commit_group boundary. The directory index structure must support this:

- Reads during the OPEN phase see the **committed snapshot** (commit_group N-1), never
  uncommitted dirty state.
- Creates in the OPEN phase append to a **per-thread dirty entry list** for the
  target directory.
- At QUIESCE → SYNC, the commit path merges all per-thread dirty lists and detects
  name collisions.

### 4.4 Level 4 — Data-path independence

**Extent-level locking, never blocked by metadata.** Data IO (read, write, truncate,
fallocate) locks at extent granularity. A write to file F never blocks a metadata
operation on the directory containing F, and vice versa.

```
Thread 0: write(/pool/ds/dir/bigfile.iso, offset=1GB, len=4KB)
  → lock extent_id=42 (data lock)

Thread 1: create(/pool/ds/dir/newfile.txt)
  → lock directory inode of /pool/ds/dir (metadata lock)

// No conflict: data locks and metadata locks are in different lock domains.
```

The lock ordering prevents deadlock: metadata operations never acquire data locks,
and data operations never acquire metadata locks. The extent lock is the terminal
lock in the lock ordering chain (§4.6).

### 4.5 Lock architecture

Extending #1206, the lock hierarchy is:

```
Pool
  └── Dataset (shared read, exclusive for lifecycle ops)
        └── Directory-inode (per-inode, not global namespace)
              └── Extent (per-extent_id, not per-file)
```

- **Pool lock**: Protects pool-wide state (dataset table, poolmap). Held shared for
  normal operations, exclusive for pool-level reconfiguration.
- **Dataset lock**: Protects dataset-level state (inode table root, space accounting).
  Held shared for all normal metadata and data operations. Held exclusive only for
  lifecycle transitions (destroy, promote).
- **Directory-inode lock**: Protects the directory index (DirIndex) for a single
  directory inode. Held exclusive for mutation (create, unlink, rename), held shared
  for readdir, held shared for lookup.
- **Extent lock**: Protects a single extent (range of bytes within a file). Held
  exclusive for write/truncate, held shared for read.

### 4.6 Lock ordering

Lock acquisition always follows the hierarchy order: 1 → 2 → 3 → 4. No operation
may attempt to acquire a lock at a higher level while holding a lock at a lower
level. This prevents deadlocks by construction.

```
// Valid (top-down):
acquire Pool shared
  acquire Dataset shared
    acquire DirectoryInode(/a) exclusive
      // mutate /a

// Valid (top-down, two directories):
acquire Pool shared
  acquire Dataset shared
    acquire DirectoryInode(/a) exclusive   // first
    acquire DirectoryInode(/b) exclusive   // second (rename /a/x → /b/y)

// NEVER valid (would deadlock):
acquire DirectoryInode(/a) exclusive
  // ... then try to ...
acquire Dataset exclusive   ← DEADLOCK: holding lower lock, acquiring higher
```

For cross-directory operations (rename), locks are acquired on both source and
target directories in inode-ID order (lower inode ID first) to prevent AB-BA
deadlocks.

## 5. CommitGroup integration

This design extends the commit_group state machine defined in #1267 with concurrency
semantics for the OPEN and QUIESCE phases.

### 5.1 Phase semantics

```
                   ┌──────────────────────────────┐
                   │            OPEN                │
                   │  Accept concurrent mutations   │
                   │  from all worker threads.      │
                   │  Each thread accumulates dirty  │
                   │  state locally.                │
                   │  Reads see committed snapshot  │
                   │  (commit_group N-1).                    │
                   └──────────────┬─────────────────┘
                                  │ auto-sync trigger OR
                                  │ explicit commit_group_sync()
                                  ▼
                   ┌──────────────────────────────┐
                   │          QUIESCE               │
                   │  Drain in-flight ops orderly.  │
                   │  No new mutations accepted.    │
                   │  Wait for all threads to       │
                   │  finish current op.            │
                   │  Promote commit_group to SYNCING.       │
                   └──────────────┬─────────────────┘
                                  │
                                  ▼
                   ┌──────────────────────────────┐
                   │           SYNC                 │
                   │  Single-threaded commit.       │
                   │  Merge per-thread accumulators.│
                   │  Detect conflicts.             │
                   │  Append to SegmentStore.       │
                   │  Advance checkpoint pointer.   │
                   └──────────────┬─────────────────┘
                                  │
                                  ▼
                            OPEN (commit_group N+1)
```

### 5.2 OPEN phase concurrency contract

During the OPEN phase:

1. **All worker threads may submit mutations concurrently.** There is no global
   mutex on the mutation path.
2. **Mutations are accumulated in per-thread transaction accumulators.** Each
   worker thread maintains a local `ThreadCommitGroupAccum` holding dirty directory
   entries, dirty inode attributes, and dirty extent map entries.
3. **Reads during OPEN see the committed snapshot** (commit_group N-1 state). A read
   never observes another thread's uncommitted mutations.
4. **The directory-inode lock gates concurrent mutations on the same directory.**
   Two threads creating entries in `/a/` both acquire the directory-inode lock
   for `/a`. They serialize on the lock acquisition, but their mutations go to
   their respective per-thread accumulators — both will be visible in the same
   commit_group commit if they insert different names.
5. **The same-thread lock-hold duration is minimal.** A thread acquires the
   and releases the lock. It does NOT hold the lock across SegmentStore I/O or
   across directory index rebuild.

### 5.3 QUIESCE phase contract

When a commit_group sync is triggered (auto or explicit):

1. **The commit_group state transitions from OPEN to QUIESCE.** This is a non-blocking
   state transition visible to all threads via an atomic flag.
2. **New mutations are rejected** with `CommitGroupError::Quiescing`. Callers retry by
   waiting for the next OPEN phase.
3. **In-flight mutations drain.** The quiesce gate waits for all threads to
   complete their current mutation (each thread checks the quiesce flag at its
   next yield point and reports completion).
4. **After all threads drain**, the commit_group transitions from QUIESCE to SYNC.
   The quiesce phase is bounded by the longest in-flight mutation time.
5. **Mutations that complete before quiesce** are included in the committing commit_group.
   Mutations that arrive during quiesce are deferred to the next commit_group.

### 5.4 Per-thread transaction accumulator

```rust
/// Per-worker-thread transaction accumulator.
///
/// One instance per worker thread, allocated at thread spawn.
/// Accumulates dirty state during the OPEN phase. Flushed to
/// the global commit_group state during SYNC.
struct ThreadCommitGroupAccum {
    /// Thread id (index into worker pool).
    thread_id: u32,

    /// Dirty directory entries, keyed by (directory_inode_id, entry_name_hash).
    /// Vec of inserts: (dir_inode, name, target_inode, entry_type).
    pending_dir_inserts: Vec<(InodeId, Vec<u8>, InodeId, DirEntryType)>,

    /// Dirty directory removals: (dir_inode, name).
    pending_dir_removes: Vec<(InodeId, Vec<u8>)>,

    /// Dirty inode attribute updates.
    pending_inode_updates: Vec<(InodeId, InodeAttr)>,

    /// Dirty extent map entries (data path — Level 4).
    pending_extent_writes: Vec<(ExtentId, ExtentDelta)>,

    /// New inode allocations (inode numbers assigned during OPEN).
    pending_new_inodes: Vec<InodeId>,

    /// CommitGroup id this accumulator belongs to.
    commit_group_id: u64,
}
```

**Flush protocol during SYNC:**

1. The sync thread iterates all `ThreadCommitGroupAccum` instances in thread-ID order
   (deterministic merge).
2. For each directory inode, it collects all `pending_dir_inserts` and
   `pending_dir_removes` across all accumulators.
3. Conflict detection runs on the collected set: same (directory, name) with
   two inserts → EEXIST on the second; insert + remove of same name → the
   remove wins (unlink-before-create ordering).
4. Valid mutations are applied to the committed directory index and written to
   the metadata SegmentStore.
5. All `ThreadCommitGroupAccum` instances are cleared for the next commit_group.

### 5.5 Back-pressure during OPEN

When a thread's local accumulator exceeds a threshold (e.g., 1024 pending entries
or 4 MiB of dirty metadata bytes), the thread yields and signals a sync hint to
the commit_group manager. The commit_group manager may initiate QUIESCE early to prevent unbounded
accumulator growth.

When the global dirty byte count exceeds `commit_group_dirty_max_bytes` (from #1267),
the commit_group manager forces QUIESCE and throttles all writer threads until SYNC
completes.

## 6. Optimistic conflict detection

### 6.1 Detection protocol

Conflict detection runs during the SYNC phase, after all per-thread accumulators
are collected. The algorithm is:

```
For each directory inode D with pending mutations:
  Let committed = committed_dir_index(D)
  Let pending   = union of all per-thread pending_inserts for D
  Let removals  = union of all per-thread pending_removes for D

  For each (name, target_inode) in pending:
    If name exists in removals:
      // Insert after remove: the insert wins.
      // (Removal takes effect first, then insert succeeds.)
      committed.insert(name, target_inode)
    Else if name exists in committed:
      If committed[name].birth_commit_group == current_commit_group:
        // Same name created twice in same commit_group → conflict.
        Return EEXIST to the second creator.
      Else:
        // Name existed before this commit_group → conflict.
        Return EEXIST to the creator.
    Else:
      // No conflict.
      committed.insert(name, target_inode)

  For each name in removals:
    If name not in committed:
      // Unlink of non-existent entry → ENOENT.
      Return ENOENT to the remover.
    Else:
      committed.remove(name)
```

### 6.2 Conflict resolution: first-writer-wins

When two threads create the same name in the same directory during the same commit_group:

1. Both threads pass the per-thread check (name is not in the committed snapshot).
2. Both append to their per-thread accumulators.
3. At SYNC, the deterministic merge processes accumulators in thread-ID order.
4. The first thread's insert (lower thread ID) succeeds.
5. The second thread's insert fails with EEXIST.

The "first writer" is defined by the deterministic merge order, not by wall-clock
time. This is acceptable because the two operations are genuinely concurrent —
neither "happened before" the other in a causal sense. The deterministic tiebreak
ensures repeatable behavior across crashes (when replaying the same commit_group state).

### 6.3 Why optimistic beats pessimistic

A pessimistic approach would require holding the directory-inode lock across the
index insertion. With optimistic concurrency:

  snapshot and accumulator append (~hundreds of nanoseconds).
- Inode allocation is lock-free (per-thread inode number pre-allocation).
- Directory index insertion is deferred to SYNC (single-threaded, but off the
  critical path).

The common case (different names in the same directory) sees near-linear scaling.
The uncommon case (same-name conflict) pays the cost of a failed commit_group-commit attempt,
but this is rare in practice.

## 7. CoW B+tree: per-thread dirty nodes

### 7.1 Design principle

The B+tree (from `tidefs-btree`) is a CoW (copy-on-write) structure. During the
OPEN phase:

- **Each worker thread clones the tree path it needs** from the committed state.
- **Mutations are applied to the thread-local clone.**
- **The committed tree is never mutated in place.**
- **At SYNC, thread-local dirty nodes are merged** into a new committed tree root.

This eliminates shared mutable state on the metadata hot path. No thread ever
waits for another thread to finish mutating a B+tree node.

### 7.2 Per-thread dirty-node table

```rust
/// Per-thread CoW B+tree dirty node set.
///
/// During the OPEN phase, when a thread modifies a directory index,
/// it copies the needed B+tree nodes from the committed tree into
/// this local table. Mutations are applied locally. At commit_group commit,
/// the local nodes are serialized to the metadata SegmentStore.
struct ThreadBtreeDirtySet {
    /// Dirty B+tree nodes, keyed by (directory_inode_id, node_offset_in_tree).
    /// The node_offset is a stable identifier for the logical position
    /// of the node within the directory's B+tree.
    dirty_nodes: Vec<(InodeId, u64, BTreeNode<u64, Vec<DirBtreeLeafEntry>>)>,

    /// Newly allocated locator IDs for dirty nodes that will be persisted.
    pending_locators: Vec<LocatorId>,

    /// CommitGroup this dirty set belongs to.
    commit_group_id: u64,
}
```

### 7.3 Commit-time merge

During SYNC, for each directory with dirty nodes:

1. Collect all `ThreadBtreeDirtySet` entries for the directory.
2. Start from the committed tree root.
3. For each dirty node: if the node's path from root matches the committed tree's
   path at the same offset, replace the committed node with the dirty node.
4. If two threads dirty the same node, the merge follows deterministic thread-ID
   order: thread 0's mutation is applied, thread 1's mutation is re-evaluated
   against the post-merge state.
5. The resulting tree is serialized to the metadata SegmentStore as a new root.

### 7.4 SegmentStore append as serialization point

The metadata SegmentStore append (step 3 of the canonical seven-step commit from
#1267) is the **single serialization point** in the metadata write path. All
per-thread mutable work happens before this point. The append itself is
single-threaded:

1. The sync thread collects all dirty nodes across all threads.
2. It builds a single ordered write batch.
3. It appends the batch to the metadata SegmentStore in one sequential write.
4. The commit record (METADATA_COMMIT_V1) is appended immediately after.

Future optimization: per-core metadata journals that allow each core to append
to its own SegmentStore partition, merged at checkpoint time. This is deferred
to a successor design.

## 8. Worker thread model

### 8.1 Thread pool architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FUSE daemon process                      │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Worker 0 │  │ Worker 1 │  │ Worker 2 │  │ Worker 3 │   │
│  │          │  │          │  │          │  │          │   │
│  │ Accum 0  │  │ Accum 1  │  │ Accum 2  │  │ Accum 3  │   │
│  │ DirtySet │  │ DirtySet │  │ DirtySet │  │ DirtySet │   │
│  │ 0        │  │ 1        │  │ 2        │  │ 3        │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │        │
│       └──────────────┼──────────────┼──────────────┘        │
│                      │              │                       │
│                      ▼              ▼                       │
│              ┌──────────────────────────┐                   │
│              │     CommitGroupManager            │                   │
│              │  (shared, single instance) │                   │
│              │  OPEN / QUIESCE / SYNC    │                   │
│              └──────────────────────────┘                   │
│                      │                                      │
│                      ▼                                      │
│              ┌──────────────────────────┐                   │
│              │     SegmentStore(s)       │                   │
│              └──────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Worker lifecycle

1. **Spawn**: Worker threads are spawned at daemon startup. The number of workers
   is configurable via `metadata_worker_threads` (default: `num_cpus::get()`).
2. **OPEN phase**: Each worker runs a loop accepting FUSE requests from its
   assigned FUSE queue. It accumulates mutations in its `ThreadCommitGroupAccum`.
3. **QUIESCE signal**: The worker checks `commit_group_manager.phase()` at the start of
   each FUSE request. If QUIESCE, it finishes its current request (if any),
   reports drain-complete, and parks.
4. **SYNC phase**: Workers are parked. The sync thread runs commit.
5. **Next OPEN**: Workers are unparked and resume accepting requests.

### 8.3 Thread-local storage contract

Each worker thread owns:

- `ThreadCommitGroupAccum` — mutation accumulator (never shared across threads)
- `ThreadBtreeDirtySet` — CoW node cache (never shared)
- `ReadSnapshot` — pointer to the committed commit_group state for reads (shared, read-only)

No mutable state is shared across worker threads during the OPEN phase. The only
shared mutable state is:

- The commit_group phase flag (atomic `u8`: OPEN=0, QUIESCE=1, SYNC=2)
- The dirty-byte counter (atomic `u64`, for back-pressure)
- The directory-inode locks (for Level 2 serialization)

## 9. Integration with FUSE daemon

### 9.1 FUSE request dispatch

FUSE requests from the kernel arrive via `/dev/fuse`. The daemon reads requests
and dispatches them to worker threads:

```
fuse_session_receive_buf()
  └── parse FUSE opcode
        └── dispatch to least-loaded worker thread
              └── worker acquires locks per hierarchy
                    └── worker performs operation
                          └── worker appends to ThreadCommitGroupAccum
                                └── worker sends FUSE reply
```

With FUSE multiqueue (#1145), each FUSE queue is assigned to a dedicated worker
thread, eliminating the dispatch step.

### 9.2 Read-only operations

Read-only operations (lookup, getattr, readdir, readlink, getxattr, listxattr)
do not acquire exclusive locks:

- `lookup(parent, name)`: acquires directory-inode lock **shared**, reads committed
  snapshot, releases lock.
- `getattr(inode)`: no directory lock; reads inode from committed snapshot.
- `readdir(dir)`: acquires directory-inode lock shared, iterates committed snapshot,
  releases lock.

Read-only operations never block behind write operations (except for the brief
shared-lock acquisition on the directory inode). This is critical for interactive
responsiveness: `ls` in one terminal should not stall behind `tar xf` in another.

### 9.3 Mutating operations

Mutating operations (create, mkdir, unlink, rmdir, rename, link, symlink, mknod,
setattr, write, truncate) follow the lock hierarchy:

1. Acquire directory-inode lock(s) exclusive (in inode-ID order for rename).
3. Append to `ThreadCommitGroupAccum`.
4. Release directory-inode lock(s).
5. Send FUSE reply.

The reply is sent **before** the commit_group commits. This is safe because:

- The mutation is recorded in the thread's accumulator.
- The commit_group will commit (or the system will crash, in which case the reply was
  already sent but the mutation is lost — acceptable for crash semantics).
- If the mutation fails at commit time (conflict), the thread has already sent
  the success reply. The conflict case is rare (same-name create in same commit_group)
  and handled by returning EEXIST on the *subsequent* operation that discovers
  the duplicate, not by retracting the reply.

**Alternative for strict correctness**: Hold the FUSE reply until after commit_group commit.
This adds latency (commit_group sync interval) to every mutating operation. Deferred to
a configurable `sync_on_mutate` mount option.

## 10. Lock service integration (local node)

### 10.1 Relationship to #1248 (cluster lock service)

This design defines **local-node** concurrency. The cluster lock service (#1248)
extends this to **cross-node** concurrency:

| Concept | Local (this design) | Cluster (#1248) |
|---|---|---|
| Directory lock | In-process `RwLock<DirIndex>` | Sharded subtree lease |
| Inode lock | Implicit via directory lock | Per-inode lease token |
| Byte-range lock | Kernel fcntl (local) | Cluster record lock via LOCK service |
| Lock ordering | Pool → Dataset → DirInode → Extent | Same ordering + cross-node lease acquisition |
| Conflict detection | Optimistic at commit_group commit | Lock service based (pessimistic) |

The local-node directory-inode lock is the **foundation** for the cluster sharded
lease: a node that holds a subtree lease for `/a/` uses its local directory-inode
lock to serialize intra-node operations, and the lease prevents other nodes from
mutating the same directory.

### 10.2 Local lock service stubs

During Phase 2 (single-node), directory-inode locks are simple in-process
`RwLock`s. The lock service crate (#1248) will replace these with lease-aware
wrappers that check cluster lease state before granting local locks.

```rust
// Phase 2 (single-node): simple RwLock
type DirInodeLock = RwLock<DirIndex>;

// Phase 3 (cluster): lease-aware wrapper
struct DirInodeLock {
    local: RwLock<DirIndex>,
    lease_state: Arc<ClusterLeaseState>,  // from #1248
}
```

## 11. Background services integration

### 11.1 Background scheduler (#1179)

The background scheduler must be aware of the parallelism model:

- **Background tasks acquire locks at the appropriate level.** A cleanup task
  scanning a directory acquires the directory-inode lock shared. A reclaim task
  freeing extents acquires extent locks exclusive.
- **Background tasks participate in QUIESCE.** When a commit_group enters QUIESCE,
  background tasks drain just like worker threads.
- **Background tasks have their own `ThreadCommitGroupAccum`.** Mutations made by
  background tasks (e.g., unlinking orphaned files) go through the same
  accumulator protocol.

### 11.2 Segment cleaner

The segment cleaner operates at the extent level (Level 4). It acquires extent
locks exclusive for the extents it moves, but never blocks metadata operations
because metadata locks and extent locks are in different domains. The cleaner's
own metadata mutations (updating extent maps to point to new segment locations)
go through the standard metadata path with per-thread accumulation.

## 12. Data structures

### 12.1 CommitGroupManager extensions

The existing `CommitGroupManager` from #1267 is extended with:

```rust
impl CommitGroupManager {
    /// Per-thread accumulators, indexed by thread_id.
    thread_accumulators: Vec<ThreadCommitGroupAccum>,

    /// Per-thread CoW dirty sets.
    thread_dirty_sets: Vec<ThreadBtreeDirtySet>,

    /// Number of active worker threads.
    worker_count: u32,

    /// Per-directory-inode locks.
    dir_inode_locks: DirInodeLockTable,

    /// Atomic counter for in-flight operations during QUIESCE.
    in_flight_count: AtomicU64,

    /// Acquire the directory-inode lock for `dir_inode`.
    fn acquire_dir_lock(&self, dir_inode: InodeId, mode: LockMode)
        -> DirInodeLockGuard;

    /// Register a completing operation (decrements in-flight count).
    fn op_complete(&self);

    /// Begin QUIESCE: set phase, wait for in-flight to reach 0.
    fn begin_quiesce(&self) -> Result<(), CommitGroupError>;

    /// Collect all thread accumulators for SYNC.
    fn collect_accumulators(&self) -> MergedAccumulator;
}
```

### 12.2 DirInodeLockTable

```rust
/// Lock table for directory inodes.
///
/// Uses a sharded hash map to reduce contention on the table itself.
/// The table is read-heavy (lookup acquires a shared lock on the table
/// to find the directory-inode lock handle).
struct DirInodeLockTable {
    /// Sharded buckets, each with its own RwLock.
    shards: Vec<RwLock<HashMap<InodeId, Arc<DirInodeLock>>>>,

    /// Number of shards (power of two, typically 64-256).
    shard_count: u32,
}
```

### 12.3 MergedAccumulator (SYNC phase)

```rust
/// Result of merging all per-thread accumulators for a commit_group.
struct MergedAccumulator {
    /// Fully resolved directory mutations (conflicts detected).
    dir_mutations: HashMap<InodeId, Vec<DirMutation>>,

    /// Resolved inode attribute updates.
    inode_updates: HashMap<InodeId, InodeAttr>,

    /// New inode allocations.
    new_inodes: Vec<InodeId>,

    /// CommitGroup id.
    commit_group_id: u64,
}

enum DirMutation {
    Insert { name: Vec<u8>, target_inode: InodeId, entry_type: DirEntryType },
    Remove { name: Vec<u8> },
}
```

## 13. Error handling

### 13.1 CommitGroup commit failure

If the commit_group commit fails (SegmentStore I/O error, disk full):

1. The commit_group is aborted (`commit_group_abort()` from #1267).
2. All per-thread accumulators are discarded.
3. All threads that submitted mutations receive `EIO`.
4. The pool enters a degraded state; manual intervention is required.

### 13.2 Conflict errors

When a conflict is detected at commit time:

1. The winning thread's mutation is applied normally.
2. The losing thread receives `EEXIST` (for create) or `ENOENT` (for unlink).
3. The error is returned to the FUSE client as if the operation had failed
   synchronously.

### 13.3 Quiesce timeout

If a worker thread does not drain within `quiesce_timeout_ms` (default 500ms):

1. The commit_group manager logs a warning identifying the stuck thread.
2. The quiesce phase proceeds anyway after the timeout (the stuck thread's
   in-flight mutation is included in the committing commit_group).
3. If the stuck thread subsequently completes, its mutation goes to the next commit_group.
4. Repeated timeouts trigger a health alert.

## 14. Configuration

```rust
/// Metadata engine parallelism configuration.
struct MetadataParallelismConfig {
    /// Number of metadata worker threads.
    /// Default: number of logical CPUs.
    worker_threads: u32,

    /// Maximum entries per ThreadCommitGroupAccum before triggering a sync hint.
    /// Default: 1024.
    accum_entry_threshold: u32,

    /// Maximum dirty bytes per ThreadCommitGroupAccum before triggering a sync hint.
    /// Default: 4 MiB.
    accum_byte_threshold: u64,

    /// Maximum time a thread may hold a directory-inode lock.
    /// Default: 10 ms (triggers a warning; not enforced).
    max_dir_lock_hold_ms: u64,

    /// Quiesce drain timeout in milliseconds.
    /// Default: 500 ms.
    quiesce_timeout_ms: u64,

    /// Whether to hold FUSE replies until commit_group commit (strict mode).
    /// Default: false (reply immediately; accept rare conflict errors).
    sync_reply_on_commit: bool,
}
```

## 15. Acceptance criteria

1. **Metadata ops on different datasets scale linearly with core count.**
   Two datasets, two cores: 2× throughput vs. 1 dataset, 1 core.

2. **Metadata ops on different directories within a dataset scale linearly.**
   Two directories, two cores: near-2× throughput vs. 1 directory, 1 core.

3. **Concurrent creates with different names in the same directory commit
   in the same commit_group.** Both entries appear on disk after a single commit_group sync.

4. **Same-name conflict detected at commit_group commit (optimistic, not lock-based).**
   Second creator receives EEXIST; first creator's entry is committed.

5. **Data IO never blocked by metadata operations.**
   A large `write()` does not stall behind a `create()` in the same directory,
   and vice versa.

6. **Benchmark: >100K directory creates/sec on multi-core.**
   Measured with a synthetic benchmark creating empty files in a single directory
   from multiple threads on a system with ≥8 cores.


### 16.1 Required tests

|---|---|
| `test_different_datasets_parallel` | Mutations on two datasets proceed without lock contention |
| `test_same_dataset_different_dirs_parallel` | Different directory mutations proceed concurrently |
| `test_same_dir_different_names_same_commit_group` | Two creates with different names commit in one commit_group |
| `test_same_dir_same_name_conflict` | Duplicate create returns EEXIST at commit |
| `test_readdir_sees_committed_snapshot` | readdir during OPEN ignores uncommitted creates |
| `test_data_io_not_blocked_by_metadata` | write() proceeds while create() is in-flight |
| `test_metadata_not_blocked_by_data_io` | create() proceeds while write() is in-flight |
| `test_lock_ordering_no_deadlock` | Stress test with random operations; no deadlocks |
| `test_quiesce_drains_all_threads` | QUIESCE waits for all in-flight ops |
| `test_quiesce_rejects_new_mutations` | New mutations during QUIESCE get CommitGroupError::Quiescing |
| `test_per_thread_accumulator_isolation` | One thread's accumulator never visible to another |
| `test_cow_btree_dirty_node_isolation` | Per-thread dirty nodes don't leak between threads |
| `test_conflict_deterministic_merge_order` | Same conflict scenario produces same result every time |
| `test_backpressure_on_accum_threshold` | Sync triggered when accumulator reaches threshold |
| `test_rename_cross_directory_lock_ordering` | rename(/a/x, /b/y) acquires locks in inode-ID order |

### 16.2 Gate command

```
cargo test --workspace -- metadata_parallelism
```

All tests in the `metadata_parallelism` test module must pass.

### 16.3 Benchmark

```
cargo bench --bench metadata_parallelism_bench
```

Target: >100K creates/sec on an 8-core system. The benchmark spawns N worker threads,
each creating M files in the same directory (different names per thread), and measures
total creates per second including commit_group sync time.

## 17. References

- #1206: Lock service architecture
- #1267: Canonical commit ordering and multi-phase commit_group state machine
- #1219: Dataset lifecycle
- #1127: FUSE daemon architecture
- #1145: FUSE multiqueue
- #1179: Background scheduler
- #1248: Cluster distributed lock service (sharded leases)
- #1276: Cross-dataset reflink and copy offload
- `docs/design/canonical-commit-ordering-commit_group-state-machine.md`
- `docs/design/cluster-distributed-lock-service-sharded-leases.md`
- `docs/design/cross-dataset-reflink-and-copy-offload.md`
- `crates/tidefs-btree/src/lib.rs` — CoW B+tree implementation
- `crates/tidefs-dir-index/src/lib.rs` — polymorphic directory index
- `crates/tidefs-vfs-engine/src/lib.rs` — VFS engine trait
- `crates/tidefs-dataset-lifecycle/src/lib.rs` — dataset lifecycle state machine
