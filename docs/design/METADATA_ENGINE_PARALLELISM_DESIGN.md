# Metadata Engine Parallelism: Multi-Core Metadata Path, Lock Sharding, Optimistic Concurrency, and Per-Core Transaction Accumulation

Maturity: **design-spec** for the multi-core metadata engine parallelism architecture.

This document closes Forgejo issue #1278.

## 1. Motivation

Storage systems that serialize metadata operations onto a single thread hit a hard
wall at 10–50K ops/sec regardless of available cores:

- **Ceph MDS**: Effectively single-threaded for namespace operations within a
  subtree. Static multi-MDS partitioning is brittle, requires manual balancing,
  and each partition is still single-threaded. ~10–50K metadata ops/sec.
- **ZFS ZPL**: Serial commit_group sync — the metadata write path is single-threaded per
  dataset. Reads can be concurrent but writes serialize through one thread.

tidefs must design for metadata multi-core scaling from day one. A four-level
parallelism taxonomy, lock sharding per-directory-inode, optimistic intra-directory
concurrency, and per-core transaction accumulation together target 100K+
metadata ops/sec on commodity multi-core hardware.

## 2. Design Decision: Four-Level Parallelism Taxonomy

The engine exposes parallelism at four granularities from coarse (free) to fine
(engineered):

### Level 1 — Per-dataset (zero-cost)

Different datasets are fully independent. They share no locks, no CoW trees, and
no transaction state. This is the cheapest parallelism: the engine simply
routes operations by dataset id.

**Guarantee**: Metadata ops on different datasets scale linearly with core count
(acceptance criterion #1). No contention, no coordination, no shared mutation.

**Mechanism**: The VFS Engine adapter (FUSE, ublk, RPC) dispatches by dataset id
before entering the lock hierarchy. Separate `LocalFileSystem` instances exist per
mounted dataset with independent commit_group state machines.

### Level 2 — Intra-dataset namespace (per-directory locking)

Different directories within the same dataset proceed in parallel. The
serialization point is the directory inode lock (level 2 in the #1206 lock
hierarchy).

```
create(/a/x, ...) and create(/b/y, ...) = parallel (different parents)
create(/a/x, ...) and create(/a/y, ...) = serialized on directory /a (level 2 lock)
```

**Guarantee**: Metadata ops on different directories within a dataset scale
linearly with core count (acceptance criterion #2).

**Mechanism**: Per-directory-inode locks (#1206 §1 level 2) acquired in
deterministic inode-id order. Operations touching the same directory queue on
that directory's lock; operations on different directories acquire separate
locks and proceed concurrently.

**Critical detail**: The directory inode lock covers *entry mutations*, not
*inode metadata* of the child. A `create()` that allocates a new inode acquires:
- Directory lock (level 2) on the parent
- Inode metadata lock (level 3) on the new child

Two `create()` calls in the same directory serialize on the directory lock,
but the child inode allocation itself is uncontended (fresh inode, no other
holders).

### Level 3 — Intra-directory (optimistic concurrency)

Commutative operations *within the same directory* commit in the same
transaction group. This is the novel contribution: optimistic, first-writer-wins
conflict detection at commit_group commit time.

```
create(/a/x) and create(/a/y) = commit in same commit_group (different names, no conflict)
create(/a/x) and create(/a/x) = second returns EEXIST at commit_group commit (optimistic detect)
```

**Guarantee**: Concurrent creates with different names in the same directory
commit in the same commit_group (acceptance criterion #3). Same-name conflict is
detected at commit_group commit time — optimistic, not lock-based (criterion #4).

**Mechanism** (see §5 for full algorithm):

1. OPEN phase: Both workers accumulate mutations into their per-core
   transaction accumulators. No directory lock is held for the entire
   operation — only briefly for directory entry layout allocation.
2. QUIESCE phase: Drain in-flight ops.
3. SYNC phase commit: Merge per-core accumulators, detect name conflicts
   in the merged directory entry set, and abort losers with EEXIST.

This is the key insight: the directory lock is not held across the entire
`create()` invocation. Workers acquire a short-lived directory-entry reservation
(a slot in the directory's CoW B+tree leaf) and proceed. The actual name
conflict is resolved at commit time.

### Level 4 — Data path (extent-level, never blocked by metadata)

Extent-level locking (level 4 in the #1206 hierarchy) isolates data IO from
metadata operations. A metadata-intensive workload (mkdir, create, unlink)
never blocks a concurrent read() or write() on a different file. Within the
same file, read() on extent [0..4096] and write() on extent [8192..12288]
proceed in parallel (different ranges, level 4 lock ordering).

**Guarantee**: Data IO never blocked by metadata operations (acceptance
criterion #5). Metadata ops never block data IO (acceptance criterion #5
converse).

## 3. Lock Sharding Architecture

### 3.1 Extended hierarchy (builds on #1206)

```
Level 0: Pool              — pool import/export, global properties
Level 1: Dataset           — dataset lifecycle, snapshot, namespace membership
Level 2: Directory-inode   — entry mutations (create, unlink, rename, mkdir, rmdir, readdir)
Level 3: Inode metadata    — setattr, nlink, truncate, getattr (shared)
Level 4: Extent            — read/write/fallocate/punch on (inode, range)
```

Level 0 is added: pool-level operations (import, export, device attachment)
require a pool lock above all dataset locks. This prevents a dataset operation
from racing with pool destruction.

### 3.2 Lock data structure sharding

Rather than a single global `HashMap<u64, LockState>`, directory-inode locks
are sharded by inode id:

```rust
/// Sharded lock table for directory inode locks.
///
/// Each shard is an independent RwLock<HashMap<u64, DirLockState>>.
/// Shard selection: inode_id % SHARD_COUNT.
struct ShardedDirLockTable {
    shards: Vec<RwLock<HashMap<u64, DirLockState>>>,
    shard_count: usize,
}
```

**Shard count**: `max(1, num_cpus::get() * 2)`. This ensures that two
operations on different directories in different shards never contend on
the lock table metadata itself.

The level-3 inode metadata lock table and level-4 extent lock table use
identical sharding. Level-0 (pool) and level-1 (dataset) are not sharded:
there is typically one pool and a bounded number of datasets, so the
contention on the table itself is negligible.

### 3.3 Lock acquisition protocol with sharding

```
fn acquire_level2_lock(inode_id: u64, mode: LockMode) -> DirLockGuard {
    let shard_idx = inode_id % SHARD_COUNT;
    let shard = &self.shards[shard_idx];
    let mut map = shard.write(); // exclusive on shard, brief
    let entry = map.entry(inode_id).or_default();
    // Try-acquire or queue on the individual directory lock
    match entry.try_acquire(mode) {
        Acquired => DirLockGuard { shard_idx, inode_id, ... },
        Queued => { drop(map); wait_and_retry(); },
    }
}
```

The critical insight: the shard lock is held only for the duration of the hash
table lookup/insert. The actual directory lock acquisition (which may block
waiting for an exclusive holder to release) happens on the individual lock
state, not under the shard lock.

## 4. Per-Core Transaction Accumulation

### 4.1 Local transaction accumulator

Each worker thread owns a `LocalCommitGroupAccumulator`:

```rust
/// Per-thread accumulator for mutations in the current OPEN commit_group.
///
/// All mutations from this thread are staged here until commit_group commit.
/// During the SYNC phase, all accumulators are merged and committed.
struct LocalCommitGroupAccumulator {
    /// Current commit_group being accumulated into.
    commit_group_id: TxnGroupId,

    /// Dirty inodes: (inode_id -> InodeMutation).
    inode_mutations: HashMap<u64, InodeMutation>,

    /// Created directory entries: (parent_inode, name) -> (child_inode, kind).
    created_entries: Vec<(InodeId, Vec<u8>, InodeId, NodeKind)>,

    /// Removed directory entries: (parent_inode, name) -> child_inode.
    removed_entries: Vec<(InodeId, Vec<u8>, InodeId)>,

    /// Extent writes: append-only log of extent mutations.
    extent_mutations: Vec<ExtentMutation>,

    /// Inode metadata changes (setattr, nlink updates).
    attr_mutations: Vec<AttrMutation>,

    /// Bytes written in this accumulator.
    dirty_bytes: u64,

    /// Operation count in this accumulator.
    dirty_ops: u64,
}
```

### 4.2 Mutation staging protocol

When a worker receives a mutating operation (e.g., `create()`), the flow is:

1. **Lock acquisition** (§3): Acquire directory-inode lock (level 2) and new-inode
   metadata lock (level 3) per the #1206 protocol.
2. **Allocate inode number**: Atomically from a per-dataset inode counter
   (lock-free atomic fetch_add).
3. **Stage mutation**: Push the directory entry creation and new inode metadata
   into `self.local_accumulator`. Release locks.
4. **Return success to caller**: The `InodeAttr` of the new inode is computed
   and returned immediately. The caller sees success *before* the commit_group commits.
5. **CommitGroup commit**: Later, during the SYNC phase, the accumulator is drained
   into the shared commit pipeline. If a name conflict is detected, the losing
   `create()` has already returned success to its caller — the error is
   surfaced as an `EEXIST` from the *conflicting* operation, not retroactively.

**Visibility rule**: A `create()` that returns success is durable-in-intent but
not durable-on-media until the commit_group commits. A lookup for the new name within
the same commit_group must see the staged entry (using a thread-local or commit_group-local
read overlay). A lookup from a different thread sees the committed state (last
committed commit_group), not the staged state. This is the "read-your-own-writes,
committed-for-others" model.

### 4.3 CoW B+tree per-thread dirty nodes

Each worker thread maintains its own set of dirty B+tree nodes:

```rust
/// Per-thread CoW B+tree dirty node cache.
///
/// During the OPEN phase, mutations generate new (copy-on-write) nodes
/// that are visible only to this thread. At commit_group commit, all threads'
/// dirty nodes are reconciled into the shared committed tree.
struct ThreadLocalBtreeCache {
    /// Dirty leaf nodes: (node_id -> CoW copy).
    dirty_leaves: HashMap<u64, BtreeLeaf>,

    /// Dirty internal nodes: (node_id -> CoW copy).
    dirty_internals: HashMap<u64, BtreeInternal>,
}
```

**Key property**: No shared mutation. Two threads modifying different parts of
the directory B+tree generate independent CoW paths. The SYNC phase merges
them by identifying the lowest common ancestor of all dirty paths and
reconstructing a single committed tree. Conflict (two threads modifying the
same leaf) is detected at merge time and resolved per the optimistic
concurrency protocol (§5).

### 4.4 SegmentStore append serialization point

The SegmentStore append is the ultimate serialization point for persistence.
During the SYNC phase:

1. Each thread's accumulator is drained into a sorted merge list.
2. The merge list produces the authoritative set of mutations for this commit_group.
3. A single writer appends metadata records to the SegmentStore in the
   canonical 7-step commit order (#1267).
4. The checkpoint pointer is updated and flushed.

**Future optimization**: Per-core metadata journals (#1280). Instead of a single
SegmentStore append, each core could have its own metadata journal partition,
with a lightweight merge of checkpoint pointers at SYNC time. This is deferred:
the single-writer append is adequate for the 100K+ ops/sec target given modern
NVMe bandwidth.

## 5. Optimistic Intra-Directory Concurrency Algorithm

### 5.1 Conflict detection at commit time

The core algorithm for level-3 parallelism:

```
Algorithm: commit_group_commit_merge_directories

Input:
  accumulators: Vec<LocalCommitGroupAccumulator>   // one per worker thread
  committed_state: &CommittedState          // last committed commit_group state

Output:
  merged: MergedCommit                      // authoritative commit_group commit
  conflicts: Vec<Conflict>                  // operations that must abort

Procedure:
  1. merged = empty MergedCommit
  2. conflicts = empty Vec

  3. // Phase 1: collect all directory entry mutations by parent
  per_dir: HashMap<InodeId, DirEntryOps> = empty

  for each acc in accumulators:
    for each (parent, name, child, kind) in acc.created_entries:
      per_dir[parent].creates.push((name, child, kind, acc.thread_id))
    for each (parent, name, child) in acc.removed_entries:
      per_dir[parent].removes.push((name, child, acc.thread_id))

  4. // Phase 2: per-directory conflict resolution
  for each (parent_inode, ops) in per_dir:
    // Start from committed directory state
    dir_state = committed_state.directories[parent_inode].clone()

    // Apply removes (no conflict possible: removes are idempotent-ish)
    for each (name, child, thread_id) in ops.removes:
      if dir_state.contains(name):
        // Record the removal for the merge
        merged.removals.push((parent_inode, name, child))
        dir_state.remove(name)
      else:
        // Already removed or never existed: no-op for this commit_group
        // (ENOENT was already returned to the caller)
        continue

    // Apply creates with conflict detection
    for each (name, child, kind, thread_id) in ops.creates:
      if dir_state.contains(name):
        // CONFLICT: name already exists
        // Could be: (a) committed state has it, or (b) another create in this commit_group
        conflicts.push(Conflict {
          kind: ConflictKind::NameExists,
          parent: parent_inode,
          name: name.clone(),
          losing_thread: thread_id,
          losing_child: child,
        })
      else:
        merged.creations.push((parent_inode, name.clone(), child, kind))
        dir_state.insert(name, child, kind)

  5. // Phase 3: merge inode mutations
  for each acc in accumulators:
    for each (inode, mutation) in acc.inode_mutations:
      if merged.inode_mutations.contains(inode):
        // Inode mutated by two threads: must be commutative
        assert!(are_commutative(mutation, merged.inode_mutations[inode]))
      merged.inode_mutations.insert(inode, mutation)

  6. // Phase 4: merge extent mutations (always commutative, per-range)

  7. return (merged, conflicts)
```

### 5.2 First-writer-wins semantics

Operations are ordered by arrival time at the accumulator. The first writer to
stage a mutation wins. Losers are notified with an error code (EEXIST for
create conflicts, ENOENT for unlink-on-missing).

**Deadlock freedom**: The algorithm never blocks during conflict detection.
It is a deterministic merge of N accumulators with O(N * M) comparisons
where M is the number of entries per directory. No locks are held during the
merge.

### 5.3 Commutativity rules

Operations are commutative (safe to merge) when they operate on disjoint
resources:

| Operation A | Operation B | Commutative? | Reason |
|-------------|-------------|-------------|--------|
| create(/d/a) | create(/d/b) | Yes | Different names |
| create(/d/a) | create(/d/a) | No (conflict) | Same name |
| create(/d/a) | unlink(/d/b) | Yes | Different names |
| create(/d/a) | unlink(/d/a) | No (conflict) | Same name: order matters |
| unlink(/d/a) | unlink(/d/b) | Yes | Different names |
| setattr(inode A, ...) | setattr(inode A, ...) | Yes* | Last writer wins on time fields; other fields conflict |
| write(inode, [0..4K]) | write(inode, [4K..8K]) | Yes | Disjoint ranges |
| write(inode, [0..8K]) | write(inode, [4K..12K]) | No (conflict) | Overlapping ranges |

*For setattr commutativity: mode, uid, gid, size changes from two concurrent
setattrs on the same inode within the same commit_group are a conflict. However, atime
and mtime updates are commutative (last writer wins, both get the current
time). The engine detects non-commutative setattr pairs and aborts the second.

## 6. CommitGroup Integration (extends #1267)

### 6.1 OPEN phase with concurrent workers

The OPEN phase of the #1267 commit_group state machine is extended to accept
concurrent mutations from all worker threads:

```
┌──────────────────────────────────────────────────────┐
│                    OPEN phase                         │
│                                                      │
│  Worker 0: LocalCommitGroupAccumulator[0] ──► mutations      │
│  Worker 1: LocalCommitGroupAccumulator[1] ──► mutations      │
│  ...                                                  │
│  Worker N: LocalCommitGroupAccumulator[N] ──► mutations      │
│                                                      │
│  Shared: dirty_bytes (atomic sum), dirty_ops (atomic) │
│                                                      │
│  Trigger: when dirty_bytes > commit_group_dirty_max_bytes      │
│           or dirty_ops > commit_group_target_ops               │
│           or elapsed > commit_group_target_secs                │
│           → transition to QUIESCE                     │
└──────────────────────────────────────────────────────┘
```

Each worker's accumulator tracks its own `dirty_bytes` and `dirty_ops`. A
shared atomic pair aggregates across workers for back-pressure and auto-sync
decisions.

### 6.2 QUIESCE phase — draining in-flight ops

```
Algorithm: quiesce_with_concurrent_workers

  1. Set commit_group_phase = Quiesce
  2. New mutations → next commit_group's accumulators (already allocated, still OPEN)

  3. // Drain in-flight operations
  for each worker in 0..num_workers:
    // Signal the worker that quiesce has started
    worker.quiesce_signal.store(true, Ordering::Release)

  // Wait for all workers to finish their current operation
  // Timeout: commit_group_quiesce_timeout_secs (default 1s)
  deadline = now + commit_group_quiesce_timeout

  loop:
    all_drained = true
    for each worker in 0..num_workers:
      if worker.inflight_count.load(Ordering::Acquire) > 0:
        all_drained = false
    if all_drained or now > deadline:
      break
    sleep(poll_interval)  // typically 100µs

  4. // Workers that didn't drain: their in-flight ops are NOT in this commit_group
  // Those ops will be captured in the next commit_group (written to current+1)
  // This is safe because the ops haven't been staged into accumulators
  // for this commit_group yet — they were still in-flight at the application layer.

  5. transition to SYNC
```

### 6.3 SYNC phase — merging and committing

```
Algorithm: sync_with_merged_accumulators

  1. // Drain all accumulators for this commit_group
  accumulators = Vec::new()
  for each worker in 0..num_workers:
    accumulators.push(worker.take_accumulator(current_commit_group))

  2. // Merge with conflict detection (§5)
  (merged, conflicts) = commit_group_commit_merge_directories(accumulators, committed_state)

  3. // Notify losers
  for each conflict in conflicts:
    send_error_to_worker(conflict.losing_thread, conflict.to_errno())

  4. // Execute 7-step commit ordering (#1267)
  commit_group_commit_seven_step(merged)

  5. // Advance commit_group
  current_commit_group = current_commit_group.next()
  commit_group_phase = Open
```

### 6.4 Back-pressure integration

Back-pressure is signaled per-worker when the global `dirty_bytes` or
`dirty_ops` exceeds thresholds:

- **Soft pressure** (`dirty_bytes > commit_group_target_bytes`): Worker finishes current
  op but queues the next op briefly (yield, not block).
- **Hard pressure** (`dirty_bytes > commit_group_dirty_max_bytes`): Worker blocks new
  mutating ops until the next SYNC completes. Read-only ops (getattr, lookup,
  readdir) are never blocked.
- **Per-worker fairness**: Workers with more accumulated dirty bytes are
  throttled more aggressively (their ops wait longer in the admission queue).

## 7. Worker Thread Model

### 7.1 Thread topology

```
┌──────────────────────────────────────────────────────────┐
│                    VFS Engine Process                     │
│                                                          │
│  ┌─────────┐  ┌─────────┐        ┌─────────┐            │
│  │Worker 0 │  │Worker 1 │  ...   │Worker N │            │
│  │ (core 0)│  │ (core 1)│        │ (core N)│            │
│  │         │  │         │        │         │            │
│  │ Acc[0]  │  │ Acc[1]  │        │ Acc[N]  │            │
│  │ BT[0]   │  │ BT[1]   │        │ BT[N]   │            │
│  └────┬────┘  └────┬────┘        └────┬────┘            │
│       │            │                  │                  │
│       └────────────┼──────────────────┘                  │
│                    │                                     │
│              ┌─────▼──────┐                              │
│              │  COMMIT_GROUP Sync  │  (single sync thread)        │
│              │  Merger    │                              │
│              └────────────┘                              │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │              Shared State (lock-free / sharded)   │    │
│  │  • ShardedDirLockTable                           │    │
│  │  • ShardedInodeLockTable                         │    │
│  │  • ShardedExtentLockTable                        │    │
│  │  • Atomic dirty_bytes / dirty_ops                │    │
│  │  • Committed B+tree (read-only, CoW snapshots)   │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### 7.2 Worker lifecycle

Each worker thread runs a loop:

```
loop:
  1. Dequeue next FUSE request (or RPC, or admin command)
  2. Classify operation:
     - Read-only (getattr, lookup, readlink, readdir, read):
       → Acquire shared locks only
       → Read from committed state (commit_group snapshot)
       → Reply immediately, no accumulator staging
     - Mutating (create, unlink, mkdir, rmdir, rename, setattr, write):
       → Acquire exclusive locks per #1206 hierarchy
       → Stage mutation in local accumulator
       → Reply success to caller
       → (Optionally: if back-pressure, queue reply until after next SYNC)
  3. Periodic: check quiesce signal, back-pressure flags
```

### 7.3 CPU affinity and NUMA awareness

- Workers are pinned to cores via `core_affinity` (Linux `sched_setaffinity`).
- Each worker's `LocalCommitGroupAccumulator` and `ThreadLocalBtreeCache` are
  allocated from the NUMA node local to that core.
- The shared committed B+tree is allocated interleaved across NUMA nodes
  (read-heavy, shared by all workers).
- The sharded lock tables are distributed: shards on a given NUMA node are
  preferred by workers on that node.

## 8. Anti-Anti-Patterns (What We Explicitly Avoid)

### 8.1 NOT: Global namespace lock

Ceph MDS uses a journal that serializes all namespace mutations within a
subtree. This is the Ceph MDS ceiling: ~10–50K ops/sec regardless of core count.

tidefs replaces the global namespace lock with:
- Per-directory-inode locks (§3)
- Optimistic intra-directory concurrency (§5)
- Per-core transaction accumulation (§4)

### 8.2 NOT: Static subtree partitioning

Ceph multi-MDS requires an administrator to partition the namespace across
MDS daemons. Partitions are static, load-imbalanced, and fragile (MDS failover
requires partition migration).

tidefs uses dynamic lock sharding: any worker can handle any directory.
Load balancing is automatic — the worker that dequeues the request handles it.

### 8.3 NOT: Single commit_group sync thread

ZFS serializes all metadata writes through a single commit_group sync thread. This is
the ZFS metadata bottleneck.

tidefs parallelizes mutation accumulation across workers (§4). The SYNC phase
is still single-threaded for the SegmentStore append (§4.4), but the critical
path (lock acquisition, inode allocation, B+tree mutation) is fully parallel.

### 8.4 NOT: Per-file locking for namespace ops

Locking at file granularity for namespace operations is wrong: a `create()`
modifies the directory, not the target file. Per-file locking would allow
two `create()` calls in the same directory to proceed in parallel but fail
to detect name conflicts until commit — exactly what we want. But per-file
locking alone doesn't protect directory entry consistency.

tidefs uses per-directory-inode locking for entry consistency, with optimistic
conflict detection to maximize intra-directory parallelism.

## 9. Benchmark Targets and Scaling Expectations

### 9.1 Acceptance criteria (from issue #1278)

| # | Criterion | Measurement |
|---|-----------|-------------|
| 1 | Metadata ops on different datasets scale linearly with core count | 2 datasets, 2x cores → 2x throughput |
| 2 | Metadata ops on different directories within dataset scale linearly | 2 dirs, 2x cores → 2x throughput |
| 3 | Concurrent creates with different names in same directory commit in same commit_group | Prove: two `create()` in same dir, different names, same commit_group |
| 4 | Same-name conflict detected at commit_group commit | Prove: second create returns EEXIST |
| 5 | Data IO never blocked by metadata | Prove: read() latency unchanged during metadata storm |
| 6 | >100K directory creates/sec on multi-core | Benchmark harness |

### 9.2 Scaling model

```
Total throughput = Σ datasets × Σ directories × min(cores, parallelism_per_dir)

Where:
  parallelism_per_dir = 1 (serial on directory lock)
                       + n_optimistic (commutative ops in same commit_group)

For a 16-core machine with 4 active directories:
  - Level 1: 4 datasets → 4x scaling (each dataset independent)
  - Level 2: 4 directories per dataset → 16 concurrent directory ops
  - Level 3: 100 creates/dir/commit_group → 100 ops commit together every commit_group

  Target: 100K creates/sec ≈ 16 cores × 100 creates/commit_group × 60 commit_group/sec
  (commit_group_target_ops = 1024, commit_group_target_secs = 1 → ~1 commit_group/sec)
  → Need ~100K ops/commit_group at 1 commit_group/sec = 100K ops/sec
  → Or ~10K ops/commit_group at 10 commit_group/sec = 100K ops/sec
```

### 9.3 Bottleneck analysis

| Component | Bottleneck? | Mitigation |
|-----------|------------|------------|
| Directory lock | Yes (level 2) | Optimistic intra-directory (level 3) |
| SegmentStore append | Yes (SYNC phase) | Future: per-core metadata journals (#1280) |
| Inode allocation | No | Atomic counter, no contention |
| CoW B+tree merge | Potential | Merge cost is O(dirty_nodes), amortized per-commit_group |
| FUSE /dev/fuse readv | Yes (single fd) | Multiple FUSE connections (FUSE_MAX_PAGES) |
| Lock table shard lock | No | Sharded by inode id, brief (<1µs) |

## 10. Relationship to Existing Designs

| Design | Integration point | This design provides |
|--------|------------------|---------------------|
| #1206 (Lock hierarchy) | Canonical lock levels | Extends from 4 levels to 5 (adds pool level 0); sharding of lock tables; integration with per-core accumulators |
| #1267 (COMMIT_GROUP state machine) | Commit ordering | Concurrent OPEN phase with per-worker accumulators; QUIESCE drain across workers; SYNC merge-and-commit |
| #1219 (Dataset lifecycle) | Per-dataset independence | Level 1 parallelism: separate `LocalFileSystem` per dataset, zero shared locks |
| #1127/#1145 (FUSE adapter) | Request dispatch | FUSE workers map 1:1 to metadata engine workers; per-core accumulators per FUSE worker thread |
| #1179 (Background services) | Background work | Background services (compaction, reclamation) run on separate worker set, don't contend with metadata ops |
| #1248 (Cluster locks) | Distributed locking | Writer lease (§9 of #1206) gates all mutating ops for a dataset on one node; intra-node parallelism per this design |
| #1280 (Per-core metadata journals) | Future optimization | Deferred: parallel SegmentStore append via per-core journals |
| #1241 (commit_group scheduling) | CONTROL lane | SYNC phase merge runs in CONTROL lane; worker threads continue handling read ops during SYNC |

## 11. Configuration

### 11.1 Tunables

| Parameter | Default | Description |
|-----------|---------|-------------|
| `metadata_worker_threads` | `num_cpus::get()` | Number of metadata engine worker threads |
| `lock_shard_count` | `num_cpus::get() * 2` | Number of shards in each lock table |
| `commit_group_target_ops` | 2048 | Ops threshold triggering SYNC |
| `commit_group_target_bytes` | 64 MiB | Byte threshold triggering SYNC |
| `commit_group_target_secs` | 5s | Time threshold triggering SYNC |
| `commit_group_dirty_max_bytes` | 512 MiB | Hard back-pressure threshold |
| `commit_group_quiesce_timeout_ms` | 1000ms | Max wait for worker drain |
| `optimistic_create_window` | unlimited | Max creates/dir/commit_group (unlimited; conflict detection is O(N) per directory) |

### 11.2 Presets

| Preset | Workers | commit_group_target_ops | commit_group_target_secs | Use case |
|--------|---------|---------------|-----------------|----------|
| `default()` | NCPU | 2048 | 5s | General workloads |
| `metadata_intensive()` | NCPU | 8192 | 2s | High metadata throughput |
| `low_latency()` | NCPU | 512 | 1s | Low commit latency |
| `bulk_create()` | NCPU | 32768 | 10s | Bulk directory creation |
| `testing()` | 2 | 16 | 0.1s | Deterministic testing |

## 12. Implementation Plan

### Phase 1: Lock sharding (depends on #1206 complete)

- Implement `ShardedDirLockTable`, `ShardedInodeLockTable`, `ShardedExtentLockTable`.
- Wire into the `LockManager` as a drop-in replacement for the per-resource HashMaps.
- No change to lock acquisition protocol, only to data structure.

### Phase 2: Per-core accumulators (depends on Phase 1, #1267)

- Implement `LocalCommitGroupAccumulator` and `ThreadLocalBtreeCache`.
- Wire into the worker thread loop.
- Extend commit_group state machine OPEN phase to accept concurrent accumulations.
- Read-your-own-writes overlay for same-commit_group visibility.

### Phase 3: Optimistic intra-directory (depends on Phase 2)

- Implement `commit_group_commit_merge_directories` algorithm.
- Name conflict detection at SYNC time.
- Loser notification (EEXIST, ENOENT) to worker threads.

### Phase 4: Worker thread topology (depends on Phase 2, #1145)

- Spawn `metadata_worker_threads` worker threads.
- Core pinning and NUMA-aware allocation.
- Back-pressure integration with per-worker admission control.

### Phase 5: Benchmark harness (depends on Phase 4)

- Implement `>100K creates/sec` benchmark.
- Scaling tests: 1/2/4/8/16 core linearity verification.
- Conflict rate microbenchmarks.
- Data-path isolation tests.

## 13. Non-Goals (Deferred)

- **Per-core metadata journals** (#1280): The SYNC phase still uses a single
  SegmentStore append. Per-core journals are a future optimization for the
  1M+ ops/sec target.
- **Dynamic worker pool resizing**: Worker count is fixed at startup. Dynamic
  resizing adds complexity (draining accumulators, migrating B+tree caches)
  without proportional benefit.
- **Work stealing**: Workers do not steal queued requests from each other.
  The FUSE ingress reader distributes work round-robin, which is adequate
  for uniform workloads.
- **NUMA migration of accumulators**: If a thread migrates to a different
  NUMA node, its accumulator is NOT migrated. This is a rare event (thread
  migration is uncommon with core pinning) and the cost of migration
  outweighs the benefit.
- **Hard real-time guarantees**: The design provides soft back-pressure and
  fairness but no hard latency bounds. Real-time metadata latency requires
  a separate design pass.

## 14. Summary

tidefs metadata engine parallelism is built on four complementary levels:

| Level | Mechanism | Scaling |
|-------|-----------|---------|
| 1. Per-dataset | Independent `LocalFileSystem` instances | Linear with datasets × cores |
| 2. Intra-dataset | Per-directory-inode lock sharding | Linear with directories × cores |
| 3. Intra-directory | Optimistic concurrency + commit-time merge | Commutative ops/commit group |
| 4. Data path | Extent-level locking, isolated from metadata | Unlimited (data path independent) |

Together, these levels provide:
- Zero-cost dataset isolation
- Lock-free lock table sharding
- Per-core mutation accumulation with no shared mutation
- Optimistic intra-directory concurrency avoiding the serial-directory bottleneck
- Clean integration with the existing #1206 lock hierarchy and #1267 commit_group state machine
- A path from 10K ops/sec (ZFS/Ceph single-thread ceiling) to 100K+ ops/sec

The design avoids every known ZFS and Ceph metadata bottleneck while remaining
implementable in phases with clear dependency ordering.
