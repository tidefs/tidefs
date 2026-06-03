# Lock Hierarchy and Deterministic Concurrency Model

This document is the source-of-truth for the tidefs lock hierarchy, optimistic
by which the storage engine, FUSE adapter, ublk surface, and future cluster VFS
RPC acquire and release locks without deadlock.

Closes DESIGN issue #1206.

See also:
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `tidefs-types-vfs-core` for the LockSpec, LockKind, and lock-owner types

## 1. Design Decision: 4-level canonical lock hierarchy

All internal engine locks (VFS semantic locks, not user-visible flock/fcntl)
are acquired in a deterministic total order defined by resource level and
identity.

| Level | Resource class | Locked by | Example operations |
|-------|---------------|-----------|--------------------|
| 1 | Dataset | dataset id | snapshot create/destroy, dataset properties, mount state |
| 2 | Directory | inode id (ascending) | rename, link, unlink, mkdir, rmdir, readdir |
| 3 | Inode metadata | inode id (ascending) | setattr, nlink updates, truncate, getattr (shared) |
| 4 | File data range | (inode id, range start) (ascending) | read/write extent-map mutations, fallocate, punch hole |

Within each level, locks are ordered by resource identity (inode id, then
range start) to break ties deterministically. This prevents AB/BA deadlock
under concurrent operations.

## 2. Lock type semantics

### 2.1 Lock modes

Each lockable resource supports three modes:

- **Shared** (read): multiple concurrent holders; used for lookups, getattr,
  readdir, read operations
- **Exclusive** (write): single holder; used for mutations that change
  metadata or data
- **Intention-shared**: a weak claim used only during the lock-set computation
  phase; prevents exclusive acquisition but permits shared holders

### 2.2 Lock ownership

Every acquired lock carries an owner token. The token is:
- An opaque `u64` for internal engine locks (anonymous, per-operation)
- Derived from FUSE `lock_owner` + PID for user-visible record locks
- The same owner token is used for deadlock detection (see section 7)

### 2.3 Lock lifecycle

```
Free -> Acquired(owner, mode) -> Held(owner, mode) -> Released -> Free
                              |
                         Upgraded (shared -> exclusive) [only when sole holder]
```

Upgrade from shared to exclusive is permitted only when no other shared
holders exist. Downgrade from exclusive to shared is always permitted.

## 3. Multi-object lock set computation

For operations touching multiple objects (rename, link, unlink), the engine
must compute the full lock set before mutating anything. The protocol:

### 3.1 Resolution phase (under shared locks)

1. Resolve pathnames to inode ids and directory entries (under shared locks
   at level 2, level 3)
2. Identify all resources that will be mutated:
   - Directories whose entries change (level 2)
   - Inodes whose metadata changes (level 3)
   - File data ranges that will be modified (level 4)
3. Read revision counters for every identified resource and cache them
4. Release all shared locks

### 3.2 Acquisition phase (deterministic ordering)

1. Build the lock request list as `[(level, id, range, mode), ...]`
2. Sort: by level (ascending), then by inode id (ascending), then by range start
3. Acquire all locks in sorted order
4. If any acquisition fails (timeout/contention): release all held locks,
   exponential backoff, retry from step 3.1


1. Compare current revision counters to cached values from step 3.1
2. If any counter has changed: release all locks, retry from step 3.1
3. If all counters match: proceed to mutation


## 4. Revision counters

Every lockable resource carries a monotonic `u64` revision counter. The
counter is incremented atomically on every exclusive mutation of that
resource.

### 4.1 Counter locations

| Resource | Counter field | Incremented on |
|----------|--------------|----------------|
| Dataset | `dataset_rev` in DatasetRecord | snapshot, rollback, property change |
| Directory | `dir_entry_rev` in DirInode | create, unlink, link, rename affecting entries |
| Inode | `inode_metadata_rev` in InodeRecord | setattr, nlink change, truncate |
| File range | `extent_map_rev` in InodeRecord | write, fallocate, punch hole |

### 4.2 Counter visibility

- Counters are read under a shared lock during the resolution phase
- Counters are incremented by the mutation itself (not separately)
- Counters are persisted: they survive daemon restart

## 5. Rename lock set (canonical hardest case)

A rename touches up to: two directories, the moved inode, and potentially an
overwritten inode.

### 5.1 Lock acquisition sequence

Given `rename(old_parent, old_name, new_parent, new_name)`:

1. Resolve: old_parent_dir_id, new_parent_dir_id, moved_inode_id,
   overwritten_inode_id (if target exists)
2. Build lock set:
   - Level 2: `min(old_parent_dir_id, new_parent_dir_id)` (exclusive)
   - Level 2: `max(old_parent_dir_id, new_parent_dir_id)` (exclusive)
   - Level 3: `moved_inode_id` (exclusive)
   - Level 3: `overwritten_inode_id` (exclusive, if target exists)
3. Acquire in sorted order (level 2 before level 3, then by id)
5. Execute the 5-step rename transaction (see issue #1205)

This ordering prevents AB/BA deadlocks even under concurrent renames.

### 5.2 Directory rename special case

When the moved inode is itself a directory, the rename lock set also
requires:
- Level 3 exclusive lock on the moved directory itself (for dot-dot entry
  update)
- The moved directory must not be an ancestor of the new parent (ENOTEMPTY
  equivalent)

## 6. Range locks for file data

Range locks serve two purposes: internal correctness (extent-map coherence)
and user-visible `fcntl` record locks. They share one implementation.

### 6.1 Interval tree structure

Per-inode interval tree keyed by `(start, end)`:
- `mode`: Shared | Exclusive
- `owner_token`: u64 (anonymous for internal, FUSE-derived for user-visible)
- `internal`: bool (true for engine correctness, false for user-visible)
- `kind`: Read | Write | Unlock (maps to F_RDLCK/F_WRLCK/F_UNLCK)

### 6.2 Internal range lock rules

- Read operations acquire shared range locks on `[offset, offset+len)`
- Write/truncate/fallocate acquire exclusive range locks
- Punch hole and zero-range modify extent maps under exclusive range locks
- Internal range locks are released at operation completion

### 6.3 User-visible lock integration

- `fcntl(F_SETLK)`: acquire or release record lock; non-blocking
- `fcntl(F_SETLKW)`: acquire record lock; block until available
- `fcntl(F_GETLK)`: query lock state for a range
- All locks released on `close()` (fd-level) and process death

Internal locks always take precedence over user-visible locks. A write
operation acquires an internal exclusive range lock; user-visible lock
requests on the same range are queued behind it.

## 7. Deadlock detection and bounded retry

### 7.1 Try-lock with yield

- All lock acquisitions use try-lock semantics
- If a lock is held: queue the request rather than spinning
- The queued request yields the CPU and awaits notification

### 7.2 Bounded retry with exponential backoff

- If a request holds locks and fails to acquire the next needed lock:
  1. Release all currently held locks
  2. Apply exponential backoff: `delay = min(base * 2^attempt, max_delay)`
  3. Retry from the resolution phase (section 3.1)
- `max_retries`: 8 (configurable)
- `base_delay`: 100us
- `max_delay`: 1s
- After exhausting retries: return EAGAIN to caller

### 7.3 Lock timeout

- No individual lock acquisition may block longer than `lock_timeout`
- Default: 5 seconds
- On timeout: release all held locks, return ETIMEDOUT

## 8. FUSE daemon integration

### 8.1 Request concurrency model

The FUSE daemon processes requests concurrently:
- Bounded worker pool (configurable, default: number of CPU cores)
- Each worker acquires its own lock set per operation
- Backpressure when all workers are busy: FUSE queue fills, kernel blocks

### 8.2 Lock owner identity

For user-visible locks, the owner identity is derived from:
- FUSE `lock_owner` field (opaque u64 provided by kernel per `open()`)
- PID of the requesting process (from `fuse_in_header.pid`)

Lock release on `close()` uses the same owner identity to find and release
all locks held by that owner for the inode.

### 8.3 Process death detection

Best-effort lock release on process death:
- When the kernel sends `FUSE_FORGET` for all open file handles
- When the FUSE session is destroyed (`FUSE_DESTROY`)
- Explicit `FUSE_INTERRUPT` handling: if a lock-acquiring request is
  interrupted, release any locks it already holds

## 9. Cluster VFS RPC integration

### 9.1 Dataset writer lease

In a cluster context, the lock hierarchy is extended with a cluster-level
concept:

- At most one node holds the dataset **writer lease** (exclusive mutation
  authority)
- Nodes without the writer lease must not apply local mutations
- A `SHARED` lease serves as a *presence token* (read-only access), not a
  read-write lock

### 9.2 Lock hierarchy in cluster context

The canonical lock hierarchy extends to:

0. **Cluster lease** (above dataset): writer lease acquisition/renewal
1-4. Same as single-node hierarchy (section 1)

A node that holds the writer lease applies the lock hierarchy locally. A node
without the writer lease:
- May acquire shared inode metadata locks for getattr/lookup
- Must forward mutations to the writer node
- Must not acquire exclusive locks at levels 2-4

### 9.3 RPC lock forwarding

When a read-write mount on a non-writer node receives a mutating request:
1. The request is serialized into an RPC
2. Forwarded to the writer node
3. Writer node applies the lock hierarchy locally
4. Returns the result (including any lock state changes)
5. Non-writer node updates its replicated state

## 10. Lock manager implementation design

### 10.1 Core types (Rust)

```rust
/// Lock mode: shared (multiple readers) or exclusive (single writer).
enum LockMode { Shared, Exclusive }

/// Lock level in the canonical hierarchy.
enum LockLevel { Dataset = 1, Directory = 2, Inode = 3, Range = 4 }

/// A requested lock on a specific resource.
struct LockRequest {
    level: LockLevel,
    resource_id: u64,
    range_start: Option<u64>,  // Some for FileDataRange, None otherwise
    mode: LockMode,
}

/// State of a lock acquisition attempt.
enum LockAttempt {
    Acquired,
    Queued,
    TimedOut,
    DeadlockDetected,
}

/// The lock manager: owns all lock state for a single daemon.
struct LockManager {
    dataset_locks: HashMap<u64, LockState>,
    directory_locks: HashMap<u64, LockState>,
    inode_locks: HashMap<u64, LockState>,
    range_locks: HashMap<u64, IntervalTree>,
    wait_queues: VecDeque<WaitingRequest>,
}
```

### 10.2 Lock acquisition algorithm

```
fn acquire_lock_set(requests: &[LockRequest], owner: u64) -> Result<LockSet, Error> {
    // Sort by (level, resource_id, range_start)
    let sorted = sort_lock_requests(requests);
    let mut held = Vec::new();

    for req in sorted {
        match try_acquire(req, owner) {
            Acquired => held.push(req),
            Queued => { release_all(&held); backoff_and_retry(); },
            TimedOut => { release_all(&held); return Err(ETIMEDOUT); },
            DeadlockDetected => { release_all(&held); return Err(EDEADLK); },
        }
    }

    Ok(LockSet { held })
}
```


```rust
    for (key, expected_rev) in expected {
        let current = read_revision_counter(key);
        if current != *expected_rev {
            return false;
        }
    }
    true
}
```

## 11. Relationship to other design issues

- **#1205** (Rename atomicity): uses this lock hierarchy for the rename
  lock-set computation; the 5-step transaction algorithm depends on
  deterministic lock ordering defined here
- **#1213** (VFS Engine API): the engine's LockSpec and LockResult types
  are the public interface to this hierarchy
- **#1190** (Writeback/commit_group): mutating transactions hold locks until commit_group
  commit; the lock hierarchy interacts with commit_group boundaries for lock duration
- **#1145** (Daemon topology): the lock hierarchy is a per-daemon concern;
  in cluster context, the SHARED dataset lease is a presence token
- **#1233** (FUSE binding): the FUSE adapter uses this hierarchy for
  concurrent request processing

## 12. Non-goals (deferred)

- **Distributed lock manager (DLM)**: this document covers single-node locking
  and dataset-scoped writer leases (section 9). A full DLM with lock migration
  and quorum-based fencing is deferred.
- **Lock persistence across daemon restart**: user-visible locks are released
  on daemon shutdown; restart begins with no held user-visible locks.
- **Byte-range lock merging/splitting optimization**: the initial
  implementation stores exact requested ranges without coalescing adjacent
  compatible locks. This is a future optimization.
- **Priority inheritance**: lock waiters are FIFO within the same mode class.
  No priority inheritance or boosting in the initial implementation.
