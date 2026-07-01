# tidefs-vfs-engine

VFS Engine trait: canonical operations defining the TideFS storage engine
interface. This crate defines `VfsEngine`, the VFS semantic boundary for
frontend adapters. FUSE, ublk, and kernel-module surfaces implement this trait
to share one engine abstraction.

## Operations

- 14 namespace operations: get_root_inode, lookup, getattr, setattr, mkdir,
  create, tmpfile, unlink, rmdir, rename, link, symlink, readlink, mknod
- 8 file I/O operations: open, release, read, write, copy_file_range, flush,
  fsync, fallocate
- 1 sparse-layout advisory: data_ranges
- 4 directory operations: opendir, releasedir, readdir, fsyncdir
- 4 extended attribute operations: getxattr, setxattr, listxattr, removexattr
- 3 advisory lock operations: getlk, setlk, setlkw
- 4 transaction-group lifecycle and writeback operations: txg_open,
  txg_commit_prepare, txg_commit_finish, write_committed_root
- 2 memory-mapped I/O operations: mmap (policy), fault (page-fault resolution)
- Block-volume operations: block_read, block_write, block_flush, block_discard
- Page-cache coherence: writeback_folios, allocate_extents, fiemap
- Intent-log: record_intent_entry, replay_intent_log
- Cache coherence: invalidate_cache_range, page_ownership_acquired,
  page_ownership_transferred, page_invalidation_needed

## Transaction-Group Lifecycle

The transaction-group (txg) trait methods enable kernel-mode write batching
and autonomous committed-root advancement without userspace daemon mediation.
This closes the crash-consistency gap in full-kernel no-daemon operation.

### Types

- `TxgId` — u64 newtype identifying a transaction group (0 = NO_TXG sentinel)
- `TxgHandle` — opaque handle returned by `txg_open`, consumed by
  `txg_commit_finish`; drop without consumption implicitly aborts
- `CommittedRoot` — 32-byte content digest identifying a durable committed
  filesystem state
- `TxgPrepareResult` — committed root, quorum flag, and engine-specific flags
  returned by `txg_commit_prepare`

### Trait Methods

```rust
fn txg_open(&self, txg_id: TxgId) -> Result<TxgHandle, Errno>
```

Opens a new transaction group. The default returns a no-op handle. Engines
must override this to create a real transaction group.

```rust
fn txg_commit_prepare(&self, handle: &TxgHandle) -> Result<TxgPrepareResult, Errno>
```

Prepares the txg for commit: flushes dirty data, finalizes intent-log entries,
and returns the proposed committed-root identifier. The default returns an
immediate result with a zero committed root.

```rust
fn txg_commit_finish(&self, handle: TxgHandle, committed_root: CommittedRoot) -> Result<(), Errno>
```

Confirms the committed root is durable and closes the txg. Consumes the handle
and marks it consumed so its drop does not trigger an abort. The default
delegates durability to [`write_committed_root`], writing the root to device 0.

```rust
fn write_committed_root(&self, committed_root: &CommittedRoot, device_index: u32) -> Result<(), Errno>
```

Writes the committed root to the pool-label superblock on the specified lower
device. This bridges `txg_commit_finish` to durable on-disk persistence: after
a transaction group commits, the new committed root is flushed to the pool
label so the next mount discovers the latest committed state without userspace
daemon mediation.

The default implementation is a no-op. Engines that back real block devices
must override this to serialize the committed root into
PoolLabelV1 and issue a synchronous block write to the label region.

### Usage Example

```rust
use tidefs_vfs_engine::{VfsEngine, TxgId, CommittedRoot};

fn commit_write_batch(engine: &dyn VfsEngine) -> Result<(), Errno> {
    // Open a new transaction group.
    let handle = engine.txg_open(TxgId(1))?;

    // Perform writes, allocates, unlinks, etc. within this txg...
    // (writeback_folios, allocate_extents, record_intent_entry, etc.)

    // Prepare for commit: flush and get proposed root.
    let result = engine.txg_commit_prepare(&handle)?;

    // If multi-node quorum is needed, collect peer acknowledgements here.
    if result.quorum_needed {
        // ... collect quorum ...
    }

    // Finalize: advance the durable committed root.
    engine.txg_commit_finish(handle, result.committed_root)?;

    Ok(())
}
```

### No-Daemon Boundary

All three txg lifecycle methods resolve within kernel authority through the
engine. No userspace daemon is required for normal filesystem operation.
This is a key enabler for full-kernel no-daemon crash consistency.

## Authority

The current VFS engine API authority is the `tidefs-vfs-engine` source crate
and the portable records in `tidefs-types-vfs-core`. Request/completion codec
shape is documented in `docs/REQUEST_CONTRACT.md`.

## KernelPoolCore (pool_core module)

`KernelPoolCore` is the shared kernel-resident pool context for POSIX VFS
and block-kmod frontends. It lives in `tidefs-vfs-engine` alongside other
shared kernel types (CommittedRoot, TxgId, TxgHandle, BlockQueueGeometry,
FiemapExtent) so every kernel crate sees one canonical pool-core API.

### Types

- **KernelPoolCore** — refcounted pool context with atomic lifecycle state.
- **KernelPoolState** — Configured / Importing / Mounted / Teardown.
- **KernelPoolConfig** — immutable pool config (UUID, lower-device
  descriptors, mount flags).
- **LowerDeviceDesc** — per-device major:minor, sector count, block size.
- **KernelPoolError** — fail-closed transition errors.

### Lifecycle

```
Configured  ──begin_import()──▶  Importing  ──complete_import()──▶  Mounted
     │                                │                                  │
     └────────begin_teardown()────────┴──────────begin_teardown()────────┘
                                       │
                                       ▼
                                    Teardown
```

All transitions use `AtomicU64` CAS loops; illegal moves return
`KernelPoolError::InvalidTransition`. Teardown is idempotent.

### Committed root

The committed root is NOT stored inside `KernelPoolCore`. An atomic
state+root update requires a kernel spinlock. The integration protocol is:

1. Kernel crate acquires its spinlock.
2. Kernel crate calls `KernelPoolCore::complete_import` (CAS Importing→Mounted).
3. Kernel crate stores the committed root in its lock-protected state.
4. Kernel crate releases the spinlock.

This keeps `tidefs-vfs-engine` free of mutable locking primitives while
the kernel crate owns the unsafe locking boundary.

### no_std

All types are `core`-only except `KernelPoolConfig::devices` which requires
the `alloc` feature for the `Vec<LowerDeviceDesc>`. The refcount and state
word are `AtomicU64` from `core::sync::atomic`.
