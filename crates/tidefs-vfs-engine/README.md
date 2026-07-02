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

The transaction-group (txg) trait methods are the VFS engine boundary for
kernel-mode write batching and committed-root advancement. The trait defaults
do not provide durability: engines without explicit txg and committed-root
authority fail closed instead of reporting a successful no-op commit.

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

Opens a new transaction group. The default returns `ENOSYS`, or `EINVAL` for
`TxgId::NO_TXG`. Engines must override this to create a real transaction group.

```rust
fn txg_commit_prepare(&self, handle: &TxgHandle) -> Result<TxgPrepareResult, Errno>
```

Prepares the txg for commit: flushes dirty data, finalizes intent-log entries,
and returns the proposed committed-root identifier. The default returns
`ENOSYS`. Engines must not report `CommittedRoot::ZERO` as a successful
non-empty commit result.

```rust
fn txg_commit_finish(&self, handle: TxgHandle, committed_root: CommittedRoot) -> Result<(), Errno>
```

Confirms the committed root is durable and closes the txg. Engines that support
txg commits consume the handle and mark it consumed so its drop does not
trigger an abort. The default returns `ENOSYS`, or `EINVAL` for
`CommittedRoot::ZERO`.

```rust
fn write_committed_root(&self, committed_root: &CommittedRoot, device_index: u32) -> Result<(), Errno>
```

Writes the committed root to the pool-label superblock on the specified lower
device. Engines that back real block devices must override this to serialize a
non-zero committed root into PoolLabelV1 and issue a synchronous block write to
the label region. The default returns `ENOSYS`, or `EINVAL` for
`CommittedRoot::ZERO`.

### Usage Example

```rust
use tidefs_vfs_engine::{CommittedRoot, Errno, TxgId, VfsEngine};

fn commit_write_batch(engine: &dyn VfsEngine) -> Result<(), Errno> {
    // Open a new transaction group.
    let handle = engine.txg_open(TxgId(1))?;

    // Perform writes, allocates, unlinks, etc. within this txg...
    // (writeback_folios, allocate_extents, record_intent_entry, etc.)

    // Prepare for commit: flush and get proposed root.
    let result = engine.txg_commit_prepare(&handle)?;
    if result.committed_root.is_zero() {
        return Err(Errno::EINVAL);
    }

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

No-daemon transaction-group durability is available only through engines that
explicitly implement txg lifecycle and committed-root writeback authority. The
default trait methods intentionally refuse that authority so scaffolding cannot
be mistaken for mounted full-kernel durability.

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
