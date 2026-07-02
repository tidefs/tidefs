# tidefs-block-kmod


TideFS block-volume kernel module — fixed-capacity block device export consuming the kmod-bridge.

This README is crate-local source orientation. Product block-device wording,
kernel-residency wording, successor/comparator wording, and release-readiness
authority are owned by `docs/KERNEL_RESIDENCY_AUTHORITY.md`,
`docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`, `validation/claims.toml`,
and the generated claim registry.

## Daemon Independence

This crate has zero dependencies on userspace daemon crates
(`tidefs-fuser`, `tidefs-posix-filesystem-adapter-*`,
`tidefs-block-volume-adapter-*`). Its dependency tree consists solely of
no_std-compatible types crates, the `blake3` hashing crate, and the
kmod-bridge substrate. No daemon-only contracts, types, or initialization
patterns are transitively pulled into the kernel build.

Verified with:
```sh
cargo tree -p tidefs-block-kmod --edges normal | grep -iE 'tidefs-fuser|posix-filesystem-adapter|block-volume-adapter'
# (produces no output)
```


## Architecture

```
Linux block layer (blk-mq queue_rq)
  ↓ queue_rq
Kbuild gendisk owner         (tidefs_block_kmod.rs under CONFIG_RUST)
  ↓
TidefsBlockDevice            (device.rs, always available)
  ↓
PoolCoreBackend → KernelPoolCore logical-volume I/O
  ↓ explicit bring-up cfg only
BlockExport → BlockExportQueue → backing buffer
```

All I/O arrives through the blk-mq `queue_rq` callback. The pool-backed
registration path refuses to register `/dev/tidefs` unless a pool-backed backend
is available. That fail-closed shape is current bring-up behavior, not a
full block-volume product claim. Bio data pages and segments are accessed
through Linux 7.0 C bindings because the current Rust-for-Linux baseline has
no safe Rust `Bio` wrapper.

### Linux 7.0 Rust-for-Linux API Gaps

The Kbuild module entrypoint (`tidefs_block_kmod.rs`) works around the
following gaps in the Linux 7.0 Rust-for-Linux block bindings:

1. **No Rust `Bio` type** — `kernel::block::bio::Bio` does not exist.
   Bio fields (`bi_sector`, `bi_size`, `bi_opf`, `bi_io_vec`, `bi_next`)
   are accessed via `unsafe` dereference of the C `struct bio` through
   `kernel::bindings`.
2. **No bio-for-each-segment iterator** — `bio_for_each_segment` is a C
   preprocessor macro, not callable from Rust.  Segment iteration walks
   `bi_io_vec` and `bi_vcnt` manually.
3. **No `kmap_local_page` / `kunmap_local` Rust wrappers** — page mapping
   uses the raw C bindings directly.
4. **`Operations` trait has no `submit_bio` method or `RequestData`** —
   the real Linux 7.0 `Operations` trait signature is
   `queue_rq(QueueData, ARef<Request>, is_last) -> Result`.
   All I/O dispatches through `queue_rq`.
5. **No `BlockMutex`** — `kernel::sync::Mutex` is used instead.

These gaps are recorded per the kernel bring-up acceptance criteria. When
upstream Rust-for-Linux adds bio abstractions, the `unsafe` C-struct
access in `queue_rq` can be replaced with safe wrapper calls.

The `submit_bio` method used in earlier
versions was a design placeholder — the real `Operations` trait in Linux 7.0
has no `submit_bio` method.


## Queue Limits



The block device registers with the Linux block layer using queue limits
that match the VfsEngine storage characteristics. These limits control
how the kernel schedules, splits, merges, and validates I/O against the
tidefs block device.



### Configured Values



| Limit | Value | Rationale |

|-------|-------|-----------|

| `logical_block_size` | 512 bytes | Standard Linux minimum I/O unit; compatible with all filesystems and partition tools. |

| `physical_block_size` | 4096 bytes | Matches VfsEngine internal block size; guides kernel alignment, merging, and discard granularity. |

| `io_min` | 512 bytes | Smallest efficient I/O unit (matches logical block). Used by filesystem mkfs stripe/stride calculations. |

| `io_opt` | 4096 bytes | Optimal I/O size (matches physical block). The I/O scheduler targets this size for throughput-sensitive operations. |

| `max_hw_sectors` | 512 sectors (256 KiB) | Maximum hardware transfer size. Derived from the source default [`tidefs_vfs_engine::BlockQueueGeometry::production()`] helper. The helper name is historical source API; this fallback geometry does not imply product-ready block storage. |

| `max_segments` | 128 segments | Sufficient for bio_vec chaining from the block layer; matches VfsEngine segment-processing capacity. |

| `max_queue_depth` | 64 tags | Blk-mq tag pool depth; limits outstanding concurrent requests. Matches the blk-mq default for single-queue devices. |

| `QUEUE_FLAG_NONROT` | Set | Declares solid-state (non-rotational) semantics. The kernel uses this to select noop/kyber/mq-deadline I/O scheduler policies instead of rotational optimisers. |



### Flow

1. `GenDisk::try_new()` allocates the gendisk and request_queue with the
   logical block size (from [`BlockQueueGeometry::logical_block_size`])
   and capacity.

2. [`BlockQueueGeometry::production()`] provides the default queue-limit
   values. When a full [`VfsEngine`] is wired (post module-registration bridge),
   these values come from [`VfsEngine::queue_limits()`] instead of the fallback
   defaults, giving device-specific storage geometry to the Linux block layer.

3. Additional queue limits (`physical_block_size`, `io_min`, `io_opt`,
   `max_hw_sectors`, `max_segments`, `QUEUE_FLAG_NONROT`) are configured
   on the request_queue after allocation.

4. `add_disk` (called within the GenDisk lifecycle) makes the device
   visible to userspace with all limits in effect.



### VfsEngine Bridge

Queue limits flow through a single method on the [`VfsEngine`] trait:

```rust
use tidefs_vfs_engine::{BlockQueueGeometry, VfsEngine};

// Default queue geometry used when no engine is wired:
let geometry = BlockQueueGeometry::production();

// Engine-wired (overrides any field):
// let geometry = engine.queue_limits();

disk.set_physical_block_size(geometry.physical_block_size);
disk.set_io_min(geometry.io_min);
disk.set_io_opt(geometry.io_opt);
disk.set_max_hw_sectors(geometry.max_hw_sectors);
disk.set_max_segments(geometry.max_segments);
```

Engines that back block devices override [`VfsEngine::queue_limits()`] to
return device-specific geometry. The default implementation (present in every
`VfsEngine` implementation through the trait default) returns conservative
bring-up geometry until a real pool engine supplies exact device limits.

### Runtime Inspection



After the kernel module is loaded, verify the configured limits via sysfs:



```sh

# Logical and physical block sizes

cat /sys/block/tidefs/queue/logical_block_size   # 512

cat /sys/block/tidefs/queue/physical_block_size  # 4096



# I/O hints

cat /sys/block/tidefs/queue/io_min  # 512

cat /sys/block/tidefs/queue/io_opt  # 4096



# Maximum transfer size and segments

cat /sys/block/tidefs/queue/max_hw_sectors_kb  # 256 (512 * 512 / 1024)

cat /sys/block/tidefs/queue/max_segments       # 128



# Queue flags (bit 4 = QUEUE_FLAG_NONROT)

cat /sys/block/tidefs/queue/rotational  # 0

```



## Backend Classification

### In-Memory Backend (Explicit Bring-Up / Test)

The `BlockExport` + `BlockExportQueue` backend is a **fixed-capacity in-memory
buffer**. It is the bring-up and test backend for the typed userspace model and
kernel module smoke tests, not a product storage backend. The Kbuild module
entrypoint no longer falls back to this backend implicitly: by default,
`tidefs_block` refuses to register `/dev/tidefs` when `/dev/tidefs_pool_member`
cannot be opened.

Bring-up jobs that intentionally need the in-memory backend must build the
module with `RUSTFLAGS_MODULE=--cfg=tidefs_block_kmod_bringup_backend`. Linux
7.0's Rust `module!` macro in the current baseline does not expose module
parameters, so this cfg is the current explicit kernel-facing switch. A runtime
module parameter can replace it once the supported Rust-for-Linux parameter
shape is wired.

- **Pool-core backend target**: The intended kernel path is the shared pool
  authority exposed as `PoolCoreBackend`/`KernelPoolCore` logical-volume I/O.
  The current hard-coded `/dev/tidefs_pool_member` open remains a bring-up
  bridge toward that authority, not final pool import, full block-volume
  product evidence, or release-readiness evidence.
- **Data movement guarantee**: The in-memory backend does move data
  (read/write/flush/discard against the flat byte buffer), so the dispatch
  path is exercised for correctness.  However, it does **not** exercise
  real block-device persistence (no physical media, no power-fail atomicity,
  no crash-consistency across host reboots).
- **Kernel callback**: The `queue_rq` callback in the kernel module
  registration path can dispatch through this in-memory backend only in
  explicit bring-up mode, moving data between kernel request pages and the
  backing buffer. This is kernel-resident data movement suitable for module-load
  and basic I/O smoke testing, but it is **not** production kernel block I/O
  validation.

## Relationship To Physical Pool Devices

`tidefs-block-kmod` exports TideFS logical volumes as Linux block devices. It
does not import the physical member devices for a pool, and it does not own a
separate store. Future product block I/O is required to route:

```text
Linux blk-mq queue_rq
  -> tidefs-block-kmod
  -> kernel-resident TideFS pool core
  -> logical volume object/layout mapping
  -> physical member block devices
```

The physical member devices are opened and owned by the kernel-resident pool
engine shared with `tidefs-kmod-posix-vfs`. The block export front-end consumes
that engine through logical-volume operations. It must not use the in-memory
`BlockExport` backend as final or product storage, and it must reject self-stacking
where a TideFS exported block device is supplied as a member device for the
same TideFS pool.

The shared architecture and execution-context rules are defined in
`docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`.


## BLAKE3-Verified Device Lifecycle

The gendisk registration lifecycle is tracked by a BLAKE3-256 domain-separated
state machine (`DeviceLifecycle`, domain: `tidefs-block-kmod-lifecycle-v1`).
Every state transition produces a deterministic digest for validation.

### Lifecycle States

| State       | Description                                          |
|-------------|------------------------------------------------------|
| Unloaded    | No resources allocated. Initial state.               |
| Allocated   | Gendisk parameters validated (name, capacity, sector size). |
| QueueReady  | Request queue limits configured and bound.           |
| Active      | Device added to block layer (add_disk). Accepts I/O. |
| Removing    | Device removal initiated (del_gendisk).              |
| Removed     | Device fully removed. Terminal.                      |
| Failed      | Unrecoverable error. Terminal.                       |

### Transition Flow

```
Unloaded → Allocated → QueueReady → Active → Removing → Removed
   │           │            │          │         │
   └───────────┴────────────┴──────────┴─────────┘
                  (error → Failed)
```

### Construction-Phase Digests

`TidefsBlockDevice::new()` runs three BLAKE3-verified transitions internally:
1. `alloc_gendisk` — validates device parameters
2. `alloc_queue` — configures request queue limits
3. `add_disk` — marks the device active

The resulting digests are exposed via `lifecycle_digests()` for validation
validation. Two devices with identical parameters produce identical digests;
devices with different names, capacities, or sector sizes produce distinct
digests.

## Submit-Bio / queue_rq I/O Data-Path Validation

The old crate-local in-memory submit_bio validation harness was removed.
Submit-bio and queue_rq claims must be proven by Linux 7.0 QEMU or mounted
kernel block-device artifacts that load the kernel module and exercise the
real device node.


## Ioctl Dispatch

The `ioctl` module (`src/ioctl.rs`) translates Linux block-layer ioctl command
numbers into backend operations. It classifies incoming `ioctl(cmd, arg)` calls,
validates user-pointer arguments, and dispatches to the `BlockBackend` trait
methods. Unsupported commands return `-ENOTTY`.

### Handled Commands

| Command | Number | IoctlCommand Variant | BlockBackend Method | Returns |
|---------|--------|-----------------------|---------------------|---------|
| `BLKGETSIZE64` | `0x80081272` | `GetSize64` | `capacity()` | `IoctlOutcome::Capacity(u64)` |
| `BLKFLSBUF` | `0x00001261` | `FlushBuf` | `flush()` | `IoctlOutcome::Ok` |
| `BLKROSET` | `0x0000125D` | `SetReadOnly` | -- (sets internal flag) | `IoctlOutcome::Ok` |
| `BLKROGET` | `0x0000125E` | `GetReadOnly` | -- (reads internal flag) | `IoctlOutcome::ReadOnly(bool)` |
| `BLKSSZGET` | `0x00001268` | `GetSectorSize` | `sector_size()` | `IoctlOutcome::SectorSize(u32)` |
| `BLKPBSZGET` | `0x0000127B` | `GetPhysicalSectorSize` | `sector_size()` | `IoctlOutcome::PhysicalSectorSize(u32)` |
| `BLKIOMIN` | `0x00001278` | `GetIoMin` | `sector_size()` | `IoctlOutcome::IoMinSize(u32)` |
| `BLKIOOPT` | `0x00001279` | `GetIoOpt` | `sector_size()` | `IoctlOutcome::IoOptSize(u32)` |
| `BLKALIGNOFF` | `0x0000127A` | `GetAlignmentOffset` | -- (returns 0) | `IoctlOutcome::AlignmentOffset(u32)` |
| `BLKIOMIN` | `0x00001278` | `GetIoMin` | `sector_size()` | `IoctlOutcome::IoMinSize(u32)` |
| `BLKIOOPT` | `0x00001279` | `GetIoOpt` | `sector_size()` | `IoctlOutcome::IoOptSize(u32)` |
| `BLKALIGNOFF` | `0x0000127A` | `GetAlignmentOffset` | -- (returns 0) | `IoctlOutcome::AlignmentOffset(u32)` |

### Error Returns

| Errno | Value | Condition |
|-------|-------|-----------|
| `ENOTTY` | -25 | Unrecognised ioctl command |
| `EFAULT` | -14 | Null user-pointer argument for pointer-requiring commands (BLKGETSIZE64, BLKROGET, BLKSSZGET, BLKPBSZGET, BLKIOMIN, BLKIOOPT). BLKALIGNOFF does not require a valid arg pointer and returns 0 even with arg=0. |
| `EIO` | -5 | Backend flush failure (BLKFLSBUF) |
| `EINVAL` | -22 | Invalid argument value (reserved) |

### BLKALIGNOFF

Returns `0` — TideFS has no allocation alignment offset. This command does not
require a valid user-pointer argument; a null arg (0) is accepted without EFAULT.

### BLKIOMIN / BLKIOOPT

Both return the backend's logical block (sector) size as the minimum and optimal
I/O size. In the kernel build environment, the kernel binding reads these values
from the `request_queue` limits (`io_min` and `io_opt`), which may differ from
the logical block size.

### Read-Only Gate

`TidefsBlockDevice` tracks a `read_only` flag controlled via `BLKROSET` /
`BLKROGET` and exposed through `set_read_only(bool)` / `is_read_only() -> bool`.
When the flag is set, all write-bio submissions are rejected with
`BridgeError::InvalidState { detail: "device is read-only" }`.

### Integration

`TidefsBlockDevice::ioctl(cmd, arg)` wraps `dispatch_ioctl()` and passes the
device backend plus its `read_only` flag. A future Kbuild ioctl callback should
call this method after extracting `cmd` and `arg` from the kernel `ioctl`
invocation.

### Validation Coverage

`src/ioctl.rs` contains 39 unit tests covering:
- Command classification for all 9 handled commands plus unknown/zero commands
- `IoctlCommand::Display` and derived `Debug`/`Clone`/`Copy`/`Eq`
- `IoctlOutcome` Debug/Clone
- `dispatch_ioctl` for every handled command with valid and null-pointer args (plus BLKALIGNOFF which accepts null)
- BLKROSET/BLKROGET round-trip (set writable, set read-only, query)
- ENOTTY for unrecognised commands
- Capacity query on a minimal (1-sector) device
- BLKIOMIN/BLKIOOPT return the logical block (sector) size as min/optimal I/O size
- BLKALIGNOFF always returns 0 (no alignment offset for TideFS)


## Blk-mq Request Completion Lifecycle

Each I/O request flows through a tag-based completion lifecycle modelled on the Linux blk-mq subsystem:

1. **Tag allocation** — A free tag is claimed from the tag pool (max depth 64). If no tags are available, the submitter blocks.
2. **submit_bio dispatch** — The request is dispatched to `BlockExportQueue::dispatch_bio`, which validates the bio range, executes the read/write/flush/discard against the backing buffer, and returns a completion status.
3. **I/O completion** — After the data transfer completes, the bio payload is available for verification.
4. **Tag release** — The tag is returned to the pool. `free + active == depth` must hold at all times.
5. **blk_status_t signaling** — The completion status (Ok or IoError) propagates to the caller, matching the Linux `blk_status_t` contract.

### Validation Coverage

The old in-memory completion-lifecycle validation harness was removed. Request
completion proof must come from QEMU/mounted-kernel block I/O validation or a
concrete product blocker.


## Request Completion Dispatch (blk_mq_end_request bridge)

The `request_completion` module (`src/request_completion.rs`) bridges VfsEngine
block I/O outcomes to Linux `blk_mq_end_request`, closing the
dispatch-to-completion loop after `queue_rq` dispatches work to VfsEngine.

### Data-Path Contract

```
queue_rq dispatch
  → VfsEngine::block_read / block_write / block_flush / block_discard
  → CompletionOutcome (status + bytes_transferred + bytes_requested)
  → RequestCompletion::complete()
    → blk_mq_end_request(status, bytes)
```

### blk_status_t Error Taxonomy

| VfsEngine Errno | BlkMqStatus  | blk_status_t    | Kernel Code | Retry? |
|-----------------|--------------|-----------------|-------------|--------|
| Success         | `Ok`         | `BLK_STS_OK`    | 0           | —      |
| `ENOSPC`        | `NoSpace`    | `BLK_STS_NOSPC` | 4           | No     |
| `EIO`           | `IoError`    | `BLK_STS_IOERR` | 1           | No     |
| `ENXIO`         | `Medium`     | `BLK_STS_MEDIUM`| 5           | No     |
| `ENOSYS`        | `IoError`    | `BLK_STS_IOERR` | 1           | No     |
| other           | `IoError`    | `BLK_STS_IOERR` | 1           | No     |
| —               | `Resource`   | `BLK_STS_RESOURCE` | 2       | Yes    |

### Partial Completions

When a VfsEngine block read or write returns fewer bytes than requested
(`bytes_transferred < bytes_requested`), the completion carries
`BlkMqStatus::Ok` with the actual byte count. The block layer uses
`blk_update_request` to advance the residual before the final
`blk_mq_end_request`.

`CompletionOutcome::partial(bytes_transferred, bytes_requested)` captures
short completions. `CompletionOutcome::residual()` returns the remaining
byte count for use with `blk_update_request`.

### CompletionOutcome

```rust
pub struct CompletionOutcome {
    pub status: BlkMqStatus,      // blk-mq status code
    pub bytes_transferred: u32,   // bytes actually transferred
    pub bytes_requested: u32,     // bytes originally requested
}
```

Constructors:

| Method | Description |
|--------|-------------|
| `ok(bytes)` | Full success: all bytes transferred |
| `partial(transferred, requested)` | Short read/write: some bytes transferred |
| `err(status, requested)` | Error: no bytes transferred |

### RequestCompletion

```rust
pub struct RequestCompletion { ... }

impl RequestCompletion {
    pub fn complete(&mut self, outcome: CompletionOutcome) -> CompletionOutcome;
    pub fn total_bytes_transferred(&self) -> u64;
    pub fn completion_count(&self) -> u64;
    pub fn error_count(&self) -> u64;
    pub fn reset_counters(&mut self);
}
```

Cargo builds record the outcome for test verification. The Kbuild entrypoint
owns the real `blk_mq_end_request` call after it translates request outcomes
to Linux block status values.

### Kernel Module Integration

In the `tidefs_block_kmod.rs` `Operations::queue_rq` callback:

1. The request is classified (read/write/flush/discard).
2. Sector, count, and buffer are extracted.
3. `BlockKmodQueueRq::dispatch()` routes to `VfsEngine`.
4. `QueueRqOutcome` is converted to `CompletionOutcome`.
5. `RequestCompletion::complete()` signals `blk_mq_end_request`.

Until the kernel-UAPI bridge wires a concrete VfsEngine, the `queue_rq`
callback fails closed (returns `QueueRqResult::IoError`).

### Validation Coverage

`src/request_completion.rs` contains 27 unit tests (all passing) covering:

| Scenario | Tests |
|----------|-------|
| CompletionOutcome constructors | 5 tests: ok, partial, error, nospace, medium |
| Residual computation | 1 test: saturating subtraction |
| From\<QueueRqOutcome\> | 2 tests: ok, error conversion |
| From\<Result\<u32, Errno\>\> | 6 tests: ok, enospc→nospace, eio→ioerror, enxio→medium, enosys→ioerror, einval→ioerror |
| completion_from_result | 4 tests: full, partial, over-requested, error |
| RequestCompletion tracking | 5 tests: counts, reset, mixed statuses, debug, default |
| BlkMqStatus completeness | 2 tests: all variants have kernel codes, complete errno mapping |
| Partial completion workflow | 1 test: residual tracking through RequestCompletion |
| Debug/Clone/Eq | 1 test |


## Request Completion Dispatch (blk_mq_end_request bridge)

The  module () bridges VfsEngine
block I/O outcomes to Linux , closing the
dispatch-to-completion loop after  dispatches work to VfsEngine.

### Data-Path Contract



### blk_status_t Error Taxonomy

| VfsEngine Errno | BlkMqStatus  | blk_status_t    | Kernel Code | Retry? |
|-----------------|--------------|-----------------|-------------|--------|
| Success         | Ok           | BLK_STS_OK      | 0           | --     |
| ENOSPC          | NoSpace      | BLK_STS_NOSPC   | 4           | No     |
| EIO             | IoError      | BLK_STS_IOERR   | 1           | No     |
| ENXIO           | Medium       | BLK_STS_MEDIUM  | 5           | No     |
| ENOSYS          | IoError      | BLK_STS_IOERR   | 1           | No     |
| other           | IoError      | BLK_STS_IOERR   | 1           | No     |
| --              | Resource     | BLK_STS_RESOURCE| 2           | Yes    |

### Partial Completions

When a VfsEngine block read or write returns fewer bytes than requested
(bytes_transferred < bytes_requested), the completion carries
BlkMqStatus::Ok with the actual byte count. The block layer uses
blk_update_request to advance the residual before the final
blk_mq_end_request.

CompletionOutcome::partial(bytes_transferred, bytes_requested) captures
short completions. CompletionOutcome::residual() returns the remaining
byte count for use with blk_update_request.

### CompletionOutcome



Constructors:

| Method | Description |
|--------|-------------|
| ok(bytes) | Full success: all bytes transferred |
| partial(transferred, requested) | Short read/write: some bytes transferred |
| err(status, requested) | Error: no bytes transferred |

### RequestCompletion

RequestCompletion records completion outcomes for test verification
(userspace) or calls blk_mq_end_request (kernel mode). It tracks
total bytes, completion count, and error count with reset support.

In the kernel module registration path, the queue_rq callback:
1. Classifies the request (read/write/flush/discard)
2. Extracts sector, count, and buffer
3. Routes through BlockKmodQueueRq::dispatch() to VfsEngine
4. Converts QueueRqOutcome to CompletionOutcome
5. Calls RequestCompletion::complete() -> blk_mq_end_request

### Validation Coverage

src/request_completion.rs contains 27 unit tests (all passing) covering
CompletionOutcome constructors, From conversions, partial-completion
workflow, RequestCompletion tracking with mixed statuses, BlkMqStatus
kernel-code completeness, and the full errno-to-blk_status_t mapping.


## Request Completion Dispatch (blk_mq_end_request bridge)

The `request_completion` module (`src/request_completion.rs`) bridges VfsEngine
block I/O outcomes to Linux `blk_mq_end_request`, closing the
dispatch-to-completion loop after `queue_rq` dispatches work to VfsEngine.

### Data-Path Contract

```
queue_rq dispatch
  -> VfsEngine::block_read / block_write / block_flush / block_discard
  -> CompletionOutcome (status + bytes_transferred + bytes_requested)
  -> RequestCompletion::complete()
    -> blk_mq_end_request(status, bytes)
```

### blk_status_t Error Taxonomy

| VfsEngine Errno | BlkMqStatus  | blk_status_t    | Kernel Code | Retry? |
|-----------------|--------------|-----------------|-------------|--------|
| Success         | Ok           | BLK_STS_OK      | 0           | --     |
| ENOSPC          | NoSpace      | BLK_STS_NOSPC   | 4           | No     |
| EIO             | IoError      | BLK_STS_IOERR   | 1           | No     |
| ENXIO           | Medium       | BLK_STS_MEDIUM  | 5           | No     |
| ENOSYS          | IoError      | BLK_STS_IOERR   | 1           | No     |
| other           | IoError      | BLK_STS_IOERR   | 1           | No     |
| --              | Resource     | BLK_STS_RESOURCE| 2           | Yes    |

### Partial Completions

Short reads/writes (bytes_transferred < bytes_requested) carry
BlkMqStatus::Ok with the actual byte count. The block layer uses
blk_update_request to advance the residual before blk_mq_end_request.
CompletionOutcome::partial() captures short completions; residual()
returns the remaining byte count.

### CompletionOutcome

```rust
pub struct CompletionOutcome {
    pub status: BlkMqStatus,      // blk-mq status code
    pub bytes_transferred: u32,   // bytes actually transferred
    pub bytes_requested: u32,     // bytes originally requested
}
```

Constructors: ok(bytes) for full success, partial(transferred, requested)
for short I/O, err(status, requested) for errors.

### RequestCompletion

RequestCompletion records completion outcomes for test verification
(userspace) or calls blk_mq_end_request (kernel mode). It tracks
total bytes, completion count, and error count with reset support.

In the kernel module registration path, the queue_rq callback:
1. Classifies the request (read/write/flush/discard)
2. Extracts sector, count, and buffer
3. Routes through BlockKmodQueueRq::dispatch() to VfsEngine
4. Converts QueueRqOutcome to CompletionOutcome
5. Calls RequestCompletion::complete() -> blk_mq_end_request

### Validation Coverage

src/request_completion.rs contains 27 unit tests (all passing) covering
CompletionOutcome constructors, From conversions, partial-completion
workflow, RequestCompletion tracking with mixed statuses, BlkMqStatus
kernel-code completeness, and the full errno-to-blk_status_t mapping.


## Build

```sh
# Userspace (no_std, without kernel bindings)
cargo build -p tidefs-block-kmod

# Linux 7.0 .ko build (requires linux-prepare shared source/build)
KDIR=/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/source \
O=/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build \
MO=/tmp/tidefs-block-kmod-module-out \
KBUILD_JOBS=8 \
make -j8 -C crates/tidefs-block-kmod

# Run all tests
cargo test -p tidefs-block-kmod
```

## GenDisk Device Registration

The active Linux 7.0 registration path lives in `tidefs_block_kmod.rs`, not in
the cargo library. Kbuild compiles that file as the module entrypoint and
includes `src/lib.rs` only for the reusable device/dispatch model.

1. `TidefsBlockModule::init()` creates the blk-mq tag set and
   `TidefsBlockDevice`.
2. `TidefsDisk::register()` allocates the gendisk/request queue with queue
   limits, write-cache/FUA flags, and owned queue data.
3. `device_add_disk()` makes `/dev/tidefs` visible.
4. On module unload, `TidefsDisk::drop()` calls `del_gendisk()` and releases
   the owned queue data.

### Module Parameter

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `DEVICE_NAME` | `&str` | `"tidefs"` | Base name for the block device (`/dev/<name>`) |

Set at module load:

```sh
modprobe tidefs_block_kmod
```

### Modprobe / Rmmod Usage

```sh
# Load the kernel module — /dev/tidefs appears
modprobe tidefs_block_kmod

# Verify the device node and sysfs queue attributes
ls -l /dev/tidefs
cat /sys/block/tidefs/queue/logical_block_size   # 512
cat /sys/block/tidefs/queue/physical_block_size  # 4096
cat /sys/block/tidefs/queue/rotational           # 0 (NONROT)

# Smoke test: write and read back a sector via dd
dd if=/dev/zero of=/dev/tidefs bs=4096 count=1
dd if=/dev/tidefs of=/tmp/readback.bin bs=4096 count=1

# Unload — del_gendisk and queue-data cleanup run from TidefsDisk::drop()
modprobe -r tidefs_block_kmod

# Confirm the device node is gone
test ! -e /dev/tidefs && echo "OK: device removed"
```

### Teardown Order Guarantee

The Kbuild module entrypoint owns the teardown sequence:

```
modprobe -r
  → TidefsBlockModule::drop()
    → TidefsDisk::drop()
      1. del_gendisk(gendisk)       // remove /dev node, sysfs entries
      2. drop queue data owner      // release BlockQueueData
```

The old `src/gendisk.rs`/`module_registration` cargo-feature path was removed
because it depended on stale Rust-for-Linux APIs and conflicted with the
working Kbuild registration authority.


## Bio Request Dispatch Architecture

The dispatch path bridges Linux `bio` requests submitted to the TideFS gendisk
into storage-backend read/write/flush/discard calls through the BLAKE3-verified
dispatch engine.

### Architecture

```
Linux block layer (blk-mq queue_rq)
  ↓
BlockKmodQueueRq::dispatch() or TidefsBlockDevice::submit_kernel_bio()
  ↓
DispatchEngine::dispatch(bio)
  ├─ classify: BioOp::Read/Write/Flush/Discard
  ├─ validate: sector range, device state (active/fenced)
  ├─ execute: BlockBackend trait → PoolCoreBackend or explicit BlockExport bring-up buffer
  └─ record: BLAKE3-256 dispatch digest (domain: tidefs-block-kmod-dispatch-v1)
```

In the Kbuild module entrypoint, `queue_rq` extracts I/O parameters from the C
`struct request`, walks the bio chain, maps pages with `kmap_local_page`,
copies data into/out of a kernel transfer buffer, and dispatches through
`submit_kernel_bio`.
Linux 7.0 does not provide Rust `Bio` or bio-iterator wrappers; bio fields
are accessed through `unsafe` C-bindgen dereference.

### BlockBackend Trait

The `BlockBackend` trait decouples dispatch logic from storage implementation.
In the in-memory model, `BlockExport` implements `BlockBackend` with a flat
byte buffer. In kernel mode, `PoolCoreBackend` implements `BlockBackend` by
routing sector-relative logical-volume operations through the pool-core
adapter. The current `RawBlockFile` bridge is still a bring-up path toward the
shared `KernelPoolCore` authority described above, not a separate production
store.

### BioOp Classification

Incoming bios are classified by operation type:

| Linux REQ_OP | BioOp | Description |
|---|---|---|
| REQ_OP_READ (0) | Read | Read sectors from the device |
| REQ_OP_WRITE (1) | Write | Write sectors to the device |
| REQ_OP_FLUSH (4) | Flush | Flush volatile write caches |
| REQ_OP_DISCARD (3) | Discard | Discard (trim/unmap) sector range |

FLUSH takes priority: a bio carrying both FLUSH and data flags is classified
as Flush, matching Linux semantics.

### BLAKE3 Dispatch Validation

Every dispatch produces a deterministic BLAKE3-256 digest (domain:
`tidefs-block-kmod-dispatch-v1`) covering the operation type, sector range,
payload hash, dispatch sequence number, and cumulative byte counters.
Two identical dispatch sequences produce identical digest chains.

### Dispatch Lifecycle

1. **Active**: Accepting bios (QueueReady→Active transition activates the engine).
2. **Fenced**: Rejecting bios (blk_mq_quiesce_queue equivalent).
3. **Inactive**: Rejecting bios (after deactivate / during Removing).

### Validation Coverage

The old in-memory dispatch-path validation harness was removed. Dispatch
validation now belongs in the Linux 7.0 QEMU block-kmod runners.


## Open/Release Lifecycle

The block device `open` and `release` operations are implemented via
[`BlockOpenGuard`] with FMODE_EXCL enforcement and backend lifecycle
integration through the [`BlockLifecycle`] trait.

### FMODE_EXCL Contract

- **Non-exclusive open**: Succeeds as long as no exclusive holder owns the
  device. Multiple non-exclusive opens may be active concurrently.
- **Exclusive open (FMODE_EXCL)**: Succeeds only when the device has zero
  active open handles. Once an exclusive holder owns the device, all
  further open requests — exclusive or non-exclusive — are rejected with
  EBUSY until the exclusive holder releases.
- **Last close**: When the open count drops to zero, the exclusive-hold
  flag is cleared and backend teardown is triggered.

### Backend Lifecycle

First open triggers [`BlockLifecycle::init`] on the storage backend for
one-time resource allocation and integrity validation. If init fails,
the open is rejected and the guard state is rolled back.

Last close triggers [`BlockLifecycle::teardown`], which flushes pending
writes and releases backend resources. The dispatch engine is deactivated
and the device transitions to the Removing→Removed lifecycle states.

### Thread Safety

`BlockOpenGuard` is not internally synchronized. The caller (kernel block
device operation handlers) is responsible for serializing open/release
calls. In the Linux kernel, the block layer already serializes `open`
and `release` per gendisk via the `bd_mutex`.

### Validation Coverage

The open/release lifecycle is validated in `src/open_release.rs` with
14 unit tests covering:

| Scenario | Tests |
|----------|-------|
| Non-exclusive open/release | Open succeeds, count tracked, release reduces count |
| Exclusive open/release | FMODE_EXCL succeeds, second exclusive rejected with EBUSY |
| Conflict enforcement | Exclusive after non-exclusive rejected; non-exclusive after exclusive rejected |
| Last-close teardown | Open count drops to zero, guard resets, re-open succeeds |
| Interleaved open/release | Mixed exclusive/non-exclusive cycles maintain correct counts |
| Empty-guard release | Release on zero-count guard is safe (underflow guarded) |

## Kernel Safety Boundaries (A14 audit — #5808)

This crate consumes the bridge safety contract from `tidefs-kmod-bridge`
(`kmod/`).  See that crate's README for the full invariant list.  The
following crate-specific rules apply.

### Opaque-pointer usage

`OpaqueBio` and `OpaqueRequestQueue` handles are constructed via
`unsafe { OpaqueBio::from_ptr(ptr) }` with a `// SAFETY:` comment naming
the kernel guarantee (e.g., bio submitted by block layer holds a reference).
Sentinels (null pointers used in default/test contexts) are permitted only
when the handle will never be dereferenced.

### Callback registration

`block_device_operations` dispatch tables register Rust functions as kernel
C callbacks via `module!`.  Signature matching is mandatory — mismatched
ABI is undefined behavior.  The `#![deny(unsafe_op_in_unsafe_fn)]` attribute
requires explicit `unsafe {}` blocks at every raw-pointer construction site.

### Lock class discipline

`KernelLockClass` and `WorkqueueFamily` discriminants follow the bridge order.
No crate-local lock class or workqueue family may be introduced without
updating the current kernel residency authority and the bridge definitions.

### Deviations and blockers

The `#![deny(unsafe_op_in_unsafe_fn)]` attribute allows unsafe blocks for
opaque-pointer construction while preventing implicit unsafe operations
inside unsafe functions.  No upstream Rust-for-Linux deviations are
recorded at this time.


## Request-Queue I/O Dispatch Validation

The old `block_kmod_io_dispatch_validation.rs` SourceModel/CargoUnit validation
report is retired. Request-queue dispatch claims must come from the Linux 7.0
QEMU harness at `nix/vm/block-kmod-io-dispatch-validation.nix`, which loads
the product module and exercises the real block device node. In-memory rows and
cargo-only dispatch rows are not product acceptance for block I/O.

## Kmod-Block Crash-Consistency Validation

The old `kmod_block_crash_consistency.rs` schema report is retired. Kernel
block crash-consistency validation must come from Linux 7.0 QEMU logs
that load the product module, run block I/O, inject the crash/reload boundary,
and verify committed-root recovery. Source/model and cargo rows are not release
proof for this gate.
