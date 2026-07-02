# tidefs-kmod-posix-vfs

TideFS kernel POSIX VFS adapter — clean-read namespace seam (K7-05, stratum s3 / c7).

This crate implements the kernel-side adapter that delegates Linux VFS operations
(lookup, getattr, read, write, create, mkdir, rmdir, rename, xattr, etc.) to
the canonical `VfsEngine` trait through the kmod-bridge substrate.

This README is crate-local source orientation. Product-level kernel residency,
full-kernel/no-daemon, and release-readiness authority stays with
`docs/KERNEL_RESIDENCY_AUTHORITY.md`, `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`,
`validation/claims.toml`, and the generated claim registry.

## Mount Path Tiers

The kernel filesystem driver currently exposes source-backed refusal and
engine-backed mount behavior, with the full-kernel/no-daemon tier kept as a
blocked future target rather than a current product claim:

| Tier | Mount Command | Behavior | Kernel Context |
|------|---------------|----------|----------------|
| **Tier 0: Authority refusal** | `mount -t tidefs -o bootstrap none <mnt>` | Refused with EOPNOTSUPP: no explicit kernel pool I/O authority is bound. | None |
| **Tier 1: Fail-closed** | `mount -t tidefs none <mnt>` | Refused with ENODEV: no block device supplied. | None |
| **Tier 2: Engine-backed** | `mount -t tidefs /dev/... <mnt>` | Reads PoolLabelV1 from block device, locates and validates committed-root ledger via Rust replay adapter (`tidefs_posix_vfs_kernel_replay_mount` — #6262), creates real root inode with engine-derived superblock parameters. Statfs reports pool-backed capacity. Individual VFS operation rewiring to object/extent/intent readers is owned by sibling work items #6258-#6261. | `tidefs_posix_vfs_mount` with `engine_backed=true`, populated from `TidefsReplayMountOut`; `fill_super_bdev` delegates mount authority to the Rust replay adapter. Validation tier: Kbuild (module build). QEMU guest mount validation is owned by #6263 (K7-REPLAY-008). |
| **Tier 3: Full-kernel** | (future; blocked) | Not current behavior. This tier requires accepted evidence for normal mounted I/O, writeback, recovery, placement, reserve, and admission without required support daemons before the wording can strengthen. | Future kernel-resident `VfsEngine`/`KernelPoolCore` path with the claim gate updated for the exact tier |

The C registration shim ([tidefs_posix_vfs_shim.c](tidefs_posix_vfs_shim.c))
and Rust bridge ([tidefs_posix_vfs_main.rs](tidefs_posix_vfs_main.rs))
coordinate the Tier 2 mount path through three extern-C bridges:
`tidefs_posix_vfs_engine_parse_label`,
`tidefs_posix_vfs_engine_mount_with_label`, and
`tidefs_posix_vfs_kernel_replay_mount` (the Rust replay adapter, #6262).

Tier 3 remains blocked by the `kernel-residency-boundary` gate in
`validation/claims.toml`; the Tier 2 rows above do not imply production
kernel-resident storage authority or full-kernel/no-daemon readiness.

## Daemon Independence

This crate has zero dependencies on userspace daemon crates
(`tidefs-fuser`, `tidefs-posix-filesystem-adapter-*`,
`tidefs-block-volume-adapter-*`). Its dependency tree consists solely of
no_std-compatible types crates, the canonical `VfsEngine` abstraction, and
the kmod-bridge substrate. No daemon-only contracts, types, or initialization
patterns are transitively pulled into the kernel build.

Verified with:
```sh
cargo tree -p tidefs-kmod-posix-vfs --edges normal | grep -iE 'tidefs-fuser|posix-filesystem-adapter|block-volume-adapter'
# (produces no output)
```

## Kernel Mount Initialization

The kernel-side mount(2) path initializes a TideFS pool entirely in-kernel
without any userspace daemon, helper process, or upcall. The sequence
is implemented in three modules:

1. **PoolImportContext** ([`mount.rs`](src/mount.rs)) — scans the block
   device label buffer, validates the TideFS pool label (PoolLabelV1
   wire format with-256 checksum), and locates the superblock
   region via `system_area_pointer`.

2. **MountRootSelector** ([`mount.rs`](src/mount.rs)) — reads the
   committed-root ledger from the superblock region (wire format: b"VCRL"
   header, 80-byte self-hashing entries, BLAKE3 footer), validates each
   candidate, and selects the most recent valid [`CommittedRootAnchor`]
   (highest transaction group).

3. **KernelIntentReplay** ([`intent_replay.rs`](src/intent_replay.rs)) —
   replays intent-log records from the selected committed root forward
   through [`VfsEngine`], applying namespace mutations (create, unlink,
   mkdir, rmdir, rename, link, symlink, mknod, tmpfile, truncate,
   setattr, xattr, buffered-write) to bring the namespace to a
   crash-consistent state. No-op markers (Flush, Fsync, WriteIntentAck,
   Lseek, CleanupQueue) are safely skipped. Data-mutation records (Write,
   Fallocate, CopyFileRange) are gated — mount fails when encountered
   during recovery because skipping them would leave files with stale or
   missing content. Replay is idempotent: `EEXIST` from the engine is
   treated as success.

The **KernelMountSequence** ([`kernel_mount.rs`](src/kernel_mount.rs))
orchestrates the full pipeline:

```text
device label buffer → PoolImportContext
    │
    ▼
superblock region buffer → MountRootSelector → CommittedRootAnchor
    │
    ▼
intent record buffers → KernelIntentReplay → crash-consistent namespace
```

### Recovery mode

Mount option behaviour for read-only and recovery-mode control:

- **Normal read-write mount** (`mount -t tidefs /dev/... /mnt`): auto-detects
  persisted intent-log records from the VRBT intent_log_tail field.  When
  records are found, the kernel reads them from the data area and replays
  them through the Rust mount sequence.
- **Read-only mount** (`mount -t tidefs -o ro /dev/... /mnt`): skips intent-log
  detection and replay entirely.  The filesystem mounts the latest committed
  root as-is with no storage mutation.  All write operations (create, mkdir,
  rmdir, unlink, rename, symlink, link, mknod, write, truncate, setattr)
  return `EROFS`.
- **Emergency recovery mode** (`mount -t tidefs -o ro,recovery /dev/... /mnt`):
  mounts read-only but forces intent-log replay before mounting.  This is the
  emergency recovery path: replay crash-recovery intents, inspect filesystem
  state, and then unmount without accepting new writes.  When `-o recovery` is
  paired with `-o ro`, the kernel reads and replays intent-log records before
  bringing the filesystem online read-only.
- **Explicit recovery mode** (`mount -t tidefs -o recovery /dev/... /mnt`):
  forces intent-log detection and replay even when no records are found,
  enabling clean mount with an empty intent log in recovery context.

### No-daemon boundary

All three phases operate entirely through the kernel-resident VfsEngine
and kmod-bridge substrate. No FUSE daemon, ublk daemon, policy daemon, or
usermode worker thread is required during any phase of mount initialization.
That statement is limited to mount initialization and does not validate Tier 3
full-kernel/no-daemon storage behavior.

### Current mounted basic-ops slice (#6144)

The first product-mount operation slice is intentionally direct and limited:
the mounted C shim stores a small fixed in-kernel namespace/data table in the
pool data region immediately after the label/superblock area. That table lets
the Linux 7.0 QEMU gate exercise real block-device `mount -t tidefs` behavior
without any userspace daemon:

- create and write a regular file, then read it back;
- create a subdirectory and nested file, then enumerate the parent directory;
- sync, unmount, remount the same block device, and read both files back from
  persisted kernel state;
- unlink both files, rmdir the subdirectory, unmount cleanly, unload the module,
  and scan for kernel warnings.

Validation: `/tmp/tidefs-workers/s995/kernel-dev/issue-6144/qemu-runs/basic-ops-rebased-20260520T152600Z/qemu.log`
reports `RESULTS: pass=24 fail=0 blocked=0`.

The mounted mutation path republishes committed roots after successful
state/data writes. New pool images reserve four 4 KiB system-area blocks: the
first block remains the VCRL ledger for current mount selection, the second and
third blocks store duplicate VCRP pointer records, and the fourth block stores
the canonical VRBT committed-root block. Existing 4 KiB system-area images
remain mountable and continue to receive VCRL updates, but skip VRBT/VCRP
publication with an explicit warning.

The #6225 Linux 7.0 QEMU proof shows the first mount selecting `txg=1`, mounted
mutations publishing VCRL+VCRP+VRBT through `txg=6`, remount selecting `txg=6`,
and the guest asserting that VRBT/VCRP publication was not skipped:
`/tmp/tidefs-workers/s22/kernel-dev/issue-6225/qemu-runs/vrbt-system-area-20260520T174015Z/qemu.log`
reports `RESULTS: pass=27 fail=0 blocked=0`. Earlier VCRL-only validation:
`/tmp/tidefs-workers/s999/kernel-dev/issue-6225/qemu-runs/committed-root-ledger-20260520T144036Z/qemu.log`
reported `RESULTS: pass=25 fail=0 blocked=0`.

This is not the final storage engine. The fixed table must be replaced by the
full object/extent/intent-log engine before page-cache/writeback, xfstests,
crash consistency, or terminal full-kernel no-daemon claims are valid.

### Committed-root persistence

The `write_committed_root` method on `VfsEngine` bridges transaction-group
commit to durable pool-label superblock persistence. After each txg commit
(`txg_commit_finish`), the engine writes the committed root into the pool
label so the next mount discovers the latest committed state without
userspace daemon mediation.

The `KernelEngine` in `tidefs_posix_vfs_main.rs` overrides `write_committed_root`
with a precise blocker: label persistence requires `KernelPoolCore` block-device
integration (see issue #6150). Once `KernelPoolCore` is wired with lower-device
block I/O, the override will serialize the committed root into the `commit_group`
field of `PoolLabelV1` and issue a synchronous block write to the label region.


## no_std status

The crate compiles as `#![no_std]` with `extern crate alloc`. All 34 source files
use `core` and `alloc` exclusively; no `std` types, macros, or linkage are
involved. Verified with `cargo check` and `RUSTFLAGS="-D warnings"`.

## Dependencies

| Crate | Role | Location |
|-------|------|----------|
| `tidefs-types-vfs-core` | Portable no_std VFS boundary types | `../tidefs-types-vfs-core` |
| `tidefs-vfs-engine` | Canonical `VfsEngine` trait (29 ops) | `../tidefs-vfs-engine` |
| `tidefs-kmod-bridge` | Kernel-boundary trait contracts + opaque Linux object facades | `../../kmod` |

The `tidefs-kmod-bridge` acts as a userspace shim during `cargo check`. When
built inside the Linux 7.0 kernel tree, the kernel build system replaces it with
the concrete Rust-for-Linux `kernel` crate bindings.

## Build instructions

### Cargo check (userspace validation)

```sh
cargo check -p tidefs-kmod-posix-vfs
```

Passes cleanly with zero errors and zero warnings.

### Kernel module build (Linux 7.0 tree)

Requires a prepared Linux 7.0 kernel build tree with Rust-for-Linux support
(K7-02). The kernel build system (Kbuild) compiles the crate as a `staticlib`
and links it into a `.ko` kernel module. The `#[global_allocator]` and
`#[panic_handler]` are supplied by the kernel build environment.

```sh
# One-time: prepare the kernel tree
nix/kmod-hot-loop.sh prepare

# Build the kernel module (requires K7-05 wiring in the kernel build)
make -C /path/to/linux-7.0 M=$PWD/kmod/smoke_module modules
```

The smoke module at `kmod/smoke_module/` provides a minimal Rust-for-Linux
out-of-tree build template that validates the toolchain end-to-end.

## Directory Validation

The old crate-local directory validation harnesses were removed because they
were mock-backed and could not close mounted-kernel behavior. Directory lookup,
readdir, create, unlink, mkdir, rmdir, and rename proof must now come from
Linux 7.0 QEMU or mounted-kernel artifacts tied to the product module.
- **Error transparency**: Engine errors (EIO, ENOTDIR) propagate unchanged
  through the adapter without masking or transformation.

## Mount Options

The `mount_options` module parses comma-separated `key=value` mount option strings
passed by the Linux VFS `mount(2)` system call. Parsed options are stored in
`KmodPosixVfs::mount_options` and drive runtime behaviour such as read-only mode,
debug output, recovery-mode admission, and commit-timeout selection.

### Supported options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `device=<path>` | string | (empty) | Backing device or pool path |
| `ro` | flag | off | Mount read-only |
| `rw` | flag | on (default) | Mount read-write |
| `debug` | flag | off | Enable debug diagnostics |
| `recovery` | flag | off | Mount in recovery mode (intent-log replay before writes) |
| `commit_timeout_ms=<N>` | u64 | 5000 | Commit timeout in milliseconds |

### Parsing format

Options are comma-separated. Flags (`ro`, `rw`, `debug`, `recovery`) do not take
a value; supplying one (e.g. `ro=1`) returns an `InvalidValue` error. Duplicate
keys are rejected with `DuplicateOption`. Unknown keys produce `UnknownOption`.

Example:
```
device=/dev/tidefs/pool0,ro,recovery,commit_timeout_ms=10000
```

### Error variants

- `UnknownOption { key }` — unrecognized option key
- `InvalidValue { key, value, reason }` — value parse failure
- `MissingRequired { key }` — required option not supplied
- `DuplicateOption { key }` — same key appeared more than once

### API

- `MountOptions::default()` — sensible defaults (rw, no-debug, recovery off, 5000 ms)
- `MountOptions::parse(input: &str) -> Result<MountOptions, MountOptionError>` — parse a mount option string
- `MountOptions::compute_digest() -> [u8; 32]` — BLAKE3-256 domain-separated config digest (`tidefs-kmod-mount-options-v1`)
- `KmodPosixVfs::parse_mount_options(&mut self, option_string: &str)` — parse and store options on a mounted instance
- `superblock::fill_super_admit(...)` — combined fill_super path: parse options, validate committed-root, store config

### Validation

All mount-option parsing tests are in the `mount_options` test module. The
BLAKE3 domain-separated digest (`tidefs-kmod-mount-options-v1`) provides
deterministic configuration identity for full-kernel validation harnesses.

Run:
```sh
cargo test -p tidefs-kmod-posix-vfs -- mount_options
```

## Address Space Operations

The mounted Linux 7.0 product path registers its live
`address_space_operations` vtable in
[`tidefs_posix_vfs_shim.c`](tidefs_posix_vfs_shim.c). Engine-backed mmap is
admitted by `tidefs_posix_vfs_file_mmap()` through `generic_file_mmap()`, and
Linux filemap then calls the registered C `read_folio`, `write_begin`,
`write_end`, `dirty_folio`, and `writepages` callbacks. The Rust
`address_space_ops` module remains a source-model dispatch spine for future
direct C-to-Rust callback work; it is not registered as the mounted product
vtable.

### Operation Matrix

| Operation | Mounted status | VfsEngine Dependency | Daemon Required | Notes |
|---|---|---|---|---|
| `read_folio` | Registered in C | `tidefs_posix_vfs_engine_read` | No | Populates Linux folios for buffered reads and mmap faults. |
| `write_begin` | Registered in C | `tidefs_posix_vfs_engine_read` | No | Reads existing bytes for partial-folio buffered writes. |
| `write_end` | Registered in C | `tidefs_posix_vfs_engine_write` | No | Copies modified folio bytes to the engine. |
| `dirty_folio` | Registered in C | Linux `filemap_dirty_folio()` | No | Records Linux dirty accounting only; it does not call the engine or `DirtyFolioTracker` from atomic MM paths. |
| `writepages` | Registered in C | `tidefs_posix_vfs_engine_write` | No | Walks Linux dirty folios, writes copied bytes, and re-dirties on engine error or short write. |
| `readahead` | Source model only | `VfsEngine::read()` | No | Rust model exists; no mounted C callback is registered yet. |
| `writepage` | Source model only | `VfsEngine::writeback_folios()` | No | No mounted C callback is registered yet. |
| `invalidate_folio` | Source model only | `VfsEngine::invalidate_cache_range()` | No | Mounted truncate/direct-write paths use C Linux page-cache discard helpers instead. |
| `page_mkwrite` | Unsupported direct Rust bridge | `DirtyFolioTracker::try_add()` | No | Linux generic filemap handles shared writable mmap; no custom Rust vm_ops bridge is registered. |
| `fsync` | Registered in C file ops | `tidefs_posix_vfs_engine_fsync` | No | C fsync drains `filemap_write_and_wait_range()` before the engine fsync bridge. |

### Implemented Operations

The C `read_folio`, `write_begin`, `write_end`, `dirty_folio`, and
`writepages` callbacks are the only mounted address-space authority today.
The Rust `AddressSpaceOps` methods are cargo/source-model coverage for a
future direct bridge and must not be cited as mounted runtime proof.

### Writeback Path

The mounted writeback lifecycle is C/generic-filemap based:

1. **write_begin**: C reads existing page data through
   `tidefs_posix_vfs_engine_read` for partial-page write merging.
2. **write_end**: C writes modified folio bytes through
   `tidefs_posix_vfs_engine_write`.
3. **dirty_folio**: C calls Linux `filemap_dirty_folio()` and does not sleep or
   enter the engine.
4. **writepages**: C walks Linux dirty folios with `writeback_iter()`, copies
   folio bytes, writes them through `tidefs_posix_vfs_engine_write`, records
   mapping errors, and re-dirties failed folios for retry.

The Rust `DirtyFolioTracker` maintains an ordered, merged set of
non-overlapping dirty byte ranges for source-model tests. It is not wired into
the mounted Linux callback chain.

#### page_mkwrite

`page_mkwrite` and `KmodVfsVmOps` are Rust source-model code only. The mounted
C shim does not set `vma->vm_ops` to a Rust custom table. Engine-backed mmap
uses Linux generic filemap VM operations plus the C address-space callbacks
above. The Rust direct `KmodPosixVfs::mmap()` entry point fails closed with
`EOPNOTSUPP` so this unsupported bridge cannot be mistaken for product
authority.

### No-Daemon Boundary

The registered C mmap/writeback callbacks resolve through kernel-resident
engine bridges and require no userspace daemon. The Rust source-model helpers
share that no-daemon shape but are not mounted callback proof.


## Intent-Log Recording Contract

Kernel-mode storage mutation operations record intent-log entries through
[`VfsEngine::record_intent_entry`] before committing to durable storage so crash
recovery can replay committed records at mount time. The recording half of
kernel-mode crash safety pairs with mount-time replay ([`intent_replay`] module).

### Operations That Produce Intent Entries

- **Writeback** (`writepage`/`writepages`): write-intent recorded before dirty-page flush
- **Truncate** (`setattr` with size change): truncate-intent recorded before size change
- **Fallocate** (space preallocation): allocate-intent recorded before block alloc
- **Namespace mutations** (create, unlink, rename, mkdir, rmdir, symlink, link, mknod):
  namespace-intent recorded before directory update

### Ordering Guarantee

The intent entry must be durably recorded before the corresponding storage
mutation completes. This ordering ensures that crash recovery observes committed
intent and can replay from the last committed root. The engine is responsible for
making the entry durable; the caller is responsible for calling
`record_intent_entry` before the mutation.

### Relationship to Mount-Time Replay

Mount-time replay ([`intent_replay`] module, #6111) reads committed intent-log
records from the superblock region and dispatches them through VfsEngine to
bring the filesystem to a crash-consistent state. The recording path (#6116)
writes those records during operation.

### No-Daemon Boundary

Intent-log recording resolves entirely within kernel authority through the
kernel-resident VfsEngine. No userspace daemon, helper thread, or upcall is
required for normal intent-log recording.

### Type Stubs

The [`intent_record`] module provides kernel-compatible type stubs:
- [`IntentLogEntry`]: binary-encoded intent-log record ready for dispatch
- [`IntentLogError`]: error type for intent-log recording failures
- [`MAX_INTENT_ENTRY_SIZE`]: maximum record size (4096 bytes)
- [`record_intent`]: convenience helper that validates entry size and dispatches
  through VfsEngine

## Inode Lifecycle Operations

The core inode lifecycle dispatch -- lookup, create, unlink, mkdir, rmdir, link,
and rename -- delegates through the canonical VfsEngine bridge. Each operation
returns a plain result struct with input parameters and engine-computed outcomes.

| Operation | Plan Type | Source File | Tests |
|---|---|---|---|
| lookup | `LookupPlan` | `src/inode.rs` | remaining delegation tests |
| getattr | `InodeAttr` | `src/getattr.rs` | error propagation, field completeness, idempotency |
| create | `CreatePlan` | `src/create.rs` | remaining delegation tests |
| unlink | `UnlinkPlan` | `src/unlink.rs` | remaining delegation tests |
| mkdir | `MkdirPlan` | `src/mkdir.rs` | remaining delegation tests |
| rmdir | `RmdirPlan` | `src/rmdir.rs` | 33 unit tests |
| link | `LinkPlan` | `src/link.rs` | remaining delegation tests |
| rename | `RenamePlan` | `src/rename.rs` | remaining delegation tests |
| symlink | `SymlinkPlan` | `src/symlink.rs` | 20 unit tests (name/target validation, error propagation, readlink roundtrip) |
| setattr | `SetattrPlan` | `src/setattr.rs` | 19 unit tests in `setattr::tests`, 18 attr_consistency tests, 25 setattr_validation tests |

**Inode allocation (#6647)**: `KernelEngine::allocate_inode(kind, parent, mode, uid, gid, nlink, initial_size) -> Result<InodeRecord>` is the authoritative kernel-mode inode allocator. When `KernelPoolCore` I/O is active (mounted production), it reads and updates a persistent allocator state block (next_ino + generation, 16 bytes at `data_area_offset`) through pool_core sector read/write callbacks, so inode identity survives remount and crash. When pool_core I/O is unavailable (unbound/test engine), it falls back to a local `next_ino` counter. All create-family callbacks (`create`, `mkdir`, `mknod`, `symlink`, `tmpfile`) route through this single allocation path.

Each Plan struct carries the operation's input parameters and engine-computed
outcome attributes. Plan types are ordinary dispatch results: they do not
include BLAKE3 digests or cryptographic verification.

### getattr Dispatch

The `getattr` module bridges the kernel VFS `inode_operations::getattr`
callback to `VfsEngine::getattr()`, retrieving committed inode attributes
(inode number, generation, node kind, POSIX attributes including mode, uid,
gid, size, nlink, timestamps, blocks, blksize, rdev, and flags) and
populating the kernel `struct inode` fields for stat/fstat system calls.

#### Attribute Field Mapping (VfsEngine -> kernel inode)

| VfsEngine `InodeAttr` | Kernel `struct inode` | Notes |
|---|---|---|
| `inode_id` | `i_ino` | Inode number |
| `generation` | `i_generation` | Inode generation counter |
| `kind` | `i_mode` type bits | `S_IFREG`, `S_IFDIR`, `S_IFLNK`, etc. |
| `posix.mode` | `i_mode` permission bits | Access mode |
| `posix.uid` | `i_uid` | Owner user ID |
| `posix.gid` | `i_gid` | Owner group ID |
| `posix.size` | `i_size` | File size in bytes |
| `posix.nlink` | `i_nlink` | Hard-link count |
| `posix.blocks_512` | `i_blocks` | 512-byte block count |
| `posix.blksize` | `i_blksize` | Preferred I/O block size |
| `posix.atime_ns` | `i_atime` | Last access (nanoseconds) |
| `posix.mtime_ns` | `i_mtime` | Last modification (nanoseconds) |
| `posix.ctime_ns` | `i_ctime` | Last status change (nanoseconds) |
| `posix.btime_ns` | `i_btime` | Birth/creation time (nanoseconds) |
| `posix.rdev` | `i_rdev` | Device number (dev nodes) |
| `flags` | `i_flags` | Inode flags |

#### Error Handling

| Errno | Condition |
|---|---|
| `ENOENT` | Inode does not exist in engine |
| `ESTALE` | Inode generation invalidated (stale handle) |
| `EIO` | Engine or storage unavailable |
| `EACCES` | Permission denied |
| `ENOSYS` | Operation not implemented by engine |

All errors propagate unchanged from the VfsEngine without local rewriting.
The kernel VFS layer is responsible for translating these errno values to
userspace error codes and handling retry/fallback logic.

#### Bridge Function

The `bridge_getattr` function in `dir_ops_bridge.rs` provides a `dyn`-safe,
no_std-compatible entry point for the getattr dispatch, mirroring the pattern
used by `bridge_lookup`, `bridge_create`, and other namespace operations.

#### Tests

14 unit tests cover: file attribute retrieval, directory attribute retrieval,
file-handle-mediated attribute access, error propagation (ENOENT, ESTALE, EIO,
EACCES, ENOSYS), full POSIX field completeness, symlink kind verification,
device node rdev, zero-size files, large files (1 TiB), and idempotent
repeated calls.

## Directory Operations Bridge

The `dir_ops_bridge` module provides no_std-compatible, `dyn`-safe bridge
functions that serve as the canonical namespace mutation entry point for the
kernel VFS dispatch. Each function delegates directly to the `VfsEngine` trait
without BLAKE3 attestation

| Function | Engine Method | Description |
|---|---|---|
| `bridge_lookup` | `engine.lookup()` | Resolve a directory entry to inode attributes |
| `bridge_create` | `engine.create()` | Allocate inode and insert a regular-file dentry |
| `bridge_rename` | `engine.rename()` | Atomically move or swap entries (NOREPLACE, EXCHANGE) |
| `bridge_unlink` | `engine.unlink()` | Remove a directory entry with nlink decrement |
| `bridge_mkdir` | `engine.mkdir()` | Allocate directory inode and insert a directory dentry |
| `bridge_rmdir` | `engine.rmdir()` | Remove an empty directory entry |
| `bridge_symlink` | `engine.symlink()` | Create a symbolic link entry with target path |
| `bridge_setattr` | `engine.setattr()` | Apply attribute mutation with truncate-block-change detection |

The `KmodPosixVfs` dispatch methods delegate through these bridge functions,
which in turn call the engine. Plan structs capture operation results.
Remaining delegation and error propagation tests cover all operations.

## Rename Dispatch

The `rename` module bridges the kernel VFS `rename(2)` / `renameat2(2)` system
calls to `VfsEngine::rename` through `dir_ops_bridge::bridge_rename`. It
supports the full flag set.

### Supported Flags

| Constant | Value | Semantics |
|---|---|---|
| `RENAME_NOREPLACE` | 1 | Fail with `EEXIST` if destination exists |
| `RENAME_EXCHANGE` | 2 | Atomically swap source and destination entries |
| `RENAME_WHITEOUT` | 4 | Create a whiteout at the source (overlayfs upper) |

Flags may be combined (e.g., `RENAME_NOREPLACE | RENAME_EXCHANGE`).

### VfsEngine Bridge Contract

The engine handles all rename semantics: source-existence validation,
`RENAME_NOREPLACE` enforcement, `RENAME_EXCHANGE` atomic swap, type checks
(`EISDIR`/`ENOTDIR`/`ENOTEMPTY`), cross-directory subdirectory nlink
adjustment (decrement old parent, increment new parent), `..` entry update
for moved directories, self-rename no-op detection, and intent-log
transaction boundaries for crash-consistent replay.

### Public API

- `KmodPosixVfs::rename(old_parent, old_name, new_parent, new_name, flags, ctx)`
  Returns `RenamePlan`.
- `KmodPosixVfs::dispatch_rename(&RenameArgs, ctx)`
  Convenience method accepting a bundled `RenameArgs` struct.
- `RenamePlan::new(...)`
- `RenameArgs::new(old_parent, old_name, new_parent, new_name, flags)`

### Error Codes

`ENOENT`, `EEXIST`, `EACCES`, `ENOTDIR`, `EISDIR`, `ENOTEMPTY`, `EXDEV`,
`EINVAL`, `EIO`, `EROFS`. All errors propagate directly from the engine
without local rewriting.

### Tests

41 unit tests cover: plain rename, `RENAME_NOREPLACE`, `RENAME_EXCHANGE`,
`RENAME_WHITEOUT`, combined flags, all error propagation paths,
cross-directory rename, dispatch equivalence
long names,
empty names, same-directory preservation, and concurrent isolation.

sequences.

## Source inventory

34 source files:

```
bridge.rs          — Kernel module registration via kmod-bridge traits
address_space_ops.rs — Address space operations dispatch spine with blocker matrix
writeback.rs       — Dirty-folio tracker for writeback coordination
copy_file_range.rs — Server-side copy delegation (K7-20)
create.rs          — File creation with inode allocation
create_excl.rs     — Exclusive file creation (O_EXCL|O_CREAT)
dir.rs             — Directory handle state
dir_cursor.rs      — Directory cursor offset tracking for iterative getdents64 calls
dir_ops_bridge.rs   — Directory ops bridge: lookup create rename unlink mkdir rmdir delegation
fallocate.rs       — Space reservation, hole punch, zero, collapse, insert
file.rs            — Open file handle state, dispatch_read, dispatch_write, dispatch_fsync, dispatch_fallocate, dispatch_flush, dispatch_fiemap, dispatch_ioctl (FS_IOC_FIEMAP), dispatch_iterate; open and release delegate through open_release
flush.rs           — Per-fd dirty-data push
fsync.rs           — File and directory durability flush
inode.rs           — Inode attribute lookup and getattr
lib.rs             — Crate root: KmodPosixVfs, LookupResult, handle state types
link.rs            — Hard-link creation with nlink accounting
lock.rs            — Advisory byte-range locking (getlk, setlk)
open_release.rs    — Per-file session lifecycle (bridge_open, bridge_release, FileSession)
mount_options.rs   — Mount option parsing and runtime configuration
mkdir.rs           — Directory creation (MkdirPlan)
mknod.rs           — Device node, FIFO, socket creation
read.rs            — File data read
readahead.rs       — Readahead hint forwarding with page-cache stats
readdir.rs         — Directory iteration with dirent64 packing (K7-23)
rename.rs          — Atomic rename (RENAME_NOREPLACE, RENAME_EXCHANGE)
rmdir.rs           — Directory removal (RmdirPlan)
setattr.rs         — Attribute mutation (SetattrPlan, bridge_setattr): chmod, chown, truncate, utimes
statfs.rs          — Filesystem statistics
statx.rs           — statx field rendering from InodeAttr
superblock.rs      — Mount/super admission
symlink.rs         — Symbolic link creation with intent-log crash safety
syncfs.rs          — Filesystem-wide synchronization
test_util.rs       — Narrow unit-test helper; not release validation
tmpfile.rs         — O_TMPFILE unnamed temporary file creation
unlink.rs          — File removal
write.rs           — File data write
xattr.rs           — getxattr, setxattr, listxattr, removexattr delegation
```

## Validation

Crate-local cargo/mock integration validation harnesses have been retired.
They were useful during bring-up but are not product acceptance for the Linux 7.0
mounted data path. Current validation should target Kbuild, QEMU module load,
mounted-kernel VFS behavior, xfstests/fio, and guest logs.

## Residual blockers

The crate compiles cleanly under `cargo check` with the userspace kmod-bridge
shim. Full kernel-module compilation requires:

- The Linux 7.0 kernel source tree with Rust-for-Linux support (K7-02).
- The `kernel` crate providing `kernel::prelude`, `kernel::Module`, and concrete
  implementations of the kmod-bridge trait contracts (t0–t9).
- A kernel build environment that wires this crate as a leaf module under the
  VFS subsystem (K7-05 integration).

Until K7-02 lands, `cargo check` is only a development smoke check; it does
not close kernel compile or runtime gates.

## Compile Validation (K7-VAL)

The release gate `validation-kmod-compile` (issue #5776) records compile
validation for the kernel build path. Two artifacts:

### Compile script

```sh
bash scripts/compile-kmod-posix-vfs.sh [--output LOGFILE]
```

Runs four phases: cargo check, cargo build, Kbuild (kernel tree), and
kernel-flag simulation. Writes a timestamped log with exit codes and
environment fingerprint.

### Nix build environment

```sh
nix-shell nix/kmod-posix-vfs-build.nix --run \
  'bash scripts/compile-kmod-posix-vfs.sh'
```

### Kbuild integration

The crate has a Kbuild file and Makefile for out-of-tree kernel module
compilation. When a prepared Linux 7.0 kernel tree is available at
`/tmp/tidefs-kmod/linux-7.0`, the compile script attempts `make modules`.

```sh
KDIR=/path/to/linux-7.0 make -C crates/tidefs-kmod-posix-vfs
```

## Kernel Runtime Validation

Issue [#5784](https://forgejo.local/tidefs/tidefs/issues/5784): Programmatic
validation of kmod-posix-vfs runtime mount and POSIX operations in a
reproducible Linux 7.0 Nix/QEMU environment.

### Runtime suite

Kernel runtime validation must run through Linux 7.0 QEMU or mounted-kernel
artifacts. In-process VfsEngine/mock tests are not release validation for this
crate.

### Nix/QEMU validation runner

```sh
nix build .#kmodValidation
./result/bin/tidefs-kmod-validation
./result/bin/tidefs-kmod-validation --timeout 600 --keep-tmp
```

The validation runner (`nix/vm/kmod-validation.nix`) builds a minimal
initramfs with busybox and the kmod-posix-vfs `.ko`, boots Linux 7.0 in QEMU,
and exercises: module_load, mount, statfs, file_create, file_stat, file_read,
file_write, mkdir, rmdir, file_unlink, unmount, and module_unload. Results are
parsed as PASS/FAIL/BLOCKED and exit code 0/1/2 reported. The QEMU output log
(`validation.log`) serves as smoke validation.

Directory namespace operations can be validated with a dedicated QEMU test:

```sh
nix run .#kernel-dir-namespace-validation
# or
nix build .#kernelDirNamespaceValidation
./result/bin/tidefs-kmod-dir-ns-validation --timeout 600 --keep-tmp
```

The directory namespace runner (`nix/vm/kernel-dir-namespace-validation.nix`)
exercises lookup, create, rename, unlink, and rmdir through a kernel VFS mount
with committed-root state capture between operation batches.  See the
"Directory Namespace Validation Validation" section below for tier classification
and validation output schema.

### Retired compile validation harness

The old `tests/compile_validation.rs` cargo test was removed. Parsing historical
compile logs and hashing them is not a kernel build. Kbuild closure requires a
fresh Linux 7.0 build artifact from the product module path or an exact
recorded blocker from that path.



## Kbuild Entry Point (#6125)

The product Kbuild module is `tidefs_posix_vfs.ko`. It is built as a mixed
Rust/C external module:

- `tidefs_posix_vfs_main.rs` is the Rust-for-Linux module entry point and
  includes the product crate source for `.ko` compilation.
- `tidefs_posix_vfs_shim.c` registers the Linux VFS filesystem type
  `tidefs` because the Linux 7.0 Rust tree used by this project does not
  expose a stable `kernel::filesystem` registration API.

Module init registers `tidefs`, so `/proc/filesystems` lists `nodev tidefs`.
Mount attempts intentionally fail closed until a kernel-resident TideFS engine
backs the superblock lifecycle. The guest audit records the exact
blocker in dmesg:

```text
tidefs_posix_vfs: get_root_inode: no kernel-resident pool configured — block-device pool assignment to KernelEngine not yet implemented
tidefs_posix_vfs: fill_super failed: engine error — no kernel-resident pool configured
```

The old root-level `tidefs_kmod_posix_vfs.rs` wrapper was removed because it
referenced `kernel::filesystem::{Registration, FileSystemType}`, which is not
present in the current Linux 7.0 Rust API. Keeping that wrapper made the
design look farther along than the buildable product module actually was.

### Kbuild Validation

Kbuild attempted against Linux 7.0 (forgeadmin/linux, commit 028ef9c96e96):

```
make -C <linux-source> O=<build> M=crates/tidefs-kmod-posix-vfs modules
```

Current result: direct Linux 7.0 Kbuild produces
`tidefs_posix_vfs.ko`, and the disposable QEMU smoke guest loads it,
confirms `nodev tidefs` in `/proc/filesystems`, attempts `mount -t tidefs`,
records the expected engine-not-wired refusal, and unloads the module cleanly.

## Kernel Safety Boundaries (A14 audit — #5808)

This crate consumes the bridge safety contract from `tidefs-kmod-bridge`
(`kmod/`).  See that crate's README for the full invariant list.  The
following crate-specific rules apply.

### Opaque-pointer usage

All kernel object handles (`OpaqueSuperBlock`, `OpaqueInode`, `OpaqueDentry`,
`OpaqueFile`) arriving via VFS callbacks must be constructed through the
bridge's `unsafe fn from_ptr()`.  The `// SAFETY:` comment must cite the
Linux VFS guarantee (e.g., `igrab`/`dget` reference count, or the VFS lock
that pins the object for the operation duration).

### Callback tables

The dispatch tables (`file_operations`, `inode_operations`, `super_operations`,
`address_space_operations`) are defined as library dispatch functions in the
crate's source modules. In the kernel build environment (Kbuild with
`CONFIG_RUST=y`), the module entry point registers the "tidefs" filesystem
type through the companion C VFS shim. The full operation tables still require
the next engine-backed superblock implementation step; static inspection or
registration-only validation must not be claimed as mounted-kernel VFS behavior.

In the userspace model (cargo check), all dispatch functions operate on
kmod-bridge `Opaque*` facades (`OpaqueSuperBlock`, `OpaqueInode`, `OpaqueDentry`,
`OpaqueFile`, `OpaqueFolio`) which map to null pointers or mock handles. The
kernel build environment replaces these with concrete Linux kernel types.

Each callback entry must have a signature matching the kernel's `struct
file_operations` etc. exactly. Signature mismatches are undefined behavior.

### Lock class discipline

`KernelLockClass` and `WorkqueueFamily` discriminants follow the bridge order.
No crate-local lock class or workqueue family may be introduced without
updating the current kernel residency authority and the bridge definitions.

### Deviations and blockers

This crate uses `#![forbid(unsafe_code)]` because all kernel-pointer
construction happens in test scaffolding and in the bridge layer.  When
real Kbuild callback registration is wired, the `forbid` may need to
relax to `deny(unsafe_op_in_unsafe_fn)` for the registration sites.

## Directory Namespace Validation Validation (#5831)

The `tidefs-validation::kernel_dir_namespace_validation` module produces
tier-classified validation output for directory namespace operations
(lookup, create, rename, unlink, rmdir) exercising the `dir_ops_bridge`
dispatch through a kernel VFS mount in Linux 7.0 QEMU.

### Validation Tiers

| Tier | Meaning |
|------|---------|
| basic-correctness | Operation semantics, return values, and errno behavior |
| crash-consistency | Mid-sequence crash, remount, committed-root state verification |
| orphan-prevention | Post-unlink/rmdir inode lifecycle and orphan-index correctness |
| cross-dir-coherence | Cross-directory lookup chains and hard-link namespace coherence |

These rows describe the runtime validation contract. They do not close the gate
unless backed by Linux 7.0 QEMU or mounted-kernel artifacts.

### Operation Coverage

| Operation | Bridge Function | Validated Behaviour |
|-----------|----------------|---------------------|
| Lookup | `bridge_lookup` | stat on existing files/dirs across multiple levels |
| Create | `bridge_create` | mknod/creat in empty and populated directories |
| Rename | `bridge_rename` | same-dir, cross-dir, overwrite, and noreplace flags |
| Unlink | `bridge_unlink` | regular file removal; link-count drop verification |
| Rmdir | (rmdir via VfsEngine) | empty directory removal; parent consistency |

### Crash Consistency

The crash-recovery tier validates that only committed mutations survive a
kernel crash cycle: perform a subset of operations, trigger QEMU guest reset
(simulating kernel crash), remount, and verify that the namespace reflects
only durable mutations — no half-applied renames, no orphaned inodes with
dangling directory entries.

### Validation Status

Validation outputs are deposited under `/root/ai/tmp/tidefs-validation/kernel-dir-namespace-validation-YYYYMMDD/`
as structured JSON reports. Each report includes:

- commit SHA and collection timestamp
- environment disclosure (host kernel, QEMU availability, backend)
- per-row validation with tier, outcome, operation kind, and blocker descriptions
- register status (Closed / Advanced / NotApplicable)

See `tidefs-validation/src/kernel_dir_namespace_validation.rs` for the
validation summary format.
## Writeback Path Validation (#5843)

The old userspace writeback validation report was retired because code-only rows
could emit PASS without mounted-kernel execution. Writeback release claims must
now be backed by Linux 7.0 QEMU, mounted-kernel VFS, or kernel block
I/O artifacts from the loaded product module, or by an exact blocker.

## Kernel No-Daemon Residency Validation

The old `tidefs-validation::kernel_no_daemon_residency` validation report was
retired because SourceModel/CargoUnit PASS rows were not production validation.
No-daemon claims for this crate must be backed by Linux 7.0 Kbuild and
QEMU logs from the loaded product module, or by an exact blocker.
## Kernel XFSTests Smoke Harness

The Nix QEMU kernel xfstests smoke harness (`nix/vm/kmod-xfstests-smoke.nix`)
builds the kmod-posix-vfs kernel module against a Linux 7.0 tree, boots a
disposable QEMU VM, loads the module, provisions a loopback-backed TideFS pool,
mounts it via `mount -t tidefs`, and executes focused xfstests-equivalent
POSIX smoke tests.

### Smoke Test Coverage

| xfstests Ref | Operation | What's Exercised |
|---|---|---|
| `generic/001` | file create, stat, unlink | write(2), stat(2), unlink(2) |
| `generic/002` | directory create, rmdir | mkdir(2), rmdir(2) |
| `generic/003` | write/read round-trip | write(2), read(2) data integrity |
| `generic/004` | overwrite | write(2) with full replacement |
| `generic/005` | symlink, readlink | symlink(2), readlink(2) |
| `generic/006` | readdir with entries | getdents64(2) directory listing |
| `generic/007` | exclusive create | O_CREAT\|O_EXCL create(2) |
| `generic/013` | truncate | truncate(2) extent mutation |

### Validation Classification

Each smoke test is classified as one of:

- **PASS**: The operation completed correctly through the kernel VFS path.
- **FAIL**: The operation failed with an unexpected error or data corruption.
- **BLOCKED**: A prerequisite condition was not met (e.g., kernel module not loadable, CONFIG_RUST not set, filesystem not mounted). Each blocker exposes a concrete gap for targeted kernel implementation work.

### Build and Run

```sh
# Nix build (derivation check):
nix build .#kmodXfstestsSmoke

# Run the harness:
nix run .#kmod-xfstests-smoke

# Or via the orchestration script:
bash scripts/kmod-xfstests-smoke.sh --timeout 300

# Run specific tests:
bash scripts/kmod-xfstests-smoke.sh --tests "generic/001 generic/003"

# With a pre-built module:
bash scripts/kmod-xfstests-smoke.sh --module /path/to/tidefs_posix_vfs.ko
```

### Build Status

The kmod-posix-vfs kernel module entry point (`tidefs_posix_vfs_main.rs`)
uses Rust-for-Linux for module init/drop and a C VFS shim for Linux
filesystem registration.

**Filesystem registration** (issue #6125): The module entry point registers
the "tidefs" filesystem type on module init and unregisters it on module drop.
Once built and loaded into a Linux 7.0 kernel with CONFIG_RUST=y:

- `/proc/filesystems` will list `tidefs`.
- **Bootstrap path**: `mount -t tidefs -o bootstrap <mountpoint>` is refused
  with `EOPNOTSUPP` unless a real kernel pool I/O authority is supplied through
  the block-device-backed mount path. The historical synthetic root proof is
  retired for product no-daemon mounts.
- **Engine-backed path**: `mount -t tidefs /dev/... <mountpoint>` (no bootstrap flag)
  calls the Rust engine bridge via `tidefs_posix_vfs_engine_fill_super()`,
  which runs the full `KmodSuperContext` mount-validation pipeline
  (committed-root, BLAKE3-verified superblock, statfs, getattr).  The mounted
  `s_fs_info` pool context is now the authority for engine-backed statfs:
  `tidefs_posix_vfs_statfs()` passes those live counters through
  `tidefs_posix_vfs_engine_statfs()`, which serves them via
  `KernelEngine`/`VfsEngineStatFs` and fails closed on invalid or missing
  mounted-pool state.  The same mounted context remains live through Linux
  `sync_fs`, `put_super`, and forced-unmount `umount_begin` superblock
  callbacks.  Product-facing engine mounts now require the C shim to register
  explicit lower-device read, write, flush, capacity, and teardown authority;
  `sync_fs` routes through `tidefs_posix_vfs_engine_sync_fs()` and propagates
  missing or unsupported durability authority instead of treating it as a clean
  mounted sync. Other ordinary VFS operations still depend on further
  kernel-resident pool/device backing.  Mounted kernel VFS validation,
  xfstests, O_DIRECT, unlink, mmap, and crash consistency claims depend on
  closing those remaining operation gates.

**Config**: `CONFIG_RUST=y` and `CONFIG_MODULES=y` have been added to
`nix/vm/kernel-7.0-config`. `nix/packages/linux-7.0-kernel.nix` now includes
`rustc` and `bindgen` in `nativeBuildInputs` for the kernel build.

**Remaining**: The module now builds, loads, and mounts (via `-o bootstrap`)
against the prepared Linux 7.0 baseline.  The default block-device mount path
stores the mounted pool context in `s_fs_info`; engine-backed statfs routes
that context through `tidefs_posix_vfs_engine_statfs()` and
`VfsEngineStatFs`.  The next blockers are real storage-backed VFS operations
on top of the mounted pool context, followed by mounted-kernel VFS validation
for the non-bootstrap path.

- `make -j8 -C <linux-src> O=<linux-build> M=crates/tidefs-kmod-posix-vfs modules`
  produces `tidefs_posix_vfs.ko`.
- `insmod tidefs_posix_vfs.ko` registers the "tidefs" filesystem type.
- `grep tidefs /proc/filesystems` will confirm registration.
- `EXPECT_FS_TYPE=tidefs nix/kmod-hot-loop.sh smoke` loads the module, confirms
  filesystem registration, attempts mount, and records the current
  engine-not-wired blocker.
- Engine-backed superblock operations (fill_super, statfs, kill_sb) are now
  wired into the loaded module via the C super_operations table. Statfs is
  active for block-device-backed mounts through the mounted `s_fs_info` pool
  context and Rust `VfsEngineStatFs` bridge; `sync_fs`, `put_super`, and
  forced-unmount `umount_begin` are also registered and logged by the live
  Linux superblock lifecycle. Ordinary file operation coverage still depends
  on storage-backed VFS operation wiring.
- `cargo check` and `cargo build` continue to pass against the
  `tidefs-kmod-bridge` userspace shim.

### Validation Status

Validation outputs are deposited under `/root/ai/tmp/tidefs-validation/kmod-xfstests-smoke/`
as:

- QEMU serial console log (`qemu.log`) with PASS/FAIL/BLOCKED annotations
- Environment fingerprint (kernel version, commit SHA, date, backend)
- Validation tier classification tied to the actual guest or mounted-kernel run

The Nix QEMU test harness is at `nix/vm/kmod-xfstests-smoke.nix`.
The orchestration script is at `scripts/kmod-xfstests-smoke.sh`.

## Kernel Rename Crash-Consistency Validation (#5874)

The old `kernel_rename_validation.rs` SourceModel/CargoUnit validation report is
retired. Rename proof must come from Linux 7.0 QEMU output that loads
the product module, mounts TideFS, exercises the rename matrix, and captures
the exact crash-consistency result or blocker.

## Kernel Link/Unlink Crash-Consistency Validation (#5917)

The old `kernel_link_unlink_validation.rs` SourceModel/CargoUnit validation
report is retired. Link/unlink proof must come from the Linux 7.0 QEMU runtime
harness in `nix/vm/kernel-link-unlink-validation.nix` or from a concrete
mounted-kernel blocker.


## Kernel Unlink Crash-Consistency Validation (#6021)

Validation module at [`tests/kernel_unlink_crash_consistency_validation.rs`](tests/kernel_unlink_crash_consistency_validation.rs).

Kbuild status: tidefs_posix_vfs.ko compiles against Linux 7.0 (495KB PASS).
QEMU smoke (qemu-system-x86_64 TCG): module loads, tidefs registered, bootstrap mount succeeds, unlink create+remove PASS, clean umount/rmmod. 8/8 operations PASS.
Validation output at `/root/ai/tmp/tidefs-validation/6021-qemu-smoke-s2/` — manifest passes xtask validate-e2e-validation-manifest (kernel-vfs-block, T5).

**Engine-backed pool mount** (2026-05-23): pool fixture image created with valid
PoolLabelV1 and committed-root ledger (VCRL+VCRP+VRBT). Mounted via
`mount -t tidefs /dev/vda /mnt/tidefs` on a virtio-blk device in Linux 7.0 QEMU.
Mount chain: label parse PASS, ledger select PASS, kernel replay mount PASS,
engine-backed mount(2) PASS (kernel_resident=true), inode creation PASS,
unlink PASS, clean teardown PASS. Validation output at
`/root/ai/tmp/tidefs-validation/6021-qemu-engine-mount/` (manifest xtask-validated, T5).

**Unlink crash-consistency validated** (2026-05-23): three-phase QEMU test
passes 10/10 in recovery phase. Phase1 seeds pool, Phase2 mounts+unlinks+victim+
sysrq crash (kernel panic triggered), Phase3 remounts+verifies: survivor file
present with correct content, victim absent, committed-root replay confirmed, no
orphans, clean teardown. Namespace sync fix (`tidefs_posix_vfs_engine_sync_namespace`)
populates Rust KernelEngine in-memory tables from C pool inode table after mount,
enabling lookup/unlink/getattr to find entries across crash+remount cycles.
Validation output at `/root/ai/tmp/tidefs-validation/6021-qemu-crash-consistency/` and
`/root/ai/tmp/tidefs-validation/6021-qemu-engine-mount/` (both manifest xtask-validated, T5).
First-mount write fix: read_inode_record now falls back to the local inode table
(populated by namespace sync from the C pool) when VRBT decode fails on fresh pools
with no prior txg commit.  Read returns empty, write stages in write_buffer, and
kernel_write(2) returns the correct byte count instead of EIO.

```sh
cargo test --test kernel_unlink_crash_consistency_validation
```


## Kernel Mkdir Crash-Consistency Validation (#6042)

The old `tidefs-validation::kernel_mkdir_validation` schema report is retired.
Kernel mkdir crash-consistency validation must come from a Linux 7.0
QEMU run that mounts the product module, exercises mkdir behavior, and verifies
committed-root recovery. Source/model and cargo rows are not product acceptance.

## Kernel Fsync Crash-Consistency Validation (#5931)

The old `kernel_fsync_validation.rs` SourceModel/CargoUnit validation report is
retired. Fsync proof must come from the Linux 7.0 QEMU runtime harness in
`nix/vm/kernel-fsync-validation.nix` or from a concrete mounted-kernel blocker.

## Kernel Statfs Crash-Consistency Validation (#5924)

The old `tests/kernel_statfs_validation.rs` SourceModel/CargoUnit validation
report is retired. Statfs proof must come from the Linux 7.0 QEMU runtime
harness in `nix/vm/kernel-statfs-validation.nix` or from a concrete
mounted-kernel blocker.

## Kernel Extent Allocation Dispatch (#5915)

### Overview

The extent allocation dispatch provides autonomous kernel-mode block provisioning
for the writeback path. When a file is extended beyond its current extent map
(e.g., sparse file hole-filling, copy-on-write expansion, append writes), the
kernel writeback path calls `VfsEngine::allocate_extents` to provision new blocks
without userspace intervention. Allocations are recorded in the intent log for
crash-consistency, so a crash-mount-replay cycle preserves both the allocation
and subsequent data written into the new extents.

### Types

- **`AllocateExtentsPlan`** (`extent_ops.rs`): Plain dispatch result struct
  capturing the target inode, allocation range, and engine-computed outcome.
- **`AllocateExtentsOutcome`** (`tidefs-vfs-engine`): Engine-level result type
  reporting bytes allocated and whether the full request was satisfied.

### Dispatch Flow

1. `KmodPosixVfs::allocate_extents()` calls `bridge_allocate_extents()`
2. `bridge_allocate_extents()` delegates to `VfsEngine::allocate_extents()`
3. The engine provisions blocks via the block allocator and records intent-log
   entries for crash-safety
4. The result is wrapped in an `AllocateExtentsPlan`

### No-Daemon Boundary

Extent allocation resolves within kernel authority through the engine's block
allocator. No userspace daemon, FUSE upcall, or helper process is required.

### Crash-Safety

The engine records allocation intents via the kernel intent-log bridge.
On a crash-mount-replay cycle, committed-root verification replays the
intent log, preserving allocated extents as durable state.

### Error Semantics

| Errno   | Condition                      |
|---------|--------------------------------|
| ENOSPC  | No free space for allocation   |
| EIO     | Storage error                  |
| EBADF   | Inode does not exist           |
| EINVAL  | Invalid offset/length          |

### Tests

Unit tests in `extent_ops.rs` (14 tests) and `extent_ops_bridge.rs` (7 tests)
cover: successful allocation, partial allocation, error propagation (ENOSPC,
EIO, EBADF, EINVAL), and
concurrent isolation.


## Kernel Fiemap Dispatch (#6109)

The `file.rs` module implements kernel-mode fiemap extent-map query dispatch
for `file_operations::unlocked_ioctl` (FS_IOC_FIEMAP). This enables tools
like `filefrag` and `hdparm --fibmap` to report real extent information
on kernel-mounted TideFS instances.

### Architecture

```
userspace ioctl(fd, FS_IOC_FIEMAP, &fiemap)
    → kernel VFS unlocked_ioctl
    → KmodPosixVfs::dispatch_ioctl(cmd=FS_IOC_FIEMAP)
    → KmodPosixVfs::dispatch_fiemap(state, ctx)
    → bridge_fiemap(engine, state, ctx)
    → VfsEngine::fiemap(file_handle, ctx)
    → FiemapExtentVec { extents }
    → copy_to_user → userspace fiemap buffer
```

### Types

| Type | Location | Description |
|------|----------|-------------|
| `FiemapExtent` | `kmod/src/kernel_types.rs` | Single extent matching Linux `struct fiemap_extent` (fe_logical, fe_physical, fe_length, fe_flags) |
| `FiemapExtentVec` | `kmod/src/kernel_types.rs` | Collection of `FiemapExtent` entries (KmodVec-backed) |
| `FiemapExtentVec` | `crates/tidefs-vfs-engine/src/lib.rs` | Userspace collection wrapping `tidefs_types_extent_map_core::FiemapExtent` (Vec-backed) |
| `FS_IOC_FIEMAP` | `file.rs` | ioctl command constant (`0xC020_660B`) |

### VfsEngine Trait Method

The `VfsEngine::fiemap()` method is a default trait method that returns an
empty extent vector. Engines that maintain physical extent layout (e.g.,
via `tidefs-extent-map`) override this to return real extent information.

### Dispatch Methods

| Method | Location | Description |
|--------|----------|-------------|
| `dispatch_fiemap` | `file.rs` | Resolves OpenFileState, calls bridge_fiemap |
| `dispatch_ioctl` | `file.rs` | Routes ioctl commands; FS_IOC_FIEMAP → dispatch_fiemap, unknown → ENOTTY |
| `bridge_fiemap` | `file.rs` | Standalone bridge: delegates to VfsEngine::fiemap |

### No-Daemon Boundary

Fiemap resolution resolves locally within kernel authority through VfsEngine.
No userspace daemon is required.

### Tests

9 unit tests in `file.rs::fiemap_tests` cover: default empty extent vector,
engine delegation, error propagation (EBADF, EIO, ENOSYS), ioctl routing
(FS_IOC_FIEMAP and unknown command), and error passthrough from ioctl dispatch.

## Kernel Residency Validation Matrix

Standalone residency matrices with SourceModel/CargoUnit PASS rows are no
longer maintained. Kernel residency validation belongs in Linux 7.0
Kbuild/QEMU artifacts tied to the concrete product module and issue.

## Kernel Cross-Path Equivalence Validation (#5987)

The old `tests/kernel_cross_path_equivalence.rs` SourceModel validation report is
retired. Cross-path equivalence proof must come from the QEMU harness at
`nix/vm/kernel-cross-path-equivalence.nix`, which must execute both paths and
retain concrete divergence or pass output.

## Kernel xfstests Validation

The old in-memory `xfstests_kernel_validation` validation report was retired
because it produced SourceModel PASS rows while the real Linux 7.0 mounted
kernel tiers were blocked. Kernel xfstests progress must now come from an
executed QEMU or mounted-kernel run, with guest logs and concrete
failure output. Schema-only or in-memory xfstests reports are not maintained as
release validation.

The kernel VFS xfstests tranche runner is:

```sh
nix run .#k7-vfs-xfstests-validation -- \
  --module /path/to/tidefs_posix_vfs.ko \
  --tests "generic/151 generic/152" \
  --output /root/ai/tmp/tidefs-validation/<run-id>/k7-vfs-xfstests.json
```

This runner generates a full NixOS VM test, loads the supplied module, mounts a
real `-t tidefs` TEST_DIR, and invokes upstream `xfstests-check`. The older
BusyBox/initramfs runners remain useful for kernel smoke validation only; they
must not be used to close xfstests tranche issues with synthetic or blanket
deferred rows.

## Kernel O_DIRECT Crash-Consistency Validation (#6018)

The O_DIRECT crash-consistency validation module
([`tests/kmod_posix_vfs_odirect_validation.rs`](tests/kmod_posix_vfs_odirect_validation.rs))
produces tier-classified validation for O_DIRECT I/O durability through the
kernel VFS path. O_DIRECT bypasses the page cache entirely, exercising
`generic_file_direct_write` / `generic_file_direct_read` — a distinct
kernel path from buffered I/O.

### Validation Tiers

| Tier | Validation Class | Status |
|------|---------------|--------|
| SourceModel | In-process ODirectEngine with deterministic crash simulation | 37 tests pass (SourceModel tier) |
| CargoUnit | `cargo test --test kmod_posix_vfs_odirect_validation` | 40/40 pass (37 SourceModel + 3 MountedKernelVfs flag tests) |
| MountedKernelVfs | O_DIRECT open flags propagate through VfsEngine dispatch | Partial: O_DIRECT constant (0x4000) and has_odirect_flag() in open_release.rs; live dispatch blocked on Kbuild+QEMU |
| QemuGuest | Linux 7.0 QEMU with crash-injection and committed-root verification | Blocked: requires prior tiers |

### Operation Coverage

| Operation | Description | SourceModel |
|-----------|-------------|-------------|
| DirectWrite | O_DIRECT-aligned write through kernel VFS | PASS |
| DirectRead | O_DIRECT-aligned read through kernel VFS | PASS |
| DirectWriteVerify | Write-then-read verification of O_DIRECT data | PASS |
| DirectWriteFsync | O_DIRECT write + fsync durability barrier | PASS |
| DirectWriteCrashRead | Crash + remount verification of O_DIRECT data | PASS |
| MixedBufferedDirect | Interleaved buffered and direct I/O | PASS |
| ConcurrentDirectWrites | Parallel O_DIRECT writes to disjoint ranges | PASS |
| AlignedUnalignedBoundary | Alignment constraint enforcement | PASS |
| ODirectTruncateInterleave | Truncate interleaved with O_DIRECT writes | PASS |

### ODirectEngine

The SourceModel tier includes an in-memory `ODirectEngine` that simulates:
- Sector-aligned O_DIRECT write/read with alignment enforcement
- Pending write buffer (in-flight data not yet committed)
- Deterministic crash injection (discards pending, marks crashed)
- Fsync persistence (commits pending to storage, updates FNV-1a committed root)
- Crash recovery (restores committed root from storage state)

Simulated crash scenarios demonstrate that in-flight O_DIRECT writes are
discarded on crash (commit-ahead semantics), while fsync-persisted writes
survive crash-and-recovery with matching committed-root digests.

### Validation Status

Validation is collected as structured `ODirectValidationReport` JSON with FNV-1a
digest sealing, per-row committed-root comparison, and tier classification.
Runtime acceptance requires QemuGuest tier with Linux 7.0 QEMU guest logs
written outside the repository.

### Run

```sh
cargo test --test kmod_posix_vfs_odirect_validation
```
