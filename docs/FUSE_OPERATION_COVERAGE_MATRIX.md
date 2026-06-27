# FUSE Operation Coverage Matrix (v0.422)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

Maturity: imported design specification from tracker-era issue #1292.

Current adapter audit: issue #1081 refreshed this matrix from source inspection
of `FuseVfsAdapter` in
`apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` and the
reply helper crate. The table below records the daemon callback surface as of
`origin/master` at `0882e2e402926eda45ee2e9e3dea8bac007a99cf`; it is a
documentation-only classification and does not change runtime behavior.

This imported document records an xfstests-grade target for every FUSE
operation TideFS expected to support. It serves as historical input for:

- The implementation checklist for the FUSE daemon
- The xfstests coverage tracker (which tests exercise which ops)
- The errno contract oracle for deterministic mapping

See also:

- `docs/VFS_ENGINE_API_CONTRACT.md` (tracker-era #1213) — VfsEngine 29-op contract
- `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md` (tracker-era #1233) — binding strategy
- `docs/PREVIEW_POSIX_SUBSET.md` — POSIX subset matrix

---

## Current adapter callback audit (issue #1081)

`impl Filesystem for FuseVfsAdapter` overrides the current fuser callback
surface instead of relying on fuser's default ENOSYS replies. The reply crate
still contains a generic `ReplyError::NotSupported -> ENOSYS` helper, and some
test doubles return ENOSYS, but source inspection found no live daemon callback
left as a fuser-default ENOSYS stub.

| FUSE operation | Daemon callback or dispatch | Verified status | Evidence and boundary |
|---|---|---|---|
| `FUSE_INIT` | `init()` | Implemented; source-inspected | Negotiates required and performance capabilities through `KernelConfig`; mount fails if required capabilities are rejected. |
| `FUSE_DESTROY` | `destroy()` | Implemented; source-inspected | Drains forget refs, shutdown/writeback, and final commit on unmount. |
| `FUSE_FORGET` | `forget()` | Implemented with tests | Dispatches to lookup-reference tracking; covered by lookup/forget lifecycle tests in `fuse_vfs_adapter.rs`. |
| `FUSE_BATCH_FORGET` | `batch_forget()` | Implemented; source-inspected | Iterates batch entries through the same `dispatch_forget()` path. |
| `FUSE_LOOKUP` | `lookup()` | Implemented with tests | Covered by mounted namespace tests and lookup reply-planning tests. |
| `FUSE_GETATTR` | `getattr()` | Implemented with tests | Covered by `getattr_stat_smoke.rs` and mounted stat coverage. |
| `FUSE_ACCESS` | `access()` | Implemented with tests | Covered by `access_mount_smoke.rs`; dispatch enforces requested access mask. |
| `FUSE_SETATTR` | `setattr()` | Implemented with tests | Covered by `setattr_flush_mount_smoke.rs` and truncate/timestamp tests. |
| `FUSE_READLINK` | `readlink()` | Implemented with tests | Covered by `symlink_readlink_tests.rs` and mounted symlink tests. |
| `FUSE_MKNOD` | `mknod()` | Implemented with tests | Covered by `mknod_smoke.rs`, `mknod_fifo_smoke.rs`, and stat/readdir rdev checks. |
| `FUSE_MKDIR` | `mkdir()` | Implemented with tests | Covered by `fuse_mkdir_create_integration.rs` and directory operation tests. |
| `FUSE_UNLINK` | `unlink()` | Implemented with tests | Covered by `fuse_link_unlink.rs` and mount integration tests. |
| `FUSE_RMDIR` | `rmdir()` | Implemented with tests | Covered by `rmdir_smoke.rs` and directory operation tests. |
| `FUSE_SYMLINK` | `symlink()` | Implemented with tests | Covered by `fuse_rename_link_symlink.rs` and symlink/readlink tests. |
| `FUSE_RENAME` | `rename()` | Implemented with tests | Covers normal rename, `RENAME_NOREPLACE`, and `RENAME_EXCHANGE`; `RENAME_WHITEOUT` is intentionally rejected until overlay/whiteout semantics enter the POSIX subset. |
| `FUSE_EXCHANGE` | `exchange()` | Implemented with tests | Linux 6.13+/macOS exchange callback dispatches through `dispatch_exchange_entry()`; covered by `rename_exchange_smoke.rs` and dispatch tests. |
| `FUSE_LINK` | `link()` | Implemented with tests | Covered by `fuse_link_unlink.rs` and VFS link smoke tests. |
| `FUSE_OPEN` | `open()` | Implemented with tests | Covered by `open_release_smoke.rs`; `O_TMPFILE` is handled as an open-flag adjunct through `dispatch_tmpfile()`, not a distinct fuser callback here. |
| `FUSE_READ` | `read()` | Implemented with tests | Covered by read/write mount smoke tests and large-file read/write coverage. |
| `FUSE_WRITE` | `write()` | Implemented with tests | Covered by read/write, writeback, dirty lifecycle, and fsync durability tests. |
| `FUSE_FLUSH` | `flush()` | Implemented with tests | Covered by `flush_release_mount_smoke.rs`; releases lock-owner scoped POSIX record locks and flushes dirty state. |
| `FUSE_RELEASE` | `release()` | Implemented with tests | Covered by open/release and flush/release smoke tests; cleans handle state and deferred delete state. |
| `FUSE_FSYNC` / fdatasync | `fsync(datasync)` | Implemented with tests | Covered by `fsync_durability.rs`, `fuse_sync_smoke.rs`, and dispatch fsync tests. |
| `FUSE_OPENDIR` | `opendir()` | Implemented with tests | Covered by directory and readdir smoke tests. |
| `FUSE_READDIR` | `readdir()` | Implemented with tests | Covered by `readdir_smoke.rs`, `readdir_vfs_smoke.rs`, and directory tests. |
| `FUSE_READDIRPLUS` | `readdirplus()` | Implemented with tests | Covered by `readdir_vfs_smoke.rs` and `dispatch_readdirplus` attribute consistency tests. |
| `FUSE_RELEASEDIR` | `releasedir()` | Implemented with tests | Covered by directory-handle lifecycle tests. |
| `FUSE_FSYNCDIR` | `fsyncdir()` | Implemented with tests | Covered by dispatch fsyncdir tests and directory sync coverage. |
| `FUSE_CREATE` | `create()` | Implemented with tests | Covered by `fuse_mkdir_create_integration.rs` and mount integration tests. |
| `FUSE_FALLOCATE` | `fallocate()` | Implemented with tests | Forwards mode bits to the engine; mode 0, KEEP_SIZE, PUNCH_HOLE, ZERO_RANGE, COLLAPSE_RANGE, and INSERT_RANGE are not classified as daemon stubs. |
| `FUSE_LSEEK` | `lseek()` | Implemented with tests | Dispatches SEEK_SET/CUR/END/DATA/HOLE; covered by `lseek_smoke.rs` and dispatch lseek tests. |
| `FUSE_BMAP` | `bmap()` | Explicitly unsupported | Returns `EOPNOTSUPP` through `unsupported_vfs_bmap_errno()`; BMAP exposes physical block-device addresses and the userspace adapter has no stable block-device address authority. FIEMAP is the extent-query path. |
| `FUSE_IOCTL` | `ioctl()` | Partial-boundary with tests | Supports `FS_IOC_FIEMAP`, `FS_IOC_FSGETXATTR`, and `TIDEFS_IOC_DEFRAG`; every other ioctl command returns `EOPNOTSUPP` rather than ENOSYS. |
| `FUSE_POLL` | `poll()` | Implemented with tests | `dispatch_poll_file()` reports regular-file readiness and tracks schedule-notify registrations; covered by `poll_mount_smoke.rs` and dispatch tests. |
| `FUSE_GETLK` | `getlk()` | Implemented with tests | POSIX advisory lock conflict reporting; covered by file-locking and xattr/ACL/lock integration tests. |
| `FUSE_SETLK` | `setlk(sleep = false)` | Implemented with tests | Nonblocking POSIX record locks; covered by file-locking smoke and lock integration tests. |
| `FUSE_SETLKW` | `setlk(sleep = true)` | Implemented with tests | Blocking POSIX record locks use fuser's abort handle to observe interrupt/cancel state. |
| `FUSE_FLOCK` | `flock()` | Implemented with tests | BSD flock path is handled separately from POSIX byte-range locks. |
| `FUSE_COPY_FILE_RANGE` | `copy_file_range()` | Implemented with tests | Uses the engine copy path when handles are registered and a writeback-cache fallback when needed; covered by `copy_file_range_smoke.rs` and dispatch tests. |
| `FUSE_GETXATTR` | `getxattr()` | Implemented with tests | Covered by `fuse_xattr_smoke.rs`, xattr backend, ACL/lock, and statx integration tests. |
| `FUSE_SETXATTR` | `setxattr()` | Implemented with tests | Covered by the xattr smoke/integration suite. |
| `FUSE_LISTXATTR` | `listxattr()` | Implemented with tests | Covered by the xattr smoke/integration suite. |
| `FUSE_REMOVEXATTR` | `removexattr()` | Implemented with tests | Covered by the xattr smoke/integration suite. |
| `FUSE_STATFS` | `statfs()` | Implemented with tests | Covered by `fuse_vfs_statfs_smoke.rs`. |
| `FUSE_SYNCFS` | `syncfs()` | Implemented with tests | Drains writeback state and commits a filesystem-wide barrier; covered by `fuse_sync_smoke.rs` and dispatch syncfs tests. |
| `FUSE_STATX` | `statx()` | Implemented with tests | Encodes `ReplyStatx`; covered by `xattr_statx_blake3_integration.rs` and dispatch statx tests. |
| `FUSE_INTERRUPT` | fuser abort handle | Binding-internal | No TideFS daemon callback is exposed; blocking `setlk(..., sleep = true)` observes `Request::abort_handle()`. |

## 1. Namespace and metadata operations

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| lookup | — | Inode-space lookup by (parent, name_bytes); surrogateescape for non-UTF8 names | ENOENT, ENOTDIR, EACCES |
| getattr | FUSE_GETATTR_FH | Returns PosixAttrs with generation number; FH variant uses open handle | EBADF, ESTALE |
| setattr | FATTR_MODE, FATTR_UID, FATTR_GID, FATTR_SIZE, FATTR_ATIME, FATTR_MTIME, FATTR_CTIME | Must preserve ctime update semantics; truncate via FATTR_SIZE; append-only rejection | EPERM, EACCES, EROFS, EFBIG, EINVAL |
| readdir | READDIRPLUS, stable cookies | Deterministic cookie assignment; READDIRPLUS returns stat bundles; stable across restarts | ENOENT, ENOTDIR |
| mkdir | mode, umask | Creates directory inode + entry; mode masking; setgid inheritance; parent mtime/ctime update | EEXIST, ENOSPC, EACCES, EROFS |
| mknod | mode, rdev, umask | FIFO, character device, block device, and socket metadata nodes preserve node kind and `rdev` through namespace persistence | EEXIST, ENOSPC, EPERM, EINVAL, EOPNOTSUPP |
| create | O_CREAT, O_EXCL, mode, umask | Creates regular file inode + entry + open handle; O_EXCL atomicity | EEXIST, ENOSPC, EACCES |
| unlink | — | Removes directory entry; decrements nlink; open/unlink semantics (deferred delete) | ENOENT, EACCES, EPERM, EISDIR |
| rmdir | — | Removes empty directory entry; non-empty fails with ENOTEMPTY | ENOENT, ENOTEMPTY, EACCES, EBUSY |
| symlink | target_bytes, name_bytes | Creates symlink inode with inline target; nlink=1 | EEXIST, ENOSPC, EACCES |
| readlink | — | Returns symlink target bytes; must work on open handle | EINVAL (not a symlink) |
| link | — | Creates hardlink entry; increments target nlink; dir targets rejected (EPERM) | EPERM, EACCES, EEXIST, EMLINK, ENOSPC |
| rename | renameat2 flags: RENAME_NOREPLACE, RENAME_EXCHANGE | Cross-directory atomic rename; RENAME_WHITEOUT is unsupported and returns EINVAL | EEXIST, ENOENT, ENOTDIR, EISDIR, EINVAL, ENOTEMPTY |

## 2. Data operations

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| open | O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_CREAT, O_TRUNC, O_EXCL, O_DIRECT, O_SYNC, O_DSYNC, O_PATH | Handle creation; O_RDONLY\|O_TRUNC → EACCES; O_DIRECT alignment enforcement; O_APPEND forces append-at-EOF | EACCES, ENOENT, EISDIR, EROFS, EINVAL |
| read | — | Read bytes from open handle; short reads allowed; O_DIRECT 4KiB alignment | EBADF, EINVAL |
| write | — | Write bytes to open handle; short writes on mid-write error (ENOSPC after partial progress); O_DIRECT alignment; advances mtime+ctime via TimestampUpdate::Write in VfsEngine | ENOSPC, EDQUOT, EBADF, EFBIG, EINVAL |
| flush | lock_owner | Called on close(2); releases POSIX record locks for lock_owner; no durability guarantee | — |
| release | lock_owner | Called on last close; best-effort OFD/flock cleanup; triggers deferred delete if nlink==0 | — |
| fsync | datasync | Durability barrier: flushes all dirty data+metadata for this file to stable storage; clears per-handle dirty flag | EBADF, EIO |
| fdatasync | — | Like fsync but metadata only if needed for data retrieval | EBADF, EIO |
| fallocate | FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE | Data-modifying modes (PUNCH_HOLE, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE, default extend) advance mtime+ctime via TimestampUpdate::Write; KEEP_SIZE-only advances ctime via MetadataChange | ENOSPC, EOPNOTSUPP, EINVAL, EBADF |

## 3. Extended attributes

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| getxattr | — | Retrieve xattr value by name; namespace prefix required; user.* requires DAC perms | ENOATTR, ENOTSUP, ERANGE, EACCES |
| setxattr | XATTR_CREATE, XATTR_REPLACE | Set xattr value; 64KiB value limit; CREATE/REPLACE flag semantics; append-only rejection | EEXIST, ENOATTR, E2BIG, ENOSPC, EPERM, ENOTSUP |
| listxattr | — | List xattr names; deterministic ordering by raw name bytes | ERANGE, ENOTSUP |
| removexattr | — | Remove xattr by name; append-only rejection | ENOATTR, EPERM, ENOTSUP |

## 4. Locking

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| getlk | F_RDLCK, F_WRLCK, F_UNLCK | Test for conflicting lock; reports conflicting lock owner+pid+range | — |
| setlk | F_RDLCK, F_WRLCK, F_UNLCK | Acquire/release POSIX advisory record lock; lock-owner scoped; same-owner coexistence; EAGAIN/EACCES on conflict (non-blocking) | EAGAIN, EACCES, EDEADLK, EBADF, EINVAL |
| setlkw | F_RDLCK, F_WRLCK, F_UNLCK | Blocking variant of setlk; interruptible by signals | EAGAIN, EACCES, EDEADLK, EINTR, EBADF, EINVAL |
| flock | LOCK_SH, LOCK_EX, LOCK_UN | BSD whole-file advisory lock surface, separate from POSIX byte-range ownership | EAGAIN, EBADF, EINVAL |

## 5. Advanced operations

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| ioctl | FS_IOC_FIEMAP, FS_IOC_FSGETXATTR, TIDEFS_IOC_DEFRAG | FIEMAP reports mapped extents; FSGETXATTR reports inode flags/extent metadata; TIDEFS_IOC_DEFRAG is the adapter-local defrag ioctl; all other commands return EOPNOTSUPP | EOPNOTSUPP, EINVAL, EBADF |
| lseek | SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE | SEEK_DATA/HOLE walk the adapter extent model; EOF is an implicit hole | ENXIO, EINVAL, EBADF |
| copy_file_range | — | Server-side copy through the engine path or writeback fallback; supports partial progress semantics | ENOSPC, EINVAL, EBADF, EPERM |
| statfs | — | Reports f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree from space accounting | — |
| syncfs | — | Mount-wide durability barrier: drains dirty page-cache pages, calls engine syncfs, and commits the txg barrier | EIO |
| statx | mask | Reports the statx field set encoded by `dispatch_statx`; used for extended inode metadata and btime-style queries | ENOENT, EINVAL |
| exchange | parent/name pairs | Atomically exchanges two regular-file data payloads while preserving inode numbers, permissions, and xattrs | ENOENT, ENOTDIR, EISDIR, EINVAL |

## 6. Coherency and lifetime operations

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| bmap | — | Explicitly unsupported by the userspace adapter; FIEMAP is the extent-query path | EOPNOTSUPP |
| poll | POLLIN, POLLOUT, FUSE_POLL_SCHEDULE_NOTIFY | Regular-file readiness plus schedule-notify registration bookkeeping | EBADF |
| notify_reply | — | Not a daemon callback in the current fuser adapter; NOTIFY_PRUNE remains a future raw-notify shim in the binding strategy doc | — |
| destroy | — | Filesystem unmount; flush and sync all pending work | — |

---

## 7. Coherency profile interaction


**Current implementation (2026-05-28):** The FUSE daemon enforces flush-boundary
write, the daemon's `FuseReadDispatch` PageCache is cleared for the target
inode. A subsequent read through any file descriptor (same or different open
file handle) therefore sees the new data without requiring a close/re-open
cycle. The kernel-side `FOPEN_KEEP_CACHE` flag is not set by default because
integration test exercises this contract with two independent writer file
descriptors and a reader that verifies both regions.

Each op must document its behavior under each named profile:

- **strict**: conservative reply TTLs, minimal caching, correctness first
- **auto**: derived from topology/lease state

---

## 8. VfsEngine operation mapping

| FUSE Op | VfsEngine Method | Notes |
|---------|-----------------|-------|
| lookup | `lookup` | Direct mapping |
| getattr | `getattr` | Direct mapping |
| access | `getattr` plus permission checks | Adapter-level permission projection |
| setattr | `setattr` | Direct mapping |
| readdir | `opendir` + `readdir` + `releasedir` | Directory handle lifecycle |
| readdirplus | `opendir` + `readdir` (with attr) + `releasedir` | VfsEngine readdir returns attrs per entry |
| mkdir | `mkdir` | Direct mapping |
| mknod | `mknod` | Direct mapping |
| create | `create` | Direct mapping |
| unlink | `unlink` | Direct mapping |
| rmdir | `rmdir` | Direct mapping |
| symlink | `symlink` | Direct mapping |
| readlink | `readlink` | Direct mapping |
| link | `link` | Direct mapping |
| rename | `rename` | Direct mapping |
| open | `open` | File handle lifecycle |
| read | `read` | Direct mapping |
| write | `write` | Direct mapping |
| flush | `flush` | Direct mapping |
| release | `release` | Direct mapping |
| fsync | `fsync` | Direct mapping |
| fsyncdir | `fsyncdir` | Direct mapping |
| fallocate | `fallocate` | Direct mapping |
| lseek | — | Adapter extent scan over engine-backed file state |
| getxattr | `getxattr` | Direct mapping |
| setxattr | `setxattr` | Direct mapping |
| listxattr | `listxattr` | Direct mapping |
| removexattr | `removexattr` | Direct mapping |
| getlk | — | Handled by `FuseVfsAdapter` internal lock tracking (not in VfsEngine) |
| setlk/setlkw | — | Handled by `FuseVfsAdapter` internal lock tracking (not in VfsEngine) |
| flock | — | Handled by `FuseVfsAdapter` internal lock tracking (not in VfsEngine) |
| ioctl | — | FIEMAP, FSGETXATTR, and TIDEFS_IOC_DEFRAG handled by adapter shims |
| poll | — | Adapter file-handle/readiness bookkeeping |
| copy_file_range | `copy_file_range` or writeback fallback | Engine path preferred; adapter fallback handles writeback-cache authority |
| statfs | `statfs` | Direct mapping |
| syncfs | `syncfs` plus adapter writeback/txg barrier | Mount-wide durability barrier |
| statx | `getattr` plus adapter metadata/xattr projection | Encoded through `ReplyStatx` |
| exchange | `read`/`write`/metadata checks | Adapter dispatch swaps regular-file data while preserving inode metadata |
| bmap | — | Explicitly unsupported at the userspace adapter boundary |

---

- Focused mounted smoke coverage now exercises FIFO, character-device,
  block-device, and socket `mknod` metadata. The broader
  `scripts/tidefs-xfstests-*`, and `nix/tidefs-posix-scoreboard.sh` must
  exercise every op before this matrix can be treated as full runtime coverage.
- Crash/fault injection at commit_group boundaries for durability ops (fsync, write)

## 10. Dependencies

- Historical tracker dependencies: #1213 (VFS Engine API — op contract definition), #1233 (FUSE binding strategy)
- Historical tracker blockers: #1145 (FUSE daemon implementation), #1127 (FUSE worker queue model)
- Historical tracker related item: #1235 (trace emission contract — FUSE ops generate traces)

---

## 11. Write Metadata Timestamp Authority

All acknowledged FUSE write paths that modify file data must route through
`LocalFileSystem::apply_timestamp_update()` (or `TimestampUpdate::Write` in
the engine `write()` path) to advance `mtime` and `ctime` uniformly.

### Audited paths (tracker-era issue #6543)

| Write path | VfsEngine method | Timestamp authority | Status |
|---|---|---|---|
| FUSE write (normal, writeback-cache, O_DIRECT, O_SYNC/O_DSYNC) | `write()` | `apply_timestamp_update(…, Write)` after flush | Covered in tracker-era #6156 provenance |
| FUSE fallocate (PUNCH_HOLE, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE, default extend) | `fallocate()` | `apply_timestamp_update(…, Write)` after data mutation | Covered in tracker-era #6543 provenance |
| FUSE fallocate (KEEP_SIZE only) | `fallocate()` | `apply_timestamp_update(…, MetadataChange)` | Covered in tracker-era #6543 provenance |
| FUSE copy_file_range | `copy_file_range()` → `write()` | Chained through `write()` → `apply_timestamp_update(…, Write)` | Covered |
| FUSE setattr/FATTR_SIZE (truncate, mounted engine path) | `setattr()` → engine truncate + `apply_metadata_setattr()` | Engine metadata is authoritative; namespace attrs are mirrored only after successful engine mutation | Covered |
| FUSE setattr/FATTR_SIZE (namespace-only fallback) | namespace layer | Namespace metadata updates are used only when the engine cannot resolve the inode | **Fallback**: legacy namespace-only test surfaces remain supported, but mounted mutations must not use stale namespace attrs as the permission or timestamp authority. |
| `fuse_write.rs` `FuseWriteDispatch` | N/A (direct inode-table manipulation) | Own `update_inode_after_write` with saturating mtime increment, no ctime authority | **Nonclaim**: this module is not wired into the FUSE daemon. Its timestamp logic is separate from the canonical authority. |

### Regression guard

`fallocate_extend_advances_mtime_and_ctime` and
`fallocate_punch_hole_advances_mtime_and_ctime` in `vfs_engine_impl.rs`
verify that fallocate data-modifying paths advance mtime and ctime through
the engine's timestamp policy.

### Nonclaim boundaries

- The non-namespace `setattr` truncation path would need `TimestampUpdate::Truncate`
  wired into `apply_metadata_setattr` if the namespace-less code path is ever
  activated.
- `fuse_write.rs` is historical write-path scaffolding; its timestamp behavior
  must be unified with the canonical `apply_timestamp_update` authority before
  it can claim write-metadata coverage.
