# FUSE Operation Coverage Matrix (v0.422)

Maturity: **design** specification closing issue #1292.

This document is the xfstests-grade specification for every FUSE operation
tidefs must support. It serves as:

- The implementation checklist for the FUSE daemon
- The xfstests coverage tracker (which tests exercise which ops)
- The errno contract oracle for deterministic mapping

See also:

- `docs/VFS_ENGINE_API_CONTRACT.md` (#1213) — VfsEngine 29-op contract
- `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md` (#1233) — binding strategy
- `docs/PREVIEW_POSIX_SUBSET.md` — POSIX subset matrix

---

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
| link | — | Creates hardlink entry; increments target nlink; dir targets rejected (EPERM) | EPERM, EEXIST, EMLINK, ENOSPC |
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

## 5. Advanced operations

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| ioctl | FS_IOC_FIEMAP, FICLONE, FIDEDUPERANGE | FIEMAP: reports mapped extents with FIEMAP_EXTENT_UNWRITTEN for v2; FICLONE: reflink clone; FIDEDUPERANGE: dedup range | EOPNOTSUPP, EINVAL, EBADF |
| lseek | SEEK_DATA, SEEK_HOLE | Unwritten extents are data; EOF is an implicit hole | ENXIO |
| copy_file_range | — | Server-side copy; partial copy on ENOSPC; append-only destination ignores src_off | ENOSPC, EINVAL, EBADF, EPERM |
| statfs | — | Reports f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree from space accounting | — |

## 6. Coherency and lifetime operations

| Op | Flags/Variants | Semantics | Errnos |
|-----|---------------|-----------|--------|
| bmap | — | Block map (optional; may return ENOSYS) | ENOSYS |
| poll | — | Poll for events (optional) | — |
| notify_reply | — | Reply to kernel notification (NOTIFY_PRUNE shim) | — |
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
| getxattr | `getxattr` | Direct mapping |
| setxattr | `setxattr` | Direct mapping |
| listxattr | `listxattr` | Direct mapping |
| removexattr | `removexattr` | Direct mapping |
| getlk | — | Handled by `FuseVfsAdapter` internal lock tracking (not in VfsEngine) |
| setlk/setlkw | — | Handled by `FuseVfsAdapter` internal lock tracking (not in VfsEngine) |
| ioctl | — | FIEMAP/BMAP handled by adapter shim (not in VfsEngine) |
| lseek | — | Kernel-resolved; adapter receives seek offset in read/write |
| copy_file_range | — | Adapter-level read+write loop (not in VfsEngine) |
| statfs | `statfs` | Direct mapping (future VfsEngine addition) |
| bmap | — | Optional; adapter-level synthetic block map |

---


  `scripts/tidefs-xfstests-*`, and `nix/tidefs-posix-scoreboard.sh` must
  exercise every op before this matrix can be treated as runtime coverage
  special-node `mknod` remains a runtime nonclaim until that row has passing
- Crash/fault injection at commit_group boundaries for durability ops (fsync, write)

## 10. Dependencies

- Depends on: #1213 (VFS Engine API — op contract definition), #1233 (FUSE binding strategy)
- Blocks: #1145 (FUSE daemon implementation), #1127 (FUSE worker queue model)
- Related: #1235 (trace emission contract — FUSE ops generate traces)

---

## 11. Write Metadata Timestamp Authority

All acknowledged FUSE write paths that modify file data must route through
`LocalFileSystem::apply_timestamp_update()` (or `TimestampUpdate::Write` in
the engine `write()` path) to advance `mtime` and `ctime` uniformly.

### Audited paths (issue #6543)

| Write path | VfsEngine method | Timestamp authority | Status |
|---|---|---|---|
| FUSE write (normal, writeback-cache, O_DIRECT, O_SYNC/O_DSYNC) | `write()` | `apply_timestamp_update(…, Write)` after flush | Covered (#6156) |
| FUSE fallocate (PUNCH_HOLE, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE, default extend) | `fallocate()` | `apply_timestamp_update(…, Write)` after data mutation | Covered (#6543) |
| FUSE fallocate (KEEP_SIZE only) | `fallocate()` | `apply_timestamp_update(…, MetadataChange)` | Covered (#6543) |
| FUSE copy_file_range | `copy_file_range()` → `write()` | Chained through `write()` → `apply_timestamp_update(…, Write)` | Covered |
| FUSE setattr/FATTR_SIZE (truncate, namespace path) | `setattr()` → namespace layer | Adapter sets mtime+ctime explicitly before engine dispatch | Covered |
| FUSE setattr/FATTR_SIZE (truncate, non-namespace path) | `setattr()` → `apply_metadata_setattr()` | `apply_metadata_setattr` does not include FATTR_SIZE in its mask | **Nonclaim**: the current daemon always uses the namespace path. The non-namespace fallback would need explicit FATTR_SIZE timestamp rules in `apply_metadata_setattr` if ever exercised. |
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
