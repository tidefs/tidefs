# TideFS POSIX FUSE Adapter Daemon — Error Taxonomy

This document enumerates every error variant the POSIX FUSE adapter daemon can
emit, maps each to the correct `errno` value per POSIX semantics, and provides
per-operation recovery-path guidance.

Last updated: 2026-05-10. Based on crate source at crate version 0.421.0.

## Table of Contents

1.  [Error Categories](#error-categories)
2.  [Error Enum Reference](#error-enum-reference)
3.  [Numeric Errno Table](#numeric-errno-table)
4.  [Per-Operation Errno Reference](#per-operation-errno-reference)
5.  [Recovery-Path Guidance](#recovery-path-guidance)
6.  [Cross-Reference: Tracing Spans](#cross-reference-tracing-spans)

## Error Categories

Every error path in the daemon maps to a POSIX errno before reaching the
kernel. Errors are grouped into five categories by recovery semantics.

### 1. Transport Errors (FUSE Channel)

The FUSE session itself can fail during mount or while reading requests from
`/dev/fuse`. These terminate the daemon process.

| Condition | Errno | Recovery |
|-----------|-------|----------|
| `fuser::spawn_mount2` failure | (process exit) | Daemon restart |
| `/dev/fuse` read failure | (process exit) | Daemon restart |
| `libc::sigaction` failure | (process exit) | Daemon restart |

### 2. Protocol Errors (Malformed Requests)

| Condition | Errno | Source |
|-----------|-------|--------|
| Invalid offset/length for read/write | `EINVAL` | fuse_vfs_adapter.rs |
| Offset+length overflow | `EFBIG` | fuse_vfs_adapter.rs |
| Cookie overflow in readdir | `EOVERFLOW` | fuse_vfs_adapter.rs |
| Cookie value out of i64 range | `ERANGE` | fuse_vfs_adapter.rs |
| Unknown ioctl command | `EOPNOTSUPP` | fuse_vfs_adapter.rs |
| Malformed FIEMAP header | `EINVAL` | fuse_vfs_adapter.rs |
| Non-UTF-8 name | `EINVAL` | fuse_vfs_adapter.rs |
| Name exceeds PATH_MAX_BYTES | `ENAMETOOLONG` | fuse_vfs_adapter.rs |
| Seek offset overflow | `EFBIG` | fuse_vfs_adapter.rs |

### 3. Filesystem Errors (POSIX Semantics)

**namespace_error_to_errno** mappings (fuse_vfs_adapter.rs:117):

| NamespaceError variant | Errno |
|------------------------|-------|
| InodeNotFound | `ENOENT` |
| AlreadyExists | `EEXIST` |
| NotEmpty | `ENOTEMPTY` |
| NotDirectory | `ENOTDIR` |
| IsDirectory | `EISDIR` |
| InvalidName | `EINVAL` |
| TooManySymlinks | `ELOOP` |
| NotSymlink | `EINVAL` |
| LinkCountOverflow | `EMLINK` |
| RenameCycle | `EINVAL` |
| (other) | `EIO` |

Additional direct errno returns:

| Condition | Errno |
|-----------|-------|
| Bad/closed file handle | `EBADF` |
| Not writable | `EBADF` |
| Inode not a directory | `ENOTDIR` |
| Inode is a directory | `EISDIR` |
| Permission denied (access) | `EACCES` |
| Permission denied (owner) | `EPERM` |
| Read-only filesystem | `EROFS` |
| Stale inode | `ESTALE` |
| xattr not found | `ENODATA` |
| Seek beyond EOF | `ENXIO` |
| Resource busy | `EBUSY` |
| Not implemented | `ENOSYS` |

### 4. Internal Errors

| Condition | Errno | Recovery |
|-----------|-------|----------|
| PageCache writeback failure | `EIO` | Log; propagate |
| Extent-map allocation full | `ENOSPC` | Propagate |
| Extent-map corruption | `EIO` | Log; propagate |
| Dirty-scheduler backpressure | `EAGAIN` | Client retries |
| Dirty-scheduler work-id exhaustion | `EIO` | Log; propagate |
| Dirty-scheduler invalid range | `EINVAL` | Propagate |
| Corrupt DirIndex | `EIO` | Log; propagate |
| Inode link-count failure | `ENOLINK` | Log; propagate |
| Mutex poisoned | `EIO` | Log; propagate |

## Error Enum Reference

### WriteError (fuse_write.rs:41)
| Variant | Errno |
|---------|-------|
| BadFileDescriptor | `EBADF` |
| NotWritable | `EBADF` |
| NoSpace | `ENOSPC` |
| IoError | `EIO` |
| InvalidArgument | `EINVAL` |

### FlushError (fuse_flush_fsync.rs:91)
| Variant | Errno |
|---------|-------|
| BadFileDescriptor | `EBADF` |
| IoError | `EIO` |
| NoSpace | `ENOSPC` |
| Interrupted | `EINTR` |

### FsyncError (fuse_flush_fsync.rs:125)
Same variants and mappings as FlushError.

### ReaddirError (readdir_dispatch.rs:38)
| Variant | Errno |
|---------|-------|
| NotFound | `ENOENT` |
| NotDirectory | `ENOTDIR` |
| Io | `EIO` |

### DaemonWriteDispatchError (write_dispatch.rs:80)
| Variant | Errno |
|---------|-------|
| Rejected { errno } | errno |
| Staging(err) | staging.to_errno() |
| Scheduler(Full) | `EAGAIN` |
| Scheduler(InvalidRange) | `EINVAL` |
| Scheduler(OutOfWorkItemIds) | `EIO` |

## Numeric Errno Table

| Errno | libc | Semantics |
|-------|------|-----------|
| SUCCESS | 0 | Success |
| EPERM | 1 | Operation not permitted |
| ENOENT | 2 | No such file or directory |
| EINTR | 4 | Interrupted function call |
| EIO | 5 | I/O error |
| ENXIO | 6 | No such device or address |
| EAGAIN | 11 | Resource temporarily unavailable |
| EACCES | 13 | Permission denied |
| EBUSY | 16 | Device or resource busy |
| EEXIST | 17 | File exists |
| ENODATA | 61 | No data available |
| ENOTDIR | 20 | Not a directory |
| EISDIR | 21 | Is a directory |
| EINVAL | 22 | Invalid argument |
| EFBIG | 27 | File too large |
| ENOSPC | 28 | No space left on device |
| EROFS | 30 | Read-only filesystem |
| EMLINK | 31 | Too many links |
| ENAMETOOLONG | 36 | File name too long |
| ENOSYS | 38 | Function not implemented |
| ENOTEMPTY | 39 | Directory not empty |
| ELOOP | 40 | Too many symbolic links |
| ENOLINK | 67 | Link has been severed |
| EOVERFLOW | 75 | Value too large |
| EBADF | 9 | Bad file descriptor |
| ERANGE | 34 | Result too large |
| EOPNOTSUPP | 95 | Operation not supported |
| ESTALE | 116 | Stale file handle |

## Per-Operation Errno Reference

### lookup (opcode 1)
- `ENOENT` — component not found
- `ENOTDIR` — not a directory
- `ENAMETOOLONG` — name too long
- `EACCES` — permission denied
- `ESTALE` — stale after lookup
- `EIO` — internal error
- `EINVAL` — non-UTF-8 name

### getattr (opcode 3)
- `ENOENT` — inode not found
- `EBADF` — bad file handle
- `ESTALE` — stale inode
- `EIO` — internal error

### read (opcode 15)
- `EBADF` — bad handle
- `EISDIR` — is a directory
- `EINVAL` — invalid offset/length
- `EFBIG` — offset+length overflow
- `ENXIO` — seek beyond EOF
- `EIO` — page-cache/extent error

### write (opcode 16)
- `EBADF` — bad handle
- `ENOSPC` — no space
- `EINVAL` — invalid offset/length
- `EFBIG` — offset+length overflow
- `EAGAIN` — scheduler backpressure
- `EIO` — I/O error

### flush (opcode 25)
- `EBADF` — bad handle
- `EIO` — writeback failure
- `ENOSPC` — extent commit failure
- `EINTR` — interrupted

### fsync/fdatasync (opcodes 26, 27)
- `EBADF` — bad handle
- `EIO` — writeback/fsync failure
- `ENOSPC` — extent commit failure
- `EINTR` — interrupted

### create/mkdir/mknod (opcodes 35, 9, 8)
- `ENOENT` — parent not found
- `ENOTDIR` — parent not a directory
- `EEXIST` — name exists / O_EXCL
- `ENOSPC` — inode table full
- `ENAMETOOLONG` — name too long
- `EACCES` — permission denied
- `EROFS` — read-only filesystem
- `EIO` — internal error

### unlink/rmdir (opcodes 10, 11)
- `ENOENT` — not found
- `ENOTDIR` — not a directory (rmdir)
- `ENOTEMPTY` — directory not empty (rmdir)
- `EACCES` — permission denied
- `EROFS` — read-only
- `EIO` — internal error

### rename (opcode 12)
- `ENOENT` — source not found
- `ENOTDIR` — not a directory
- `EEXIST` — NOREPLACE conflict
- `EISDIR` — directory/non-directory mismatch
- `ENOTEMPTY` — non-empty target
- `EINVAL` — rename cycle
- `EBUSY` — mountpoint busy
- `EROFS` — read-only
- `EIO` — internal error

### readdir/readdirplus (opcodes 28, 44)
- `EBADF` — bad handle
- `ENOTDIR` — not a directory
- `ENOENT` — inode not found
- `EOVERFLOW` — cookie overflow
- `ERANGE` — cookie out of range
- `EIO` — corrupt DirIndex

### fallocate (opcode 43)
- `EBADF` — bad handle
- `EISDIR` — is a directory
- `EOPNOTSUPP` — unsupported mode
- `EINVAL` — invalid offset/length
- `ENOSPC` — extent-map full
- `EIO` — internal error

### setattr (opcode 4)
- `ENOENT` — inode not found
- `ESTALE` — stale inode
- `EPERM` — chown without privilege
- `EROFS` — read-only
- `EACCES` — permission denied
- `EIO` — internal error

### xattr operations
- `ENODATA` — attribute not found
- `ENOENT` — inode not found
- `ENOSYS` — not implemented
- `EIO` — internal error

### Advisory locks (getlk, setlk)
- `ENOSYS` — not implemented
- `EAGAIN` — lock conflict
- `EACCES` — lock conflict (alt)

## Recovery-Path Guidance

### Transport Errors
- Do not retry. The FUSE session is dead.
- Tear down the daemon. Log and exit.

### Protocol Errors
- Propagate to client immediately. No retry.
- Client is responsible for retry with corrected parameters.

### Filesystem Errors
- Propagate to client. Deterministic POSIX conditions.
- `ESTALE`: client should re-lookup.

### Internal Errors
- `EAGAIN` (backpressure): client retries with exponential backoff.
- `ENOSPC`: client frees space or extends filesystem.
- `EIO`: log at WARN/ERROR, propagate. May indicate corruption.
- `EINVAL`: propagate; may indicate programming error.

### Lock Errors
- `EAGAIN`/`EACCES`: client retries or uses setlkw for blocking locks.

## Cross-Reference: Tracing Spans (#4147)

| Span | Category |
|------|----------|
| fuse.dispatch.lookup | Filesystem |
| fuse.dispatch.getattr | Filesystem + Internal |
| fuse.dispatch.read | Filesystem + Protocol + Internal |
| fuse.dispatch.write | Filesystem + Protocol + Internal |
| fuse.dispatch.flush | Internal |
| fuse.dispatch.fsync | Internal |
| fuse.dispatch.create | Filesystem + Internal |
| fuse.dispatch.unlink | Filesystem + Internal |
| fuse.dispatch.rename | Filesystem + Internal |
| fuse.dispatch.readdir | Filesystem + Protocol + Internal |
| fuse.dispatch.fallocate | Filesystem + Protocol + Internal |
| fuse.dispatch.setattr | Filesystem + Internal |
