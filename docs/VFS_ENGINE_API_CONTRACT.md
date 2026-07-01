# VFS Engine API contract: canonical types, ops, semantics (v1.0-draft)

Maturity: **implemented-source** — core types in `tidefs-types-vfs-core`,
trait operations in `tidefs-vfs-engine` (#1488), verified (#1557).

**Current tracking issue**: [#1887](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1887)
**Original design issue**: [#1213](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1213)

This document settles the canonical VFS Engine API contract for tidefs.
It is the single source of truth for the interface between frontend adapters
(FUSE daemon, ublk surface, admin proxy, VFS_RPC) and the storage engine.

The contract operates in **inode space**, not path space. Every frontend
adapter must translate its wire protocol into these types and operations.
This unifies the FUSE adapter (#1145), ublk surface (future), admin proxy
(#1209), and cluster VFS_RPC (#1234) behind a common engine abstraction.

See also:
- `docs/TIDEFS_DOCTRINE.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/POSIX_CHARTER_TEST_XFSTESTS_MATRIX_P5-04.md`
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`
- `docs/FUSE_REQUEST_WORKER_QUEUE_MODEL_P5-02.md`

## VFS Boundary Role

This document records the VFS operation boundary: what every operation
**means** across frontend surfaces, independent of how it is encoded on the wire
or written to disk. Current authority still depends on source-backed
classification, live GitHub issue/PR state, and the claims gate rather than the
deleted three-contract historical root.

## Metrics snapshot

| Metric | Count |
|---|---:|
| Primitive types | 3 |
| Struct/record types | 12 |
| Enum types | 2 |
| Namespace operations | 13 |
| File I/O operations | 7 |
| Directory operations | 4 |
| Extended attribute operations | 4 |
| Invariant rules | 14 |
| Blocked downstream issues | 10 |

---

## 1. Decisive design choices

The VFS Engine API is the canonical operational interface. These choices are
fixed and apply across all frontend adapters:

1. **Inode space, not path space**: The engine sees `InodeId`, not paths.
   Path resolution is the adapter's responsibility. The engine provides
   `lookup(parent, name)` for directory traversal.

2. **Names are raw bytes**: File and directory names are `bytes`, not
   strings. xfstests uses names with non-UTF-8 bytes, embedded nulls, and
   shell-special characters. No adapter or engine may assume UTF-8.

3. **Ctx carries request identity**: Every mutating operation receives a
   `RequestCtx` with uid, gid, pid, umask, and supplementary groups.
   Ownership and permission checks use this context.

4. **umask is adapter policy**: If `FUSE_DONT_MASK` is negotiated, the
   kernel does not apply umask and the engine must apply it. Otherwise the
   kernel already applied umask and the engine must not re-apply it.

5. **Generation tracks inode lifetime**: Every `InodeAttr` carries a
   `generation` counter. The adapter uses it for stale-handle detection
   (ESTALE on mismatch).

6. **DirEntry.cookie is stable**: `cookie` values persist across mounts
   for POSIX `seekdir`/`telldir` compatibility. The engine owns cookie
   assignment; the adapter must not reinterpret them.

7. **create/mkdir applies Linux owner/mode inheritance**: uid from ctx,
   gid from ctx (or parent gid if setgid), mode adjusted by umask.
   See #1198 for the full POSIX semantics specification.

8. **setattr.valid uses FUSE bit positions**: The `FATTR_*` bitmask is the
   canonical way to express which attributes are being changed. The engine
   must use the same bit positions as Linux FUSE.

9. **Operations are synchronous at the engine boundary**: The engine
   returns `Result<T, Errno>` for every operation. Async batching, writeback
   caching, and transaction grouping happen **below** this API.

10. **One contract, many surfaces**: The same types and ops serve the FUSE
    daemon (local userspace), VFS_RPC (cluster forwarding), ublk (block
    volume), and admin proxy (management). No surface gets a different
    semantic contract.

---

## 2. Primitive types

These are the unbranded integer types shared across all operations:

```text
InodeId    = u64     # stable inode identity
Generation = u64     # incremented on every inode re-use; mismatch = ESTALE
Errno      = u16     # Linux errno values (0 = success, positive values per Linux ABI)
```

`Errno` uses Linux-native positive errno values (EPERM=1, ENOENT=2, etc.).
The engine returns `Result<T, Errno>` — `Ok(T)` for success, `Err(e)` with a
positive Linux errno on failure.

---

## 3. Core record types

### 3.1 RequestCtx

Carries the calling process identity for permission checks and ownership
inheritance:

| Field | Type | Purpose |
|---|---|---|
| `uid` | `u32` | Effective user ID |
| `gid` | `u32` | Effective group ID |
| `pid` | `u32` | Process ID (for lock ownership) |
| `umask` | `u32` | File creation mask; 0 if unknown or FUSE_DONT_MASK negotiated |
| `groups` | `[u32]` | Supplementary group IDs |

### 3.2 EngineFileHandle

An open file handle, chosen by the frontend adapter (FUSE `fh`):

| Field | Type | Purpose |
|---|---|---|
| `inode_id` | `InodeId` | Inode this handle refers to |
| `open_flags` | `u32` | O_RDONLY / O_WRONLY / O_RDWR / O_APPEND / O_DIRECT / ... |
| `fh_id` | `u64` | Adapter-chosen opaque handle id (FUSE `fh`) |
| `lock_owner` | `u64` | Lock owner for flush, release, getlk/setlk |

### 3.3 EngineDirHandle

An open directory handle:

| Field | Type | Purpose |
|---|---|---|
| `inode_id` | `InodeId` | Directory inode |
| `dh_id` | `u64` | Adapter-chosen opaque handle id |

### 3.4 SetAttr

Mirrors `fuse_setattr_in.valid` for expressing which attributes to change:

| Field | Type | Purpose |
|---|---|---|
| `valid` | `u32` | FATTR_* bitmask (see §4) |
| `mode` | `u32` | New file mode (permissions + type bits) |
| `uid` | `u32` | New owner UID |
| `gid` | `u32` | New owner GID |
| `size` | `u64` | New file size (truncate if smaller, zero-fill if larger) |
| `atime_ns` | `u64` | New access time, nanoseconds since epoch |
| `mtime_ns` | `u64` | New modification time |
| `ctime_ns` | `u64` | New change time |

### 3.5 LockSpec

Mirrors C `struct flock` for POSIX advisory locks:

| Field | Type | Purpose |
|---|---|---|
| `typ` | `u32` | Lock type: `F_RDLCK` (0), `F_WRLCK` (1), `F_UNLCK` (2) |
| `whence` | `u32` | `SEEK_SET` (0), `SEEK_CUR` (1), `SEEK_END` (2) |
| `start` | `u64` | Start offset (interpreted with `whence`) |
| `end` | `u64` | End offset (inclusive); `u64::MAX` means to EOF |
| `pid` | `u32` | Process ID owning the lock |

### 3.6 NodeKind

The POSIX file type:

```text
NodeKind = Dir | File | Symlink | CharDev | BlockDev | Fifo | Socket | Whiteout
```

### 3.7 PosixAttrs

The full set of POSIX stat attributes:

| Field | Type | Purpose |
|---|---|---|
| `mode` | `u32` | File mode including type bits (`S_IFMT` + permissions) |
| `uid` | `u32` | Owner UID |
| `gid` | `u32` | Owner GID |
| `nlink` | `u32` | Hard link count |
| `rdev` | `u32` | Device number for char/block special files |
| `atime_ns` | `u64` | Access time, nanoseconds |
| `mtime_ns` | `u64` | Modification time |
| `ctime_ns` | `u64` | Change time (metadata change) |
| `btime_ns` | `u64` | Birth/creation time (0 if unsupported) |
| `size` | `u64` | File size in bytes |
| `blocks_512` | `u64` | `st_blocks` in 512-byte units |
| `blksize` | `u32` | Optimal I/O block size (`st_blksize`) |

### 3.8 InodeFlags

Per-inode behavioural flags:

| Field | Type | Purpose |
|---|---|---|
| `immutable` | `bool` | Cannot be modified or deleted (chattr +i) |
| `append_only` | `bool` | Writes append only; no overwrites (chattr +a) |
| `noatime` | `bool` | Access time updates suppressed |
| `nodump` | `bool` | Excluded from dump/backup (chattr +d) |

### 3.9 InodeAttr

The complete inode attribute bundle returned by `getattr` and friends:

| Field | Type | Purpose |
|---|---|---|
| `inode_id` | `InodeId` | The inode's identity |
| `generation` | `Generation` | Inode generation (ESTALE on mismatch) |
| `kind` | `NodeKind` | POSIX file type |
| `posix` | `PosixAttrs` | Full stat attributes |
| `flags` | `InodeFlags` | Per-inode behavioural flags |

`subtree_rev` is incremented on any change to the inode or its descendants.
`dir_rev` is incremented on any change to directory entries. Adapters use
these for NOTIFY_INVAL_ENTRY / NOTIFY_INVAL_INODE heuristics.

### 3.10 DirEntry

A single directory entry:

| Field | Type | Purpose |
|---|---|---|
| `name` | `bytes` | Raw entry name; not assumed UTF-8 |
| `inode_id` | `InodeId` | Target inode |
| `kind` | `NodeKind` | File type (from `readdir`/`readdirplus`) |
| `generation` | `Generation` | Inode generation at readdir time |
| `cookie` | `u64` | Stable offset cookie for seekdir/telldir |

### 3.11 StatFs

Filesystem statistics (`statfs`/`statvfs`):

| Field | Type | Purpose |
|---|---|---|
| `block_size` | `u32` | Fragment size (`f_frsize`) |
| `fragment_size` | `u32` | Block size (`f_bsize`) |
| `total_blocks` | `u64` | Total data blocks |
| `free_blocks` | `u64` | Free blocks |
| `avail_blocks` | `u64` | Free blocks available to unprivileged users |
| `files` | `u64` | Total file inodes |
| `files_free` | `u64` | Free inodes |
| `name_max` | `u32` | Maximum filename length |
| `fsid_hi` | `u32` | Filesystem ID (high 32 bits) |
| `fsid_lo` | `u32` | Filesystem ID (low 32 bits) |

---

## 4. SetAttr.valid mapping (FATTR_*)

The kernel expresses setattr intent via `fuse_setattr_in.valid`.
The engine uses the same bit positions as the canonical reference:

| Bit | Constant | Meaning |
|---|---|---|
| 0 | `FATTR_MODE` | Change file mode |
| 1 | `FATTR_UID` | Change owner UID |
| 2 | `FATTR_GID` | Change owner GID |
| 3 | `FATTR_SIZE` | Change file size (truncate/grow) |
| 4 | `FATTR_ATIME` | Change access time |
| 5 | `FATTR_MTIME` | Change modification time |
| 6 | `FATTR_FH` | File handle is valid (for `setattr` with open file) |
| 7 | `FATTR_ATIME_NOW` | Set atime to current time |
| 8 | `FATTR_MTIME_NOW` | Set mtime to current time |
| 9 | `FATTR_LOCKOWNER` | Lock owner field is valid |
| 10 | `FATTR_CTIME` | Change change time |

Time semantics:
- `UTIME_OMIT`: time bit not set in `valid` — leave unchanged
- `UTIME_NOW`: `FATTR_ATIME_NOW` or `FATTR_MTIME_NOW` set — ignore the
  corresponding `*_ns` value and set to current time
- `UTIME`: time bit set in `valid`, no `*_NOW` — use the `*_ns` value

The engine must also update ctime when any setattr changes mode, uid, gid,
size, atime, or mtime (Linux convention: ctime always updates on metadata
change unless `FATTR_CTIME` is explicitly set).

---

## 5. Namespace operations

All namespace operations receive a `RequestCtx`. Path traversal is the
adapter's responsibility; the engine receives parent `InodeId` and raw
name bytes.

### 5.1 get_root_inode

```
get_root_inode(ctx: RequestCtx) -> Result<InodeId, Errno>
```

Returns the root inode of the filesystem. This is the adapter's entry point
for mount and path resolution.

### 5.2 lookup

```
lookup(parent: InodeId, name: bytes, ctx: RequestCtx) -> Result<InodeAttr, Errno>
```

Look up `name` in directory `parent`. Returns the target inode's attributes.
Errors: `ENOENT` (not found), `ENOTDIR` (parent is not a directory),
`EACCES` (search permission denied).

### 5.3 getattr

```
getattr(inode: InodeId, handle: Option<EngineFileHandle>, ctx: RequestCtx) -> Result<InodeAttr, Errno>
```

Get attributes for `inode`. When `handle` is provided, it carries the open
file handle context (some filesystems use this for per-open inode state).
Errors: `ESTALE` (generation mismatch), `ENOENT` (deleted).

### 5.4 mkdir

```
mkdir(parent: InodeId, name: bytes, mode: u32, ctx: RequestCtx) -> Result<InodeAttr, Errno>
```

Create subdirectory `name` in `parent` with initial `mode`. Ownership: uid
from ctx.uid, gid from ctx.gid (or parent gid if setgid bit set on parent).
umask applied if FUSE_DONT_MASK is not negotiated. Returns the new directory's
attributes. Errors: `EEXIST`, `ENOSPC`, `ENOTDIR`, `EACCES`, `ENAMETOOLONG`.

### 5.5 create

```
create(parent: InodeId, name: bytes, mode: u32, flags: u32, ctx: RequestCtx)
    -> Result<(InodeAttr, EngineFileHandle), Errno>
```

Create regular file `name` in `parent` with `mode` and `flags` (O_RDWR,
O_EXCL, O_TRUNC, etc.). Returns the new file's attributes and an open
file handle. Ownership inheritance same as mkdir. Errors: `EEXIST`,
`ENOSPC`, `ENOTDIR`, `EACCES`.

### 5.6 tmpfile

```
tmpfile(parent: InodeId, mode: u32, flags: u32, ctx: RequestCtx)
    -> Result<(InodeAttr, EngineFileHandle), Errno>
```

Create an unnamed temporary file linked into `parent` (O_TMPFILE semantics).
The file has no directory entry until linked. Returns attributes and open
handle. Errors: `ENOSPC`, `EACCES`, `EOPNOTSUPP`.

### 5.7 unlink

```
unlink(parent: InodeId, name: bytes, ctx: RequestCtx) -> Result<(), Errno>
```

Remove `name` from directory `parent`. The inode's nlink is decremented;
if nlink reaches 0 and no open handles exist, the inode is scheduled for
deletion. Errors: `ENOENT`, `EPERM` (directory), `EBUSY` (open handles on
the target when filesystem requires last-close deletion), `EACCES`.

### 5.8 rmdir

```
rmdir(parent: InodeId, name: bytes, ctx: RequestCtx) -> Result<(), Errno>
```

Remove empty subdirectory `name` from `parent`. Errors: `ENOENT`, `ENOTEMPTY`,
`ENOTDIR`, `EBUSY` (open handles), `EACCES`.

### 5.9 rename

```
rename(old_parent: InodeId, old_name: bytes,
       new_parent: InodeId, new_name: bytes,
       flags: u32, ctx: RequestCtx) -> Result<(), Errno>
```

Atomically rename `old_name` in `old_parent` to `new_name` in `new_parent`.
`flags` carries renameat2 flags: 0 (plain rename), `RENAME_NOREPLACE` (1),
`RENAME_EXCHANGE` (2); `RENAME_WHITEOUT` (4) currently returns `EINVAL` (not yet implemented). See #1205 for the full
atomicity specification. Errors: `EEXIST` (NOREPLACE), `ENOENT`, `ENOTDIR`,
`EISDIR` (target is dir but source is not), `ENOTEMPTY` (target dir not empty),
`EXDEV` (cross-filesystem not supported).

### 5.10 link

```
link(target: InodeId, new_parent: InodeId, new_name: bytes, ctx: RequestCtx)
    -> Result<InodeAttr, Errno>
```

Create hard link `new_name` in `new_parent` pointing to `target` inode.
Increments nlink. Returns target's updated attributes. Errors: `EMLINK`
(link count exceeded), `EPERM` (directory hard link), `EXDEV`, `ENOSPC`,
`EACCES`.

### 5.11 symlink

```
symlink(parent: InodeId, name: bytes, target: bytes, ctx: RequestCtx)
    -> Result<InodeAttr, Errno>
```

Create symbolic link `name` in `parent` containing `target` as its value.
Returns the new symlink's attributes. Ownership: uid/gid from ctx (symlinks
have their own ownership, independent of target). Errors: `EEXIST`, `ENOSPC`,
`ENOTDIR`, `EACCES`.

### 5.12 readlink

```
readlink(inode: InodeId, ctx: RequestCtx) -> Result<bytes, Errno>
```

Read the target of symlink `inode`. Returns the symlink's target as raw bytes.
Errors: `EINVAL` (not a symlink), `ENOENT`.

### 5.13 mknod

```
mknod(parent: InodeId, name: bytes, mode: u32, rdev: u32, ctx: RequestCtx)
    -> Result<InodeAttr, Errno>
```

Create a special file (device node, FIFO, socket) named `name` in `parent`.
`mode` includes the file type, `rdev` is the device number for char/block
devices. Returns the new inode's attributes. Errors: `EPERM` (insufficient
privilege for device nodes), `EEXIST`, `ENOSPC`.

---

## 6. File I/O operations

### 6.1 open

```
open(inode: InodeId, flags: u32, ctx: RequestCtx) -> Result<EngineFileHandle, Errno>
```

Open `inode` with `flags` (O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_TRUNC,
O_DIRECT, ...). Returns a file handle the adapter uses for subsequent I/O.
The engine may return a handle with `fh_id=0` if no adapter-local identifier
is needed; the adapter sets it before use. Errors: `ENOENT`, `EACCES`,
`EISDIR`, `ETXTBSY`.

### 6.2 release

```
release(fh: EngineFileHandle) -> Result<(), Errno>
```

Release (close) a file handle. Called when the last reference is dropped.
The engine must flush pending writes before returning. After release, the
handle is invalid. Errors: none defined for the close itself (flush failures
are surfaced via `flush`/`fsync`, not `release`).

### 6.3 read

```
read(fh: EngineFileHandle, offset: u64, size: u32, ctx: RequestCtx)
    -> Result<bytes, Errno>
```

Read up to `size` bytes from `fh` starting at `offset`. Returns the bytes
actually read (may be less than `size` at EOF). `offset` is absolute file
position; the engine ignores any O_APPEND or per-handle seek position.
Errors: `EBADF` (not open for reading), `EIO`.

### 6.4 write

```
write(fh: EngineFileHandle, offset: u64, data: bytes, ctx: RequestCtx)
    -> Result<u32, Errno>
```

Write `data` to `fh` at `offset`. Returns the number of bytes written
(may be less than `data.len()` on ENOSPC or partial write). `offset` is
absolute; the engine ignores per-handle seek position. Errors: `EBADF`
(not open for writing), `ENOSPC`, `EIO`.

### 6.5 flush

```
flush(fh: EngineFileHandle, ctx: RequestCtx) -> Result<(), Errno>
```

Flush dirty data for `fh`. This is called on every `close()` (even if the
file was not modified) and on `fsync()`. The engine must ensure all
previously written data for this handle reaches stable storage. Errors: `EIO`.

### 6.6 fsync

```
fsync(fh: EngineFileHandle, datasync: bool, ctx: RequestCtx) -> Result<(), Errno>
```

Synchronize file data and metadata. If `datasync` is true, only data and
metadata needed to retrieve the data (size, mtime) must be flushed; other
metadata (atime) may be skipped. Equivalent to Linux `fsync`/`fdatasync`.
Errors: `EIO`.

### 6.7 fallocate

```
fallocate(fh: EngineFileHandle, mode: u32, offset: u64, length: u64, ctx: RequestCtx)
    -> Result<(), Errno>
```

Allocate or manipulate file space. `mode` is the `fallocate(2)` flags:

| Flag | Value | Meaning |
|---|---|---|
| `FALLOC_FL_KEEP_SIZE` | 1 | Don't update file size |
| `FALLOC_FL_PUNCH_HOLE` | 2 | Deallocate range (must also specify KEEP_SIZE) |
| `FALLOC_FL_ZERO_RANGE` | 16 | Zero range without deallocation |
| `FALLOC_FL_UNSHARE_RANGE` | 64 | Unshare reflinked extents |

The default (mode=0) allocates `length` bytes starting at `offset` and
extends the file size to `offset+length` unless KEEP_SIZE is set.
Errors: `ENOSPC`, `EOPNOTSUPP`, `EINVAL`.

---

## 7. Directory operations

### 7.1 opendir

```
opendir(inode: InodeId, ctx: RequestCtx) -> Result<EngineDirHandle, Errno>
```

Open directory `inode` for reading. Returns a directory handle. The engine
prepares any iteration state needed for subsequent `readdir` calls.
Errors: `ENOTDIR`, `EACCES`, `ENOENT`.

### 7.2 releasedir

```
releasedir(dh: EngineDirHandle) -> Result<(), Errno>
```

Release directory handle. After this, the handle is invalid. Called on
`closedir()`.

### 7.3 readdir

```
readdir(dh: EngineDirHandle, offset: u64, ctx: RequestCtx)
    -> Result<(entries: [DirEntry], has_more: bool), Errno>
```

Read directory entries starting from `offset`. `offset` is either 0 (start
of directory) or a `DirEntry.cookie` from a previous call (continuation).
Returns a batch of entries and `has_more=true` if more entries remain.
The adapter must call again with the last returned cookie to continue.
Errors: `EBADF`, `EIO`.

**Design rule**: The engine may return entries in any order, but the ordering
must be stable within a single `opendir`/`releasedir` session. Cookies must
be stable across mounts. `.` and `..` entries are the adapter's
responsibility; the engine should not return them.

### 7.4 fsyncdir

```
fsyncdir(dh: EngineDirHandle, datasync: bool, ctx: RequestCtx) -> Result<(), Errno>
```

Synchronize directory metadata. If `datasync` is true, only the directory's
entry data (names and inode pointers) must be flushed; other metadata may
be skipped. Errors: `EIO`.

---

## 8. Extended attribute operations

### 8.1 getxattr

```
getxattr(inode: InodeId, name: bytes, ctx: RequestCtx) -> Result<bytes, Errno>
```

Get extended attribute `name` of `inode`. Returns the attribute value.
If the adapter probes with an empty buffer (size=0), the engine returns
empty bytes and the adapter should report the attribute size from the
kernel protocol, not the engine response. Errors: `ENODATA` (attribute not
found), `ERANGE` (value too large for adapter buffer), `EACCES`.

### 8.2 setxattr

```
setxattr(inode: InodeId, name: bytes, value: bytes, flags: u32, ctx: RequestCtx)
    -> Result<(), Errno>
```

Set extended attribute `name` to `value`. `flags` is one of:
0 (create or replace), `XATTR_CREATE` (1, fail if exists),
`XATTR_REPLACE` (2, fail if not exists). Errors: `EEXIST`, `ENODATA`,
`ENOSPC`, `EACCES`.

### 8.3 listxattr

```
listxattr(inode: InodeId, ctx: RequestCtx) -> Result<bytes, Errno>
```

List all extended attribute names for `inode`. Returns null-separated
(`\0`) name bytes, with a final null (Linux `listxattr` convention).
When the adapter's buffer is smaller than the full name list, the engine
returns `ERANGE` and the adapter retries with a larger buffer.

### 8.4 removexattr

```
removexattr(inode: InodeId, name: bytes, ctx: RequestCtx) -> Result<(), Errno>
```

Remove extended attribute `name`. Errors: `ENODATA`, `EACCES`.

---

## 9. Key design rules and invariants

### 9.1 Name handling

- Names are **raw bytes**, never assumed UTF-8
- The engine must handle embedded nulls (`\0`) in names for lookup/unlink
  correctly — xfstests generic/453 creates filenames with embedded nulls
- Maximum name length is `NAME_MAX` (usually 255 bytes); longer names get
  `ENAMETOOLONG`
- `.` and `..` are never passed by the adapter; the engine must not return
  them in `readdir`

### 9.2 umask handling

The engine must track whether `FUSE_DONT_MASK` is negotiated:
- If negotiated: kernel does NOT apply umask; engine must apply ctx.umask
- If not negotiated: kernel already applied umask; engine must NOT re-apply

### 9.3 create/mkdir ownership

When creating files or directories:
- uid := ctx.uid
- gid := ctx.gid, unless parent has setgid bit, then gid := parent.gid
- mode := (mode & ~ctx.umask) when umask applies
- For `mkdir` specifically: if parent has setgid, the new directory also
  inherits the setgid bit

### 9.4 readdir cookies

- Cookie values are opaque to the adapter
- Cookie 0 always represents the start of the directory
- Cookies must be stable across unmount/remount cycles
- The engine may return entries in any order within a session, but the
  cookie for each entry must remain stable

### 9.5 Inode lifetime and generation

- InodeId values may be reused after the inode is deleted and a tombstone
  epoch passes
- Generation increments on every inode reuse
- getattr with a stale generation returns ESTALE
- Adapters use generation for FUSE `stale` file-handle detection

### 9.6 Lock ownership

- `EngineFileHandle.lock_owner` identifies the lock owner for POSIX lock
  operations
- The engine tracks locks per inode, subdivided by lock_owner
- `release` with a specific lock_owner may release all locks held by that
  owner on the inode

### 9.7 ctime updates

The engine must update `ctime` to the current time when:
- mode, uid, or gid changes
- atime or mtime is explicitly set
- size changes (via truncate or write)
- xattrs change (setxattr, removexattr)
- link count changes (link, unlink, rename)

The engine must NOT update ctime when:
- atime is updated implicitly by read (unless `noatime` constraint)
- Only `FATTR_CTIME` is set in setattr (caller is explicitly restoring ctime)

### 9.8 xattr buffer handling

For `getxattr`, when the adapter probes with an empty buffer, the engine
returns empty bytes. The adapter uses the return size from the kernel
protocol, not the engine response length. For `listxattr`, when the adapter's
buffer is smaller than the full name list, the engine returns `ERANGE` and
the adapter retries with a larger buffer (Linux standard pattern).

### 9.9 Unlink while open

When `unlink` removes the last link to an inode that has open file handles:
- The inode must remain accessible through those handles
- Space reclamation is deferred until the last handle is released
- POSIX requires this semantic for correct `O_TMPFILE` and temporary file
  patterns

### 9.10 fallocate hole semantics

- `FALLOC_FL_PUNCH_HOLE`: deallocates the range, reads return zeroes,
  file size unchanged (requires KEEP_SIZE)
- `FALLOC_FL_ZERO_RANGE`: zeroes the range without deallocation; space
  remains allocated
- Default fallocate: allocates space, file size extends to offset+length
  unless KEEP_SIZE

### 9.11 Hard link limit

The engine must enforce a link count limit (typically 2^32-1 for modern
filesystems, or a smaller per-filesystem maximum). Exceeding it returns
`EMLINK`.

### 9.12 Symlink ownership

Symlinks have their own inode with uid/gid/mode independent of the target.
These attributes are used for permission checks in the containing directory,
not for following the symlink. Changing a symlink's ownership does not
affect the target.

### 9.13 Directory size

Directory size (`st_size`) semantics are filesystem-dependent. The engine
should report a value that grows/shrinks with the number of entries, but
the exact formula is unspecified. Adaptations for readdir compatibility
should not depend on directory size.

### 9.14 Unsupported operations

Operations the engine does not support return `ENOSYS`. The adapter may
implement fallbacks (e.g., `mknod` returning `ENOSYS` and the adapter
synthesizing FIFO semantics). The engine should not return `ENOSYS` for
operations listed in this contract unless genuinely unimplemented.

---

## 10. Relationship to existing code

### 10.1 Current fuse_preview.rs

The FUSE in `crates/tidefs-local-filesystem/src/fuse_preview.rs`
currently implements a subset of these operations against the local
filesystem. The types in this document are the **target** API — the preview
code should be refactored toward these types as the engine API is
formalized.

### 10.2 Existing type crates

The VFS Engine API types are implemented in two crates:

- `tidefs-types-vfs-core` — portable `no_std` core types (11 types, 69 tests)
- `tidefs-vfs-engine` — the 29-operation `VfsEngine` trait (6 tests)

Legacy crates that carry types which overlap with this contract:

- `tidefs-types-posix-filesystem-adapter-core`
- `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime`
- `tidefs-local-filesystem`

The two-crate split (`types-vfs-core` / `vfs-engine`) avoids circular
dependencies between the engine trait and adapter implementations.
This supersedes the earlier suggestion of a single `tidefs-types-vfs-engine` crate.

### 10.3 VFS_RPC (#1234)

The VFS_RPC wire protocol must be a direct encoding of the operations in
this contract. Every operation maps to exactly one VFS_RPC method.
Method IDs, idempotency tokens, and term/epoch fencing are specified in
#1234 — this document defines **what** the methods do, not how they are
encoded.

---

## 11. Dependencies

### 11.1 Issues this contract depends on

| Issue | What | Status |
|---|---|---|
| #1198 | POSIX semantics spec | Ownership/mode inheritance rules |

### 11.2 Issues blocked by this contract

This is the **INTERFACE issue**. The following depend on the canonical types
and ops defined here:

| Layer | Issue | What depends |
|---|---|---|
| L3 (namespace) | #1205 | Rename atomicity — namespace ops against VFS types |
| L3 (namespace) | #1206 | Lock hierarchy — lock ordering depends on VFS ops |
| L3 (namespace) | #1207 | Orphan index — inode lifecycle in VFS contract |
| L3 (namespace) | #1219 | Dataset lifecycle — ACTIVE/DESTROYING/TOMBSTONE via VFS |
| L3 (storage) | #1289 | Directory index polymorphism — dir ops on VFS types |
| L3 (storage) | #1290 | Xattr storage polymorphism — xattr ops on VFS types |
| L3 (snapshots) | #1232 | Snapshot deadlist — snapshot ops in VFS contract |
| L11 (ublk) | #1216 | ublk volume — block surface maps to VFS inode types |
| L11 (fuse) | #1233 | FUSE binding — FUSE ops mapped to VFS ops |
| L11 (trace) | #1235 | Trace emission — trace events reference VFS ops |

See #1284 (DESIGN dependency matrix) for the full Layer 3 chain.

---


- The types defined here exist as Rust structs/enums in a crate
- Every operation listed here has a corresponding Rust trait method
- The FUSE adapter compiles against these types
- At least one adapter integration test exercises the full cycle:
  create → getattr → write → read → fsync → readdir → unlink → rmdir

---

## 13. Implementation history

| Date | Event | Issue |
|---|---|---|
| 2026-05-02 | Core types implemented: all 11 types in `tidefs-types-vfs-core`, 69 tests | #1306 |
| 2026-05-02 | 24 VFS engine trait/interface operations deferred | #1340 |
| 2026-05-03 | 29 VFS engine trait/interface operations implemented in `tidefs-vfs-engine` | #1488 |
| 2026-05-04 | Core types verified: 75 tests across both crates, cargo check clean | #1557 |
| 2026-05-04 | Contract maturity promoted to `implemented-source`; implementation tracking consolidated | #1887 |

---

## 14. Remaining deferred items

- Trait/interface operations: implemented per #1488 (no longer deferred).
- FUSE adapter full-cycle integration test (see §12): deferred to wire-up.
- VFS_RPC wire-protocol encoding (#1234): deferred to transport lane.
