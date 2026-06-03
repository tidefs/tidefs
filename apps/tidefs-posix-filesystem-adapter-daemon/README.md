# tidefs-posix-filesystem-adapter-daemon

FUSE daemon that mounts a TideFS filesystem backed by `VfsEngine` via the
`LocalFileSystem` store. The daemon accepts POSIX filesystem operations
through the Linux FUSE kernel interface and dispatches them to the VFS engine.

## FUSE Validation Test Suites

| Test File | Tests | Domain |
|-----------|-------|--------|
| `fuse_vfs_link_smoke.rs` | 1 | — |
| `fuse_rename_link_symlink.rs` | 3 | — |
| `fuse_link_unlink.rs` | 22 | `tidefs-fuse-link-unlink-v1` |
| `rmdir_smoke.rs` | 7 | — |
| `fuse_xattr_smoke.rs` | 16 | — |
| `xattr_statx_blake3_integration.rs` | 3 | `tidefs-fuse-xattr-statx-v1` |

### rmdir_smoke.rs

Mounted FUSE integration tests for rmdir through the VFS-backed adapter.
Covers empty-directory removal, ENOTEMPTY rejection for non-empty
directories, ENOTDIR when targeting a regular file, ENOENT for
nonexistent entries, EBUSY for the mount root, inode recycling on
recreate, and post-rmdir stat returning ENOENT.

### fuse_link_unlink.rs

BLAKE3-verified link/unlink validation harness exercising hardlink creation
and removal through a real FUSE mount. Validates nlink integrity, EMLINK
saturation, cross-directory linking, concurrent isolation, remount
persistence, FIFO/directory error paths, and domain-separation determinism
(domain: `tidefs-fuse-link-unlink-v1`).

### fuse_xattr_smoke.rs

Mounted FUSE integration tests for getxattr, setxattr, listxattr, and
removexattr through the VFS adapter. Covers round-trip, XATTR_CREATE /
XATTR_REPLACE flags, error paths (ENODATA, ERANGE, EPERM), remount
persistence, and trusted.* / security.* namespace filtering.

### xattr_statx_blake3_integration.rs

BLAKE3-verified xattr-statx integration tests validating statx replies
carry xattr/ACL presence metadata and that BLAKE3 xattr state digests
are deterministic across mount cycles (domain: `tidefs-fuse-xattr-statx-v1`).

## Supported Operations

| Operation       | Opcode | Status      | Notes |
|-----------------|--------|-------------|-------|
| lookup          | 1      | Implemented |       |
| forget          | 2      | Implemented |       |
| getattr         | 3      | Implemented |       |
| setattr         | 4      | Implemented |       |
| readlink        | 5      | Implemented |       |
| symlink         | 6      | Implemented |       |
| mknod           | 8      | Implemented |       |
| mkdir           | 9      | Implemented |       |
| unlink          | 10     | Implemented |       |
| rmdir           | 11     | Implemented |       |
| rename          | 12     | Implemented |       |
| link            | 13     | Implemented |       |
| open            | 14     | Implemented |       |
| read            | 15     | Implemented |       |
| write           | 16     | Implemented |       |
| statfs          | 17     | Implemented |       |
| release         | 18     | Implemented |       |
| fsync           | 20     | Implemented |       |
| **getxattr**    | **22** | **Implemented** | Backed by local-filesystem xattr storage |
| **setxattr**    | **6**  | **Implemented** | XATTR_CREATE/XATTR_REPLACE supported |
| **listxattr**   | **23** | **Implemented** | NUL-separated packed name list |
| **removexattr** | **24** | **Implemented** |       |
| opendir         | 27     | Implemented |       |
| readdir         | 28     | Implemented |       |
| releasedir      | 29     | Implemented |       |
| fallocate       | 43     | Implemented |       |
| lseek           | 46     | Implemented | SEEK_DATA/SEEK_HOLE |
| **statx**       | **52** | **Implemented** | STATX_BASIC_STATS + STATX_BTIME + STATX_ATTRS |
| copy_file_range | 47     | Implemented | Read-write loop through engine; intent-logged for crash recovery |

## Zero-Copy Paths (Splice / Sendfile)

The daemon advertises FUSE splice capabilities during FUSE_INIT
(FUSE_SPLICE_WRITE, FUSE_SPLICE_MOVE, FUSE_SPLICE_READ). These flags tell the
kernel it can use pipe splicing for FUSE read/write operations. The daemon's
read and write handlers do not require special splice logic: the kernel manages
the zero-copy pipe path transparently.

sendfile(2) on FUSE files works through the same splice mechanism:
the kernel issues a FUSE_READ with the splice flag, the daemon replies with
the requested data range, and the kernel splices bytes directly into the
socket or destination fd.

copy_file_range between two FUSE fds on the same mount is handled by the
daemon's FUSE_COPY_FILE_RANGE handler. The engine copy reads source data and
writes it to the destination via the read/write path. When only one fd is a
FUSE file, the kernel falls back to splice-based copy internally.

The storage-level reflink_chunked_content primitive (content-addressed dedup
redirects) is available for future zero-copy intra-filesystem copy_file_range
optimisations.

| Capability               | Negotiated | Mechanism |
|--------------------------|-----------|----------|
| FUSE_SPLICE_READ         | Yes       | Kernel splices FUSE_READ replies into pipe/socket fds |
| FUSE_SPLICE_WRITE        | Yes       | Kernel splices pipe/socket writes into FUSE_WRITE requests |
| FUSE_SPLICE_MOVE         | Yes       | Page-moving between pipe and FUSE device |
| FUSE_COPY_FILE_RANGE     | Handled   | Daemon-side byte-range copy via engine read/write loop |

## Xattr Namespaces

| Namespace                | Access Control      | Status    |
|--------------------------|---------------------|-----------|
| `user.*`                 | Any uid             | Supported |
| `system.posix_acl_access`| File owner or root  | Supported |
| `system.posix_acl_default`| Dir owner or root  | Supported |
| `trusted.*`              | Root only           | Supported |
| `security.*`             | Root only           | Stub      |

## Statx Attributes

The `dispatch_statx` path populates `stx_attributes` with:

| Flag                          | Condition                            |
|-------------------------------|--------------------------------------|
| `STATX_ATTR_XATTR_PRESENT`    | Inode has any extended attribute     |
| `STATX_ATTR_POSIX_ACL_ACCESS` | `system.posix_acl_access` is present |
| `STATX_ATTR_POSIX_ACL_DEFAULT`| `system.posix_acl_default` is present|

## BLAKE3 Integrity

Xattr state digests are computed with domain `tidefs-fuse-xattr-statx-v1`
for deterministic validation. See `src/xattr_integrity.rs`.

## Mount Options

| Flag | Default | Description |
|------|---------|-------------|
| `--writeback-cache` | off | Opt in to FUSE writeback-cache for buffered writes. |
| `--no-writeback-cache` | — | Explicitly disable writeback-cache (default). |
| `--writeback-cache-timeout <s>` | 60 | Max age in seconds of dirty pages before background flush. |
| `--sync` | off | Force synchronous writes (durability barrier per write). |
| `-o <options>` | — | Comma-separated FUSE mount options (atime, sync, async, intent_log_write=…). |
| `--no-intent-log-write` | off | Disable buffered-write intent-log recording for crash safety. |
| `--coherency <profile>` | writeback | Caching coherency profile (strict, writeback, nearline, async, offline). |

### Writeback-cache default

The FUSE writeback-cache is **disabled by default** (safe direct-write path).
Use `--writeback-cache` to opt into kernel-buffered writes. This default
avoids acknowledging writes before payloads reach the storage engine.
