# POSIX Compliance Matrix

Last updated: 2026-06-03

This document tracks which POSIX filesystem operations work correctly through
the TideFS FUSE mount, which have known gaps, and which are untested.

Status: DONE = implemented and tested, GAP = implemented with known issues,

## File Operations

| Operation | Status | Notes |
|---|---|---|
| open (O_RDONLY) | DONE | |
| open (O_WRONLY) | DONE | |
| open (O_RDWR) | DONE | |
| open (O_CREAT) | DONE | |
| open (O_EXCL) | DONE | |
| open (O_TRUNC) | DONE | |
| open (O_APPEND) | UNTEST | Implemented, no dedicated xfstests coverage |
| open (O_DIRECTORY) | DONE | |
| open (O_NOFOLLOW) | UNTEST | |
| creat | DONE | Via open(O_CREAT\|O_WRONLY\|O_TRUNC) |
| close | DONE | |
| read | DONE | |
| write | DONE | |
| write (sparse) | DONE | Sparse I/O with hole skipping |
| pread | DONE | Via FUSE read with offset |
| pwrite | DONE | Via FUSE write with offset |
| readv | DONE | |
| writev | DONE | |
| lseek (SEEK_SET) | DONE | |
| lseek (SEEK_CUR) | DONE | |
| lseek (SEEK_END) | DONE | |
| lseek (SEEK_DATA) | DONE | |
| lseek (SEEK_HOLE) | DONE | |
| truncate | DONE | |
| ftruncate | DONE | |
| fallocate (mode 0) | DONE | EOF extension, zero-fill |
| fallocate (FALLOC_FL_KEEP_SIZE) | UNTEST | |
| fallocate (FALLOC_FL_PUNCH_HOLE) | GAP | Implemented, limited test coverage |
| fsync | DONE | |
| fdatasync | DONE | |
| syncfs | DONE | |
| sync | UNTEST | |
| poll | DONE | Implemented for regular files |
| flock (BSD) | DONE | |
| fcntl (F_GETLK) | DONE | POSIX advisory lock query |
| fcntl (F_SETLK) | DONE | POSIX advisory lock, non-blocking |
| fcntl (F_SETLKW) | DONE | POSIX advisory lock, blocking |
| mmap | NONE | No mmap support yet |
| readahead | UNTEST | Kernel-mediated via FUSE_READ; sequential readahead in fuse_vfs_adapter |
| fiemap | UNTEST | |
| copy_file_range | DONE | |

## File Metadata Operations

| Operation | Status | Notes |
|---|---|---|
| stat | DONE | |
| fstat | DONE | |
| lstat | DONE | |
| statx | DONE | |
| fstatx | DONE | |
| access | DONE | R_OK/W_OK/X_OK/F_OK |
| faccessat | UNTEST | |
| chmod | DONE | |
| fchmod | DONE | |
| chown | DONE | |
| fchown | DONE | |
| utimensat | DONE | |
| futimens | DONE | |
| name_to_handle_at | NONE | |
| open_by_handle_at | NONE | |

## Directory Operations

| Operation | Status | Notes |
|---|---|---|
| mkdir | DONE | |
| mkdirat | DONE | |
| rmdir | DONE | Non-empty directory rejection (ENOTEMPTY) |
| opendir | DONE | |
| readdir | DONE | |
| readdirplus | UNTEST | |
| rewinddir | UNTEST | |
| closedir | DONE | |
| getdents | DONE | Via readdir |
| getdents64 | DONE | Via readdir |

## Namespace Operations

| Operation | Status | Notes |
|---|---|---|
| link | DONE | Hard link creation |
| unlink | DONE | |
| rename | DONE | |
| renameat2 (RENAME_NOREPLACE) | DONE | |
| renameat2 (RENAME_EXCHANGE) | DONE | Atomic swap |
| symlink | DONE | |
| readlink | DONE | |
| mknod (S_IFREG) | DONE | |
| mknod (S_IFIFO) | DONE | Mounted smoke verifies FIFO metadata and duplicate-name errno |
| mknod (S_IFBLK) | DONE | Mounted smoke verifies block-device mode and `rdev` metadata |
| mknod (S_IFCHR) | DONE | Mounted smoke verifies character-device mode, `rdev` metadata, and `/dev/null` write-through behavior |
| mknod (S_IFSOCK) | DONE | Mounted smoke verifies socket mode and zero `rdev` metadata |

## Extended Attribute Operations

| Operation | Status | Notes |
|---|---|---|
| getxattr | DONE | |
| setxattr | DONE | |
| listxattr | DONE | |
| removexattr | DONE | |
| POSIX ACL (system.posix_acl_default) | DONE | ACL inheritance for directories |

## Filesystem-Level Operations

| Operation | Status | Notes |
|---|---|---|
| statfs | DONE | |
| fstatfs | DONE | |
| statvfs | DONE | |
| mount | DONE | FUSE mount |
| umount | DONE | fusermount3 -u |

## File Lock Operations

| Operation | Status | Notes |
|---|---|---|
| flock (LOCK_SH) | DONE | |
| flock (LOCK_EX) | DONE | |
| flock (LOCK_UN) | DONE | |
| flock (LOCK_NB) | DONE | |
| fcntl (F_GETLK/F_SETLK/F_SETLKW) | DONE | Byte-range locks |
| lockf | UNTEST | POSIX lockf, should map to fcntl |

## xfstests Coverage

| Test | Status | Notes |
|---|---|---|
| generic/419+ | UNTEST | |

## Known Gaps

1. **mmap**: No mmap support. Fundamental gap for database workloads and
   executable loading from TideFS mounts. Kernel-mediated page cache
   integration needed.

2. **copy_file_range**: Implemented via VfsEngine::copy_file_range
   byte-range copy primitive with capacity reservation.

3. **FALLOC_FL_PUNCH_HOLE**: Implemented in extent map layer but limited
   FUSE integration test coverage.

4. **O_APPEND**: Implemented at VFS engine level but no xfstests coverage
   for atomic append semantics across multiple writers.

5. **xfstests coverage**: The current #6582 and #6584 smoke tranches
   through #6598 tranches (`generic/051`-`generic/418`) have QEMU/KVM FUSE
   preconditions, #6588/#6592/#6594 teardown busy failures, and the #6596
   `generic/346` hard hang. The #6596 failures include read-only/special-node
   expected-output drift, ACL and timestamp update drift, 600s timeout hangs,
   truncate-down timestamp drift, ACL inheritance/userns errno drift, and
   ENOSPC/ftruncate/file-exists behavior. The #6598 failures add
   ENOSPC/ftruncate/file-exists behavior, missing temp cleanup after checksum,
   a direct-I/O timeout hang, ftruncate EIO/ENOSPC behavior,
   special-node/find-by-type setup drift, and checksum read EIO; the
   `generic/375` ACL/SGID drift was rechecked on 2026-06-04 with adapter
   file/directory regressions plus direct mounted FUSE reproduction and is no
   longer carried as an expected ACL failure. The #6587, #6589, #6591, #6593,
   #6595, #6597, and #6599 mounted-kernel VFS
   23 pass rows, 11 product failures, 12 unsupported rows, and 4 skipped rows;
   #6589 has 14 pass rows, 3 product failures, 29 unsupported rows, and 4
   skipped rows; #6591 has 4 pass rows, no product failures, 43 unsupported
   rows, and 3 skipped rows; #6593 has 5 pass rows, 7 product failures, 36
   unsupported rows, and 2 skipped rows; #6595 has 3 pass rows, 7 product
   failures, 38 unsupported rows, and 2 skipped rows; #6597 has 13 pass rows,
   11 product failures, 21 unsupported rows, and 5 skipped rows; and #6599 has
   8 pass rows, 8 product failures, 32 unsupported rows, and 20 skipped rows.
   None of the accepted K7
   matrices has deferred, harness-fail, or environment-refusal rows. The
   broader xfstests suite is not yet integrated as a release gate.

6. **POSIX ACL enforcement**: ACLs are encoded/decoded and structurally
   needs broader coverage.

7. **Directory readdir cookies**: Directory position tracking across
   directory modifications during readdir needs edge-case testing.

## Verification Methodology

To verify a status:
1. Mount TideFS: `cargo run -p tidefs-posix-filesystem-adapter-daemon -- mount --store /tmp/store --mount /tmp/mnt`
2. Run the POSIX operation through standard tools (`touch`, `mkdir`, `ln`, etc.)
3. Verify correct behavior, error codes, and persistence across remount
4. Run corresponding xfstests test if available
