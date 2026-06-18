# POSIX semantics OW-106 (v0.409)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 106 for the userspace FUSE
preview. It covers the first useful-preview semantics that were intentionally
left out of the v0.408 mount path: file fsync, directory fsync,
unlink-while-open, and rename-over-target.

## Durability boundary

`fsync-file` and `fsync-directory` now return success only after the local
filesystem asks the Local Object Store to sync. Namespace and file-content
mutations are still published through the existing transaction objects and
root-slot publication path. The resulting success boundary is therefore:

1. mutation writes content, inode, directory, superblock, and transaction
   manifest objects as needed;
2. mutation publishes a committed root-slot candidate;
3. fsync calls the Local Object Store sync boundary.

The preview adapter does not claim per-inode media ordering beyond that
root-slot publication and Local Object Store sync boundary. The mounted preview
does make an honest success/failure claim: if the backing store sync fails, the
FUSE fsync returns `EIO`.

## Rename replacement

`rename-over-target` is implemented in `LocalFileSystem::rename`, not only in
the FUSE adapter. Replacement is committed as one namespace mutation through the
same root-slot publication path as ordinary rename. The rules are:

- regular file or symlink replacement removes the target directory entry and
  drops the target inode when it was the final link;
- directory replacement is allowed only when the target directory is empty;
- file-over-directory, directory-over-file, non-empty-directory replacement, and
  moving a directory into its own subtree are rejected before committing.

The FUSE adapter preserves an already-open replaced regular file in session
state until the final handle release.

## Open-handle lifetime

`unlink-while-open` is a session lifetime rule. The committed local filesystem
must not persist unreachable orphan inodes because the mount invariant gate
rightly rejects unreachable non-directory inodes. Instead, FUSE session state in
the adapter owns volatile open-handle content:

- last-link unlink of an open regular file removes the durable namespace entry;
- the open handle continues to read and write a session-owned content buffer;
- the session-owned buffer is dropped on final `release`;
- the buffer is not persisted as orphan inodes and is not visible after remount.

That boundary matches the current preview architecture: durable namespace truth
lives in root-slot commits, while open unlinked file lifetime is a live FUSE
session concern.


The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-posix-semantics
```

Focused implementation tests cover:

- local filesystem file replacement rename;
- local filesystem empty-directory replacement rename;
- local filesystem invalid replacement rejection;
- FUSE adapter unlink-while-open handle retention;
- FUSE adapter rename-over-open-target handle retention;
- live FUSE smoke with file fsync, directory fsync, unlink-while-open, and
  rename-over-target.
