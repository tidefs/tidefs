# Local snapshots and rollback (OW-108) (v0.416)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 108 for the Local Filesystem.
Local snapshots are named references to an authenticated committed-root. They
are not directory copies, hidden mutable branches, or repair-time guesses.

## Contract

Each new snapshot stores a `SnapshotSummary` in the authenticated superblock
catalog. The catalog is encoded under the `VFSSNAP1` marker and is covered by
the committed-root superblock digest, so changing snapshot metadata changes the
authenticated committed root.

A snapshot records:

- the snapshot name;
- the source transaction id;
- the source filesystem generation;
- the committed-root summary, including root-authentication fields;
- the generation at which the snapshot catalog entry was published.

Snapshot names use the same byte-level component rules as local path names:
non-empty, at most 255 bytes, no slash, no NUL, and not `.` or `..`.

## Rollback

`LocalFileSystem::rollback_to_snapshot` loads the snapshot source root through
superblock digest, manifest digest, transaction manifest, namespace invariants,
and referenced objects before publishing anything.

Rollback then publishes a new authenticated committed root from the snapshot
namespace. The current snapshot catalog is preserved, and `next_inode_id` is
kept monotonic so post-rollback creates do not reuse inode ids consumed by later
discarded history.

In short: rollback publishes a new authenticated root; it does not move the live
filesystem back onto an old root slot.

## Reclamation

Safe local reclamation treats snapshot roots as protected committed roots in
addition to the normal newest-root retention policy. The compaction plan
preserves exact root-slot locations for snapshot roots, verifies protected roots
directly after compaction, and only then reports mutation as safe.

The required safety rule is explicit: safe reclamation protects snapshot roots.
Allocator reservation counts snapshot roots even when a snapshot source root is
hidden behind newer root-slot versions, so new writes cannot spend capacity that
is still needed for rollback.

## Source surfaces

- `LOCAL_SNAPSHOT_ROLLBACK_SPEC`
- `SNAPSHOT_CATALOG_MAGIC_ASCII`
- `SnapshotSummary`
- `SnapshotRollbackReport`
- `LocalFileSystem::list_snapshots`
- `LocalFileSystem::snapshot_summary`
- `LocalFileSystem::create_snapshot`
- `LocalFileSystem::delete_snapshot`
- `LocalFileSystem::rollback_to_snapshot`


The source tests cover:

- snapshot isolation across later writes and creates;
- rollback publishing a new authenticated root instead of moving live state to
  an older root slot;
- snapshot catalog persistence across reopen;
- safe reclamation preserving snapshot roots so later rollback still works.
- allocator reservation preserving hidden snapshot-root content before admitting
  new writes.

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-local-snapshots
```

The stable implementation-tracked non-release command name is
`tidefs-xtask check-local-snapshots`.

## Still open

This slice does not implement clones, a user-facing snapshot CLI, snapshot quota
policy, transparent snapshot browsing, incremental receive/resume, non-empty
target merge, network send/receive transport, or distributed snapshot
replication. v0.417 adds the first fresh-root changed-record send/receive pass
