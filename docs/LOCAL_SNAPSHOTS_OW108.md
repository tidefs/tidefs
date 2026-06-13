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

## Current lifecycle authority

Current mounted snapshot lifecycle authority is the intersection of:

- `state.snapshots` entries whose kind is a data-retaining regular snapshot or
  clone;
- the canonical dataset catalog entry at `root@<name>`;
- the lifecycle GC pin for the full snapshot traversal-root identity.

Retention pruning uses the explicit snapshot delete path, so hold-protected
snapshots are skipped and pruned snapshots release the matching dataset catalog
entry and lifecycle pin. Clone create/delete/promote transitions now maintain
the same catalog and lifecycle-pin authority. Clone catalog entries carry the
clone flag until promotion, and promotion repairs the catalog entry to a
regular snapshot entry while preserving the traversal-root pin reference.

Rollback and send/export entry points fail closed when data-retaining snapshot
records do not match catalog entries or lifecycle pin refcounts. Reopen
reconciles missing data-retaining snapshot catalog entries and pins from the
durable snapshot catalog, and removes stale `root@...` catalog entries that no
longer have a data-retaining snapshot record. Bookmark records remain
non-retaining replication anchors and are excluded from send/recovery protected
root expansion.

This authority still does not close TFR-010. Snapshot-pinned bytes must later
feed the placement receipt and rebuild/reclaim authority tracked by #17 and
#18 before TideFS can claim unified deadlist, capacity, or distributed
snapshot-reclaim correctness.

## Source surfaces

- `LOCAL_SNAPSHOT_ROLLBACK_SPEC`
- `SNAPSHOT_CATALOG_MAGIC_ASCII`
- `SnapshotSummary`
- `SnapshotRollbackReport`
- `LocalFileSystem::list_snapshots`
- `LocalFileSystem::snapshot_summary`
- `LocalFileSystem::create_snapshot`
- `LocalFileSystem::delete_snapshot`
- `LocalFileSystem::prune_snapshots`
- `LocalFileSystem::create_clone`
- `LocalFileSystem::delete_clone`
- `LocalFileSystem::promote_clone`
- `LocalFileSystem::rollback_to_snapshot`


The source tests cover:

- snapshot isolation across later writes and creates;
- rollback publishing a new authenticated root instead of moving live state to
  an older root slot;
- snapshot catalog persistence across reopen;
- safe reclamation preserving snapshot roots so later rollback still works;
- allocator reservation preserving hidden snapshot-root content before admitting
  new writes;
- retention pruning of regular snapshots while skipping held snapshots and
  excluding clones/bookmarks;
- clone delete/promote/reopen reconciliation against catalog entries and
  lifecycle pins;
- rollback and send/export rejection when snapshot catalog or pin authority has
  drifted.

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-local-snapshots
```

The stable implementation-tracked non-release command name is
`tidefs-xtask check-local-snapshots`.

## Still open

This slice does not implement a user-facing snapshot/clone CLI, snapshot quota
policy, transparent snapshot browsing, incremental receive/resume, non-empty
target merge, network send/receive transport, or distributed snapshot
replication. v0.417 adds the first fresh-root changed-record send/receive pass
