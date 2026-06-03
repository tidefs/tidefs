# Safe local reclamation (OW-103) (v0.413)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document describes historical tracker item 103 for the local filesystem
preview. The implemented slice is mutating local GC over the append-only Local
Object Store: it can tombstone unprotected live objects and retire segment
files only after a root-retention proof names the committed roots and exact
root-slot locations that must survive.

## Safety boundary

Safe reclamation is allowed only when `RootRetentionPlan` has no retention debt.
If fewer valid committed roots exist than the policy requires,
`LocalFileSystem::safe_reclaim_unprotected_objects()` fails with
`FileSystemError::RetentionDebt` and does not start reclamation.

The operation preserves protected root-slot locations and:

- every protected committed root named by the retention plan;
- every exact protected root-slot location named by
  `protected_root_slot_locations`;
- every object key required by protected transaction manifests;
- the currently selected committed root and live namespace state.

## Store mutation sequence

`LocalObjectStore::compact_retaining()` performs the mutation in this order:

1. Verify all protected exact root-slot locations can still be read.
2. Keep all segments containing protected exact root-slot locations.
3. Copy protected non-root objects out of segments that may be retired.
4. Write tombstones for unprotected keys that are live or could otherwise
5. Sync the store.
6. Remove only segment files not needed for protected exact locations or newly
   written protected copies/tombstones. This is the only segment retirement
   path in the current local preview.
7. Reopen the store and verify the protected exact locations are still readable.

This is not production fsck. It does not guess repairs or rewrite namespace
roots and object graph to preserve.

## Source surfaces

- `StoreRetentionCompactionReport`
- `LocalObjectStore::compact_retaining`
- `SafeReclamationReport`
- `LocalFileSystem::reclaim_unprotected_objects`
- `LocalFileSystem::safe_reclaim_unprotected_objects`
- `FileSystemError::RetentionDebt`


The primary regression test is
root-slot locations, reopens the filesystem, and checks that the current file
content and recovery audit are still valid.

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-safe-local-reclamation
```

The stable implementation-tracked non-release command name is
`tidefs-xtask check-safe-local-reclamation`.


```text
```

## Non-goals

This OW-103 slice does not implement online scrub, block export, or distributed
snapshot roots to reclamation protection. v0.417 changed-record send/receive
This slice also does not rewrite protected root-slot records, because exact
root-slot fallback locations are part of the no-production-fsck recovery proof.
