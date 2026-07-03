# Send/receive changed-record stream

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source and
> `docs/REVIEW_TODO_REGISTER.md`.

This document describes historical tracker item 109 for the Local Filesystem
preview. The implemented stream is a local changed-record send/receive format over
manifest-backed committed roots. It is not distributed replication, background
resync, or conflict resolution.

## Contract

`VFSSEND1` is the versioned changed-record stream for this slice. A stream
contains one current authenticated committed root plus any snapshot source roots
referenced by the current snapshot catalog.

Each exported root carries:

- the committed-root summary;
- the transaction manifest record;
- every transaction object named by that manifest;
- every versioned content manifest and content chunk named by that manifest.

uses the existing root-authentication, superblock digest, manifest digest,
transaction-manifest checksum, namespace invariant, and content-chunk checksum
checks.

## Receive

Receive targets a root path that does not already exist. The receiver writes
reconstructs transaction objects from decoded state, re-signs imported roots
with the destination root-authentication key, verifies the selected received
root, and only then renames the staging directory into place.

Snapshot roots are imported before the current root. The current snapshot
catalog is rewritten to reference the destination-signed root summaries, so
snapshot rollback still works after receive with the destination key.

Incremental receive is local-only authority for an existing target. The stream
must be marked incremental and carry `from_root`; the target must already have
that exact manifest-backed, authenticated base identity in recovery audit and
the base must be protected by a data-retaining snapshot or clone record with
matching catalog and lifecycle-pin authority. Before publishing the received
current root, receive verifies the target can load the protected base root and
that every content object named by incoming manifests, including omitted
unchanged content, is present and checksum-valid in the target store. Placement
epochs are reported as stable only when both sides carry the same explicit
epoch; mismatched explicit epochs refuse the incremental receive, and absent
evidence remains unknown/unstable.

Current VFSSEND2 send-side authority emits a lineage manifest as the first
send record, before snapshot or object payload records. The manifest names the
source pool/dataset, target root, stream format version, target-root digest,
and either a pinned base-root id plus base-root digest for incrementals or an
explicit no-base declaration for full sends. Incremental send construction
fails before object records are planned when the requested base root is absent,
unpinned, or bound to a different dataset/root than the stream header.

## Source Surfaces

- `SEND_RECEIVE_CHANGED_RECORD_SPEC`
- `SEND_RECEIVE_STREAM_MAGIC_ASCII`
- `ChangedRecordExport`
- `ChangedRecordImportReport`
- `ChangedRecordObjectRole`
- `LocalFileSystem::export_changed_records`
- `LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key`


The source tests cover:

- current-root plus snapshot-root round-trip into a fresh receiver;
- receive with a different destination root-authentication key;
- encoded stream round-trip through `VFSSEND1`;
- rollback to an imported snapshot after receive;
- corrupt changed-record payload rejection before the target root is published.
- incremental receive refusal for missing, loose, divergent, or unprotected
  base roots and for missing omitted content before a new selected root is
  published.

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-send-receive
```

The stable implementation-tracked non-release command name is `tidefs-xtask check-send-receive`.

## Still Open

This slice does not implement incremental resume, distributed replication,
network transport authorization, placement receipts, deadlist/reclaim
accounting, non-empty target conflict resolution, or multi-writer conflict
resolution. It is local send/receive authority for committed-root
round-tripping and fail-closed incremental apply; it is not an OpenZFS/Ceph-class
replication claim.
