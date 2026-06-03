# Send/receive changed-record stream (OW-109) (v0.417)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

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

The implementation-tracked non-release gate is:

```text
cargo run -p tidefs-xtask -- check-send-receive
```

The stable implementation-tracked non-release command name is `tidefs-xtask check-send-receive`.

## Still Open

This slice does not implement incremental resume, non-empty target merges,
network transport, distributed authorization, or multi-writer conflict
resolution. It is the first local send/receive proof that committed-root
without operator repair.
