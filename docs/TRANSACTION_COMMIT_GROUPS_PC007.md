# transaction model / commit groups / dirty buffers

TFR-019 authority classification: historical input. This imported note records
the transaction-model closeout wording for review; it is not release authority
without reconciliation against current source and validation evidence.

This document is the implementation-tracked non-release transaction-model note
for the current preview scope. It does not add a new transaction engine. It binds the existing
Local Filesystem transaction-root implementation, transaction manifests,
root-slot publication, dirty content/chunk staging, sync failure behavior, and
FUSE fsync boundary into one explicit release-gate model.

## Claim Boundary

The historical closeout treated the current local/FUSE implementation as an
implemented-source transaction model:

- commit groups are local root transactions identified by a transaction id;
- dirty buffers are staged as content/chunk, inode, directory, superblock, and
  transaction-manifest objects before publication;
- root-slot publication is the only namespace/file truth boundary;
- `fsync-file` and `fsync-directory` success requires root-slot publication plus
  Local Object Store sync;
- `fdatasync`, `O_SYNC`, and `O_DSYNC` are bound to the same caller-barrier law
  when a later adapter exposes them.

This is not a claim that the current FUSE implementation implements distinct
`O_DSYNC` open-flag handling. The current live mount path exposes file and
directory fsync; future `O_DSYNC` admission must reuse the barrier model below
instead of inventing a faster or weaker path.

## Commit Group Law

The current local commit group is:

`commit_group_0.local_root_transaction`

It contains exactly one local filesystem successor publication attempt. The
group is prepared under a transaction id and becomes visible only if the
root-slot candidate is selected as a valid committed root on reopen or live
operation.

The commit-group order is:

1. Prepare staged namespace/file state in memory.
2. Write dirty content manifests and per-chunk content objects as needed.
3. Write transaction inode objects.
4. Write transaction directory objects.
5. Write the transaction superblock object.
6. Write the transaction manifest object covering the staged objects.
7. Sync transaction objects.
8. Write the root-slot commit candidate.
9. Sync the root-slot commit.
10. Treat the committed root as the only live namespace/file truth.

Transaction objects without a root-slot commit are staging data. A malformed or

## Dirty Buffer Lifecycle

Dirty state follows:

| Stable name | Stage | Meaning |
|---|---|---|
| `dirty_buffer_0.memory_successor` | Staged in-memory successor state | Not durable and not publication truth. |
| `dirty_buffer_1.content_object_staged` | Versioned content/chunk objects written | Bytes exist in the object store but are not authoritative. |
| `dirty_buffer_2.metadata_object_staged` | Transaction inode/directory/superblock objects written | Metadata exists but is not authoritative. |
| `dirty_buffer_4.transaction_objects_synced` | Staged objects synced | Candidate can be referenced by a root-slot commit. |
| `dirty_buffer_6.root_slot_synced` | Root-slot commit synced | Durable publication boundary for the local preview. |
| `dirty_buffer_7.recovered_or_retired` | Reopen selected or skipped candidate | Invalid candidates are skipped or reported; no repair is guessed. |

manifest decide which bytes and metadata are visible.

## Fsync And O_DSYNC Barrier Law

The current FUSE implementation maps `fsync-file` and `fsync-directory` to:

`fsync_odsync_0.caller_barrier_root_slot_sync`

That barrier requires:

- all mutation objects needed by the current root have been written;
- a root-slot commit candidate has been published;
- `LocalFileSystem::sync_all` has reached the Local Object Store sync boundary;
- any backing sync failure is reported as an error, not as success.

Future `fdatasync`, `O_SYNC`, and `O_DSYNC` handling must be equivalent or
stricter:

- `fdatasync` may narrow metadata scope only when namespace/link-count truth is
  not affected;
- `O_SYNC` must wait for the full caller-barrier boundary before reporting the
  write complete;
- `O_DSYNC` must wait for data durability and any metadata required to retrieve
  that data after recovery;
- none of these modes may treat page-cache cleanliness, FUSE session state, or
  object-store append visibility as publication by itself.

This binds the transaction model to the `publication_pipeline` class
`seal.publication_pipeline.caller_barrier.s4` and to the local fsync boundary.

## Source Coverage

|---|---|
| Commit groups have a visible publication boundary | `crates/tidefs-local-filesystem/src/lib.rs::persist_state_until_boundary` writes transaction objects, syncs them, publishes the root-slot commit, then syncs the root-slot commit; `docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md` names the same order. |
| Dirty objects are staging until a committed root selects them | `crates/tidefs-local-filesystem/src/lib.rs::uncommitted_transaction_objects_are_ignored_on_reopen`. |
| Invalid manifests cannot become live truth | `crates/tidefs-local-filesystem/src/lib.rs::invalid_transaction_manifest_makes_newer_root_candidate_unselectable`. |
| Pre-publish sync failure rolls back live state | `crates/tidefs-local-filesystem/src/lib.rs::pre_publish_sync_failure_rolls_back_live_state`. |
| Root-slot sync failure is old-or-new and does not reuse the transaction id | `crates/tidefs-local-filesystem/src/lib.rs::root_sync_failure_keeps_live_state_and_avoids_transaction_id_reuse`. |
| Fsync succeeds only after the backing sync boundary | `crates/tidefs-local-filesystem/src/lib.rs::LocalFileSystem::sync_all`, `docs/POSIX_SEMANTICS_OW106.md`, and the FUSE `fsync`/`fsyncdir` path through `sync_all`. |
| Page-cache/mmap durability cannot bypass publication | `crates/tidefs-local-filesystem/src/lib.rs::page_cache_writeback_mmap_spec_covers_open_work_204_acceptance_gate`. |

## Non-Claims

This document does not claim:

- a POSIX-complete durability implementation;
- live `O_DSYNC` flag parsing in the current FUSE implementation;
- a production distributed transaction protocol;
- a block-volume flush/FUA implementation;
  source tests.

It does require later work to consume this model rather than adding a second
commit-group, dirty-buffer, or synchronous-write dialect.
