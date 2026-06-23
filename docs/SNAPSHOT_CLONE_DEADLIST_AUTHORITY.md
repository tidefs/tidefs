# Snapshot, Clone, Deadlist, and Send/Receive Storage Model Authority

> TFR-010 investigation outcome: live-behavior snapshot. This document is a
> design/planning authority, not a production-readiness claim. Deadlist
> integration and distributed snapshot shipping remain open design items
> tracked by `docs/REVIEW_TODO_REGISTER.md` TFR-010 notes.

## 1. Snapshot Lifecycle

### 1.1 Storage representation

Every snapshot, clone, and bookmark is a `SnapshotRecord` held in the in-memory
snapshot state map (`FileSystemState::snapshots`). The record carries:

- `name`: validated UTF-8 snapshot name as raw bytes.
- `root`: the `CommittedRootSummary` at the moment of creation.
- `created_at_generation`: filesystem generation at creation time.
- `kind`: `Snapshot`, `Clone`, or `Bookmark`.
- `origin`: for clones, the origin snapshot name; `None` otherwise.
- `hold_count` and `hold_tag`: reference-counted deletion prevention.

Source: `crates/tidefs-local-filesystem/src/records.rs` (SnapshotRecord, SnapshotKind).

### 1.2 Create

`create_snapshot(name)`:
- Validates the name (ASCII alphanumeric + `._-:@`, 1–255 bytes).
- Ensures no existing entry has the same name.
- Commits a mutation that bumps the generation, inserts the record with
  `SnapshotKind::Snapshot`, persists the snapshot state, and reconciles
  the catalog entry and lifecycle pin.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` create_snapshot.

### 1.3 Delete

`delete_snapshot(name)`:
- Requires `hold_count == 0`.
- Ensures snapshot authority consistency before deletion.
- Removes the record from the state map, unpins the lifecycle root, and
  removes the catalog entry.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` delete_snapshot.

### 1.4 Hold and release

Holds are reference-counted deletion-prevention locks. `hold_snapshot_tagged(name, tag)`
increments `hold_count`; `release_snapshot(name)` decrements it. When `hold_count`
reaches 0, the hold tag is cleared. Bookmarks cannot be held.

`check_deletable(name)` fails with `SnapshotHeld` while `hold_count > 0`.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` hold/release/check_deletable.

### 1.5 Retention pruning

`prune_snapshots(policy)` applies `SnapshotRetentionPolicy` (max count or max age
in generations) only to `SnapshotKind::Snapshot` records. Clones and bookmarks
are excluded. Held snapshots are reported as skipped but never pruned.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` prune_snapshots, SnapshotRetentionPolicy.

### 1.6 Object-protection contract

Each data-retaining snapshot or clone (kind `Snapshot` or `Clone`) pins its
traversal root in the lifecycle GC pin set. The pin prevents the GC from
reclaiming blocks reachable from that root. Bookmarks do not pin roots and
therefore do not retain data.

A snapshot or clone is protected while:
1. its `SnapshotRecord` exists in the snapshot state map,
2. a matching catalog entry exists in `DatasetCatalog` with path `root@<name>`
   and `DatasetType::Snapshot` (plus `DatasetFlags::CLONE` for clones), and
3. its traversal root is pinned in the lifecycle `GcPinSet` with a pin count
   at least equal to the number of snapshot records sharing that root.

The three-part authority is verified by `ensure_snapshot_authority_consistent`
and per-record by `ensure_snapshot_record_authority`.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` ensure_snapshot_authority_consistent,
ensure_snapshot_record_authority.

## 2. Clone Lineage

### 2.1 Create

`create_clone(clone_name, source_snapshot)`:
- Requires the source snapshot or clone to be data-retaining.
- Copies the source's `CommittedRootSummary` into the clone record.
- Sets `SnapshotKind::Clone` and records the origin name.
- Pins the shared root and creates a catalog entry with `DatasetFlags::CLONE`.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` create_clone.

### 2.2 Delete

`delete_clone(name)` removes the clone entry but leaves the origin unaffected.
Unlike ZFS, TideFS clones are independent snapshot entries; deleting a clone
does not require promoting it or its origin.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` delete_clone.

### 2.3 Promote

`promote_clone(name)` severs the origin link:
- Verifies the origin snapshot still exists and is data-retaining.
- Replaces the record with `SnapshotKind::Snapshot` and clears the `origin` field.
- Reconciles the catalog entry (removes the `CLONE` flag).
- The promoted entry retains the same root and creation generation.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` promote_clone.

### 2.4 Lineage tracking

Clone ancestry is tracked through the `origin` field on `SnapshotRecord`. There
is no ancestry graph or parent-child index beyond this direct origin reference.
Clone creation is point-in-time: a clone shares the source's root at creation
time but does not receive subsequent updates to the source.

### 2.5 Interaction with destruction

When an origin snapshot is deleted while clones reference it, the clone's
`origin` field becomes dangling but the clone's data blocks remain protected by
its own lifecycle pin and catalog entry. The clone remains usable; the dangling
origin is detectable via `clone_origin()` which returns the stored name even
when the origin snapshot no longer exists.

## 3. Bookmark Model

### 3.1 Purpose

Bookmarks are lightweight, non-retaining anchors for incremental replication.
They reference a snapshot's root identity without pinning data blocks.

### 3.2 Lifecycle

`create_bookmark(name, source_snapshot)` inserts a `SnapshotKind::Bookmark` record.

`delete_bookmark(name)` removes it.

Bookmarks cannot be held (`HoldOnBookmark` error). They are excluded from
retention pruning and GC pin accounting.

Source: `crates/tidefs-local-filesystem/src/snapshot.rs` create_bookmark, delete_bookmark.

## 4. Deadlist Model (design gap)

### 4.1 Current state

TideFS has **no deadlist implementation**. The live snapshot, clone, and
bookmark records in `FileSystemState::snapshots` are the sole mechanism for
tracking which objects are reachable. Object deletion uses the object store's
delete tombstone (record kind 2), which removes the key from the live index
but does not reclaim segment space.

There is no deadlist accounting for:
- Which blocks became unreachable after a snapshot deletion.
- Which segments can be compacted or retired.
- Space reclamation scheduling or capacity forecasting.

### 4.2 Object-store interaction gap

The `LocalObjectStore` provides:
- Put (record kind 1): append a payload, index by `ObjectKey`.
- Delete tombstone (record kind 2): remove the key from the live index.
- Replay: rebuild the latest-object index from all segments.

There is no per-object reference count, no block birth-time tracking, and no
integration between snapshot deletion and space reclamation. When a snapshot is
deleted, its unpinned traversal root no longer protects blocks reachable only
through that root, but no mechanism walks the resulting unreferenced blocks to
add them to a deadlist for eventual segment compaction.

### 4.3 Future requirements

A deadlist integration must:
- Derive a deadlist from the set of unpinned roots vs. currently pinned roots.
- Populate deadlist entries in the object store (new record kind or segment).
- Allow the allocator to reclaim deadlist-covered segments.
- Respect clone shared-block semantics: a block reachable through a clone's
  origin must not be reclaimed while any clone still pins that root.

These remain open design items tracked under TFR-010.

Source: `docs/REVIEW_TODO_REGISTER.md` TFR-010, snapshot.rs module docstring.

## 5. Send/Receive Stream Format

### 5.1 Stream identity

- Spec: `VFSSEND1` (magic bytes `b"VFSSEND1"`).
- Stream version: 1.
- Stream type: changed-record export. Each root in the stream carries a set of
  changed object records (inodes, directories, content, superblock, transaction
  manifest, etc.).

Source: `crates/tidefs-local-filesystem/src/constants.rs` SEND_RECEIVE constants.

### 5.2 Full export

`export_changed_records_from_root` exports all roots (current root plus all
snapshot roots) sorted by `transaction_id`. Each root's records include all
objects known at that root's generation. The export is self-describing: it
carries the stream spec, stream version, current root identity, per-root
records with object keys and checksums, and optional placement epoch.

Source: `crates/tidefs-local-filesystem/src/send_receive.rs` export_changed_records_from_root.

### 5.3 Incremental export

`export_incremental_changed_records(from_root, to_root)` exports only new or
changed objects between two committed roots. The filter rule:
- Structural records (inodes, directories, superblock, transaction manifest)
  are always included.
- Content records (`VersionedContent`, `VersionedContentChunk`) are included
  only when their `(object_key, checksum)` pair is not present in the base
  root's transaction manifest.

This mirrors ZFS `zfs send -i <base> <target>`.

Source: `crates/tidefs-local-filesystem/src/send_receive.rs` export_incremental_changed_records.

### 5.4 Record types in the stream

Each `ChangedObjectRecord` carries:
- `object_key`: 32-byte `ObjectKey`.
- `role`: the record's role (e.g. `TransactionManifest`, `Inode`, `Directory`,
  `VersionedContent`, `VersionedContentChunk`, etc.).
- `payload`: the raw object bytes.
- `checksum`: 64-bit integrity digest over the payload.

Source: types in `crates/tidefs-local-filesystem/src/types.rs`.

## 6. Receive Path

### 6.1 Empty-target receive

`receive_changed_records_into_empty_root` receives a full (non-incremental)
stream into a new, empty target:
1. Validates the export (spec match, record checksums, no duplicate keys).
2. Validates sender authority (cross-pool authorization).
3. Creates a staging directory and persists objects into the staging store.
4. Supports checkpoint-based resume for interrupted streams.
5. On success, publishes the received roots into the target's object store
   under a new root-authentication key (re-signs imported roots).

Source: `crates/tidefs-local-filesystem/src/send_receive.rs` receive_changed_records_into_empty_root.

### 6.2 Incremental receive

`receive_incremental_changed_records` receives an incremental stream into an
existing target that must already contain the base snapshot:
1. Validates the export.
2. Validates sender authority.
3. Locates the base root on the target (must be a data-retaining snapshot or
   clone with a matching root identity, protected by the local snapshot/catalog/
   lifecycle-pin authority).
4. Validates that omitted content objects (those unchanged between base and
   incremental target) are actually present in the target's object store.
5. Persists new/changed objects directly into the target's primary store
   (no staging).
6. Publishes a new root slot with re-authenticated imported roots.

Source: `crates/tidefs-local-filesystem/src/send_receive.rs` receive_incremental_changed_records,
verify_incremental_base_root_authority, validate_incremental_omitted_content_objects.

### 6.3 Base root authority

The incremental receive base root must:
- Be a data-retaining snapshot or clone in the target's `FileSystemState::snapshots`.
- Have a catalog entry matching the snapshot record.
- Have a lifecycle pin protecting its traversal root.
- Be validated by `verify_incremental_base_root_authority`.

If no authorized base root exists, the receive fails with
`IncrementalReceiveBaseRootConflict`. The merge plan (see §6.4) relaxes
this fail-closed gate.

Source: `crates/tidefs-local-filesystem/src/send_receive.rs` verify_incremental_base_root_authority,
validate_local_incremental_receive_contract.

### 6.4 Merge planning

When a target has conflicting content (different object versions at the same
key), `ReceiveMergePlan` provides per-object decisions:
- `KeepLocal`: preserve the target's version.
- `KeepRemote`: overwrite with the stream's version.

The merge plan is produced by `receive_merge_planner::resolve_merge_policy`
after a conflict inventory is collected. When a merge plan is present, the
fail-closed base-root-authority gate is relaxed: the receive proceeds even
when the target does not pin the exact base root, and per-object decisions
govern which stream objects are imported.

Source: `crates/tidefs-local-filesystem/src/receive_merge_planner.rs`,
`crates/tidefs-local-filesystem/src/receive_persistence.rs`.

### 6.5 Receive checkpoint

Interrupted non-incremental receives can resume via a checkpoint persisted in
the staging store. The checkpoint records the export identity (a digest of
spec, stream version, and root identities) plus the set of already-persisted
object keys. On resume, already-persisted keys are skipped.

Source: `crates/tidefs-local-filesystem/src/send_receive.rs` ReceiveCheckpoint,
compute_export_identity, receive_changed_records_into_staging_with_skip.

## 7. Cross-Subsystem Contracts

### 7.1 Crate ownership

| Concept | Owning crate |
|---------|-------------|
| Snapshot state map, lifecycle operations | `tidefs-local-filesystem` (snapshot.rs) |
| Snapshot/tombstone state machine | `tidefs-dataset-lifecycle` |
| Dataset catalog, snapshot entries | `tidefs-dataset-catalog` |
| GC pin set, traversal roots | `tidefs-gc-pin-set` (integrated via lifecycle) |
| Object persistence, put/delete/replay | `tidefs-local-object-store` |
| Snapshot metadata types | `tidefs-types-vfs-core` |
| Send/receive stream format, export/import | `tidefs-local-filesystem` (send_receive.rs) |
| Receive merge planning | `tidefs-local-filesystem` (receive_merge_planner.rs, receive_persistence.rs) |

### 7.2 Invariants crossing crate boundaries

1. **Snapshot authority invariant**: For every data-retaining snapshot or clone
   record in `FileSystemState::snapshots`, there must be a matching catalog
   entry and a lifecycle pin. For every catalog entry with path `root@<name>`,
   there must be a matching snapshot record. Pin counts must match.

2. **Clone shared-root invariant**: A clone shares its traversal root with its
   origin. The lifecycle pin count for that root must be at least (1 for the
   origin + 1 for each clone referencing it). Deleting the origin must not
   unpin the root while clones still reference it (enforced by independent
   lifecycle pins per record).

3. **Incremental receive base-root invariant**: The base root for an incremental
   receive must be a data-retaining snapshot or clone in the target, protected
   by the snapshot authority. The target must hold all content objects that
   the incremental stream omits.

4. **Stream integrity invariant**: Every changed-record export must carry a
   self-describing spec and stream version. Every record must carry a checksum.
   The receiver must validate the spec, version, and per-record checksums
   before persisting any object.

5. **Deadlist invariant (planned, not implemented)**: After a snapshot is
   deleted and its lifecycle pin is released, blocks reachable only through
   that snapshot's root must be added to a deadlist. No block may appear on
   a deadlist while any pinned root still references it.

### 7.3 What the authority model requires of future changes

- Any new snapshot or clone lifecycle operation must go through the three-part
  authority (state map, catalog, lifecycle pins) and call
  `ensure_snapshot_authority_consistent` before mutating.
- Any deadlist implementation must integrate with the GC pin set: deadlist
  entries must be derived from the set of unpinned traversal roots, and
  deadlist consumption must respect clone shared-root semantics.
- Any send/receive extension must preserve the VFSSEND1 stream spec versioning
  contract and the incremental content-filter rule.
- Cross-node or distributed snapshot shipping requires a separate authority
  extension beyond the local-only model described here.

## 8. Scope Boundaries

### 8.1 In scope (this document)

- Single-node local-filesystem snapshot, clone, bookmark, hold, and retention.
- Single-node local-filesystem send/receive stream format, export, and import.
- Cross-subsystem contracts between snapshot state, catalog, lifecycle pins,
  and object store.
- Design gaps: deadlist integration and space reclamation.

### 8.2 Out of scope

- Distributed snapshot shipping, cross-node clone, or multi-pool replication.
- RDMA send/receive transport.
- Production backup/restore product claims.
- Production recovery time objective (RTO) or recovery point objective (RPO)
  guarantees.
- Online deadlist scrubbing, segment compaction, or production allocator
  integration (these remain open TFR-010 items).
