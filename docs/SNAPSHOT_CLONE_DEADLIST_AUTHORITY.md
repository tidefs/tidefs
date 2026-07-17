# Snapshot, Clone, Deadlist, and Send/Receive Storage Model Authority

> TFR-010 investigation outcome: live-behavior snapshot. This document is a
> design/planning authority, not a production-readiness claim. The deadlist
> integration decision is recorded in section 4; implementation remains open
> under the follow-up issue map in section 4.8. Distributed snapshot shipping
> is recorded separately in `docs/design/distributed-snapshot-shipping.md`.

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
The current local snapshot-table path records clones as separate entries.
Deleting a clone removes that entry without modifying the origin entry.

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

## 4. Deadlist Model (design decision)

### 4.1 Current implementation baseline

TideFS still has **no wired local snapshot deadlist derivation path**. Snapshot
and clone deletion remove the `SnapshotRecord`, release the lifecycle GC pin,
and remove the catalog entry, but they do not walk the released root or enqueue
reclaim work for objects that became snapshot-only garbage.

The object store already has lower-level reclaim machinery that the deadlist
model must use instead of bypassing:

- The legacy `drain_dead_segments` entry point now fails closed and does not
  physically free segments.
- `tidefs-dead-object-reclaim-queue` persists receipt-bound dead-object work.
- `tidefs-reclaim-receipts` persists committed physical-free evidence.
- `tidefs-snapshot-extent-pins` persists the `SnapshotExtentPinSet`; corrupt
  persisted pin state fails closed, and the receipt-bound reclaim gate denies
  reclaim while an extent is still snapshot-pinned.

### 4.2 Chosen integration model

The chosen model is **released-root derivation feeding the existing
receipt-bound dead-object reclaim pipeline**.

When a snapshot or clone is deleted, the lifecycle operation remains
authoritative first: state-map removal, catalog removal, and lifecycle unpin
must all succeed before deadlist work is considered. The deadlist derivation
input is then the released traversal root plus the local live-root set:

- the current committed dataset root,
- every data-retaining snapshot or clone root still pinned in the lifecycle
  GC pin set,
- and any other lifecycle traversal roots that a background service has pinned
  as GC barriers.

The derivation walk produces dead-object candidates only for object keys
reachable from the released root and unreachable from every live root. The
deadlist is therefore an object/extent candidate set, not a direct segment-free
command. Candidates are persisted to the local object store's receipt-bound
dead-object queue, and physical segment reuse is allowed only after the
receipt-bound drain verifies committed deadlist evidence, stable generation
boundaries, and `SnapshotExtentPinSet` clearance.

The allocator must not consult an in-memory deadlist directly and must not
reuse deadlist-covered space through a snapshot-delete fast path. It only sees
freed capacity after the receipt-bound drain has committed reclaim receipts and
returned segments to the pool.

### 4.3 Clone shared-root semantics

Clones and promoted clones are independent data-retaining snapshot records.
They pin their own lifecycle root even when that root is byte-for-byte the
same as the origin snapshot root.

Deadlist derivation must preserve that refcounted root authority:

- If deleting one record only decrements a shared-root lifecycle pin count, no
  object from that root may be enqueued for deadlist reclaim.
- If the root pin count reaches zero, derivation must still subtract the
  current committed dataset root and every other live pinned root before
  emitting candidates.
- `SnapshotExtentPinSet` remains the physical reclaim backstop: an object that
  is accidentally queued while any snapshot extent pin still references it is
  denied by the receipt-bound reclaim gate rather than freed.

### 4.4 Persistence and lifecycle

Deadlist work must be durable. The initial implementation should use the
object-store named objects that already exist for reclaim state:

- `tidefs-dead-object-reclaim-queue`: pending or receipt-bearing dead-object
  candidates derived from released roots.
- `tidefs-reclaim-receipts`: committed evidence for physical frees performed
  by the receipt-bound drain.
- `tidefs-snapshot-extent-pins`: the persisted extent pin guard consulted
  before physical reclaim.

If the root-difference walk needs resumability, crash recovery, or batching
beyond a single transaction, the derivation implementation must add a small
versioned cursor object rather than storing cursor state inside
`SnapshotRecord`. That cursor format is deliberately left to the derivation
and queue follow-ups because it depends on the final walk shape and queue API.

The lifecycle is:

1. Snapshot or clone deletion commits the state/catalog/lifecycle-pin change.
2. Derivation walks the released root against the live-root set and persists
   queue entries or a fail-closed pending cursor.
3. A subsequent receipt-bound drain processes stable, eligible entries only when
   receipt evidence and snapshot-extent-pin clearance agree.
4. Queue acknowledgement happens only after the physical-free receipt has been
   persisted; receipts survive replay as committed evidence.

### 4.5 Send/receive interaction

Deadlist entries are local receiver state and must not be transmitted in
VFSSEND1 or VFSSEND2 streams. A sender does not know the receiver's clone set,
current root, lifecycle pins, or snapshot extent pins, so transmitted deadlist
entries would couple two independent GC authorities.

Incremental receives that create or update roots do not populate or clear
deadlists by themselves. Future received snapshot-deletion deltas trigger the
same local derivation path after the receiver applies the deletion to its own
snapshot/catalog/lifecycle-pin authority. The receive trigger boundary is
tracked by #1259; it must call the derivation API selected here rather than
defining a separate distributed deadlist model.

### 4.6 Alternatives considered

**Allocator consults the deadlist directly.** Rejected. A direct allocator
lookup would bypass committed receipt evidence, stable-generation checks, and
the `SnapshotExtentPinSet` guard that already protects physical reclaim.

**Synchronous snapshot-delete frees or unlinks objects.** Rejected. Deletion
must remain an authority mutation first; expensive root walking, receipt
publication, and segment freeing need resumable fail-closed state so a held
clone, crash, or partial walk cannot free shared data.

**Sender transmits deadlist entries during replication.** Rejected. The
receiver alone knows whether a root is still pinned by a local clone or other
local lifecycle root.

**Introduce a global per-object reference count before deriving deadlists.**
Rejected for the initial local model. The live roots already define the safety
boundary, and a root-difference walk can be introduced without changing every
put/delete path. If future capacity evidence proves root walking is too costly,
that belongs in a separate design issue.

### 4.7 Evidence reviewed

- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` as created by closed #1246.
- Closed #1246 body and acceptance criteria.
- `docs/REVIEW_TODO_REGISTER.md` TFR-010 notes.
- `crates/tidefs-local-filesystem/src/snapshot.rs` snapshot/clone lifecycle,
  hold/release, catalog reconciliation, and lifecycle pin management.
- `crates/tidefs-local-filesystem/src/records.rs` `SnapshotRecord` and
  `SnapshotKind`.
- `crates/tidefs-dataset-lifecycle/src/lib.rs` and
  `crates/tidefs-dataset-lifecycle/src/destroy_worker.rs` lifecycle pin and
  destroy traversal model.
- `crates/tidefs-gc-pin-set/src/lib.rs` `GcPinSet` and
  `SnapshotExtentPinSet`.
- `crates/tidefs-local-object-store/src/store.rs` and
  `crates/tidefs-local-object-store/src/reclaim_queue.rs` receipt-bound
  dead-object reclaim, reclaim receipts, and snapshot extent pin persistence.
- `crates/tidefs-local-object-store/src/snapshot.rs` legacy snapshot catalog
  storage.
- `crates/tidefs-snapshot-pruner/src/pruner.rs` existing prune evidence and
  deadlist-pin scaffolding.
- `crates/tidefs-local-filesystem/src/send_receive.rs` VFSSEND1 local
  send/receive and incremental base-root authority.
- `docs/design/distributed-snapshot-shipping.md` VFSSEND2 distributed
  shipping decision and #1259 receive-trigger follow-up.

### 4.8 Follow-up implementation issue map

| Issue | Responsibility | Expected write set | Validation tier |
| --- | --- | --- | --- |
| #1263 | Add the released-root derivation API that walks the released root, subtracts the current root and pinned lifecycle roots, and returns dead-object candidates without enqueueing or freeing. | `crates/tidefs-local-filesystem/src/deadlist.rs`, `crates/tidefs-local-filesystem/src/lib.rs` | Focused derivation unit tests plus `git diff --check`. |
| #1264 | Persist snapshot-deadlist candidates into the object-store receipt-bound reclaim machinery and keep physical reclaim gated by receipts and snapshot extent pins. | `crates/tidefs-local-object-store/src/store.rs`, `crates/tidefs-local-object-store/src/reclaim_queue.rs`, `crates/tidefs-gc-pin-set/src/lib.rs` only if the pin-set API needs a narrow helper | Focused object-store unit tests for queue persistence, receipt gating, pinned denial, corrupt pin evidence, replay, plus `git diff --check`. |
| #1265 | Wire local `delete_snapshot` and `delete_clone` to call derivation and enqueue only after the state/catalog/lifecycle-pin mutation succeeds. | `crates/tidefs-local-filesystem/src/snapshot.rs` | Focused local-filesystem unit tests for ordinary delete, clone-shared-root delete, clone delete, hold refusal, queued-work persistence where applicable, plus `git diff --check`. |
| #1259 | Add the receive-side trigger that calls the #1263 derivation API after a received snapshot-deletion delta is applied locally. | `crates/tidefs-local-filesystem/src/send_receive.rs` | Trigger unit tests with a stub or the final API; two-node validation only after the derivation API exists. |
| #1266 | Decide reclaim drain cadence, queue-size limits, operator reporting, and capacity/accounting integration after the core machinery has evidence. | `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` section 4.9 | Documentation/design/source-inspection only for the policy decision; split source work before implementation. |

### 4.9 Receipt-Bound Reclaim Drain Policy

The local snapshot/deadlist path does not own a separate physical-freeing
loop. Reclaim moves through the existing receipt-bound reclaim chain:

- `record_reclaim_delta()` feeds the local B+tree reclaim queue, and
  `tick_background_services()` drains that queue through `Pool::delete()`.
  The local handoff budget is 1024 entries per background-service tick.
- `Pool::delete()` feeds object-store reclaim queues. Physical segment freeing
  remains reserved for receipt-bound dead-object clearance after committed
  evidence authorizes the object ids.
- The receipt-bound physical drain is attempted only when local filesystem
  state is clean/committed and is bounded to 1024 entries per tick. Idle and
  error backoff are 32 clean ticks; a new local handoff wakes the idle path.
- The shared reclaim consumer defaults to 1024 queue entries per drain and 64
  dead segments per free batch before checkpointing.

Space pressure is a capacity/admission classifier, not a separate snapshot
deadlist drain contract. Current defaults classify warning, sync, and critical
at 70%, 85%, and 95% used capacity, with a 5% emergency reserve. They do not
define a separate 256-entry synchronous reclaim drain.

Operator reporting must distinguish queued deadlist/reclaim debt from
physically freed capacity. Mounted statfs and allocator-visible availability
must flow through `CapacityAuthority` and committed receipt-bound reclaim
evidence, not direct trust in in-memory deadlist entries.

This policy does not claim snapshot delete completion, distributed deadlists,
final capacity/accounting integration, production allocator behavior,
performance, release readiness, or successor/comparator parity.

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

5. **Deadlist invariant (design decided, not implemented)**: After a
   snapshot or clone is deleted and its lifecycle pin is released, objects
   reachable only through that released root must be persisted as
   receipt-bound dead-object candidates. No object may appear on the deadlist
   while the current committed root or any pinned traversal root still
   references it, and no deadlisted object may be physically reclaimed while
   any snapshot extent pin still references it.

### 7.3 What the authority model requires of future changes

- Any new snapshot or clone lifecycle operation must go through the three-part
  authority (state map, catalog, lifecycle pins) and call
  `ensure_snapshot_authority_consistent` before mutating.
- Any deadlist implementation must follow the section 4 decision: entries are
  derived from released roots after subtracting the current root and pinned
  lifecycle roots, persisted through the receipt-bound dead-object reclaim
  path, and consumed only after snapshot extent pins and reclaim receipts allow
  physical free. Consumption must respect clone shared-root semantics.
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
- Deadlist integration decision: released-root derivation feeding the
  receipt-bound dead-object reclaim pipeline.

### 8.2 Out of scope

- Distributed snapshot shipping, cross-node clone, or multi-pool replication.
- RDMA send/receive transport.
- Production backup/restore product claims.
- Production recovery time objective (RTO) or recovery point objective (RPO)
  guarantees.
- Online deadlist scrubbing, segment compaction policy, production allocator
  scheduling, and final capacity/accounting integration beyond the
  receipt-bound reclaim boundary recorded in section 4.9.
