# Snapshot Quota Policy

Status: design policy for GitHub issue #698. This document decides the
accounting boundary for retained snapshot roots before runtime quota
enforcement grows more snapshot-specific behavior.

This is not an implementation document. It does not change capacity code,
statfs projection, snapshot lifecycle code, placement receipts, rebuild,
rebake, reclaim, or send/receive behavior.

## Evidence Reviewed

- `docs/LOCAL_SNAPSHOTS_OW108.md`: mounted snapshot lifecycle authority is the
  intersection of data-retaining snapshot/clone records, `root@<name>` catalog
  entries, and lifecycle GC pins. Bookmarks are explicitly non-retaining local
  anchors. The document still leaves snapshot quota policy, unified deadlists,
  placement receipts, snapshot-reclaim accounting, and distributed snapshot
  replication open.
- `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`: `pinned_snapshot_bytes` and
  per-snapshot `deadlist_bytes` are O(1) observability counters for bytes held
  by snapshot deadlists. The #638 statfs decision says those bytes are reported
  through dataset, snapshot, and operator views, not by reducing POSIX
  `statfs.f_bfree` or `statfs.f_bavail`.
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`: `pinned_snapshot_bytes` is a
  classification of bytes already covered by `logical_used_bytes`, not an
  additional `logical_alloc_bytes` addend. `snapshot_reserve_bytes` is a policy
  reservation and pressure signal, not a second statfs subtraction.
- `docs/REVIEW_TODO_REGISTER.md`: TFR-007 remains open because capacity,
  quota, statfs, reservations, allocator extents, reclaim, and store-layer
  space books do not yet have one authority. TFR-010 remains open because local
  snapshot lifecycle is not unified with deadlist accounting, placement
  receipts, distributed send/receive authority, conflict resolution, or
  integrated snapshot reclaim.
- GitHub issue #649 owns runtime cleanup for excluding
  `pinned_snapshot_bytes` from POSIX statfs and admission-consumed accounting.
- GitHub issue #680 owns the broader capacity/accounting authority design.
- GitHub issue #18 is now an umbrella for placement receipt driven rebuild and
  reclaim, with child issues owning non-overlapping implementation slices.

## Decision

Snapshot-retained bytes count against the live dataset quota domain exactly
once. They do not count against a separate hard snapshot byte quota in the
current authority model.

The live dataset quota domain means the dataset or clone-family space domain
that owns the retained root. A data-retaining regular snapshot or clone is a
live root for logical accounting purposes. Bytes reachable only because of that
root remain part of `logical_used_bytes`; deleting or overwriting the active
namespace does not make those bytes free while a retained root still protects
them.

`pinned_snapshot_bytes`, per-snapshot `deadlist_bytes`, and
`reclaimable_bytes` classify retained bytes for operators, retention policy,
cleaner pressure, and physical watermarks. They are not extra quota addends.
Adding them on top of `logical_used_bytes` would double-count the same retained
content.

TideFS may later add explicit snapshot retention budgets, but until #680
defines the capacity authority that owns quota/reserve enforcement those
budgets are soft policy signals. They may drive admission warnings, pressure
events, pruning candidates, and operator reports. They must not make TideFS
drop or refuse to preserve an extent that an existing retained root requires
for correctness.

POSIX statfs remains a projection of ordinary write availability in the live
quota/domain after logical allocations, reservations, orphan bytes, slop, root
reserve, transient holds, and physical backpressure. It must not subtract
`pinned_snapshot_bytes` a second time. Issue #649 owns the remaining runtime
and test cleanup for that rule.

## Alternatives Considered

| Model | Result | Rationale |
| --- | --- | --- |
| Count retained bytes once in the live dataset quota domain | Chosen | Matches `logical_used_bytes` as bytes reachable from any live root, keeps quota and statfs from double-counting, and preserves correctness when an old root must pin content. |
| Count retained bytes only in a separate snapshot byte quota | Rejected | Would let active dataset quota ignore roots that still consume logical and physical capacity, and would split authority before #680 defines the owner. |
| Count retained bytes in both live quota and a hard snapshot byte quota | Rejected for now | This can be useful as a future retention budget, but hard enforcement before #680 risks double charging and refusing required deadlist pins. |
| Count retained bytes in neither quota domain | Rejected | This would overstate available capacity and hide retained-root pressure from operators and admission policy. |

## Per-Object Policy

| Object | Quota accounting | Operator capacity view | Boundaries |
| --- | --- | --- | --- |
| Regular snapshot | Bytes reachable from the snapshot root count once in the owning dataset quota domain through `logical_used_bytes`. When an active namespace overwrite or delete leaves an extent reachable only from a snapshot, deadlist accounting classifies it as `pinned_snapshot_bytes` without adding a second charge. | Show snapshot count, per-snapshot state, and `deadlist_bytes`/`pinned_snapshot_bytes` separately from POSIX statfs availability. | Snapshot create itself need not increase pinned bytes; later frees classify retained bytes. Runtime deadlist implementation remains outside this issue. |
| Clone | A clone shares the parent dataset or clone-family space domain until a later authority defines independent clone promotion. Shared extents and clone-private writes charge that domain once. The origin snapshot remains retention-protected while live clones reference it. | Show clone lineage and origin pins so operators can see why the origin cannot be destroyed and why its retained bytes remain charged. | This policy does not implement or prove future independent clone promotion or cross-dataset clone quota transfer. |
| Bookmark | A bookmark is a non-retaining replication anchor. It does not protect data extents, does not create deadlist pins, and does not count as snapshot-retained byte usage. | Bookmarks may be listed as metadata anchors, but must not be reported as retained-byte consumers. | Send/receive anchoring and distributed bookmark behavior remain outside this policy. |
| Destroyed-but-draining snapshot | After destroy freeze, no new entries enter that snapshot's deadlist. Existing entries remain charged to the same logical quota domain until the destroy worker either moves them to another retaining root or frees them in a committed transition. | Report remaining DESTROYING deadlist bytes as reclaimable/draining capacity, not as immediately available quota credit. | This policy does not implement destroy cursors, crash resumption, or physical reclaim ordering. |
| Deadlist-pinned extent | The extent is retained data, so it remains in `logical_used_bytes`; `pinned_snapshot_bytes` identifies the subset held by snapshot deadlists. | Expose it to dataset, snapshot, metrics, cleaner, and pressure views. Do not subtract it again from POSIX `f_bfree`/`f_bavail`. | Physical scarcity can still throttle writes through watermarks even when statfs reports logical availability. |

## Follow-Up Issue Map

| Follow-up | Owner and write set | Non-overlap boundary |
| --- | --- | --- |
| POSIX statfs and admission cleanup | Existing issue #649. Expected write set: `crates/tidefs-local-filesystem/src/capacity_authority.rs`, `crates/tidefs-space-accounting/src/lib.rs`, `crates/tidefs-types-space-accounting-core/src/lib.rs`, and docs only as needed. | Implements the #638/#698 rule that `pinned_snapshot_bytes` does not reduce POSIX `f_bfree` or `f_bavail`. It must not define the whole capacity authority, placement receipts, distributed reclaim, or operator CLI UX. |
| Capacity and quota authority | Existing issue #680. Expected write set: `docs/CAPACITY_ACCOUNTING_AUTHORITY.md` or equivalent authority doc, plus `docs/REVIEW_TODO_REGISTER.md` TFR-007 notes. | Decides the single owner for quotas, reserves, statfs, physical watermarks, and reporting. It should consume this policy when mapping implementation issues, but must not implement snapshot lifecycle runtime code in the design slice. |
| Operator retained-root capacity reports | To be opened by #680's follow-up map after the authority document chooses the reporting owner. Expected write set should be limited to the selected operator/reporting surface, such as `apps/tidefsctl/` and narrow reporting docs, and should avoid #649's capacity/statfs crates unless #680 explicitly assigns that overlap. | Presents regular snapshots, clones, bookmarks, DESTROYING snapshots, `pinned_snapshot_bytes`, and `reclaimable_bytes` without changing POSIX statfs or production quota enforcement. |
| Placement receipt and distributed reclaim correctness | Existing issue #18 and its child issues, currently #674, #675, and #676 for narrowed implementation slices. Expected write sets remain the placement, locator, rebuild, rebake, reclaim, local object store, local filesystem, storage-node, and transport paths named by those issues. | Proves where retained extents physically live and when reclaim is safe. It must not use this policy as proof of quota enforcement, statfs correctness, or operator capacity reporting. |
| Snapshot lifecycle/deadlist runtime implementation | A later issue should be created only after #680 and the relevant #18 child scopes leave a non-overlapping write set. Expected write set should name snapshot metadata, deadlist cursor, and lifecycle paths precisely. | Implements regular snapshot and DESTROYING deadlist behavior. It must not absorb #649 statfs cleanup or #18 receipt/reclaim ownership. |

## Non-Claims

This policy does not prove production quota enforcement. The capacity authority
remains open under TFR-007 and issue #680.

This policy does not prove placement receipt authority, distributed snapshot
replication, degraded reads, rebuild, rebake, or safe physical reclaim. Those
remain under issue #18 and its child issue map.

This policy does not prove clone promotion into an independent dataset space
domain. Until a later authority defines that transition, clones share the
origin clone-family quota domain described above.

This policy does not require POSIX statfs to expose snapshot-retained bytes.
Operators need explicit dataset/snapshot views for retained-root capacity; POSIX
`df` remains the ordinary write-availability projection.

This policy does not change the local snapshot runtime, send/receive,
placement/rebuild code, statfs code, or quota code in issue #698.
