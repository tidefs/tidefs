# Capacity Accounting Authority

Status: design decision for GitHub issue #680 and TFR-007.

This document records the mounted capacity/accounting boundary after surveying
the current allocator, quota, statfs, reclaim, dedup, inode, adapter, and
operator-reporting surfaces. It does not change runtime behavior.

## Decision

Mounted dataset capacity is owned by `crates/tidefs-local-filesystem` through
`CapacityAuthority`, backed by the committed counter and statfs/admission model
in `crates/tidefs-space-accounting` and
`crates/tidefs-types-space-accounting-core`.

That authority owns mounted user-visible capacity semantics:

- write/admission ENOSPC decisions for mounted datasets;
- POSIX/FUSE `statfs` and `statvfs` block-counter derivation;
- quota/domain availability arithmetic once quota inputs are resolved;
- commit-group application of logical, physical, reserved, orphan, and
  snapshot-classification deltas;
- the projection boundary consumed by storage adapters and operator tools.

Physical placement remains a separate lower-layer authority. Block allocators,
segment cleaners, dedup tables, inode tables, object-store pool statistics,
FUSE reply builders, and `tidefsctl` commands are inputs, producers, or
projections. They must not decide mounted quota, mounted `statfs`, or mounted
write admission independently.

The current source does not fully implement this decision. The implementation
still bridges several ledgers, so TFR-007 remains open until the follow-up map
below is closed or superseded. Issue #1191 narrows this by moving the remaining
mounted `fallocate_file` and `zero_range` allocation admissions onto the
capacity reservation lifecycle and by making `LocalFileSystem::statfs()` treat
allocator reports as projections instead of mutating them as availability
mirrors.

## Evidence Reviewed

- `docs/REVIEW_TODO_REGISTER.md`: TFR-007 records the live split across
  allocation, quotas, `statfs`, reserves, logical/physical counters, reclaim,
  obligation ledgers, and store-layer persistence.
- `crates/tidefs-space-accounting/` and
  `crates/tidefs-types-space-accounting-core/`: define the current
  source-owned logical admission, physical allocator pressure,
  `DatasetSpaceCountersV1`, `SpaceDelta`, `PoolPhysicalCountersV1`, space
  domains, and POSIX `statfs` projection inputs.
- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` and
  `crates/tidefs-local-filesystem/src/snapshot.rs`: snapshot-pinned bytes are
  separately observable and must not be double-counted in POSIX `statfs`;
  snapshot reclaim remains tied to lifecycle pins, deadlists, and
  placement/rebuild work.
- `crates/tidefs-block-allocator/`: owns physical free-block tracking,
  transactional reservations, quota-table reserve/commit/release bookkeeping,
  commit-epoch fencing, root-reserve block counters, and TRIM/UNMAP dispatch.
  Its README currently overclaims "single authority" for admission/quota across
  the storage pool; the current local-filesystem code narrows it to a lower
  physical placement input.
- `crates/tidefs-dataset-properties/`: defines `space.quota` as inherited
  dataset property metadata and provenance. It is not the runtime quota
  enforcer.
- `crates/tidefs-data-cleaner/`: models refcount-driven unlinked-block cleanup
  and reports estimated reclaimed bytes, but its own docs say it is not wired
  into mounted product reclaim.
- `crates/tidefs-cleanup-engine/` and
  `crates/tidefs-cleanup-job-core/`: schedule deferred cleanup and publish
  progress/estimated bytes freed. They do not decide user-visible availability.
- `crates/tidefs-dedup/` and
  `crates/tidefs-local-filesystem/src/dedup_refcount.rs`: own dedup identity,
  canonical locator/refcount state, and reclaim obligations for canonical
  objects. They are delta producers, not mounted capacity authorities.
- `crates/tidefs-inode-table/`: owns inode-number records, slot allocation,
  generation, and free-list state. Capacity code may consume inode counts for
  `statfs.files`/`statfs.ffree`, but it must not own inode lifetime.
- `crates/tidefs-local-filesystem/`: contains `CapacityAuthority`,
  `LocalFileSystem::statfs()`, `statvfs()`, `commit_space_delta()`,
  quota-table checks, allocator reports, object-store `SpaceBook` sync, and
  physical pool counter refresh. This is the only layer currently positioned to
  bind mounted admission, committed accounting, statfs, and adapter projection.
- `apps/tidefs-posix-filesystem-adapter-daemon/`: production capacity dispatch
  points at the local-filesystem `CapacityAuthority`; the old
  `CapacityFacade`, admission lifecycle, and tracker are test-only fixtures.
- `apps/tidefsctl/`: `dataset list` reports `available` from
  `LocalFileSystem::statfs()` and leaves `used` unset; `dataset list-props`
  reports property metadata such as `space.quota`. It is a projection surface.
- Current GitHub state: PR #613 and PR #761 have merged, admitting issue #1191
  as the runtime closeout slice for the remaining mounted local-filesystem and
  accounting bridges.

## Surface Classification

| Surface | Current capacity/accounting role | Decision boundary |
|---|---|---|
| `tidefs-local-filesystem::CapacityAuthority` | Mounted facade over committed accounting, transient holds, statfs derivation, and pool refresh. Source comments currently overstate completion. | Primary mounted capacity authority facade. |
| `tidefs-space-accounting` | Dataset counter runtime with `statfs`, admission checks, pending deltas, pool counters, and quota hierarchy helpers. Its crate docs correctly say TFR-007 is not complete. | Primary committed counter and admission model behind the facade. |
| `tidefs-types-space-accounting-core` | Persistent/shared counter, delta, pool, snapshot, and domain types. | Primary data model for authority state and deltas. |
| `tidefs-block-allocator` | Physical free-block bitmap, per-inode reserve/commit/release bookkeeping, root reserve, allocation diagnostics, commit-epoch pending allocation fences, trim. | Physical placement and lower-level free-space input. Not mounted quota/statfs authority. |
| `tidefs-dataset-properties` | `space.quota` schema, inheritance, validation, and provenance. | Configuration schema/input. Runtime enforcement belongs to the authority. |
| `tidefs-local-object-store` `SpaceBook` and pool stats | Store-layer counter persistence, pool capacity snapshots, object/segment statistics. | Persistence and physical input. Must not be an independent mounted capacity decision path. |
| Data cleaner and cleanup crates | Deferred reclaim scheduling, cursor/progress state, estimated freed bytes. | Reclaim producers. Authority consumes committed reclaim deltas/evidence. |
| Dedup crates and local dedup refcount | Dedup identity, canonical refcount, bytes-saved/accounting observations, reclaim obligations. | Delta/reclaim producers. Authority accounts only committed logical/physical effects. |
| Inode table | Inode slot allocation, generations, free-list persistence, inode counts. | Inode authority. Capacity projects inode counts into statfs only. |
| POSIX adapter daemon capacity module | Production module documents that capacity semantics live in local filesystem; legacy facade/tracker remain under `cfg(test)`. | Adapter/reply projection. No independent production capacity lifecycle. |
| `tidefsctl` dataset commands | Operator projection of `statfs` availability and dataset property records. | Reporting consumer. No authority decisions. |

## Authority Models Compared

### Model A: Mounted dataset authority backed by committed counters

`tidefs-local-filesystem::CapacityAuthority` is the single mounted facade. It
stores the mounted transient view, delegates committed statfs/admission
arithmetic to `tidefs-space-accounting`, persists committed deltas through the
local filesystem/object-store boundary, and publishes a stable projection to
FUSE, kernel, block-export, and operator consumers.

This is the chosen model because it matches the only layer that sees all inputs
needed for mounted semantics: dataset identity, quota ancestors, logical
mutations, reservations, extent writes, unlink/orphan state, snapshot
classification, pool physical counters, object-store persistence, and adapter
projection. It also preserves the existing separation between logical
admission and lower physical placement.

### Model B: Pool-global allocator authority with dataset projections

The block allocator would own admission, quota, and statfs, while datasets
receive projections from allocator state. This keeps free-block accounting
close to physical placement and can make physical ENOSPC diagnostics simple.

This model is rejected for mounted capacity semantics. The allocator does not
own dataset property provenance, clone-family domains, snapshot-pinned byte
classification, orphan bytes, logical reservations, dedup sharing, inode slot
counts, or object-store counter persistence. Making it the mounted authority
would either force it to import unrelated dataset semantics or recreate the
same bridge in a lower layer. The allocator remains the physical placement and
free-block authority.

### Model C: Adapter-local or tool-local authority facades

Each consumer would own a small capacity facade: FUSE reply code, block export,
and `tidefsctl` could compute values from whichever lower counter is convenient.

This model is rejected. TideFS already has evidence of drift from adapter-local
facades and CLI projections. Adapter-local arithmetic can make `df`, write
admission, quota reporting, and background reclaim disagree. Adapters and tools
may cache or format capacity data, but they must consume authority outputs.

## Chosen Boundary

The primary capacity authority crates are:

- `crates/tidefs-local-filesystem`: mounted facade and integration boundary,
  including `CapacityAuthority`, `LocalFileSystem::statfs()`, `statvfs()`,
  `commit_space_delta()`, and the projection exported to engines/adapters.
- `crates/tidefs-space-accounting`: committed dataset counter runtime,
  statfs/admission arithmetic, pending delta lifecycle, pool counter
  integration, and quota hierarchy calculations.
- `crates/tidefs-types-space-accounting-core`: shared persistent/core types for
  counters, deltas, physical pool counters, snapshot space records, and space
  domains.

The projection/consumer/input crates are:

- `crates/tidefs-block-allocator`: physical block placement, transactional
  reservation/fencing, free-space and root-reserve reports, trim.
- `crates/tidefs-dataset-properties`: quota/property schema and provenance.
- `crates/tidefs-local-object-store`: pool physical statistics and counter
  persistence input.
- `crates/tidefs-data-cleaner`, `crates/tidefs-cleanup-engine`, and
  `crates/tidefs-cleanup-job-core`: reclaim progress and committed free-space
  evidence producers.
- `crates/tidefs-dedup` and local dedup refcount code: dedup identity,
  refcount, and reclaim obligation producers.
- `crates/tidefs-inode-table`: inode slot authority and statfs inode-count
  input.
- `apps/tidefs-posix-filesystem-adapter-daemon`: FUSE adapter/reply consumer.
- `apps/tidefsctl`: operator reporting consumer.

## Non-Claims

This decision does not claim:

- production quota hierarchy enforcement is complete;
- every write/fallocate/truncate/unlink/copy/writeback path has been collapsed
  onto one implementation lifecycle;
- snapshot quota policy or pinned-snapshot statfs behavior beyond the #638
  decision and follow-up implementation work;
- multi-pool, multi-device, or cluster-wide fairness;
- block-export or ublk ENOSPC parity with mounted local filesystem behavior;
- dedup physical-byte savings are already charged through mounted capacity;
- deferred reclaim immediately changes user-visible availability before a
  committed reclaim delta is published;
- `SpaceBook` and `SpaceAccounting` are already one persistence lifecycle;
- test-only adapter capacity facades are production APIs;
- this document closes TFR-007 by itself.

## Follow-Up Issue Map

The rows below are intentionally non-overlapping by expected write set. Runtime
rows that would have overlapped #613 or #761 were gated until those PRs merged;
issue #1191 was the admitted mounted admission/statfs projection closeout slice.
Issue #1467 inspected the post-#1191 residuals and split the remaining work
instead of treating store persistence, physical pool projection, reclaim
evidence, dedup obligations, and mounted consumer wiring as one runtime PR.
The rows for #1504 through #1508 are the resulting non-overlapping closeout
map and are now closed lineage, not live implementation blockers. TFR-007
still remains open through the current blocked
`capacity-quota-reserve-accounting` product-admission gate in
`validation/claims.toml`; those closed rows do not by themselves validate final
capacity, quota, reserve, reclaim, dedup, or mounted statfs readiness.

| Slice | Issue | Expected write set | Sequencing and acceptance |
|---|---|---|---|
| Scope overclaim cleanup | #857 | `crates/tidefs-block-allocator/README.md`, `crates/tidefs-block-allocator/src/lib.rs` docs/comments only | Narrow allocator wording to physical placement, transactional reservation/fencing, and lower free-space input. |
| Adapter facade retirement | #858 | `apps/tidefs-posix-filesystem-adapter-daemon/src/capacity/` and adapter tests that import it | Delete or further quarantine the test-only `CapacityFacade`, admission lifecycle, and tracker so release code cannot consume an adapter-local capacity API. |
| Operator capacity projection | #859 | `apps/tidefsctl/src/commands/dataset.rs` and focused CLI tests/docs only | Make `dataset list` report authority-derived used/available fields instead of mixing `statfs` availability with unset `used`. |
| Dataset quota input bridge | #860 | `crates/tidefs-dataset-properties/` plus focused property-resolution tests | Expose resolved `space.quota` as a typed authority input. Runtime enforcement in local filesystem/space-accounting is a separate gated row. |
| Runtime authority closeout | #1191 | `crates/tidefs-local-filesystem/src/capacity_authority.rs`, `crates/tidefs-local-filesystem/src/statfs.rs`, `crates/tidefs-local-filesystem/src/lib.rs`, `crates/tidefs-space-accounting/src/lib.rs`, `crates/tidefs-types-space-accounting-core/src/lib.rs`, `crates/tidefs-local-object-store/src/store.rs` | Closed by PR #1464 for the mounted `fallocate_file()` / `zero_range()` admission and statfs projection slice; post-#1191 residuals remain split below. |
| Store `SpaceBook` persistence boundary | #1504 | `crates/tidefs-space-accounting/src/lib.rs`, `crates/tidefs-local-object-store/src/store.rs` | Closed. Historical row for making store-layer `SpaceBook` either a committed `SpaceAccounting` persistence/projection sink or a typed producer; it no longer represents a live blocker in this map. |
| Physical pool input projection | #1505 | `crates/tidefs-local-filesystem/src/capacity_authority.rs`, `crates/tidefs-local-filesystem/src/statfs.rs`, `crates/tidefs-types-space-accounting-core/src/lib.rs` | Closed. Historical row for defining physical pool counter fields that may constrain authority projections without independently deciding mounted admission or mounted `statfs`; it no longer represents a live blocker in this map. |
| Reclaim evidence producer integration | #1506 | `crates/tidefs-data-cleaner/`, `crates/tidefs-cleanup-engine/`, `crates/tidefs-cleanup-job-core/` | Closed. Historical row for publishing committed reclaim evidence while keeping estimated or scheduled cleanup as a non-claim for mounted availability until committed deltas exist; it no longer represents a live blocker in this map. |
| Dedup obligation evidence integration | #1507 | `crates/tidefs-dedup/`, `crates/tidefs-local-filesystem/src/dedup_refcount.rs` | Closed. Historical row for typing dedup obligation evidence without changing mounted write-path wiring; it no longer represents a live blocker in this map. |
| Mounted residual consumer wiring | #1508 | `crates/tidefs-local-filesystem/src/lib.rs` plus focused local-filesystem tests | Closed. Historical row for consuming only the explicit inputs or recorded non-claims from #1504 through #1507; it no longer represents a live blocker in this map. |
| Dedup delta producer integration | #790 | `crates/tidefs-dedup/` plus the minimal write-path consumer identified by #790 | Make dedup decisions publish committed logical/physical deltas or explicit reclaim obligations to the authority. |
| Physical reclaim delta integration | #791 | `crates/tidefs-segment-cleaner/` plus the minimal reclaim/allocator consumer identified by #791 | Feed committed physical reclaim evidence into authority inputs without broadening into defrag, snapshot deadlists, or distributed rebuild. |
| Example statfs projection cleanup | #785 | `crates/tidefs-fuser/examples/simple.rs` | Keep example statfs from teaching hardcoded placeholder accounting; consume real backing state or document a proper engine hook. |

## Merge Gate

TFR-007 may be narrowed after this design lands, but it must remain open until
the runtime authority closeout and any required consumer-projection slices have
validated that mounted admission, POSIX/FUSE statfs, dataset quota input,
reclaim, dedup, inode-count projection, and operator reporting all consume this
boundary.
