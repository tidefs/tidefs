# Inode Namespace Authority

Maturity: current design and mounted implementation boundary for TFR-004.

Decision id: `tfr-004.dataset_inode_authority.v1`.

This document decides the owner boundary for dataset-scoped inode identity and
records how the selected mounted carrier applies it. It does not claim
production readiness or close TFR-004 by itself.

## Scope

This decision covers:

- inode number allocation and reuse within a mounted dataset;
- persisted inode IDs in local-filesystem records, namespace records,
  snapshots, committed roots, and replay;
- dataset root identity and the current root dataset bridge;
- FUSE lookup/forget references and adapter lookup caches;
- the relationship between `LocalFileSystem`, `tidefs-namespace`,
  `tidefs-inode-table`, and FUSE adapter registries;
- old pre-release catalog handling for inode and root dataset mismatches.

This decision does not by itself prove crash consistency for rename, replay,
special nodes, or lookup caches. Current runtime evidence belongs to the
focused carrier tests named by the implementing issue and pull request.

## Current Mounted Implementation

The selected local mounted carrier applies the decision as follows:

- `DatasetInodeAuthority` inside `tidefs-local-filesystem` owns the dataset ID,
  root inode, allocation cursor, explicit-ID observation, and recovery seeding.
- `VfsLocalFileSystem` consumes local-filesystem inode and directory state
  directly. It has no optional `InodeTable`, setter, or mirrored allocation
  branch.
- `FuseVfsAdapter` attaches no `Namespace`. Lookup, attributes, mutation,
  rename, directory iteration, and xattrs project the VFS engine without a
  namespace fallback, mirrored durable attributes, or merged directory view.
- FUSE lookup counts, forget counts, and path/negative caches are derived
  kernel-reference state only. The selected adapter has no inode-table-backed
  lookup/read/write batch, and `tidefs-namespace` remains outside the selected
  mounted carrier.
- The mounted pool lifecycle checks stable inode identity through rename,
  hard-link, unlink, clean export/reimport, and crash recovery.

## Original Decision Evidence

The original decision was based on the following source state. It is preserved
as decision rationale, not as the current implementation map; the current map
is above and in `docs/ARCHITECTURE.md`.

Documentation:

- `docs/REVIEW_TODO_REGISTER.md` records TFR-004 split authority between
  `LocalFileSystem`, `tidefs-namespace`, `tidefs-inode-table`, and FUSE
  lookup/forget state.
- `docs/REVIEW_TODO_REGISTER.md` records recent TFR-004 cleanup commits:
  root dataset ID alignment, fail-closed mismatched root catalogs, explicit
  namespace inode ID preservation, inode-table corruption fail-closed behavior,
  and LocalFileSystem-backed namespace `rdev` preservation. The register also
  records that these cleanup slices did not settle a single dataset-scoped
  inode authority.
- `docs/UNRELEASED_AUTHORITY_POLICY.md` says pre-release internal formats and
  fixtures are not compatibility commitments unless an issue names a real
  external ABI, protocol, or operator-owned data set.

Local filesystem:

- `crates/tidefs-local-filesystem/src/lib.rs` has a global
  `FileSystemState` containing global inode maps, directory maps, known inode
  IDs, extent maps, and `next_inode_id`.
- `LocalFileSystem::next_inode_id()`, `alloc_inode_id()`,
  `insert_inode_at()`, and the internal `allocate_inode_id()` currently expose
  or mutate that global allocator. `insert_inode_at()` advances the same global
  cursor when namespace persistence supplies an explicit ID.
- The root dataset catalog now uses `ROOT_DATASET_ID` for the root bridge and
  fails closed on persisted root catalog ID mismatch, but that bridge is not a
  dataset-scoped inode authority.
- `crates/tidefs-local-filesystem/src/recovery.rs` reconstructs
  `next_inode_id` from committed roots, superblock state, and snapshot or
  bitmap summaries. Recovery therefore already participates in allocator
  authority and cannot be outside the chosen boundary.

Namespace:

- `crates/tidefs-namespace/src/lib.rs` has `MemInodeTable`, an atomic bump
  allocator with a `HashMap` and freed set. It is a namespace-local allocator,
  not a durable mounted dataset authority.
- `Namespace` delegates allocation to `PersistentInodeStore` when present and
  otherwise falls back to `MemInodeTable`.
- `crates/tidefs-namespace/src/persistence.rs` defines
  `NamespaceDatasetIdentity` and persistent stores that are dataset-keyed and
  preserve explicit IDs.
- `crates/tidefs-namespace/src/local_fs_persist.rs` bridges namespace
  allocation to `LocalFileSystem` by using explicit `attrs.inode` when present,
  otherwise `fs.next_inode_id()`, and inserting with `fs.insert_inode_at()`.
  It preserves `rdev` through the bridge, but generic replay still lacks a
  device-number authority.

Inode table:

- `crates/tidefs-inode-table/src/inode_table_impl.rs` describes
  `InodeTable` as an authoritative inode-number-to-attributes registry, but
  the same file carries a TFR-004 marker because the table has a separate
  allocation and state model.
- `InodeTableInner` owns slots, a free list, generation state, and open
  reference counts; `allocate()`, `lookup()`, and `commit()` persist a cursor,
  generation, and free list through `crates/tidefs-inode-table/src/persist.rs`.
- That state can be useful as an adapter or kernel-facing projection, but it
  must not be a second durable mounted dataset allocator.

FUSE adapter:

- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` has
  namespace-first lookup paths, engine lookup/getattr fallbacks, lookup count
  maps, forget reference counts, path lookup caches, negative cache state, and
  removed-lookup attributes.
- `dispatch_lookup_via_namespace()` and `dispatch_lookup()` project mounted
  namespace or engine attributes into FUSE replies, then update lookup tracking
  and cache state.
- `bump_forget_refcount()` and `dispatch_forget()` track kernel lookup
  references and decide when adapter caches can be invalidated.
- At decision time, the now-retired pre-contraction `fuse_lookup_forget.rs`
  wrapped `tidefs-inode-table::InodeTable` for an unwired lookup/forget batch.
  Its removal left kernel reference accounting in `FuseVfsAdapter` itself.

## Owner Models Compared

### Model A: `LocalFileSystem` Owns Allocation, Namespace Is A Projection

At decision time this matched much of the source: `LocalFileSystem` stored
inode maps, the global cursor, directory state, content/extents, committed
roots, recovery, and snapshot inputs. Namespace persistence could project into
it.

Rejected as the final model because the current owner is global to
`LocalFileSystem`, not explicitly dataset-scoped. Treating the existing global
state as settled authority would keep mounted dataset identity, snapshots, and
old root catalog behavior coupled to a root-level bridge.

Allowed migration shape: the dataset-scoped authority may be extracted inside
or next to `tidefs-local-filesystem` first, because that crate already owns the
records, recovery, content, and snapshot state that must consume it.

### Model B: Namespace Owns Allocation, `LocalFileSystem` Is A Backing Store

This would make `Namespace` and `PersistentInodeStore` the primary inode
allocator, with `LocalFileSystem` storing records behind it.

Rejected because namespace does not own content extents, committed roots,
snapshot retention, recovery reconstruction, root dataset admission, or mounted
storage failure policy. Making namespace the durable owner would either move
those storage responsibilities into namespace or leave allocator state split at
the crash/recovery boundary.

The selected mounted carrier no longer uses `Namespace` as its name and
directory-entry projection. Any distinct namespace consumer may allocate
durable IDs only through the dataset inode authority; its memory allocator
remains acceptable only for isolated in-memory use and tests that are not
mounted dataset authority.

### Model C: Dedicated Dataset-Scoped Inode Authority

This model creates one explicit authority for inode IDs within each dataset.
`LocalFileSystem`, namespace, inode-table projections, and FUSE adapter
registries all consume that authority instead of duplicating durable allocation
decisions.

Chosen. It is the only model that can make allocation, explicit persisted IDs,
root identity, snapshots, recovery, namespace replay, and adapter references
share one boundary without promoting an existing projection to durable
ownership.

## Decision

TideFS will use a dedicated dataset-scoped inode authority.

The authority owns:

- fresh inode allocation for each dataset;
- the reserved dataset root inode identity;
- validation and insertion of explicit persisted inode IDs;
- allocator cursor or free-space state used to avoid reuse while IDs remain
  live in the dataset;
- recovery reconstruction of allocator state from committed roots, snapshots,
  and namespace replay inputs;
- the rule that a persisted inode ID belongs to exactly one mounted dataset
  authority at a time.

The authority lives as a focused local-filesystem module because
`tidefs-local-filesystem` owns the durable records, content/extents, committed
roots, snapshots, and recovery code that consume it. The boundary is the
dataset inode authority, not an adapter registry or namespace projection.

## Boundary Rules

### Inode Allocation

All durable mounted inode allocation goes through `DatasetInodeAuthority`.
Recovery reconstructs it from the selected durable inode IDs, and explicit ID
insertion advances its reuse-prevention state.

`Namespace` is not attached to the selected mounted carrier. Any other
persistent namespace consumer must not allocate mounted IDs independently; the
fallback `MemInodeTable` is only an in-memory non-carrier projection.

`tidefs-inode-table` must not allocate durable mounted inode IDs. Its state may
remain useful for non-mounted tests or kernel-reference projections, but
`VfsLocalFileSystem` does not consume it and it is not the mounted dataset
owner.

### Persisted Inode IDs

Persisted inode IDs are authoritative only when accepted by the dataset inode
authority for the dataset being opened or replayed. Explicit IDs loaded from
namespace records, committed roots, snapshots, or recovery inputs must be
preserved when valid and must advance or seed the authority's reuse-prevention
state.

Replay must fail closed when a persisted ID conflicts with the dataset
authority's invariants. It must not silently remap inode IDs, allocate fresh
IDs for loaded persistent entries, or treat an adapter registry as durable
truth.

### Dataset And Root Identity

Dataset identity and root inode identity are part of the same mounted dataset
boundary. `ROOT_DATASET_ID` seeds fresh roots through
`DatasetInodeAuthority`; root-level adapter or namespace state is not a second
identity owner.

A mounted dataset's root inode ID must be stable across reopen, snapshot
selection, and namespace replay. It must be rejected if a persisted catalog or
record would attach the mounted root to a different dataset authority without
an explicit compatibility issue.

### Snapshots And Recovery

Snapshots and committed roots consume inode authority; they do not allocate
new identities by themselves. Opening a snapshot or recovering a committed root
must reconstruct the dataset authority state from the selected durable records
and refuse conflicts.

Future clone/send/receive work may define cross-dataset translation, but this
decision does not authorize implicit inode ID remapping across datasets.

### FUSE Lookup References

FUSE lookup and forget state owns only kernel lookup references, adapter cache
invalidation, negative cache state, and lookup hotness. It does not own durable
inode allocation, existence, reuse, or persisted ID recovery.

`lookup_counts`, `forget_refcounts`, path caches, and removed-lookup attributes
are projections of mounted dataset identity. `FuseVfsAdapter` obtains existence
and attributes from the VFS engine rather than consulting an inode-table batch
or falling back to a second namespace.

### Old Catalogs

Old pre-release catalogs whose root dataset or inode authority state conflicts
with the current mounted dataset authority must fail closed by default. TideFS
has no public release or named operator-owned data set that makes those
catalogs a compatibility promise.

The only default root-catalog creation case is first mount with no persisted
catalog. Existing persisted catalog bytes that cannot be decoded or loaded are
refused rather than treated as an empty catalog, and a persisted `root` entry
whose dataset ID differs from the mounted root is refused rather than
rewritten.

Migration is allowed only if a future GitHub issue names the external boundary
or operator-owned data set, the validation plan, and the removal or graduation
criteria required by `docs/UNRELEASED_AUTHORITY_POLICY.md`. Closed issue #666
implemented the current fail-closed policy.

### Special-Node `rdev`

Special-node `rdev` preservation through the LocalFileSystem-backed namespace
bridge is evidence that the bridge can carry device numbers. It is not enough
to close generic replay authority.

Issue #667 tracked and closed the separate `rdev` intent/replay slice. Changes
to allocator or namespace ownership must preserve that behavior without making
the adapter or a namespace mirror authoritative again.

## Implementation Sequence

The decision was implemented and then contracted through these bounded issues:

| Issue | Slice | Resulting boundary |
|---|---|---|
| #664 | Extract the dataset-scoped allocator owner. | Durable allocation, explicit IDs, root identity, recovery reconstruction, and snapshot/reopen seeding belong to local-filesystem's dataset authority. |
| #665 | Make FUSE lookup references a projection. | Kernel lookup references, forget handling, and cache invalidation do not own durable allocation. |
| #666 | Settle old catalog policy. | Conflicting pre-release catalog identity fails closed unless a named external boundary authorizes migration. |
| #667 | Replay special-node `rdev` through intent authority. | Device-number persistence does not change generic inode ownership. |
| #2397 | Remove residual mounted namespace and inode-table fallbacks. | The selected VFS/FUSE carrier has one namespace identity and propagates engine results without a second mounted authority. |

## Validation For This Decision

The original decision issue required bounded source inspection and
`git diff --check`. Implementation changes require focused local-filesystem and
adapter checks plus the existing `tidefsctl` pool-remount lifecycle row for
stable inode identity across clean reopen and crash recovery. Do not add a new
claim, manifest, or validation harness for this boundary.
