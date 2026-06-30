# Online Dataset Rename Namespace Catalog Design

**Issue**: [#1282](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1282)
**Status**: design-spec
**Maturity**: spec-draft — defines the pool-wide dataset catalog, online rename mechanics,
and namespace hierarchy management
**Priority**: P2
**Lane**: storage-core
**Prior-art pressure**: ZFS-style dataset rename couples dataset naming to
mount lifecycle; this design targets stable dataset identity without treating
that target as a validated current online-rename claim.

## 1. Problem Statement

ZFS-style prior art couples "filesystem" and "mount point" at the operator
boundary. A dataset is simultaneously a filesystem namespace and a mount
boundary, making rename a disruptive operator event:

- `zfs rename pool/a pool/b` requires unmounting `pool/a` first, or using
  `-u` which unmount-renames-remounts automatically. Either way, open file
  handles become stale, the mount point changes, and services must be
  reconfigured.
- Dataset destroy similarly requires ensuring nothing is mounted,
  complicating automation and orchestration.

In cloud/container environments where datasets proliferate (one per tenant,
per volume, per snapshot schedule), the design target is that renaming a
tenant's dataset or restructuring namespace hierarchy does not require
application downtime. The POSIX `rename(2)` on directories within a dataset
works through a different boundary; this design applies that lesson to the
dataset-root catalog target.

This design separates dataset identity from mount semantics. It is not a
current parity, online-rename, or superiority claim.

## 2. Architectural Principle: Dataset as Logical Namespace, Not Mount Point

### 2.1 Core separation

The TideFS design treats three concerns that the ZFS-style prior-art pressure
couples as distinct:

| Concern | ZFS-style prior art | TideFS design target |
|---|---|---|
| **Filesystem namespace** | Tied to dataset = mount point | Dataset is a logical namespace within the pool; identity is a stable UUID |
| **Mount domain** | Per-dataset mount | Pool is the mount domain; a single FUSE daemon mounts the pool |
| **Path within hierarchy** | Dataset name = mount path | Dataset name is a mutable catalog entry; the pool root directory maps names to dataset root inodes |

### 2.2 Invariant: stable identity across rename

```
Dataset identity:
  dataset_id: UUID          ← STABLE across rename, clone, promote, send/recv
  root_inode_id: u64        ← STABLE across rename (the root inode itself
                              doesn't move)
  name: bytes               ← MUTABLE — rename updates this
  parent_dataset_id: Option<UUID>  ← MUTABLE — reparent updates this
```

All open file handles, locks, leases, and FUSE inode numbers remain valid
across a dataset rename because the dataset's `root_inode_id` never changes.
Only the catalog's name entry is modified.

### 2.3 What this enables

- Operators can restructure dataset hierarchies without application downtime
- Dataset "promotion" (clone → independent dataset) is a simple rename +
  property change
- Multi-tenant orchestrators can rename tenant datasets as part of
  migration/reshuffling
- Nothing in the on-media format ties dataset identity to a path
- Cross-dataset reflink (#1276) benefits from stable dataset identity —
  extent sharing references `dataset_id`, not name

## 3. Dataset Catalog Data Structures

### 3.1 Catalog root

The dataset catalog is a persistent B+tree rooted in the pool superblock
(system area). It maps stable `dataset_id` (UUID v4) to
`DatasetCatalogEntryV1`.

```
PoolSuperblockV1 {
    ...
    dataset_catalog_root: u64,     // byte offset to catalog B+tree root
    dataset_catalog_height: u8,     // B+tree height
    dataset_count: u32,             // live dataset count (excludes tombstones)
    ...
}
```

### 3.2 Catalog entry

```rust
/// Per-dataset catalog entry persisted in the pool's dataset catalog B+tree.
/// Keyed by `dataset_id` (UUID v4, 16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DatasetCatalogEntryV1 {
    /// Stable dataset identifier (UUID v4). This is the B+tree key.
    dataset_id: [u8; 16],

    /// Mutable human-readable name. UTF-8 bytes, 1..255 bytes.
    /// Must be unique within the parent dataset's namespace.
    name_len: u8,
    name: [u8; 255],               // zero-padded to 255

    /// Parent dataset in the namespace hierarchy.
    /// None for the pool root dataset(s). Mutable on reparent.
    parent_dataset_id: Option<[u8; 16]>,

    /// The root inode of this dataset. STABLE — never changes on rename.
    /// All file handles reference inodes rooted at this inode.
    root_inode_id: u64,

    /// Lifecycle state (ACTIVE, DESTROYING, TOMBSTONE). See #1219.
    state: u8,                      // DatasetStateV1 discriminant

    /// Creation commit_group and timestamp.
    creation_commit_group: u64,
    creation_time_secs: u64,

    /// Last rename commit_group (0 if never renamed).
    last_rename_commit_group: u64,

    /// Feature flags bitmask. See #1223.
    feature_flags: u64,

    /// Space accounting domain ID. See space accounting model.
    space_domain_id: u64,

    /// Reserved for future use.
    reserved: [u8; 96],
}
```

Total entry size: 512 bytes (fixed). This allows efficient B+tree packing
without variable-width entries in interior nodes.

### 3.3 Why UUID key instead of name key

| Approach | Pros | Cons |
|---|---|---|
| **UUID key** | Stable across rename; rename is O(1) in-place update; all references (leases, locks, reflink extents) use stable ID | Requires separate name→UUID index for lookup |
| **Name key** | No name index needed; catalog walk returns sorted names | Rename requires delete+insert (two B+tree ops); all external references break |

tidefs chooses UUID key because:
1. All internal references (extent sharing, lease tables, snapshot catalogs,
   cluster lock service) must point at a stable identifier.
2. A rename that changed the primary key would require cascading updates to
   every referencing data structure — the same coupling pressure this design
   intentionally avoids.
3. The name→UUID lookup index is a secondary structure that can be updated
   atomically with the catalog entry.

### 3.4 Name-to-UUID index

A secondary B+tree, also rooted in the pool superblock, maps
`(parent_dataset_id, name)` pairs to `dataset_id`. This is the lookup path
for `tidefsctl dataset rename <old> <new>` and for walking the pool namespace
hierarchy.

```rust
/// Secondary index entry. Key: (parent_dataset_id, name).
struct DatasetNameIndexEntryV1 {
    parent_dataset_id: [u8; 16],   // 16 zero bytes for root children
    name_len: u8,
    name: [u8; 255],
    dataset_id: [u8; 16],          // points to catalog entry
}
```

During rename, both the catalog entry's `name` field and the name index are
updated atomically within a single commit_group. The index update is: delete old
`(parent, old_name)` entry, insert new `(new_parent, new_name)` entry.

## 4. Online Rename Algorithm

### 4.1 Operation: `rename_dataset`

```
rename_dataset(
    dataset_id: UUID,
    new_name: &[u8],
    new_parent_dataset_id: Option<UUID>,
    flags: u32,
) -> Result<(), DatasetRenameError>
```

### 4.2 Pre-conditions

1. **Dataset exists**: `dataset_id` must be present in catalog with
   `state == ACTIVE`.
2. **New name valid**: `new_name` must be 1..255 bytes, UTF-8,
   no `\0`, no `/`.
3. **No name conflict**: No existing dataset under `new_parent_dataset_id`
   has `new_name`.
4. **No cycle**: If `new_parent_dataset_id` differs from current parent,
   the new parent must not be a descendant of `dataset_id`.
5. **New parent exists**: If `new_parent_dataset_id` is provided, it must
   exist in the catalog with `state == ACTIVE` or be the pool root (None).
6. **Not a descendant**: A dataset cannot be reparented into its own subtree
   (prevents namespace cycles).

### 4.3 Atomic commit (single commit_group)

All mutations below are committed in a single commit_group. Either all succeed or
none do.

```
Step 1: Acquire catalog write lock (pool-level exclusive lock, level 1
        in hierarchy).


Step 3: Update catalog entry:
    entry.name = new_name
    entry.parent_dataset_id = new_parent_dataset_id
    entry.last_rename_commit_group = current_commit_group

Step 4: Update name index:
    DELETE from name_index WHERE (old_parent, old_name)
    INSERT into name_index ((new_parent, new_name) -> dataset_id)

    "dataset <old_name> renamed to <new_name> under <new_parent>"

Step 6: Commit commit_group.
```

### 4.4 What does NOT happen during rename

- **No unmount**: The pool remains mounted; the FUSE daemon continues
  serving all file handles.
  descriptors, memory mappings, and directory handles remain valid.
- **No lease revocation**: Writer leases, reader leases, and byte-range
  locks are scoped to `dataset_id`, not name. They survive rename unchanged.
- **No extent remapping**: Extent maps reference physical locators via
  `ExtentId`; nothing in the extent layer cares about dataset name.
- **No snapshot rename**: Local snapshots (#1232) are keyed by `snap_id`,
  not dataset name. Snapshots belong to a `dataset_id` and are unaffected
  by its rename.
- **No send/recv breakage**: Send/recv streams (#1251) reference
  `dataset_id`; the receiver resolves the name from the catalog at
  receive time.

### 4.5 Flags

```
DatasetRenameFlags: u32 {
    NOREPLACE       = 0x01,  // Fail with EEXIST if new_name already taken
    ALLOW_REPARENT  = 0x02,  // Allow changing parent_dataset_id
                             // (default: same-parent only)
}
```

- `NOREPLACE` matches POSIX `renameat2 RENAME_NOREPLACE` semantics applied
  to the catalog namespace.
- `ALLOW_REPARENT` gates the potentially risky operation of moving a dataset
  to a different parent. Default behavior (without this flag) only permits
  same-parent renames.
  catching name conflicts or cycle errors early.

### 4.6 Cycle detection

When `ALLOW_REPARENT` is set and `new_parent_dataset_id` differs from the
current parent:

```rust
fn is_ancestor_or_self(ancestor: UUID, descendant: UUID,
                       catalog: &Catalog) -> bool {
    let mut current = descendant;
    loop {
        if current == ancestor {
            return true;  // cycle would be created
        }
        match catalog.get_parent(current) {
            Some(parent) => current = parent,
            None => return false,  // reached pool root — no cycle
        }
    }
}
```

The check walks the parent chain from `new_parent_dataset_id` to the pool
root. If `dataset_id` appears in the chain, the rename is rejected with
`EINVAL` (cannot move a dataset into its own subtree).

## 5. FUSE Namespace Integration

### 5.1 Pool root directory

The FUSE daemon mounts the **pool**, not individual datasets. The pool root
directory contains:

```
/mnt/tidefs/              ← FUSE mount point (pool root)
├── dataset_a/            ← root_inode of dataset_a
├── dataset_b/            ← root_inode of dataset_b
│   ├── file1.txt
│   └── subdir/
└── tenants/
    ├── tenant_x/         ← root_inode of tenant_x's dataset
    │   └── volumes/
    │       └── vol1/     ← root_inode of vol1 (parent = tenant_x)
    └── tenant_y/
```

The pool root is a synthetic directory managed by the FUSE daemon. Each
entry is a directory whose inode is the dataset's `root_inode_id`. The
FUSE daemon resolves dataset→root_inode from the catalog.

### 5.2 Lookup path

```
lookup(pool_root, "dataset_a"):
  1. Query name_index for (parent=None, name="dataset_a") → dataset_id
  2. Query catalog for dataset_id → DatasetCatalogEntryV1
  3. Check state == ACTIVE
  4. Return root_inode_id with S_IFDIR attributes
```

### 5.3 Atomic rename visibility

Under the commit_group commit model (#1267), catalog updates are atomic: a concurrent
`lookup` or `readdir` on the pool root sees either the pre-rename state
(old name) or the post-rename state (new name), never a partial intermediate
state. This is enforced by:
- The catalog write lock serializes all namespace mutations.
- Read operations (lookup, readdir) acquire a shared lock or read from the
  committed catalog snapshot.
- The commit_group boundary guarantees that all mutations in the rename commit_group commit
  together.

### 5.4 readdir on pool root

The pool root `readdir` enumerates all datasets whose `parent_dataset_id`
is None (direct children of the pool root) by scanning the name index.
This is a catalog-level scan, not a directory inode scan.

```
readdir(pool_root) →
  (inode=dataset_a.root_inode_id, name="dataset_a", type=DT_DIR)
  (inode=dataset_b.root_inode_id, name="dataset_b", type=DT_DIR)
  (inode=tenants_ds.root_inode_id,  name="tenants",  type=DT_DIR)
```

`readdir` on a dataset root inode behaves normally — it lists the files and
directories within that dataset.

## 6. Control Plane Integration

### 6.1 Admin service RPC

```
// Rename a dataset within the pool namespace.
// ADMIN service (service_id=0x09), method RENAME_DATASET.
RENAME_DATASET {
    dataset_id: UUID,                    // existing dataset to rename
    new_name: bytes,                     // 1..255 UTF-8 bytes
    new_parent_dataset_id: Option<UUID>, // None = keep current parent
    flags: u32,                          // DatasetRenameFlags
}
→ RENAME_DATASET_RESPONSE {
    status: RenameStatus,
    old_name: bytes,                     // previous name (for audit)
    rename_commit_group: u64,                     // commit_group in which rename committed
}
```

### 6.2 CLI

```
tidefsctl dataset rename <dataset-name> <new-name>
tidefsctl dataset rename --parent <new-parent> <dataset-name> <new-name>
tidefsctl dataset rename --dry-run --parent <new-parent> <dataset-name> <new-name>
```

### 6.3 Error codes

| Error | Condition |
|---|---|
| `ENOENT` | `dataset_id` not found in catalog |
| `EEXIST` | `new_name` already taken under `new_parent` (with NOREPLACE) |
| `EINVAL` | Name contains `\0` or `/`, or name too long, or cycle detected |
| `EBUSY` | Dataset is not in ACTIVE state (e.g., DESTROYING) |
| `EPERM` | Caller lacks admin capability |
| `ENOTDIR` | `new_parent_dataset_id` is not a directory-typed dataset |
| `EROFS` | Pool is in read-only state (exported, or filesystem error) |

## 7. Integration with Existing Designs

### 7.1 Dataset lifecycle (#1219)

The lifecycle state machine (`DatasetStateV1`) gates rename:
- **ACTIVE**: rename allowed.
- **DESTROYING**: rename refused (return `EBUSY`). The dataset identity is
  being dismantled.
- **TOMBSTONE**: rename refused (return `ENOENT` — the dataset no longer
  exists for namespace purposes).

The rename commit_group uses the same commit path as lifecycle transitions. If a
rename commit_group races with a destroy commit_group, the commit_group ordering resolves the conflict
deterministically — the later commit_group's pre-conditions will detect the state
change and fail.

### 7.2 Pool topology (#1254)

- Dataset catalog is part of the pool's system area. Pool import/export
  preserves the catalog.
- Pool export: the catalog is written to all devices as part of the pool
  label and system area checkpoint.
- Pool import: the catalog is read from the device with the highest `commit_group`.
- Cluster-shared pools: the catalog is the authoritative source for dataset
  identity across all nodes.

### 7.3 Rename atomicity (#1205)

The intra-dataset rename algorithm (5-step transaction/locking algorithm for
`renameat2`) operates on inodes within a dataset. Dataset renames operate on
the catalog. They are independent mechanisms:

| Aspect | Intra-dataset rename (#1205) | Dataset rename (this design) |
|---|---|---|
| Scope | Inodes within one dataset | Dataset entries in pool catalog |
| Lock hierarchy | Level 2 (parent dir), Level 3 (inode) | Level 1 (catalog write lock) |
| Commit unit | Directory entry maps + dir_rev | Catalog B+tree + name index |
| Error on cross-scope | `EXDEV` | N/A (different operation) |

Interaction: if a dataset rename commits between an intra-dataset rename's
resolve phase and its commit phase, no conflict occurs — the dataset rename
changes the catalog, while the intra-dataset rename touches directory entries
within the dataset's inode tree. The `root_inode_id` is unchanged, so the
intra-dataset operation sees a consistent view.

### 7.4 Cross-dataset reflink (#1276)

Cross-dataset reflink relies on stable `dataset_id` for extent sharing:
- Extent sharing references `(dataset_id, extent_id)`, never dataset name.
- The pool-wide refcount table keys on `ExtentId`, not path.

### 7.5 CommitGroup state machine (#1267)

Dataset rename is a transactional event committed through the standard commit_group
pipeline:
- **Open phase**: Catalog write lock acquired; rename metadata prepared.
- **Commit phase**: Catalog entry + name index updates written to commit_group
  journal.
- **Sync phase**: Journal flushed to stable storage.
  namespace change.

### 7.6 Cluster membership and lock service (#1283, #1248)

- Writer leases and distributed locks are scoped to `(dataset_id, inode_id)`.
  Dataset rename changes neither, so no lease revocation is needed.
  update their catalog caches.
- The ADMIN service routes `RENAME_DATASET` to the pool's owner node, which
  executes the rename and propagates the catalog update.

### 7.7 Snapshot and send/recv (#1232, #1251)

- Snapshots are keyed by `(dataset_id, snap_id)`. Dataset rename does not
  affect snapshot identity.
- Send streams carry `dataset_id` in the stream header. The receiver
  resolves the name from the local catalog at receive time.
- If a dataset is renamed between an incremental send's base snapshot and
  the current snapshot, the send stream is unaffected — it references
  `dataset_id`.

### 7.8 Space accounting

- `DatasetSpaceCountersV1` is keyed by `space_domain_id`, not dataset name.
- The `space_domain_id` is stored in `DatasetCatalogEntryV1` and remains
  constant across rename.

## 8. On-Media Format Impact

### 8.1 New structures

- `DatasetCatalogEntryV1` (512 bytes fixed): new persistent record type.
- `DatasetNameIndexEntryV1` (variable): new persistent index entry type.
- Pool superblock gains `dataset_catalog_root`, `dataset_catalog_height`,
  `dataset_count` fields.

### 8.2 Forward compatibility

- The catalog is a new pool-level structure. Pools created before this
  design have no catalog; the import path detects the absence (zero
  `dataset_catalog_root` in superblock) and creates an initial catalog by
  scanning existing dataset records.
- The catalog uses a versioned magic (`"DSC1"` as a 4-byte magic at the
  catalog root) for forward compatibility.
- Unknown fields in `DatasetCatalogEntryV1.reserved` are preserved on
  read/modify/write.

### 8.3 Feature flag

A pool-level feature flag (`FEATURE_DATASET_CATALOG`) gates the catalog.
When set:
- All dataset namespace operations go through the catalog.
- The pool root `readdir` uses the catalog.
- Rename operations are enabled.

When not set (legacy pools):
- Dataset names are stored inline in dataset system areas (current
  behavior).
- Rename is not available (returns `ENOSYS`).
- Pool upgrade to set the feature flag is a separate administrative
  operation tracked in a future issue.

## 9. Implementation Phases

### Phase 1: Core types and catalog structure (this issue)
- Define `DatasetCatalogEntryV1`, `DatasetNameIndexEntryV1` in
  `tidefs-types-dataset-lifecycle-core` or a new
  `tidefs-types-dataset-catalog-core` crate.
- Define `DatasetRenameFlags` and `DatasetRenameError`.
- Define pool superblock extensions for catalog root.
- Define the `DatasetCatalog` trait (CRUD operations, name lookup,
  hierarchy walk).
- This phase is design-only; Rust structs are documented but wire-up is
  deferred.

### Phase 2: Catalog storage engine
- Implement the catalog B+tree in `tidefs-local-object-store`.
- Implement the name index B+tree.
- Pool import path: detect missing catalog, bootstrap from existing dataset
  records.
- Pool export path: checkpoint catalog to system area.

### Phase 3: Rename operation
  detection, and atomic commit_group commit.
- Implement name index update within the rename commit_group.
- Implement ADMIN service RPC handler.
- Implement `tidefsctl dataset rename` CLI.

### Phase 4: FUSE integration
- Pool root directory: `lookup` and `readdir` via catalog.
  directory cache).
- Path resolution through dataset boundaries.

### Phase 5: Cluster integration
- Catalog replication in cluster-shared pools.
- ADMIN service routing for rename on non-owner nodes.

### Phase 6: Legacy migration
- Pool upgrade tool: set `FEATURE_DATASET_CATALOG` feature flag.
- Migration of legacy dataset name records to catalog entries.
- Verification tool: check catalog consistency with on-disk dataset
  records.

## 10. Concurrency Model

### 10.1 Lock hierarchy

```
Level 0: Pool superblock lock (protects catalog root pointer)
Level 1: Catalog write lock (protects catalog B+tree + name index)
Level 2: Dataset lifecycle lock (per-dataset state transitions)
Level 3: Intra-dataset directory entry locks (per #1206 lock hierarchy)
```

A dataset rename acquires levels 0 → 1:
1. Pool superblock lock (shared): read catalog root pointer.
2. Catalog write lock (exclusive): mutate catalog entry + name index.
3. Release in reverse order.

### 10.2 Serialization with lifecycle transitions

A destroy operation on the same dataset:
1. Acquires catalog write lock (exclusive).
2. Reads dataset state → ACTIVE.
3. Transitions to DESTROYING (writes state field in catalog entry).
4. Releases catalog write lock.

A rename operation on the same dataset:
1. Acquires catalog write lock (exclusive). Blocked until destroy releases
   it.
2. Reads dataset state → DESTROYING (not ACTIVE).
3. Rename fails with `EBUSY`.
4. Releases catalog write lock.

The catalog write lock serializes rename and destroy, ensuring mutual
exclusion.

### 10.3 Read concurrency

Catalog reads (lookup, readdir) acquire a shared lock on the catalog or
read from the last committed commit_group snapshot. They never block on rename; they
see consistent pre-rename or post-rename state.

## 11. Performance Budget

| Operation | Complexity | Target latency |
|---|---|---|
| `rename_dataset` (same parent) | O(1) catalog update + O(1) index update + O(log N) B+tree insertion | < 1ms (single commit_group) |
| `rename_dataset` (reparent) | O(depth) cycle check + O(1) catalog update + O(log N) B+tree ops | < 2ms |
| `lookup(pool_root, name)` | O(log N) name index lookup + O(1) catalog read | < 100µs |
| `readdir(pool_root)` | O(M) name index scan (M = children of root) | < 10ms for 1000 datasets |

The critical path (rename with same parent) is a single-commit_group operation
touching exactly two B+tree entries (catalog entry + name index entry).
No data movement, no extent allocation, no inode tree traversal.

## 12. Tradeoffs and Design Rationale

### 12.1 Why UUID-keyed catalog instead of name-keyed?

**Decision**: UUID-keyed catalog with secondary name index.

**Rationale**: Stable identifiers are essential for every internal
reference — extents, leases, locks, snapshots, send streams, cluster
consensus. Making the name the primary key would require cascading updates
to all of these on every rename, recreating an incumbent coupling pressure at a
different layer. The cost is a secondary index and an extra lookup on name-based
operations, which is a O(log N) B+tree probe — negligible compared to the
disruption of a cascade.

### 12.2 Why pool-level mount instead of per-dataset mount?

**Decision**: Single pool FUSE mount; datasets appear as subdirectories.

**Rationale**: This targets the mount-point identity problem directly.
ZFS requires per-dataset mounts because each dataset is an independent
`zpl` filesystem instance with its own superblock. tidefs has a single pool
superblock and a single FUSE daemon; datasets share the same inode space
(though logically partitioned). This is closer to CephFS's subvolume model,
while avoiding a CephFS-style subtree-pinning dependency in the design target.

### 12.3 Why allow reparenting but gate it behind a flag?

**Decision**: `ALLOW_REPARENT` flag required to change `parent_dataset_id`.

**Rationale**: Same-parent rename is the 95% case and is provably safe
(no cycles possible, no hierarchy restructuring). Reparenting to a
different parent requires cycle detection and has semantic implications
(space accounting parent, property inheritance). Gating it behind a flag
makes the operator explicitly acknowledge the reparent, matching the
principle of least surprise.

### 12.4 Why fixed-size catalog entries (512 bytes)?

**Decision**: Fixed-size `DatasetCatalogEntryV1` entries.

**Rationale**: Fixed-size entries enable efficient B+tree implementation —
interior nodes store fixed-width keys without per-entry length metadata,
splitting is deterministic, and binary search in leaf nodes is
branch-predictable. The 255-byte name field (plus 1-byte length) matches
`NAME_MAX`, and the 96-byte reserved block leaves room for future fields
without format changes.

### 12.5 Prior-Art Comparison to ZFS and CephFS

This table is a design-target comparison only. It does not claim current
TideFS parity, validated online rename support, cross-dataset reflink support,
cluster-catalog production readiness, or superiority over ZFS/CephFS. Product
comparisons remain gated by #875 and #928/#930 evidence.

| Feature | ZFS prior art | CephFS prior art | TideFS design target |
|---|---|---|---|
| Dataset rename requires unmount | Yes | N/A (no dataset concept) | Target: no |
| Dataset identity | Name + GUID | N/A | UUID (stable) |
| Mount domain | Per-dataset | Per-filesystem | Per-pool |
| Namespace restructuring | Disruptive (unmount required) | Subvolume pinning to rank | Target: online, non-disruptive |
| Cross-dataset reflink | No | No reflink | Planned target (#1276) |
| Cluster awareness | No | Native | Planned cluster catalog (#1283) |

## 13. Testing Strategy

### 13.1 Unit tests (Phase 1-2)

- Catalog entry serialization/deserialization round-trip.
- Name index insertion, deletion, conflict detection.
- Cycle detection: self-parent, direct cycle, indirect cycle.
- Lock ordering: catalog write lock serializes concurrent renames.

### 13.2 Integration tests (Phase 3)

- Same-parent rename: open file handle survives rename.
- Reparent rename: dataset moves to new parent; readdir on old parent no
  longer shows it.
- Rename + concurrent writes: data written before rename is readable after
  rename.
- Rename + snapshot: snapshot taken before rename remains accessible by
  snap_id.
- Rename during destroy: rename on DESTROYING dataset returns EBUSY.
- Cross-dataset reflink survives rename: shared extents remain valid.
- Crash during rename: commit_group recovery restores consistent state (either old
  name or new name, never both or neither).

### 13.3 Cluster tests (Phase 5)

- Concurrent renames from different nodes are serialized (ADMIN routes to
  owner).

### 13.4 Performance tests

- 1000-dataset rename throughput: measure commit_group commit latency.
- 10000-dataset catalog scan (readdir): measure pool root readdir latency.
- Concurrent rename + readdir: verify no stalls, no inconsistent state.

## 14. Related Issues and Documents

| Issue/Doc | Relationship |
|---|---|
| #1219 — Dataset lifecycle | State machine gates rename; only ACTIVE datasets can be renamed |
| #1254 — Pool topology | Catalog is part of pool system area; import/export preserves it |
| #1205 — Rename atomicity | Intra-dataset rename; complementary to dataset-level rename |
| #1276 — Cross-dataset reflink | Stable dataset_id enables cross-dataset extent sharing |
| #1267 — CommitGroup state machine | Rename commits through standard commit_group pipeline |
| #1283 — Cluster membership | Catalog is authoritative source for dataset identity cluster-wide |
| #1248 — Distributed lock service | Locks scoped to dataset_id, not name |
| #1223 — Feature flags | FEATURE_DATASET_CATALOG gates catalog availability |
| #1232 — Snapshots | Snapshots reference dataset_id, survive rename |
| #1251 — Send/recv | Send streams carry dataset_id; receiver resolves name from catalog |
| `docs/DATASET_LIFECYCLE_DESIGN.md` | Lifecycle state machine reference |
| `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` | Pool label and system area layout |
| `docs/design/cross-dataset-reflink-and-copy-offload.md` | Pool-wide extent sharing |
| `docs/design/rename-atomicity-spec-renameat2-flags-5-step-algorithm.md` | Intra-dataset rename spec |
| Deleted ZFS/Ceph mistake lineage | Historical mistake #19 input retained in git history |

## 15. Gate

- `cargo check --workspace` passes clean (this is a design-only issue;
  no Rust implementation).
- Design reviewed against related specs (#1219, #1254, #1205, #1276,
  #1267).
- All integration points documented in §7.
- On-media format impact documented in §8.
- Implementation plan with 6 phases documented in §9.
