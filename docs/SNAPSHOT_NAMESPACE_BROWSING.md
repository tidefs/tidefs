# Snapshot Namespace Browsing

Issue: #699 (original decision), #768 (re-evaluation)
Date: 2026-06-21 (original), 2026-06-24 (re-evaluation)
Status: re-evaluated; Alternative B chosen for implementation

This document decides whether TideFS exposes snapshot content through a
transparent browsable namespace (ZFS-style `.snapshot` directories), through an
operator-only materialization/export path, or through no browsable namespace at
all. It records the chosen boundary for lookup identity, inode generation,
permission/ACL evaluation, mutation refusal, rollback interaction, and snapshot
deletion races, and maps the decision to non-overlapping follow-up
implementation issues.

The original #699 decision (2026-06-21) chose Alternative C (operator-only
export) and deferred Alternative B until the inode-authority chain (#664-#667)
and FUSE namespace stress work (#295) were closed. This re-evaluation (#768,
2026-06-24) assesses Alternative B against the now-stabilized implementation
and chooses it as the next implementation target.

ZFS references in this document are user-expectation and prior-art inputs only.
They do not claim TideFS parity with ZFS `.snapshot` behavior or validated
snapshot browsing support.

## Evidence Reviewed

### Original evidence (#699)

- `docs/LOCAL_SNAPSHOTS_OW108.md` — snapshot catalog, rollback, reclamation,
  lifecycle authority, operator CLI surface, and the open transparent-browsing
  item.
- `docs/INODE_NAMESPACE_AUTHORITY.md` — dataset-scoped inode authority decision
  for TFR-004, follow-up implementation map (#664-#667), and the explicit
  boundary between durable inode identity and FUSE lookup references.
- `docs/OPERATOR_UAPI_AUTHORITY.md` — `tidefsctl` command classification,
  live-owner routing, and the boundary between the code registry and release
  operator UAPI.
- `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md` — FUSE adapter as an environment
  boundary, not a filesystem-semantics authority.
- `crates/tidefs-vfs-engine/` and `tidefs-types-vfs-core` — inode-space
  operations, lookup(parent, name) -> InodeAttr, generation tracking for
  ESTALE, and the contract that InodeId, InodeAttr, and Generation are the
  canonical VFS vocabulary.
- `docs/design/posix-acl-xattr-codec-and-evaluation-design.md` — ACL evaluation
  against caller credentials,
  mode-ACL synchronisation, and default-ACL inheritance.
- Open issue #295 / PR #613 — active FUSE namespace stress work.
- Closed issue #442 / merged PR #682 — POSIX ACL inheritance boundaries.

### New evidence for re-evaluation (#768)

**Inode-authority closure (#664-#667).** All four inode-authority issues are
closed and their PRs are merged:

- #664 (inode-authority: extract dataset-scoped allocator owner)
- #665 (fuse: make lookup references a dataset inode projection)
- #666 (inode-authority: settle old catalog fail-closed policy)
- #667 (namespace: replay special-node rdev through intent authority) — PR #899
  merged 2026-06-22

The dataset-scoped inode authority now owns allocation, persisted IDs, root
identity, and recovery seeding. `InodeId` (u64) and `Generation` (u64) are the
canonical vocabulary. The `InodeTable` manages slot allocation, generation, and
free-list persistence independently of the FUSE adapter's lookup/forget state.
This settles the boundary question that blocked Alternative B in the original
evaluation: there is now a single dataset-scoped InodeId space against which
snapshot-root InodeIds and generation spaces can be projected.

**FUSE namespace stress resolution.** #295 is open as an umbrella tracking
issue, but the substantive FUSE namespace work that originally gated this
design is resolved:

- `generic/001` (copy/rename/unlink churn) — fixed by PR #613
- `generic/006` (permname namespace stress) — preserved through child work
- `generic/007` and `generic/011` (namespace stress) — proven by PR #384

The remaining `generic/013` fsstress CPU exhaustion is tracked by child #929,
split into PR #1132 (localfs sparse overlay chunk scans) and #1175 (adapter
writeback-cache clean write-through invalidation hang). These are write-path
performance/correctness issues that do not change the FUSE namespace semantics
(lookup, readdir, synthetic entry handling, read-only enforcement) that inform
the Alternative B design.

**ACL infrastructure.** Issue #442 and PR #682 (POSIX ACL inheritance
boundaries) are closed/merged. The `tidefs-permission` and `tidefs-posix-acl`
crates provide mode-bit permission checking, POSIX ACL evaluation, xattr
namespace validation, and a unified access-decision API keyed by
`MountIdentity`. This settles the "ACL evaluation against frozen ACLs" concern:
the permission engine already evaluates ACLs against caller credentials (uid,
gid, groups) and a mount identity token; snapshot entries would supply their
frozen ACL xattrs through the same evaluation path.

**Operator export baseline (#764-#766).** All three operator-export follow-up
issues are closed:

- #764 (snapshot-export-cli): `tidefsctl snapshot export` and `extract`
  commands, 2026-06-21
- #765 (snapshot-export-session): `SnapshotExportSession` loads a snapshot
  committed root into a `VfsLocalFileSystem`, exposes `root_inode_id` and
  `generation`, and manages FUSE session teardown, 2026-06-23
- #766 (snapshot-export-hold): export-session hold lifecycle, 2026-06-23

The export session implementation demonstrates that snapshot committed-root
loading, root InodeId extraction, generation tracking, and read-only session
plumbing are working. This is the stable baseline against which transparent
browsing is re-evaluated.

**Current snapshot codebase.** The following implementation surfaces are
relevant to the Alternative B design:

- `crates/tidefs-local-filesystem/src/snapshot.rs` — `SnapshotRecord`,
  `SnapshotDescriptor`, committed-root summaries, hold lifecycle, lifecycle
  pin/unpin.
- `crates/tidefs-local-filesystem/src/export.rs` — `SnapshotExportSession`,
  `SnapshotExportSummary`, `root_inode_id`, committed-root loading.
- `crates/tidefs-dir-index/src/lib.rs` — `DirIndex`, `DirEntry`, `DirCookie`,
  synthetic `.` and `..` entries at cookies 1 and 2.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/readdir_dispatch.rs` —
  `iter_dir_entries`, synthetic entry emission, cookie-based pagination.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` —
  `dispatch_lookup`, `dispatch_readdir`, `check_not_read_only`,
  `permission_mount_identity`.
- `crates/tidefs-permission/src/lib.rs` — `InodeAttr` trait, `check_access`,
  `MountIdentity`, POSIX ACL re-exports.
- `crates/tidefs-inode-table/src/inode_table_impl.rs` — `InodeTable`,
  `create`, `lookup`, `validate_generation`, generation tracking.

## Alternatives Compared

### Alternative A: No Transparent Browsing

Unchanged from the original #699 evaluation. Snapshot content is accessible
only through the operator CLI. The `.snapshot` name has no special meaning.

**Re-evaluation note.** This alternative is no longer the recommended choice.
The inode-authority closure and FUSE namespace stabilization remove the primary
technical obstacles that made it necessary in the original decision. Choosing
it now would permanently forgo self-service file recovery without a technical
justification.

### Alternative B: Read-Only Virtual Snapshot Namespace (.snapshot)

Every directory presents a synthetic `.snapshot` entry that is not persisted
as a regular directory entry. Readdir includes `.snapshot` alongside `.` and
`..`. Lookup inside `.snapshot` returns a directory of named snapshots; each
snapshot directory contains the file tree as it existed at snapshot time.
All entries under `.snapshot` are read-only, and mutation operations return
EROFS.

This is the ZFS model, familiar to operators and users.

**Re-evaluation against stabilized implementation.**

The three blockers from the original #699 evaluation are now resolved:

1. *Inode-authority intersection.* The dataset-scoped inode authority (#664-#667)
   owns InodeId allocation and generation tracking for the dataset. Snapshot
   InodeIds can be projected from the same authority: the snapshot committed
   root already contains InodeIds allocated by the same allocator. Lookup
   inside a snapshot tree resolves the same InodeIds through the same
   `InodeTable`, but with the snapshot generation space checked by
   `validate_generation`. This avoids the "whose allocator owns snapshot
   InodeIds" question that blocked the original evaluation.

2. *FUSE namespace stress.* The resolved stress rows (generic/001, 006, 007,
   011) prove that the FUSE adapter's lookup, readdir, getattr, and forget
   paths are stable under namespace churn. The remaining #1175 writeback-cache
   issue is a write-path concern that does not affect the read-only `.snapshot`
   browsing path or the synthetic-entry mechanisms already exercised by `.`
   and `..` entries.

3. *ACL infrastructure.* The `tidefs-permission` and `tidefs-posix-acl` crates
   provide the evaluation engine. Snapshot entries carry frozen ACL xattrs from
   snapshot time; the same `check_access` function evaluates them against the
   current caller's credentials. The `MountIdentity` token binds evaluation to
   the dataset mount, and the snapshot root's generation space provides the
   generation guard needed for ESTALE on deletion.

**Design for synthetic directory entries.**

The `.snapshot` entry is a synthetic directory entry, analogous to `.` and
`..`. It is not persisted in the directory index. It is emitted by
`iter_dir_entries` at a reserved cookie value (cookie 3, after `.` at 1 and
`..` at 2). The entry carries:

- `name`: `b".snapshot"`
- `inode_id`: a well-known snapshot-root sentinel `InodeId` that the lookup
  path recognizes
- `kind`: `NodeKind::Dir`
- `generation`: the current snapshot catalog generation (so that snapshot
  creation/deletion triggers ESTALE for stale readdir cookies)

The snapshot-root sentinel InodeId must not collide with any live InodeId. The
design reserves `InodeId(1)` for this purpose (`Ino::NONE` is 0, and the
`InodeTable` starts allocation at slot 1, but slot 1 is already used by the
live root inode). Since the InodeTable allocator starts at 1 and the live root
occupies it, the sentinel can use a value outside the dataset's allocator range
such as `InodeId::SNAPSHOT_ROOT_SENTINEL = InodeId(u64::MAX)`. The lookup path
detects this sentinel and routes to the snapshot-catalog lookup.

Lookup on `.snapshot` returns a directory whose entries are the named snapshots
in the catalog. Each snapshot entry maps to a synthetic InodeId derived from
the snapshot's catalog key (e.g., `InodeId(SNAPSHOT_BASE | catalog_index)`).
Lookup on a snapshot-named entry loads the snapshot's committed root and
projects its root InodeId (from the committed-root summary) for subsequent
tree traversal.

**Design for snapshot-root InodeId/generation spaces.**

Each snapshot committed root records its root `InodeId` and the `generation`
at which the snapshot was taken. The snapshot tree's InodeIds are the same
InodeIds that exist in the live committed-root namespace, because snapshots
share the same dataset-scoped allocator. The distinction between live and
snapshot handles is carried by the generation:

- A live handle carries an InodeId and a generation from the live committed
  root's generation space.
- A snapshot handle carries the same InodeId but the generation from the
  snapshot committed root's generation space.

`validate_generation(ino, generation)` in `InodeTable` returns the inode
attributes only when the stored generation matches the handle's generation.
If an inode slot is reused (unlinked and reallocated) between snapshot time
and live time, the snapshot handle carries the old generation and fails the
generation check, correctly returning ESTALE.

The snapshot catalog's own generation is a monotonic counter that increments
on snapshot creation and deletion. Lookup handles into the snapshot-catalog
directory carry this generation; if a snapshot is deleted between readdir and
lookup, the generation mismatch returns ESTALE.

**Design for read-only enforcement.**

The FUSE adapter's `check_not_read_only()` currently returns EROFS when the
adapter's global `read_only` flag is set. For per-subtree read-only
enforcement, the adapter tracks whether an inode handle was obtained through a
snapshot root. The tracking uses a handle-flag or an inode-annotation path:

- **Option 1 (handle flag).** The FUSE file-handle table (`file_handles`) stores
  a `snapshot_subtree: bool` flag per open handle. `dispatch_write`,
  `dispatch_setattr`, and other mutation operations check this flag before
  proceeding. This keeps the read-only check at the adapter boundary without
  threading a flag through the VFS engine.

- **Option 2 (VFS engine flag).** The VFS engine's `InodeAttr` or `VfsEngine`
  trait gains an `is_read_only_subtree` method. Every mutation handler in the
  engine checks this flag before performing the operation. This centralizes
  the check but requires touching every engine mutation handler.

The recommended approach is Option 1 for the initial implementation, because
it confines the `.snapshot` awareness to the adapter layer where synthetic
entry handling already lives. Option 2 is a potential refinement if performance
or cross-engine consistency requires it.

For `dispatch_create`, `dispatch_mkdir`, `dispatch_unlink`, `dispatch_rmdir`,
`dispatch_rename`, and `dispatch_setattr`, if the parent directory or target
inode carries the snapshot-subtree flag, the operation returns EROFS before
acquiring the engine lock. `dispatch_write` and `dispatch_truncate` check the
file handle's snapshot-subtree flag.

**Design for ACL evaluation against frozen ACLs.**

Snapshot entries carry the ACL xattrs (`system.posix_acl_access`,
`system.posix_acl_default`) that were stored at snapshot time. The permission
evaluation path is:

1. The FUSE adapter obtains `InodeAttr` for the snapshot inode, including its
   frozen `uid`, `gid`, and `mode`.
2. If the inode has ACL xattrs, the adapter decodes them via
   `tidefs_posix_acl::decode_posix_acl_xattr`.
3. `tidefs_permission::check_access` evaluates the mode bits and ACL entries
   against the caller's `RequestCtx.uid`, `RequestCtx.gid`, and
   `RequestCtx.groups`.
4. The `MountIdentity` binds the evaluation to the dataset mount; the snapshot
   tree uses the same dataset ID and the current mount epoch.

**Mask narrowing and default-ACL inheritance** apply only to ACL modification
(create, mkdir, setxattr). Since the snapshot subtree is read-only, mask
narrowing and default-ACL inheritance are never triggered for snapshot entries.
This simplifies the frozen-ACL evaluation: it is purely a read-time access
check.

**Legacy ACL formats.** If a snapshot predates an ACL format change, the
`decode_posix_acl_xattr` function may fail to parse the xattr. In that case,
the adapter falls back to mode-bit-only permission checking, which is always
available from the inode's `mode` field. This is the same fallback used for
inodes without ACL xattrs.

**Design for rollback interaction.**

Rollback publishes a new live committed root but preserves the snapshot
catalog entries, including the pre-rollback snapshots. The snapshot catalog is
not affected by rollback: rollback creates a new live state, but the snapshots
that captured previous states remain in the catalog.

After rollback:
- `.snapshot` entries still list all snapshots in the catalog, including
  snapshots taken before the rollback.
- Lookup into a pre-rollback snapshot returns the tree as it existed at
  snapshot time, which is independent of the current live state.
- Open handles into a snapshot tree survive rollback because they reference
  the snapshot's committed root, not the live root. The snapshot root's
  generation is unchanged by rollback.

This is the same behavior as the operator export session: a `SnapshotExportSession`
opened before rollback continues to reference the snapshot's committed root and
is unaffected by the live-root change.

**Design for snapshot deletion races.**

When an operator deletes a snapshot while a user has an open handle into its
tree:

1. The snapshot catalog record is removed.
2. The snapshot's committed root remains pinned (via lifecycle pin) as long as
   open handles reference it. The pin is released when the last handle is
   forgotten.
3. A new lookup into a deleted snapshot returns ENOENT (the catalog entry is
   gone). A stale readdir cookie that maps to a deleted snapshot skips the
   entry.
4. An existing open handle carries the snapshot's generation. When the
   snapshot is deleted, the generation check at the next operation
   (`validate_generation`) returns ESTALE because the snapshot catalog
   generation has advanced.

The lifecycle-pin mechanism already exists in `crates/tidefs-local-
filesystem/src/snapshot.rs` (`pin_snapshot_record_root` /
`unpin_snapshot_record_root`). The export-hold implementation (#766) uses the
same mechanism to prevent snapshot deletion while an export session is active.
For `.snapshot` browsing, each open handle into a snapshot tree acquires a
temporary reference on the lifecycle pin; the pin is released on forget.

**Residual risks.**

- **#1175 writeback-cache hang.** The adapter writeback-cache clean-write
  invalidation hang is a write-path issue under extreme fsstress. It is not
  expected to affect read-only `.snapshot` browsing, but if writeback-cache
  dirty pages block read operations on the same inode that is being browsed
  through a snapshot, there may be an unexpected interaction. Recorded as an
  implementation-phase risk; the `.snapshot` implementation should include a
  focused test that browses a file through `.snapshot` while the live file is
  under writeback pressure.

- **Inode slot reuse between snapshot and live.** If a file is unlinked and its
  inode slot is reused between snapshot time and live time, a snapshot handle
  carries the old generation and correctly fails `validate_generation`. This
  relies on generation monotonicity in `InodeTable`, which is already
  validated by the inode-table tests. No additional work needed.

- **`.snapshot` entry in non-snapshot datasets.** Datasets without snapshots
  should omit the `.snapshot` entry entirely. The readdir path checks whether
  the dataset's snapshot catalog is non-empty before emitting the synthetic
  entry. An empty catalog produces no `.snapshot` entry.

### Alternative C: Operator-Only Materialization/Export

The operator-export path (#764-#766) is the current stable implementation.
`tidefsctl snapshot export` opens a read-only FUSE session at an explicit
export path; `tidefsctl snapshot extract` extracts a single file.

**Re-evaluation note.** Alternative C is the current working baseline and
remains available regardless of the Alternative B decision. The operator-export
commands continue to work and are not deprecated. Alternative B adds a
self-service path for ordinary users without removing the operator path.

## Decision

**Choose Alternative B (Read-Only Virtual Snapshot Namespace) as the next
implementation target.**

The inode-authority chain (#664-#667) is closed, FUSE namespace stress (#295)
is resolved for namespace semantics, the ACL infrastructure (#442/#682) is in
place, and the operator-export baseline (#764-#766) demonstrates that snapshot
committed-root loading and read-only session plumbing are working. The three
original blockers are resolved.

Alternative C (operator-only export) remains the current working path and is
not deprecated. Alternative B builds on the same snapshot committed-root
loading infrastructure that Alternative C uses, adding synthetic `.snapshot`
entries and lookup routing in the FUSE adapter.

### Chosen Boundary

**Lookup identity.** Snapshot content is reachable through a synthetic
`.snapshot` entry in every directory of a dataset that has snapshots. The
`.snapshot` directory contains named snapshot entries; each snapshot directory
contains the file tree as it existed at snapshot time. All entries under
`.snapshot` are read-only.

**InodeId/generation spaces.** Snapshot InodeIds are the same InodeIds
allocated by the dataset-scoped allocator. Snapshot handles carry the snapshot
committed root's generation. `validate_generation` distinguishes live handles
from snapshot handles and returns ESTALE for stale handles after slot reuse.

**Permission/ACL evaluation.** Snapshot entries carry frozen ACL xattrs from
snapshot time. `tidefs_permission::check_access` evaluates them against the
current caller's credentials. Mask narrowing and default-ACL inheritance are
not triggered (read-only subtree). Legacy ACL formats fall back to mode-bit
checking.

**Mutation refusal.** The FUSE adapter's file-handle table tracks whether a
handle was obtained through a snapshot root. Mutation operations check this
flag and return EROFS before acquiring the engine lock.

**Rollback interaction.** The snapshot catalog survives rollback. Open handles
into snapshot trees reference the snapshot's committed root and are unaffected
by the live-root change. New lookups see the preserved catalog entries.

**Snapshot deletion races.** Deleted snapshots are removed from the catalog.
Open handles carry the snapshot's generation; `validate_generation` returns
ESTALE on next use after deletion. Lifecycle pins prevent committed-root
reclamation while handles are open.

## Follow-Up Implementation Map

Each follow-up issue has a non-overlapping write set. No follow-up edits FUSE,
kernel, VFS, ACL, or snapshot runtime source until its own design gates are
satisfied.

| Issue | Slice | Primary write set | Gate |
|---|---|---|---|
| (E) snapshot-dotdir-readdir | Emit synthetic `.snapshot` entry in `iter_dir_entries` at reserved cookie 3, with the snapshot-root sentinel InodeId and catalog generation. | `apps/tidefs-posix-filesystem-adapter-daemon/src/readdir_dispatch.rs`, `crates/tidefs-types-vfs-core/src/lib.rs` (sentinel constant) | Requires this decision documented. |
| (F) snapshot-dotdir-lookup | Route lookup on the snapshot-root sentinel InodeId to snapshot-catalog enumeration. Each catalog entry maps to a synthetic InodeId. | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` (lookup dispatch), `crates/tidefs-local-filesystem/src/snapshot.rs` (catalog enumeration adapter) | Gates on (E) for sentinel InodeId. |
| (G) snapshot-tree-traversal | Lookup inside a snapshot-named directory loads the snapshot's committed root and projects its root InodeId. Subsequent lookups traverse the snapshot tree through the same engine lookup path with snapshot generation. | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` (lookup dispatch, file-handle tracking), `crates/tidefs-local-filesystem/src/export.rs` (committed-root loading reuse) | Gates on (F) for catalog-entry to snapshot mapping. |
| (H) snapshot-readonly-enforce | Add snapshot-subtree flag to file-handle table. Check flag in `dispatch_create`, `dispatch_mkdir`, `dispatch_unlink`, `dispatch_rmdir`, `dispatch_rename`, `dispatch_setattr`, `dispatch_write`, `dispatch_truncate`. | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` (mutation dispatch), `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_write.rs` | Gates on (G) for file-handle creation through snapshot path. |
| (I) snapshot-acl-evaluation | Integrate frozen ACL xattr retrieval from snapshot inodes with `tidefs_permission::check_access`. Test mask-narrowing and default-ACL suppression. Test legacy-format fallback. | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` (getattr/lookup with ACL), `apps/tidefs-posix-filesystem-adapter-daemon/tests/` (ACL-on-snapshot tests) | Gates on (G) for snapshot inode attribute retrieval. |
| (J) snapshot-deletion-race | Wire lifecycle pin acquire/release on snapshot-tree handle open/forget. Validate generation on each operation through the snapshot handle. | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_lookup_forget.rs` (forget with pin release), `crates/tidefs-local-filesystem/src/snapshot.rs` (pin API exposure) | Gates on (G) for handle tracking through snapshot tree. |
| (K) snapshot-browse-validation | Focused FUSE validation: readdir with `.snapshot`, lookup into snapshot tree, read a known file, verify EROFS on mutation, verify ESTALE after snapshot deletion, verify ACL enforcement on snapshot entries. | `apps/tidefs-posix-filesystem-adapter-daemon/tests/` (new integration test file) | Gates on (E)-(J) complete. |

### Non-Overlap

- (E) touches only readdir dispatch and the sentinel constant definition. It
  does not edit lookup, mutation, ACL, or snapshot code.
- (F) adds catalog-enumeration routing in lookup dispatch. It does not change
  readdir or tree-traversal paths.
- (G) adds snapshot committed-root loading to lookup dispatch. It reuses
  `SnapshotExportSession`'s committed-root loading path without modifying it.
- (H) adds read-only enforcement checks to mutation dispatch. It does not
  change lookup, readdir, or snapshot code.
- (I) adds ACL retrieval and testing. It does not change the permission engine
  or the mutation paths.
- (J) adds lifecycle-pin management to forget. It does not change the pin
  mechanism itself.
- (K) is a test-only slice that validates the integrated behavior.
- None of these issues overlap with active PRs for storage-intent, adapter-lib,
  or localfs sparse-chunk-scan work.

## Validation Tier

This issue is documentation/design work. Required validation:

- Source inspection against the evidence listed above.
- `git diff --check`.
- No mounted FUSE, kernel, xfstests, ACL, or runtime validation belongs to
  this design slice.

Follow-up implementation issues (E)-(J) require:

- Focused Rust validation for touched crates through the TideFS GitHub Actions
  runner (Focused Rust workflow).
- For issues (G)-(H): unit tests for snapshot-tree lookup and read-only
  enforcement.
- Issue (K) requires a QEMU Smoke or focused FUSE workflow row for integrated
  `.snapshot` browsing validation.

## Still Open After This Decision

- The follow-up implementation issues (E)-(K) remain open. The design
  decision enables them; it does not implement them.
- The #1175 writeback-cache hang is an implementation-phase risk for `.snapshot`
  browsing under concurrent writeback pressure. It is not a design gate.
- Snapshot quota policy is not addressed here.
- Distributed snapshot replication and incremental receive resume are separate
  work.
- `.snapshot` visibility control (per-dataset enable/disable, mount option to
  hide `.snapshot`) is a follow-up product decision, not designed here.

## Issue References

- Original design decision: [#699](https://github.com/tidefs/tidefs/issues/699)
- This re-evaluation: [#768](https://github.com/tidefs/tidefs/issues/768)
- Operator export follow-ups (baseline): [#764](https://github.com/tidefs/tidefs/issues/764), [#765](https://github.com/tidefs/tidefs/issues/765), [#766](https://github.com/tidefs/tidefs/issues/766)
- Inode-authority: [#664](https://github.com/tidefs/tidefs/issues/664), [#665](https://github.com/tidefs/tidefs/issues/665), [#666](https://github.com/tidefs/tidefs/issues/666), [#667](https://github.com/tidefs/tidefs/issues/667)
- FUSE namespace stress: [#295](https://github.com/tidefs/tidefs/issues/295), [#929](https://github.com/tidefs/tidefs/issues/929)
- ACL infrastructure: [#442](https://github.com/tidefs/tidefs/issues/442), [#682](https://github.com/tidefs/tidefs/issues/682)
