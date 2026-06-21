# Snapshot Namespace Browsing

Issue: #699
Date: 2026-06-21
Status: design decision for follow-up implementation mapping

This document decides whether TideFS exposes snapshot content through a
transparent browsable namespace (ZFS-style `.snapshot` directories), through an
operator-only materialization/export path, or through no browsable namespace at
all. It records the chosen boundary for lookup identity, inode generation,
permission/ACL evaluation, mutation refusal, rollback interaction, and snapshot
deletion races, and maps the decision to non-overlapping follow-up
implementation issues.

ZFS references in this document are user-expectation and prior-art inputs only.
They do not claim TideFS parity with ZFS `.snapshot` behavior or validated
snapshot browsing support.

## Evidence Reviewed

- `docs/LOCAL_SNAPSHOTS_OW108.md` — snapshot catalog, rollback, reclamation,
  lifecycle authority, operator CLI surface, and the open transparent-browsing
  item.
- `docs/INODE_NAMESPACE_AUTHORITY.md` — dataset-scoped inode authority decision
  for TFR-004, follow-up implementation map (#664–#667), and the explicit
  boundary between durable inode identity and FUSE lookup references.
- `docs/OPERATOR_UAPI_AUTHORITY.md` — `tidefsctl` command classification,
  live-owner routing, and the boundary between the code registry and release
  operator UAPI.
- `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md` — FUSE adapter as an environment
  boundary, not a filesystem-semantics authority.
- `docs/VFS_ENGINE_API_CONTRACT.md` — inode-space operations, lookup(parent,
  name) -> InodeAttr, generation tracking for ESTALE, and the contract that
  InodeId, InodeAttr, and Generation are the canonical VFS vocabulary.
- `docs/POSIX_ACL_XATTR_CODEC_DESIGN.md` and `docs/design/posix-acl-xattr-
  codec-and-evaluation-design.md` — ACL evaluation against caller credentials,
  mode-ACL synchronisation, and default-ACL inheritance.
- Open issue #295 / PR #613 — active FUSE namespace stress work.
- Closed issue #442 / merged PR #682 — POSIX ACL inheritance boundaries.
- The current snapshot operator surface in `apps/tidefsctl/src/commands/
  snapshot.rs`: create, list, destroy, send, receive, rollback, clone,
  bookmark, hold, release, holds, prune. No browse, export-to-path, or
  materialization command exists.
- The local-filesystem snapshot implementation in `crates/tidefs-local-
  filesystem/src/snapshot.rs`: clones, bookmarks, holds, and retention
  pruning; snapshot records store committed-root summaries but do not
  expose a per-snapshot root-inode for namespace traversal.
- `crates/tidefs-namespace/src/lookup.rs` — `lookup_entry(dir, parent, name)`
  and `lookup_path(dirs, symlinks, path)` operate on the live directory-index
  map; there is no snapshot-root switching or multi-root traversal.

## Alternatives Compared

### Alternative A: No Transparent Browsing

Snapshot content is accessible only through the operator CLI (`tidefsctl
snapshot`). Users of the mounted filesystem cannot see or traverse past
snapshot state. File recovery from snapshots requires operator action (list
snapshots, rollback the dataset, or receive old content into the live
namespace). The `.snapshot` name has no special meaning in any directory.

Strengths:

- No FUSE namespace changes, no synthetic directory entries, no
  cross-committed-root lookup paths.
- No permission or ACL ambiguity: every lookup reaches the live committed-root
  namespace.
- No snapshot-deletion races during browsing: browsing is not supported, so
  there is nothing to race.
- Rollback is the single authority for restoring past state, keeping the
  mutation surface simple.
- Does not interact with active inode-authority (#664), FUSE namespace stress
  (#295/#613), or ACL (#442) work.

Limits:

- No self-service file recovery for ordinary users. Recovering a deleted file
  requires an operator to rollback the entire dataset or to receive the file
  through a send/receive pipeline.
- Users familiar with ZFS `.snapshot` expectations have no equivalent.

### Alternative B: Read-Only Virtual Snapshot Namespace (.snapshot)

Every directory presents a synthetic `.snapshot` entry that is not persisted
as a regular directory entry. Readdir includes `.snapshot` alongside `.` and
`..`. Lookup inside `.snapshot` returns a directory of named snapshots; each
snapshot directory contains the file tree as it existed at snapshot time.
All entries under `.snapshot` are read-only, and mutation operations return
EROFS or EACCES.

This is the ZFS model, familiar to operators and users.

Strengths:

- Self-service file recovery: users can `cp /mnt/data/.snapshot/daily.0/
  lostfile .` without operator involvement.
- Familiar model for anyone who has used ZFS.
- The read-only namespace is a well-understood kernel/FUSE concept.

Limits:

- **Lookup identity**: snapshot entries would carry the same InodeId as the
  live file at snapshot time. After rollback or inode reuse, a live file could
  share an InodeId with a snapshot entry representing different content. The
  adapter must maintain separate generation spaces for live and snapshot
  entries, or the VFS engine must grow a dataset-root discriminator. Issue #664
  is still extracting the dataset-scoped inode authority; adding snapshot-root
  discrimination before that lands would duplicate or conflict with that work.
- **Inode generation**: InodeAttr.generation tracks inode reuse for ESTALE.
  A snapshot entry's generation is frozen at snapshot time. If the live inode
  is deleted, reused, and re-created with the same ID, a cached snapshot
  lookup handle would carry a stale generation. The adapter would need to
  track which generation space (live vs. snapshot root) an InodeId belongs to.
- **Permission/ACL evaluation**: snapshot entries carry the ACL and mode bits
  from snapshot time. Access evaluation against the current caller's
  credentials (RequestCtx.uid, gid, groups) against a frozen ACL is
  conceptually clean but interacts with #442/#682 ACL infrastructure. Mask
  narrowing, default-ACL inheritance, and supplementary-group evaluation must
  be tested for snapshot entries. If the snapshot predates an ACL format
  change, the evaluator must reject or handle legacy formats.
- **Mutation refusal**: every mutating VFS operation (create, mkdir, unlink,
  rename, write, truncate, setattr, setxattr, removexattr) must detect that
  the target inode lives under a snapshot root and return EROFS. This requires
  threading a read-only flag through the VFS engine ops or through the adapter
  dispatch path, touching every mutation handler.
- **Rollback interaction**: rollback publishes a new committed root but
  preserves the snapshot catalog. After rollback, `.snapshot` entries must
  still reflect the pre-rollback committed roots, not the new live state.
  Browse handles open before rollback must either survive (pointing at the
  preserved snapshot root) or return ESTALE.
- **Snapshot deletion races**: if an operator deletes a snapshot while a
  user has an open handle into its tree, the handle must return ESTALE on
  next use. The adapter must track which snapshot root each handle references
  and detect deletion. This is similar to the existing unlink-while-open
  session rules but applied to entire subtree roots.
- **Active PR overlap**: PR #613 (FUSE namespace stress) touches lookup,
  getattr, readdir, and forget paths. PR #682 (ACL inheritance) touches
  permission evaluation. A `.snapshot` synthetic-directory implementation
  would edit the same adapter dispatch paths and would need to coordinate
  with those PRs.

### Alternative C: Operator-Only Materialization/Export

An operator can materialize a snapshot as a read-only mount at an explicit
export path, without changing the live FUSE namespace. A new command such as
`tidefsctl snapshot export @daily.0 /mnt/recovery` opens the snapshot's
committed root through a separate read-only FUSE session or a temporary
bind-mount. The export is a distinct mount with its own root inode, generation
space, and session lifetime; it does not appear in the live namespace.

The command may also support a one-shot file extract mode: `tidefsctl
snapshot extract @daily.0 path/to/file > recovered.bin` for cases where a full
mount is unnecessary.

Strengths:

- Builds on existing infrastructure: snapshot committed-root loading,
  live-owner routing, and the `tidefsctl` operator boundary.
- No FUSE namespace changes: the live mount's lookup, readdir, and mutation
  paths are untouched.
- Clean permission boundary: the operator controls who can export; exported
  mounts are read-only and scoped to the export session.
- No synthetic directory entries, no generation-space ambiguity, no ACL
  snapshot-vs-live confusion.
- Snapshot deletion is a session-lifetime problem: the export session can hold
  a temporary deletion-prevention hold or fail closed when the snapshot
  is deleted.
- Does not overlap with active #295/#613 (FUSE namespace stress) or #442/#682
  (ACL) work.

Limits:

- Not self-service for ordinary users; file recovery requires operator
  involvement or a separate automation layer.
- A full mount for recovery may be heavyweight for a single-file extraction.
  The design should include a lightweight extract path.
- Does not satisfy ZFS `.snapshot` expectations, but records the gap and the
  prerequisites for future transparent browsing.

## Decision

**Choose Alternative C (Operator-Only Materialization/Export) as the
immediate boundary.**

TideFS does not implement transparent snapshot browsing (Alternative B) at this
time and does not close the door on it permanently. The operator-only export
path is the right intermediate step because:

1. It avoids intersecting active inode-authority, FUSE namespace stress, and
   ACL implementation slices.
2. It reuses existing snapshot-catalog, committed-root, and `tidefsctl`
   operator-boundary infrastructure.
3. It provides a working recovery path (operator exports a snapshot, then
   copies needed files) without changing the mounted namespace contract.
4. It records clear prerequisite gates for future transparent browsing so a
   follow-up design issue can re-evaluate when those gates are closed.

### Chosen Boundary

**Lookup identity.** Snapshot content is reachable only through a separate
export session. The exported root carries its own committed-root identity; the
live namespace's root inode and the export session's root inode are distinct
and do not share an InodeId space. No transparent `.snapshot` synthetic
entries are created in the live namespace. This boundary is compatible with
the inode authority decision in `docs/INODE_NAMESPACE_AUTHORITY.md` because
each mounted dataset (live or export) owns its own inode authority.

**Inode generation.** Each export session is a separate mount with its own
generation space. The live mount's generation counters are unaffected. An
export session's generation counters are frozen at the snapshot's committed
state. If the export session is long-lived, it uses the same ESTALE rules as a
live mount: generation mismatch on a cached handle returns ESTALE. The session
is read-only, so generation cannot advance during the export.

**Permission and ACL evaluation.** The export session evaluates permissions
against the snapshot-time ACL and mode bits using the caller's credentials
(RequestCtx). Since the export session is operator-initiated, the operator can
choose whether the export mount applies caller credentials (for delegated
recovery) or root-equivalent credentials (for operator recovery). This choice
is an export-command parameter, not a per-lookup decision.

**Mutation refusal.** The export session is mounted read-only. All mutating
operations return EROFS. This is enforced at the session level rather than
through per-inode flags, keeping the VFS engine mutation paths unchanged.

**Rollback interaction.** An export session pins the snapshot's committed root
for the session lifetime through a temporary hold mechanism (similar to the
existing `tidefsctl snapshot hold` infrastructure). If the operator attempts to
destroy a snapshot that has an active export, the destroy fails until the hold
is released. Rollback publishes a new live committed root; active export
sessions are unaffected because they reference a different (snapshot) root.

**Snapshot deletion races.** Active export sessions prevent snapshot deletion
through the hold mechanism. When no export references a snapshot, deletion
proceeds normally. If a future implementation adds long-lived export sessions
that survive operator disconnect, the export daemon must release the hold on
session teardown.

## Follow-Up Implementation Map

Each follow-up issue has a non-overlapping write set and does not edit FUSE,
kernel, VFS, ACL, or snapshot runtime source until the relevant design gates
are closed.

| Issue | Slice | Primary write set | Gate |
|---|---|---|---|
| (A) snapshot-export-cli | Add `tidefsctl snapshot export` and `tidefsctl snapshot extract` commands plus operator-authz entries. | `apps/tidefsctl/src/commands/snapshot.rs`, `apps/tidefsctl/src/commands/authz.rs`, `apps/tidefsctl/src/commands/classification.rs` | Requires this decision documented. |
| (B) snapshot-export-session | Implement a read-only export session that loads a snapshot committed root, opens it through a FUSE session, and tears down cleanly. | `crates/tidefs-local-filesystem/src/` (new `export.rs` or similar), `apps/tidefs-posix-filesystem-adapter-daemon/src/` (read-only session plumbing) | Gate on #664 (inode authority extraction) merged. The export session must consume the dataset-scoped inode authority, not the legacy FileSystemState allocator. |
| (C) snapshot-export-hold | Add export-session hold lifecycle: acquire hold on export start, release on teardown, refuse destroy while held. | `crates/tidefs-local-filesystem/src/snapshot.rs`, `crates/tidefs-local-filesystem/src/` (hold integration) | Gate on snapshot hold infrastructure already implemented; this slice only adds the export-driven hold path. |
| (D) snapshot-browse-transparent-design | Re-evaluate Alternative B after #664, #665, #666, #667, and the FUSE namespace stress work (#295) are closed. This design issue must decide whether to proceed with `.snapshot` directories or stay with operator-only export. | `docs/SNAPSHOT_NAMESPACE_BROWSING.md` (update) | All listed prerequisite issues closed. |

### Non-Overlap

- Issue (A) touches only `tidefsctl` command registration and authz. It does
  not edit local-filesystem, namespace, FUSE adapter, or ACL code.
- Issue (B) adds a read-only session path that consumes the new inode authority
  from #664. It does not change the live-namespace lookup, mutation, or ACL
  paths.
- Issue (C) extends existing snapshot hold infrastructure. It does not change
  the hold semantics for non-export use cases.
- Issue (D) is a future design gate, not an implementation slice.
- None of these issues overlap with PR #613 (FUSE namespace stress), PR #682
  (ACL boundaries), or the #664–#667 inode-authority chain.

## Validation Tier

This issue is documentation/design work. Required validation:

- Source inspection against the evidence listed above.
- `git diff --check`.
- No mounted FUSE, kernel, xfstests, ACL, or runtime validation belongs to
  this design slice.

Follow-up implementation issues (A)–(C) require:

- Focused Rust validation for touched crates through the TideFS GitHub Actions
  runner (Focused Rust workflow).
- For issue (B): a smoke test that exports a snapshot, reads a known file
  through the export session, verifies read-only enforcement, and tears down
  cleanly. This may use a QEMU smoke or focused FUSE workflow row; the
  specific dispatch is scoped by that issue.

Issue (D) is a design issue with the same validation tier as this one.

## Still Open After This Decision

- Transparent snapshot browsing (Alternative B) remains explicitly deferred,
  not rejected. The gate is the closure of the inode-authority chain and FUSE
  namespace stress work.
- Snapshot quota policy is not addressed here (tracked elsewhere in the
  snapshot lifecycle authority).
- Distributed snapshot replication and incremental receive resume are separate
  work tracked by send/receive issues.
- Export sessions that survive operator disconnect (daemon-mode export) are
  not designed here; the initial export command is synchronous and
  session-scoped.

## Issue References

- Design decision issue: [#699](https://github.com/tidefs/tidefs/issues/699)
- Follow-up (A) snapshot-export-cli: [#764](https://github.com/tidefs/tidefs/issues/764)
- Follow-up (B) snapshot-export-session: [#765](https://github.com/tidefs/tidefs/issues/765)
- Follow-up (C) snapshot-export-hold: [#766](https://github.com/tidefs/tidefs/issues/766)
- Follow-up (D) snapshot-browse-transparent-design: [#768](https://github.com/tidefs/tidefs/issues/768)
