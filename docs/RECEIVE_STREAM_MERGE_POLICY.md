# Receive-stream merge policy: non-empty target and resume semantics

This document records the receive-stream merge policy for the TideFS local
filesystem changed-record receive path.  It decides the permitted target,
conflict, and resume states, names the authority for each, and maps follow-up
implementation issues.  It is the design artifact for issue #700.

**Status**: decided / not yet implemented.

**Last updated**: 2026-06-20, initial policy recording from issue #700
investigation.

**Authority inputs**:

- `docs/SEND_RECEIVE_OW109.md` — current send/receive contract and still-open
  items.
- `docs/LOCAL_SNAPSHOTS_OW108.md` — snapshot lifecycle authority and still-open
  items.
- `docs/REVIEW_TODO_REGISTER.md` TFR-010 and TFR-017 — snapshot/send-receive
  coherence and transport/cluster authority gaps.
- `crates/tidefs-local-filesystem/src/send_receive.rs` — current receive
  implementation (staging, checkpoint, base-root protection, omitted-content
  validation).
- `crates/tidefs-local-filesystem/src/encoding.rs` — changed-record stream
  versions.
- Issue #566 / PR #623 — active base-root contract integration work.

---

## 1. Receive target classification

Every receive target falls into one of three classes at stream-open time:

### 1.1 Empty target

The target root path does not exist or contains no TideFS pool state.  The
receiver creates a fresh pool from the stream.

- **Permitted**: full streams (v1, v3) only.
- **Incremental streams**: refused — an incremental stream requires an
  existing base root; an empty target has none.
- **Implementation status**: already enforced by
  `receive_changed_records_into_empty_root`.

### 1.2 Compatible non-empty target

The target root path exists, contains a live TideFS pool, and **the pool's
recovery audit contains a committed root whose identity matches the stream's
`from_root`**.  The matching root must also be **protected by a data-retaining
snapshot or clone record** with consistent catalog and lifecycle-pin authority.

- **Permitted**: incremental streams (v2, v4) only.
- **Full streams**: refused — a full stream would overwrite the existing
  pool; a fresh empty-target receive is the correct path for that intent.
- **Implementation status**: already enforced by
  `receive_incremental_changed_records` and `verify_incremental_base_root_authority`.

### 1.3 Conflicting non-empty target

The target root path exists and contains a live TideFS pool, but **the pool's
recovery audit does not contain a committed root matching the stream's
`from_root`**, or the matching root exists but is not protected by a
data-retaining snapshot/clone.

#### Policy decision: fail-closed, operator-forced

A conflicting non-empty target **refuses the receive** with a classified
error.  TideFS does not attempt automatic conflict resolution, content
merging, or divergent-history stitching inside the receive path.

The operator must resolve the conflict through one of these explicit actions
before re-attempting the receive:

1. **Delete and re-receive**: destroy the target pool (or receive into a
   fresh path) and run a full receive, then replay incremental streams on top.
2. **Create the missing base snapshot**: if the target pool has the base-root
   content but no snapshot protecting it, create a snapshot that pins that
   root, then retry the incremental receive.
3. **Rollback to a shared ancestor**: roll back the target to a snapshot that
   matches the stream's `from_root`, then retry.

The error returned names:

- the stream's `from_root` identity (transaction id, generation, superblock
  checksum);
- whether the base root was found in the recovery audit;
- whether it was found but not protected by a data-retaining snapshot/clone;
- the suggested operator actions.

**Rationale**: automatic merge inside receive would require TideFS to decide
which inodes, directories, extent maps, and snapshot catalog entries to keep
when two pools have diverged.  That is a general dataset merge problem, not a
stream-transport problem.  Solving it correctly requires per-object conflict
classification, operator-policy input (keep-local, keep-remote, merge-latest,
manual), and probably a separate merge planner that can be tested
independently of the receive transport.  Until that merge planner exists and
is validated, the receive path must fail closed rather than silently discard
or corrupt data.

**Follow-up issue**: create a `receive-merge-planner` design issue that
defines the merge model, conflict taxonomy, operator policy surface, and
validation tier.  That issue is not a prerequisite for the fail-closed policy
recorded here; it is a future enhancement.

---

## 2. Resume checkpoint authority

### 2.1 Current staging-based resume

The current implementation writes a `ReceiveCheckpoint` to the staging store
during receive.  The checkpoint records:

- the export identity (a blake3 digest of spec, stream version, and sorted
  root identities);
- the total expected record count;
- the set of object keys already persisted.

On retry, if a staging directory exists with a matching checkpoint, the
receiver skips already-persisted keys.  If the checkpoint is missing or
mismatched, the staging directory is removed and the receive restarts from
scratch.

**This resume mechanism is intentionally scoped to a single receive attempt**
(one process invocation or one crash-restart cycle while the staging directory
survives).  It is not cross-host, cross-restart-with-cleanup, or
distributed-replication resume.

### 2.2 What durable state proves an import can resume

For the staging-based checkpoint to be valid on retry, the staging directory
and its checkpoint must survive.  The staging directory is placed under the
target parent directory as `.${name}.receive-staging-${pid}-${nanos}`.  It is
removed on successful completion, and also removed on non-retryable errors
(currently all errors except the successful path — the error path also
removes it).

**Policy decision**: staging removal on error is too aggressive.  The
checkpoint is designed for resume, but the error path destroys it.  The
implementation should preserve the staging directory and checkpoint on errors
that are plausibly retryable (I/O error, crash, timeout, stream corruption
before all records are written) and only remove it on errors that make the
checkpoint unrecoverable (export identity mismatch, stream decode failure
before any keys were persisted, target pool corruption that invalidates the
base root).

**Follow-up issue**: `receive-checkpoint-preserve-on-retryable-error`.

### 2.3 Cross-restart resume

When the staging directory is cleaned up (e.g. `/tmp` rotation, host reboot
with tmpfs staging, operator cleanup), the checkpoint is lost and the receive
must restart from scratch.

**Policy decision**: cross-restart resume with durable checkpoint is deferred.
The staging store is already a durable object store; the checkpoint is
persisted as a named key within it.  Making it survive `/tmp` cleanup requires
placing the staging directory on the same filesystem as the target pool (the
current placement under the target parent already does this when the target
parent is on durable storage).  The remaining gap is not removing the staging
directory after a crash — which is already the case (the process dies before
cleanup).  So the current design already supports crash-restart resume as long
as the staging directory is on durable storage and the error-path cleanup is
fixed per §2.2.

**No new issue required** — this is covered by the §2.2 follow-up.

---

## 3. Base-root protection interaction

The current `verify_incremental_base_root_authority` requires that the base
root be protected by a data-retaining snapshot or clone record.  This policy
**upholds and strengthens** that requirement:

- A **snapshot** that retains data (kind is `Snapshot` or `Clone`, not
  `Bookmark`) is sufficient.
- A **clone** that retains data is also sufficient; clone promotion preserves
  the root identity and the lifecycle pin.
- A **bookmark** is explicitly **not** sufficient — bookmarks are
  non-retaining replication anchors.  If a bookmark is the only record
  pointing at the base root, the incremental receive must fail because
  reclaim could free the base-root objects before or during the receive.
- If the base root is found in the recovery audit but **no data-retaining
  snapshot or clone protects it**, the receive fails with a classified error
  naming the missing protection and suggesting a snapshot create.
- If the base root is found and protected, but the **catalog entry or
  lifecycle pin is inconsistent** (detected by
  `ensure_snapshot_authority_consistent` and
  `ensure_snapshot_record_authority`), the receive fails before any objects
  are persisted.

This is already the implemented behavior.  No policy change.

---

## 4. Omitted content and clone/bookmark anchors

### 4.1 Omitted content validation

Incremental streams omit unchanged content records (VersionedContent,
VersionedContentChunk) from the stream.  The receiver must already have them
from the baseline state.  The current implementation validates that every
content object named by incoming manifests — including omitted unchanged
content — is present and checksum-valid in the target store before publishing
the received current root.

**Policy decision**: upheld.  No change.  The omitted-content validation is a
correctness requirement, not an optimization.

### 4.2 Clone and bookmark anchors in send/receive

Send exports include snapshot roots referenced by the current snapshot
catalog.  Clone catalog entries carry the clone flag until promotion;
promotion repairs the catalog entry to a regular snapshot entry while
preserving the traversal-root pin reference.  Bookmark entries are excluded
from send/recovery protected-root expansion.

**Policy decision**: the receive path must preserve clone flags and bookmark
exclusion on import.  The current `rewrite_snapshot_roots_for_import`
rewrites snapshot root summaries to reference destination-signed roots but
does not inspect or mutate the snapshot kind.  The snapshot catalog entries
are transported as `TransactionSnapshotCatalogEntry` changed records, which
preserve the full `SnapshotRecord` including kind.  No change required.

---

## 5. Distributed replication non-claims

The current send/receive path is **local authority only**.  It does not
claim:

- network transport authorization;
- multi-host stream coordination;
- distributed conflict resolution;
- cross-pool deadlist/reclaim accounting;
- placement-receipt-gated receive.

**Policy decision**: the local receive path must not silently accept streams
that carry distributed claims it cannot validate.  The stream format currently
has no distributed-claim fields, so no rejection rule is needed today.  When
distributed fields are added (e.g. pool uuid, sender epoch, membership
generation), the receiver must validate them against local pool identity and
refuse streams from unknown or conflicting pools unless the operator
explicitly authorizes cross-pool receive.

**Follow-up issue**: `receive-cross-pool-authorization` — define the
operator-controlled cross-pool receive authorization surface and the stream
fields that gate it.

---

## 6. Implementation sequencing

The following is the ordered implementation sequence, respecting the active
PR #623 (base-root contracts, draft, not yet merged):

1. **This policy** (issue #700, artifact: this document).  No source edits.
   No dependency on #623 merge.

2. **Follow-up issues** (created from this document):
   - `receive-checkpoint-preserve-on-retryable-error` — fix staging cleanup
     on retryable errors (§2.2).
   - `receive-conflicting-target-error` — implement the classified error for
     conflicting non-empty targets (§1.3).
   - `receive-merge-planner` — design issue for the general dataset merge
     model (§1.3 rationale).
   - `receive-cross-pool-authorization` — design issue for cross-pool receive
     gating (§5).

3. **Implementation issues** — write sets defined in each follow-up issue.
   None of these edit send/receive encoding or the active PR #623 write set
   (`receive_persistence.rs`, `persistence_integration.rs`,
   `send_receive.rs`, `tests.rs`).  They are safe to start after this policy
   is recorded and can land independently of #623 merge (the conflicting-target
   error adds a new error variant; the checkpoint-preserve change touches the
   error-cleanup path that #623 does not edit).

---

## 7. Validation tier

Documentation/design validation:

- `git diff --check` on this file.
- Source inspection to confirm no conflict with active PR #623 write set.
- Issue body cross-reference: each follow-up issue names this policy as its
  design authority.

Focused Rust send/receive checks and runtime import validation belong to the
follow-up implementation issues after this policy is recorded.
