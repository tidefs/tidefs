# Content Object Version Authority

Maturity: design authority for the local content-object version boundary under
TFR-005. Produced under GitHub issue #746.

This document separates the content-identity use of `data_version` from the
storage-liveness and reclaim-ordering evidence that reclaim paths must use.
It is a documentation slice only: it does not change reclaim dispatch, rebake
policy, storage format, object keys, or runtime behavior.

## Upstream Blocker

`docs/TIMESTAMP_GENERATION_AUTHORITY.md` section 9 item 5 recorded that
`data_version` had two meanings in the current implementation:

- content identity for content object key generation;
- a storage-ordering hint around reclaim liveness and orphan cleanup.

This document resolves the authority naming part of that blocker. Follow-up
implementation issues own any runtime separation.

## Content Identity

`data_version` is a content-identity token owned by
`tidefs-local-filesystem`.

For a file-like inode, the durable content identity is:

```text
(inode_id, data_version)
```

For a chunked content object, the chunk selector extends that identity:

```text
(inode_id, data_version, chunk_index)
```

The token answers "which content version does this inode record reference?"
It does not answer "is an older object unreachable?" or "is it safe to free
this physical placement now?"

Current content-identity evidence:

- `crates/tidefs-local-filesystem/src/types.rs:2144` defines
  `InodeRecord`, and `:2156` stores `data_version`.
- `crates/tidefs-local-filesystem/src/encoding.rs:744` encodes inode
  records, with `:758` writing `inode.data_version`.
- `crates/tidefs-local-filesystem/src/encoding.rs:811` decodes the persisted
  inode `data_version`.
- `crates/tidefs-local-filesystem/src/encoding.rs:1004` encodes inline
  content, with `:1009`-`:1011` writing `(inode_id, data_version, len)`.
- `crates/tidefs-local-filesystem/src/encoding.rs:1080` and `:1089` encode
  content-manifest and chunk `data_version` fields; `:1122`, `:1145`, and
  `:1163` decode them.
- `crates/tidefs-local-filesystem/src/content.rs:255` validates inline
  content identity; `:267` rejects content whose `data_version` differs from
  the inode record.
- `crates/tidefs-local-filesystem/src/content.rs:285` validates chunked
  manifest identity; `:295` rejects manifests whose `data_version` differs
  from the inode record.
- `crates/tidefs-local-filesystem/src/content.rs:406` decodes chunk payloads;
  `:407`-`:414` checks non-dedup chunks against the manifest
  `data_version`.

## Key Generation

Content object keys are content-identity projections. They are not reclaim
liveness proofs.

Current key evidence:

- `crates/tidefs-local-filesystem/src/object_keys.rs:39` marks the TFR-005
  debt that `data_version` is storage key material.
- `crates/tidefs-local-filesystem/src/object_keys.rs:40`-`:44` derives the
  versioned content object key from `(inode_id, data_version)`.
- `crates/tidefs-local-filesystem/src/object_keys.rs:47`-`:55` derives the
  versioned chunk key from `(inode_id, data_version, chunk_index)`.
- `crates/tidefs-local-filesystem/src/content.rs:795`-`:804` writes sparse
  content manifests under `content_object_key_for_version(...)`.
- `crates/tidefs-local-filesystem/src/content.rs:1471`-`:1499` rewrites
  inline punch-hole content under the new `data_version` key.
- `crates/tidefs-local-filesystem/src/content.rs:1545`-`:1563` writes
  modified chunk content under the new `data_version` key and records the
  chunk placement receipt generation.
- `crates/tidefs-local-filesystem/src/allocation.rs:35`-`:50` looks up the
  current content layout through the inode's `(inode_id, data_version)` key.
- `crates/tidefs-local-filesystem/src/allocation.rs:81`-`:87` projects
  chunk allocation entries through `(inode_id, chunk_ref.data_version,
  chunk_index)`.

## Reclaim Liveness Guard

Reclaim must consume a separate guard authority. The named boundary for this
slice is the **reclaim liveness guard**:

```text
death_commit_group
+ stable_committed_txg
+ replacement/base placement receipt epoch and generation
+ orphan replay watermark when orphan recovery participates
```

Those fields answer "has the operation that made this object dead become
stable, and is the replacement/base placement evidence durable enough to
retire the old physical placement?" They are not aliases for `data_version`.

Current guard evidence:

- `crates/tidefs-types-reclaim-queue-core/src/lib.rs:881`-`:909` defines
  `DeadObjectEntry`, including `death_commit_group`, `eligible`,
  `enqueued_at_txg`, and `replacement_receipt`.
- `crates/tidefs-types-reclaim-queue-core/src/lib.rs:942`-`:950` defines the
  txg eligibility rule: `death_commit_group < stable_committed_txg`.
- `crates/tidefs-types-reclaim-queue-core/src/lib.rs:952`-`:988` adds
  replacement receipt evidence and stable receipt-generation checks.
- `crates/tidefs-reclaim-queue-core/src/dead_object_queue.rs:305`-`:329`
  drains only entries passing the txg/eligibility rule.
- `crates/tidefs-reclaim-queue-core/src/dead_object_queue.rs:355`-`:383`
  drains the receipt-bound path only after the caller supplies a stable
  committed receipt generation.
- `crates/tidefs-reclaim-queue-core/src/dead_object_queue.rs:417`-`:498`
  gates reclaim on `OrphanReplayWatermark` when orphan recovery participates.
- `crates/tidefs-types-orphan-index-core/src/lib.rs:233`-`:241` defines
  `OrphanReplayWatermark` as the durable cursor reclaim compares before
  releasing orphan-associated storage; `:272`-`:278` defines `covers(...)`.
- `crates/tidefs-local-object-store/src/pool/mod.rs:2174`-`:2193` enqueues
  replaced physical objects with `death_txg` derived from the replacement
  receipt generation, then attaches the replacement receipt.
- `crates/tidefs-local-object-store/src/pool/mod.rs:2557`-`:2577` keeps the
  compatibility txg drain, and `:2580`-`:2623` exposes the explicit
  `stable_committed_txg` plus `stable_committed_generation` drain.
- `crates/tidefs-reclaim/src/lib.rs:1230`-`:1276` uses
  `dequeue_receipt_bound_batch_with_stable_generation(...)` for the
  release-facing dead-object physical reclaim path.

## Current Coupling Sites To Preserve Until Follow-Up Work

The current implementation still discovers or orders some reclaim work through
keys that embed `data_version`. This issue names the boundary but does not
change those paths.

- `crates/tidefs-local-filesystem/src/lib.rs:70`-`:85` documents the current
  production reclaim chain: local B+tree queue, `tick_background_services`,
  `LocalObjectStore::delete()`, and receipt-bound dead-object drain.
- `crates/tidefs-local-filesystem/src/lib.rs:3760`-`:3767` exposes the local
  B+tree reclaim queue depth; that queue is the frontend fed by file
  mutations.
- `crates/tidefs-local-filesystem/src/lib.rs:3819`-`:3838` drains local queue
  entries by `ObjectKey` and pre-computes receipt durability for those keys.
  If the key is a content key, its name includes `data_version`, but the
  liveness decision is the receipt durability gate, not the key's version
  number.
- `crates/tidefs-local-filesystem/src/lib.rs:3885`-`:3893` deletes only keys
  whose placement receipt is durable.
- `crates/tidefs-local-filesystem/src/lib.rs:3916`-`:3971` builds rewrite
  trim plans from old/new content keys and either queues trimmable keys or
  defers `(old_key, new_key)` pairs.
- `crates/tidefs-local-filesystem/src/lib.rs:3974`-`:4004` promotes deferred
  rewrite trims only after `replacement_key_receipt_is_durable(...)` reports
  the replacement key stable.
- `crates/tidefs-local-filesystem/src/orphan_cleanup.rs:183`-`:194` deletes
  legacy and versioned orphan content object keys by scanning `data_version`
  values. This is key discovery for today's format, not an authority that
  lower versions are always reclaimable.
- `crates/tidefs-local-filesystem/src/orphan_cleanup.rs:220`-`:228` scans
  orphan chunk keys by `(data_version, chunk_index)` when cleaning dedup
  redirects, again as key discovery rather than a liveness proof.
- `crates/tidefs-local-filesystem/src/background_reclaim.rs:36`-`:44` and
  `:90`-`:123` still describe deterministic B-tree-order reclaim queue
  processing for the model/test surface. The production liveness decision must
  remain with the receipt/commit/orphan guard named above.

## Boundary Rules

- A new content write may stamp `data_version` from the current generation or
  commit tick, but once persisted the token is content identity, not the
  reclaim clock.
- Reclaim must not treat `old.data_version < current.data_version` as a
  sufficient safety proof.
- Reclaim must not infer orphan replay completion from the highest or lowest
  content `data_version` it can find.
- Reclaim may use content keys that contain `data_version` to find the object
  to delete, but the delete must be authorized by the reclaim liveness guard.
- Orphan cleanup may scan versioned key names to discover stale keys in the
  current format, but that scan does not define ordering, reachability, or
  storage-format compatibility.
- Future implementation issues #675 and #676 own policy and runtime changes
  for receipt-driven read/scrub/repair/rebuild consumers and rebake/reclaim
  trims. This document only names the boundary those slices must preserve.

## Non-Claims

This document does not:

- change code, on-disk format, object key names, or runtime behavior;
- change reclaim dispatch, rebake policy, deadlist policy, or orphan cleanup;
- close TFR-005;
- close issues #675 or #676.
