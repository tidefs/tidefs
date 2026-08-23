# Mounted Transform Authority Raw-Store Inventory

Maturity: current guardrail for TFR-006 and GitHub issue #218.
Issue #637 records the scrub/repair identity boundary.
Issue #2582 records one bounded local two-copy live-owner repair path.
Issue #2584 records one bounded exact two-copy missing-member rebuild path.
Mounted device-level compression remains blocked.
Mounted device-level encryption remains blocked.

The mounted `LocalFileSystem` must not claim device-level compression or
encryption until every production raw-store path below is removed, routed
through one transform-aware authority, or explicitly proven raw-only.

## Ordering Terms

These terms are the guardrail vocabulary for compression, encryption, dedup,
checksums, and reclaim:

- plaintext identity: logical file or extent bytes before compression and
  encryption; dedup fingerprints are over this identity unless a later issue
  changes the contract.
- compression frame: bytes emitted by the mounted content encoder or by a
  lower object-store compression wrapper.
- encryption frame: nonce, ciphertext, and authentication tag emitted by the
  lower object-store encryption wrapper.
- checksum: integrity digest over the exact bytes owned by the checked layer.
- raw media bytes: bytes stored in the primary `LocalObjectStore` data device
  when the mounted filesystem bypasses `PoolStore`.
- reclaim identity: object key or locator identity used for lifetime and
  cleanup decisions; it is not the same as plaintext identity.

For a fully transformed write, the intended ordering remains:

```text
plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes
```

Reclaim identity must be derived from the committed placement/object authority,
not from whichever transform frame happened to be convenient to scan.

## Status Values

- transform-aware: the path names and applies a mounted transform authority for
  the bytes it handles.
- metadata/raw-only: the path only handles media keys, counters, roots, sealed
  key records, or other storage metadata whose contract is explicitly raw.
- validation-only raw staging: a private crash-recovery validation authority
  constructs raw commit-boundary fixtures without exposing a mounted
  production write/read path or enabling mounted device transforms.
- blocked: the path still handles mounted filesystem data or recovery state
  through a raw handle and blocks device-level mounted transforms.
- later receipt/placement issue: the path belongs to placement receipt,
  locator, rebuild, or default media work and is deliberately outside this
  slice.

## Raw-Store Surfaces

| Path | Inventory note |
|---|---|
| `crates/tidefs-local-object-store/src/pool/mod.rs` | Pool accessors, pool-level accounting, and transform-pipeline `PoolStore` escape hatches. This is the lower object-store authority, not a mounted-filesystem proof. |
| `crates/tidefs-local-filesystem/src/lib.rs` | Mounted production, recovery, reclaim, capacity, scoped diagnostics, corruption fixtures, and raw drain/test assertions classified below. |
| `crates/tidefs-local-filesystem/src/content.rs` | Mounted content and scrub authorities route mounted bytes through the Pool; explicit non-pool transaction helpers retain raw-store access. |
| `crates/tidefs-local-filesystem/src/intent_log.rs` | `IntentLogRawStateAuthority` owns direct raw-store metadata and replay-payload access, classified separately below. |
| `crates/tidefs-local-filesystem/src/crash_recovery.rs` | `CrashMatrixStagingAuthority` stages validation content through Pool receipt authority and uses raw access only for transaction/root control at deliberate crash boundaries. |
| `crates/tidefs-local-filesystem/src/journal_cleaner.rs` | Production metadata key scanning plus focused tests. |
| `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` | Mounted VFS/admin key-management paths plus focused tests. |

New production raw-store access must be classified here by behavior and
consumer; exact source-match counts are not an authority or completion gate.

## Production Classification

| Mounted path group | Source surface | Status | Classification |
|---|---|---|---|
| Open, committed-root selection, retired fixed-superblock refusal, intent-log load, and commit-group recovery | `MountedOpenRecoveryAuthority` in `src/lib.rs` | transform-aware in raw-only mode | The mounted open path rejects configured device transforms before pool creation, selects current committed roots through Pool validation, and fails closed on the retired pre-release fixed-superblock marker without publishing a replacement root. Intent-log load, commit-group recovery, and quota/space/orphan metadata remain behind one raw-only/no-device-transforms authority. The unbound raw transaction-group replay path is removed so it cannot replace Pool-validated recovered state. Raw primary-store trust in this group is scoped to the current fail-closed transform mode and remains a non-claim for mounted device-level compression/encryption while any other production blocked row remains. |
| Mounted root selection, reclaim protection, root retention, and selected committed-root summary | canonical dataset-root load and retention plus `audit_recovery_pool`, `plan_root_retention_pool`, and their callers in `src/recovery.rs` and `src/lib.rs` | canonical Pool metadata/content authority; raw non-canonical root-slot history | Canonical mounted publication writes transaction superblocks, manifests, inode records, directories, extent maps, and snapshot records through Pool metadata placement receipts before publishing the typed filesystem root. Canonical reopen and retention require those receipts, validate the authenticated manifest, and load surviving replica bytes through Pool authority. A two-member replicated regular-file Pool and the real FUSE carrier reopen read-only with member zero physically absent: the surviving nonzero-index label preserves the durable member count, and each canonical object still requires a current receipt, replay seal, digest, and exact present replica. Ordinary writable incomplete-topology import remains refused. The explicit `DeviceRebuildOnly` owner below may arm only one exact Pool lifecycle mutation while its namespace and ordinary recovery stay read-only. Non-canonical root-slot diagnostics and deliberate crash-boundary fixtures still use raw-primary history and do not own mounted reopen. General writable degraded operation, transform-aware device rebuild, root-slot diagnostic convergence, and exact signed-root vote identity remain separate work; this row does not claim mounted device-level transforms while any production `blocked` row remains. |
| Mounted recovery probe, recovery audit, and online verifier | `MountedCommittedRootRepairAuthority`, `recovery_probe_pool`, `audit_recovery_pool`, and `verify_online_pool` | raw-primary metadata plus strict Pool content authority | Mounted diagnostics scan root slots and transaction metadata in the raw recovery store, then load and validate every committed content object through current Pool placement receipts. Missing, stale, malformed, or receiptless content cannot make a root healthy. |
| Public/raw internal store exposure and scoped diagnostics | `MountedRawStoreDiagnostics`, `dataset_space_usage`, `verify_file_checksum_tree_for_diagnostic`, `committed_root_pointer`, `suspect_log_stats`, and test-only mounted scrub/transaction/content-receipt projections in `src/lib.rs` | metadata/diagnostic scoped | `store_ref` and `object_store` have been removed. Dataset usage, checksum-tree validation, committed-root-pointer access, suspect-log stats, transaction-superblock assertions, VFS receipt assertions, and mounted scrub tests now consume typed projections that do not return `&LocalObjectStore`. Current content-object presence is no longer answered by this raw diagnostic authority; it requires a strict current Pool receipt in the mounted content row below. The POSIX committed-root diagnostic caller now routes through `committed_root_pointer`. No public `&LocalObjectStore` bypass remains on the mounted filesystem for this row. |
| Reclaim, orphan cleanup, snapshot protection, and mounted allocation accounting | `record_reclaim_delta`, persisted mounted reclaim queue load/store, `prepare_orphan_reclaim_entries`, `collect_snapshot_protected_content_keys`, `drain_local_reclaim_queue_into_store`, `reclaim_unprotected_objects`, `commit_space_delta`, Pool allocation-entry helpers, and journal cleaner key scans | strict Pool authority for mounted content protection, durable logical reclaim obligations, logical reclaim preflight, startup usage, and capacity admission; metadata-only orphan reconciliation; physical receipt-bound drain disabled; metadata/raw-only for journal-cleaner accounting scans | Reclaim identity is an object-key/locator lifetime concern. The integrity-checked mounted queue is read and written only through current Pool receipts, retained across compaction, ordered before committed-root publication, and durably records handoff state before completed originals are removed. Layout derivation, recursive retained snapshot/clone protection, dedup redirect/canonical preflight, replacement proof, startup usage, and current/replaced/retained-root capacity entries use exact current Pool receipts; every non-hole allocation entry is backed by a validated current content read. Mount-time orphan recovery queues exact keys from a still-present inode and strict layout, while metadata cleanup has no object-store handle. Uncertain authority fails closed and keeps original local reclaim work pending. Successful logical handoff leaves lower receipt-bound physical entries queued. The mounted path does not compare filesystem-root generations with Pool receipt generations or treat a global receipt-allocation frontier as root stability; physical reuse waits for exact obsolete-placement tokens durably bound to an authenticated filesystem root and cleared against retained roots and snapshots. Journal-cleaner metadata scans retain their raw-only classification and do not authorize mounted device transforms. |
| Scrub and repair | `run_scrub_repair_scheduling`, `dispatch_repair_from_bridge`, `compare_mounted_replicated_repair`, `SharedPoolDatasetOwner::live_pool_repair`, and `Pool::repair_current_replicated_target` | receipt/root-authorized for one bounded local current two-copy live-owner target repair; blocked for scheduled, distributed, rebuild, and device-transform repair paths | Local scrub consumes the mounted content scrub/read authority for inline content bodies and content chunks, reports findings against `ScrubBlockId` plus plaintext-length identity, and records checksum-layer, receipt, and raw/media diagnostic evidence. The closed #652 slice makes the legacy scheduling/dispatch bridge require matching mounted scrub identity, checksum-layer evidence, verified receipt evidence, and a fresh current data version before its truncate, mark-corrupt, or reconstruct strategy can mutate content. That bridge still mutates through `LocalObjectStore` rather than the current Pool/root authority, so its scheduled repair path remains blocked even with the evidence gate. Separately, the #2582 live-owner path authorizes only one corrupt content-chunk target plus one clean source under an exact current writable two-copy Pool receipt. It authenticates current and retained roots, refreshes the full comparison immediately before writeback, publishes a higher replacement receipt, reconciles embedded receipt generations into authenticated filesystem and snapshot roots, and requires a clean re-scrub. It does not enable the legacy scheduler as the `pool repair` carrier, select distributed members, repair dual corruption, rebuild a failed device, or authorize mounted device transforms. Compression frames, encryption frames, checksum bytes, and raw media bytes remain lower-layer evidence or diagnostics; they must not be the product repair identity for mounted content. The row remains blocked while any remaining repair path or other production row bypasses the mounted transform authority. |
| Recovery-only missing-member rebuild | `RecoveryPolicy::DeviceRebuildOnly`, `Pool::rebuild_missing_member`, `Pool::finish_missing_member_rebuild`, and `PoolDatasetOwner::complete_mounted_missing_member_rebuild` | receipt/root-authorized for one exact local two-copy missing member; namespace read-only; blocked for mounted device transforms and every broader rebuild | One explicit survivor-only owner authenticates current and retained roots before arming a scoped raw Pool mutation. It admits only an exact `Replicated { copies: 2 }` topology, the full durable missing GUID, and a distinct blank same-backing candidate. Versioned checksummed labels persist identity and progress before candidate initialization. Each current receipt must have one clean authenticated survivor payload; successor receipts target survivor plus replacement, and the mounted owner copy-on-writes every affected current or retained manifest and publishes authenticated roots before redundant successor topology labels. Crash/reopen resumes from label authority before candidate publication, during root reconciliation, and after successor topology publication without a host marker file. FUSE mutation remains `EROFS`; replay, repair writeback, timestamps, writeback/background work, reclaim, compression/encryption tuning, general writable degradation, erasure/cluster rebuild, and transform-frame repair remain refused. This row does not unblock mounted device-level compression or encryption. |
| File content reads, writes, sparse operations, reflink, copy-file-range, truncate, punch-hole, zero-range, read overlay, content inspection | `create_file_like`, `replace_content`, `rewrite_content_*`, `read_content*`, `reflink_*`, `truncate_file`, `free_extent_range`, `punch_hole`, `zero_range`, `inspect_filesystem_content_objects`, `current_content_object_exists_for_diagnostic`, and related helpers in `src/lib.rs` plus inode-based open-unlinked/`O_TMPFILE` operations and whole-file copy fast paths in `vfs_engine_impl.rs` | transform-aware for mounted content compression, plaintext dedup, and receipt-producing content writes; blocked for remaining device-level compression/encryption raw paths | The main content-write population paths route durable chunk writes through `PoolStoreMut::put_with_receipt`. Mounted full/range reads, layout reads, sparse seek layout reads, reflink and rewrite layout planning, extent/content inspection, current-content presence diagnostics, reclaim layout reads, open-unlinked and `O_TMPFILE` handle operations, and whole-file copy fast paths use strict current Pool receipt authority. Sparse overlay, patch, punch-hole, and reflink mutation helpers preserve and compare each chunk receipt generation before rewriting; dedup canonical reads require a strict current receipt and retain their content-addressed key check. Same-key historical self-heal remains available only to explicit non-pool raw-store consumers and cannot authorize mounted mutation. The row remains blocked for device-level compression/encryption until intent-log, send/receive, inode/directory fallback, journal-cleaner scans, and other residual raw paths are routed or proven raw-only. |
| Snapshot export/import and send/receive | `rollback_to_snapshot`, `export_changed_records`, `export_incremental_changed_records` | blocked | Changed-record export/import carries an explicit stored-frame/no-device-transform contract for transform-disabled streams. The VFSSEND1 codec now binds that contract to a typed metadata tuple covering plaintext identity, transform-frame identity, checksum layer, stored-frame authority, and refusal state; decode rejects mismatched tuples, and receive validation rejects the transform-required typed refusal before staging or publish. The row remains blocked until persisted key-handle/lease and per-frame metadata can replay mounted device transforms through the ordered contract. |
| Intent-log head and entry records | `IntentLogRawStateAuthority` in `src/intent_log.rs` behind intent-log load, flush, and clear paths | metadata/raw-only | Head and entry records describe log ordering, replay ranges, payload digests, and inode metadata. They do not contain mounted file payload bytes. |
| Intent-log data payload objects | `IntentLogRawStateAuthority` behind `write_data_payload`, `read_data_payload`, sync-write production, and Pool replay | blocked | Per-entry payload objects contain mounted file plaintext keyed by log entry id. Replay validates their recorded length and digest before publishing receipt-backed content, but their raw staging path remains mounted content rather than metadata-only storage. |
| Namespace-create and metadata-setattr intent production | `MountedMetadataIntentRawStateAuthority` behind `namespace_create_intent` and `metadata_setattr_intent` in `src/lib.rs` | metadata/raw-only through mounted authority | Replayable namespace-create intents contain directory-entry and inode metadata, while metadata-setattr intents carry the post-setattr inode record and logical size; neither carries mounted file payload bytes. The mounted authority records `MetadataRawOnlyNoDeviceTransforms`, routes append and sync through the intent-log raw-state authority, and preserves accepted, flushed, pressure-refused, and typed error behavior. This classification does not change fsync, commit, rollback, or replay ordering and remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Fsync, commit, rollback, and sync-write residuals | `sync_write_intent`, `flush_intent_log_if_needed`, `fsync_*`, `sync_*`, `fdatasync_inode`, `do_commit`, `rollback_mutation_delta` | blocked | Caller-visible durability barriers, sync-write intent production, commit records, and rollback deltas still need source-backed classification or routing before they can be removed from the blocked mounted-transform residual set. |
| Directory/inode fallback reads | `inode` | blocked | This path still recovers inode records directly from raw store keys. |
| Live dataset key administration | `live_dataset_seal_key`, `live_dataset_rotate_key` in `vfs_engine_impl.rs` plus `tidefs_encryption::secret_handle` lifecycle assessment | metadata/raw-only | These paths store sealed key records rather than file payloads. Issue #1823 adds source-owned key access states for active, rotating, revoked, quarantined, retired, missing, stale, and recovery-after-crash evidence, and it refuses cryptographic-erase claim review unless transform metadata, stored-frame reachability, media/remanence limits, and fully encrypted payload classification are present. The row remains metadata/raw-only and non-enabling for mounted device-level encryption while production blocked rows remain. |
| Directory/inode fallback reads | `inode_record_only`, `ensure_inode_loaded_for_write` in `src/lib.rs` plus `committed_inode_record` | metadata/raw-only through transform-aware authority | `inode_record_only`, `ensure_inode_loaded_for_write`, and `committed_inode_record` now route inode and directory fallback reads through `MountedMetadataFallbackAuthority` which records the `RawMetadataOnlyNoDeviceTransforms` mode. Focused invariant coverage preserves missing inode/directory `CorruptState` errors, mismatched inode-id rejection, and typed inode/directory decode errors at this fallback boundary. Device-level compression/encryption claims remain blocked while any production `blocked` row remains. The `inode()` path still reads inode objects through the raw store and needs a follow-up slice. |
| Crash-matrix boundary staging | `CrashMatrixStagingAuthority` in `src/crash_recovery.rs` | validation-only Pool content plus raw control staging | This private helper writes crash-matrix content through receipt-producing Pool authority and uses the raw primary store only for transaction records, root slots, and deliberate control-record corruption at selected crash boundaries. It is not a mounted product write path and does not authorize mounted device-level compression or encryption claims while production `blocked` rows remain. |
| Other placement, locator, rebuild, and default pool-media writes | #17, #18, #91 surfaces outside the exact #2584 lifecycle row above | later receipt/placement issue | The bounded missing-member path above does not authorize any other placement, locator, rebuild, or default-media write path. |

## Scrub/Repair Identity Boundary

Issue #637 reviewed this inventory, the deleted scrub/repair/resilver
historical lineage,
`crates/tidefs-local-filesystem/src/scrub.rs`,
`crates/tidefs-local-filesystem/src/repair.rs`, closed stale-generation repair
issue #591, and the closed placement-receipt umbrella #18.

The current local scrub source routes inline and chunk block reads through
`read_mounted_content_scrub_block`, records mounted plaintext identity plus
checksum-layer evidence, and keeps missing, stale, unavailable, and unbound
receipt evidence visible in the scrub report. The closed #652 work makes the
legacy repair bridge carry that mounted evidence into scheduling and requires
matching subject, checksum layer, verified receipt generation, and current
data version immediately before its existing truncate, mark-corrupt, or
reconstruct dispatch can mutate content. That path still receives a raw
`LocalObjectStore`; the evidence gate does not provide Pool-owned receipt-target
comparison, target-only replacement, authenticated-root reconciliation, or the
live-owner carrier added by #2582. It therefore remains a blocked scheduled
repair path.

The #2582 path is separate from the legacy scheduling/dispatch bridge.
`tidefsctl pool repair` routes to the selected mounted local owner, compares
both targets named by one exact current `Replicated { copies: 2 }` receipt,
and authorizes writeback only for `SingleReplicaCorruption` with one clean
source and one corrupt target. It then refreshes that authority, performs the
target-only replacement, publishes a higher receipt generation, reconciles
every affected current or retained-root manifest, publishes the authenticated
roots, and requires a clean re-scrub. Missing or changed authority and every
other comparison remain non-writeback outcomes.

The mounted product boundary is:

```text
ScrubBlockId + current data_version + plaintext content identity
  + checksum-layer evidence
  + placement/receipt evidence status
```

The bounded #2582 live-owner writeback additionally requires the exact current
two-copy receipt generation, policy, and target identities plus target-by-target
read and checksum outcomes. Receipt target order comes only from that receipt;
it is not distributed membership evidence and cannot be reconstructed from
current topology or raw media layout.

Plaintext content identity is the logical mounted file/extent bytes after the
content reader has applied every mounted content and device transform needed to
interpret the committed object. Checksum-layer evidence remains attached to the
exact encoded or transformed bytes owned by that layer; it is evidence for the
finding, not the repair identity. Raw media bytes, compression frames, and
encryption frames may be lower-device diagnostics, but they cannot authorize a
mounted content repair.

The identity work and bounded carrier remain separate:

| Issue | Slice | Current boundary |
|---|---|---|
| #650 | Add the transform-aware mounted content scrub/read authority. | Closed; the mounted content reader remains the source of scrub plaintext and checksum-layer evidence. |
| #651 | Route local scrub through that authority and keep findings non-writeback. | Closed; scrub emits the mounted identity and receipt evidence consumed by later gates. |
| #652 | Require transform-aware scrub evidence before legacy repair dispatch can write or mark mounted content. | Closed; the scheduler/dispatch bridge now fails closed on missing, mismatched, stale, or unverified mounted evidence. Its raw-store mutation authority remains blocked, and it is not the #2582 live-owner carrier. |
| #2582 | Repair one corrupt target of a current local two-copy receipt through the mounted owner. | Bounded to target-by-target receipt comparison, target-only replacement, receipt/root reconciliation, and clean re-scrub; it does not admit scheduled, distributed, rebuild, dual-corruption, or device-transform repair. |
| #2584 | Rebuild one exact absent member of a local two-copy Pool through a recovery-only mounted owner. | Bounded to label-authoritative missing GUID/index identity, one clean survivor, successor receipt/root reconciliation, redundant topology publication, crash resume, and a namespace that remains read-only; it does not admit general degraded writes, transform-aware, erasure-coded, clustered, or hot-spare rebuild. |

Closed issues #591 and #18 are historical stale-generation and receipt-authority
lineage, not future gates and not support claims. The scrub/repair identity work
in #637, #650, #651, and #652 plus the bounded #2582 carrier remains
non-enabling for mounted device-level transforms while any production
`blocked` row remains in this inventory. In that state:

- mounted device-level compression remains blocked.
- mounted device-level encryption remains blocked.

## Current Mounted Transform Claim

Mounted local-filesystem device-level compression and encryption are blocked
behind this inventory. The lower object-store stack may still expose transform
wrappers, but a mounted filesystem open with device compression or encryption
must fail closed while any production `blocked` row remains.

Issue #1823 narrows key-lifecycle behavior without changing this claim: revoked
or retired key state, by itself, is not cryptographic erase, secure erase,
sanitization, decommissioning readiness, or remanence proof. Plaintext,
compressed-only, unencrypted, partially transformed, raw-store-bypassed, or
previously exposed media remain explicit non-claim/refusal inputs until the
transform authority and media/remanence evidence prove otherwise.
