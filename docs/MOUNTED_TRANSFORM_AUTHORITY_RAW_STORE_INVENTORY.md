# Mounted Transform Authority Raw-Store Inventory

Maturity: current guardrail for TFR-006 and GitHub issue #218.
LocalFS has no foreground scrub or corruption-repair scheduler.
Mounted device-level compression remains blocked.
Mounted device-level encryption remains blocked.

The mounted `LocalFileSystem` must not claim device-level compression or
encryption until every production raw-store path below is removed, routed
through one transform-aware authority, or explicitly proven raw-only. The
inventory is checked by:

```text
cargo run -p tidefs-xtask -- check-mounted-transform-authority
```

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

## Raw-Store Inventory

Current `raw_primary_store()` and `raw_primary_store_mut()` matches:

| Path | Inventory note |
|---|---|
| `crates/tidefs-local-object-store/src/pool/mod.rs` | Pool accessors, pool-level accounting, and transform-pipeline `PoolStore` escape hatches. This is the lower object-store authority, not a mounted-filesystem proof. |
| `crates/tidefs-local-filesystem/src/lib.rs` | Mounted production, recovery, reclaim, capacity, scoped raw-store diagnostics, fail-closed recovery fixtures, and raw drain/test assertions classified below. |
| `crates/tidefs-local-filesystem/src/content.rs` | `MountedContentReadAuthority` and focused receipt tests route mounted and verifier reads through current Pool authority. |
| `crates/tidefs-local-filesystem/src/intent_log.rs` | `IntentLogRawStateAuthority` owns the direct raw-store payload write for durability/replay metadata. |
| `crates/tidefs-local-filesystem/src/crash_recovery.rs` | `CrashMatrixRawStagingAuthority` owns validation-only raw commit-boundary staging. |
| `crates/tidefs-local-filesystem/src/journal_cleaner.rs` | Production key scans and focused assertions. |
| `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` | Live mounted VFS/admin key-management paths plus encryption-feature tests. |

New production raw-store access must have a classification below. Exact source
occurrence counts are not a correctness gate.

## Production Classification

| Mounted path group | Source surface | Status | Classification |
|---|---|---|---|
| Open, committed-root selection, v0.390 import, intent-log load, commit-group recovery, allocator scan | `MountedOpenRecoveryAuthority` in `src/lib.rs` | transform-aware in raw-only mode | The mounted open path rejects configured device transforms before pool creation. Committed roots, v0.390 import, intent-log state, commit-group recovery, txg replay, and allocator scans use the explicit raw recovery store; quota, space-counter, and orphan-index objects retain strict Pool receipt authority because their production writers use `Pool::put`. Missing auxiliary objects initialize empty, while corrupt, unreadable, or conflicting receipt authority causes mount/open to fail rather than resetting state. Raw primary-store trust in this group is scoped to the current fail-closed transform mode and remains a non-claim for mounted device-level compression/encryption while any other production blocked row remains. |
| Recovery probe, audit, online verifier, root retention, and selected committed-root summary | `MountedCommittedRootRepairAuthority` behind `probe_recovery*`, `recovery_audit`, `online_verifier_report`, `root_retention_plan`, `safe_root_retention_plan`, `reclaim_unprotected_objects`, and `selected_current_root_summary` in `src/lib.rs` | metadata/raw-only through transform-aware authority | These operator recovery/probe paths inspect committed-root slots, transaction manifests, protected root-slot locations, and storage metadata through `MetadataRawOnlyNoDeviceTransforms`. The authority names `plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes`, deliberately handles no mounted file plaintext, compression frame, encryption frame, or content checksum state, and remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Public/raw internal store exposure and scoped diagnostics | `MountedRawStoreDiagnostics`, `dataset_space_usage`, `verify_file_checksum_tree_for_diagnostic`, `current_content_object_exists_for_diagnostic`, `committed_root_pointer`, `suspect_log_stats`, and test-only transaction/content-receipt projections in `src/lib.rs` | metadata/diagnostic scoped | `store_ref` and `object_store` have been removed. Dataset usage, checksum-tree validation, current content-object presence checks, committed-root-pointer access, suspect-log stats, transaction-superblock assertions, and VFS receipt assertions consume typed projections that do not return `&LocalObjectStore`. The POSIX committed-root diagnostic caller routes through `committed_root_pointer`. No public `&LocalObjectStore` bypass remains on the mounted filesystem for this row. |
| Reclaim and snapshot-protection key scans | `record_reclaim_delta`, `collect_snapshot_protected_content_keys`, `drain_local_reclaim_queue_into_store`, `reclaim_unprotected_objects`, `commit_space_delta`, and journal cleaner key scans | metadata/raw-only for keys; transform-aware for mounted content layout reads; blocked for remaining raw allocation/recovery scans | Reclaim identity is an object-key/locator lifetime concern. `record_reclaim_delta` now reads mounted content layouts through `MountedContentReadAuthority` before deriving chunk reclaim indexes, while snapshot protection, allocation accounting, journal-cleaner key scans, and recovery scans keep their raw key/metadata classification and do not authorize mounted device transforms. |
| File content reads, writes, sparse operations, reflink, copy-file-range, truncate, punch-hole, zero-range, read overlay, content inspection | `create_file_like`, `replace_content`, `rewrite_content_*`, `read_content*`, `reflink_*`, `truncate_file`, `free_extent_range`, `punch_hole`, `zero_range`, `inspect_filesystem_content_objects`, and related helpers in `src/lib.rs` plus anonymous tmpfile reads and whole-file copy fast paths in `vfs_engine_impl.rs` | transform-aware for mounted content compression, plaintext dedup, and receipt-producing content writes; blocked for remaining device-level compression/encryption raw paths | The main content-write population paths route durable chunk writes through `PoolStoreMut::put_with_receipt`. Mounted full/range reads, cached layout reads, sparse seek layout reads, reflink and rewrite layout planning, extent/content inspection, reclaim layout reads, anonymous tmpfile reads, and whole-file copy fast paths go through `MountedContentReadAuthority`. Sparse overlay, patch, punch-hole, and reflink mutation helpers read existing layouts, chunks, and dedup canonical objects through `ContentWriteStore::get`, so mounted `PoolStoreMut` callers retain the pool transform route while transaction-serialization callers remain explicit raw-store users. Historical-version self-heal remains a raw fallback. The row remains blocked for device-level compression/encryption until commit/recovery, intent-log, send/receive, allocation accounting, journal-cleaner scans, and other residual raw paths are routed or proven raw-only. |
| Snapshot export/import and send/receive | `rollback_to_snapshot`, `export_changed_records`, `export_incremental_changed_records` | blocked | Changed-record export/import carries an explicit stored-frame/no-device-transform contract for transform-disabled streams. The VFSSEND1 codec now binds that contract to a typed metadata tuple covering plaintext identity, transform-frame identity, checksum layer, stored-frame authority, and refusal state; decode rejects mismatched tuples, and receive validation rejects the transform-required typed refusal before staging or publish. The row remains blocked until persisted key-handle/lease and per-frame metadata can replay mounted device transforms through the ordered contract. |
| Intent-log raw records and payloads | `IntentLogRawStateAuthority` in `src/intent_log.rs` behind intent-log load, flush, replay, and clear paths | metadata/raw-only | Intent-log head records, entry records, and per-entry replay payload objects are durability/replay metadata keyed by log entry id. The authority handles no mounted file plaintext, compression frame, encryption frame, or content checksum state. Missing log state initializes empty; corrupt or unreadable state propagates and refuses mount. This remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Namespace-create and metadata-setattr intent production | `MountedMetadataIntentRawStateAuthority` behind `namespace_create_intent` and `metadata_setattr_intent` in `src/lib.rs` | metadata/raw-only through mounted authority | Replayable namespace-create intents contain directory-entry and inode metadata, while metadata-setattr intents carry the post-setattr inode record and logical size; neither carries mounted file payload bytes. The mounted authority records `MetadataRawOnlyNoDeviceTransforms`, routes append and sync through the intent-log raw-state authority, and preserves accepted, flushed, pressure-refused, and typed error behavior. This classification does not change fsync, commit, rollback, or replay ordering and remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Fsync, commit, rollback, and sync-write residuals | `sync_write_intent`, `flush_intent_log_if_needed`, `fsync_*`, `sync_*`, `fdatasync_inode`, `do_commit`, `rollback_mutation_delta` | blocked | Caller-visible durability barriers, sync-write intent production, commit records, and rollback deltas still need source-backed classification or routing before they can be removed from the blocked mounted-transform residual set. |
| Live dataset key administration | `live_dataset_seal_key`, `live_dataset_rotate_key` in `vfs_engine_impl.rs` plus `tidefs_encryption::secret_handle` lifecycle assessment | metadata/raw-only | These paths store sealed key records rather than file payloads. Issue #1823 adds source-owned key access states for active, rotating, revoked, quarantined, retired, missing, stale, and recovery-after-crash evidence, and it refuses cryptographic-erase claim review unless transform metadata, stored-frame reachability, media/remanence limits, and fully encrypted payload classification are present. The row remains metadata/raw-only and non-enabling for mounted device-level encryption while production blocked rows remain. |
| Directory/inode fallback reads | `inode`, `inode_record_only`, `ensure_inode_loaded_for_write`, and `committed_inode_record` in `src/lib.rs` | metadata/raw-only through transform-aware authority | All mounted inode and directory fallback reads route through `MountedMetadataFallbackAuthority`, which records the `RawMetadataOnlyNoDeviceTransforms` mode. Focused invariant coverage preserves missing inode/directory `CorruptState` errors, mismatched inode-id rejection, and typed inode/directory decode errors at this fallback boundary. Device-level compression/encryption claims remain blocked while any production `blocked` row remains. |
| Crash-matrix boundary staging | `CrashMatrixRawStagingAuthority` in `src/crash_recovery.rs` | validation-only raw staging | This private helper stages raw commit-boundary objects for crash-matrix validation only. It is not a mounted product write path and does not authorize mounted device-level compression or encryption claims while production `blocked` rows remain. |
| Placement, locator, rebuild, and default pool-media writes | #17, #18, #91 surfaces | later receipt/placement issue | This issue deliberately does not edit those write paths. |

## Integrity Verification Boundary

`verify_online_pool` reads current and snapshot content through
`MountedContentReadAuthority`, so missing, stale, corrupt, conflicting, or
unreadable receipt authority prevents a clean operator-visible verifier result.
LocalFS has no scrub-to-repair schedule, raw-store reconstruction, or automatic
corruption writeback path. Any future repair path must publish and re-read Pool
receipt authority rather than revive a raw-store scheduler. This verifier
boundary does not enable mounted device-level transforms while any production
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
