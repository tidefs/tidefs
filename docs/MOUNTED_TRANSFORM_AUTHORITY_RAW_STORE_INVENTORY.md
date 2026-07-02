# Mounted Transform Authority Raw-Store Inventory

Maturity: current guardrail for TFR-006 and GitHub issue #218.
Issue #637 records the scrub/repair identity boundary.
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

## Checked Raw-Store Counts

Current `raw_primary_store()` and `raw_primary_store_mut()` matches:

| Path | Current matches | Inventory note |
|---|---:|---|
| `crates/tidefs-local-object-store/src/pool/mod.rs` | 9 | Pool accessors, pool-level accounting, and transform-pipeline `PoolStore` escape hatches. This is the lower object-store authority, not a mounted-filesystem proof. |
| `crates/tidefs-local-filesystem/src/lib.rs` | 67 | Mounted production, recovery, reclaim, capacity, a scoped raw-store diagnostic projection, a pool-backed content-inspection diagnostic fallback, fail-closed recovery corruption fixtures, and raw drain/test assertions that remain blocked or raw-only as classified below. |
| `crates/tidefs-local-filesystem/src/intent_log.rs` | 1 | `IntentLogRawStateAuthority` owns the direct raw-store payload write for durability/replay metadata. |
| `crates/tidefs-local-filesystem/src/crash_recovery.rs` | 1 | `CrashMatrixRawStagingAuthority` owns validation-only raw commit-boundary staging. |
| `crates/tidefs-local-filesystem/src/journal_cleaner.rs` | 7 | One production key-scan path plus six unit-test assertions. |
| `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` | 6 | Live mounted VFS/admin paths plus encryption-feature tests. |

The check intentionally fails when these counts change. Any new raw-store
access must update this inventory with a status classification before the
branch can pass the guard.

## Production Classification

| Mounted path group | Source surface | Status | Classification |
|---|---|---|---|
| Open, committed-root selection, v0.390 import, intent-log load, commit-group recovery, allocator scan | `MountedOpenRecoveryAuthority` in `src/lib.rs` | transform-aware in raw-only mode | The mounted open path now rejects configured device transforms before pool creation, then routes committed-root selection, v0.390 import, intent-log load, commit-group recovery, txg replay, quota/space/orphan metadata, and allocator scan through one raw-only/no-device-transforms authority. Raw primary-store trust in this group is scoped to the current fail-closed transform mode and remains a non-claim for mounted device-level compression/encryption while any other production blocked row remains. |
| Recovery probe, audit, online verifier, root retention, and selected committed-root summary | `MountedCommittedRootRepairAuthority` behind `probe_recovery*`, `recovery_audit`, `online_verifier_report`, `root_retention_plan`, `safe_root_retention_plan`, `reclaim_unprotected_objects`, and `selected_current_root_summary` in `src/lib.rs` | metadata/raw-only through transform-aware authority | These operator repair/probe paths inspect committed-root slots, transaction manifests, protected root-slot locations, and storage metadata through `MetadataRawOnlyNoDeviceTransforms`. The authority names `plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes`, deliberately handles no mounted file plaintext, compression frame, encryption frame, or content checksum state, and remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Public/raw internal store exposure and scoped diagnostics | `MountedRawStoreDiagnostics`, `dataset_space_usage`, `verify_file_checksum_tree_for_diagnostic`, `committed_root_pointer`, `suspect_log_stats`, and test-only mounted scrub/transaction/content-receipt projections in `src/lib.rs` | metadata/diagnostic scoped | `store_ref` and `object_store` have been removed. Dataset usage, checksum-tree validation, committed-root-pointer access, suspect-log stats, transaction-superblock assertions, VFS receipt assertions, and mounted scrub tests now consume typed projections that do not return `&LocalObjectStore`. The POSIX committed-root diagnostic caller now routes through `committed_root_pointer`. No public `&LocalObjectStore` bypass remains on the mounted filesystem for this row. |
| Reclaim and snapshot-protection key scans | `record_reclaim_delta`, `collect_snapshot_protected_content_keys`, `drain_local_reclaim_queue_into_store`, `reclaim_unprotected_objects`, `commit_space_delta`, and journal cleaner key scans | metadata/raw-only for keys; blocked for content-layout reads | Reclaim identity is an object-key/locator lifetime concern, but several scans still read mounted content layouts through the raw store. |
| Scrub and repair | `schedule_scrub_repairs`, `scrub_repair_pass`, `dispatch_scheduled_repairs` | blocked; scrub read evidence routed | Local scrub now consumes the mounted content scrub/read authority for inline content bodies and content chunks, reports findings against `ScrubBlockId` plus plaintext-length identity, and records checksum-layer, receipt, and raw/media diagnostic evidence. Repair dispatch still consumes scrub findings through the existing non-writeback scheduling boundary and has not been changed to require transform-aware evidence before writeback. Compression frames, encryption frames, checksum bytes, and raw media bytes remain lower-layer evidence or diagnostics; they must not be the product repair identity for mounted content. The row remains blocked until #652 and the other follow-up implementation issues below are complete and no production blocked row remains. |
| File content reads, writes, sparse operations, reflink, copy-file-range, truncate, punch-hole, zero-range, read overlay, content inspection | `create_file_like`, `replace_content`, `rewrite_content_*`, `read_content*`, `reflink_*`, `truncate_file`, `free_extent_range`, `punch_hole`, `zero_range`, `inspect_filesystem_content_objects`, and related helpers in `src/lib.rs` plus anonymous tmpfile reads and whole-file copy fast paths in `vfs_engine_impl.rs` | transform-aware for mounted content compression, plaintext dedup, and receipt-producing content writes; blocked for remaining device-level compression/encryption reads and raw paths | The main content-write population paths now route durable chunk writes through `PoolStoreMut::put_with_receipt`, but mounted content still has raw read, layout, reclaim, sparse, commit, recovery, whole-file copy, and content-inspection raw paths before device-level transforms can become a product claim. |
| Snapshot export/import and send/receive | `rollback_to_snapshot`, `export_changed_records`, `export_incremental_changed_records` | blocked | Changed-record export/import now carries an explicit stored-frame/no-device-transform contract for transform-disabled streams and receive validation rejects transform-required streams before publish. The row remains blocked until typed transform metadata can replay mounted device transform frames through the ordered contract. |
| Intent-log raw records and payloads | `IntentLogRawStateAuthority` in `src/intent_log.rs` behind intent-log load, flush, replay, and clear paths | metadata/raw-only | Intent-log head records, entry records, and per-entry replay payload objects are durability/replay metadata keyed by log entry id. The authority handles no mounted file plaintext, compression frame, encryption frame, or content checksum state, preserves existing missing/corrupt record behavior, and remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Fsync, commit, rollback, and namespace mutation residuals | `sync_write_intent`, `namespace_create_intent`, `metadata_setattr_intent`, `flush_intent_log_if_needed`, `fsync_*`, `sync_*`, `fdatasync_inode`, `do_commit`, `rollback_mutation_delta` | blocked | Caller-visible durability barriers, namespace-create and metadata-setattr intent production, commit records, and rollback deltas still need source-backed classification or routing before they can be removed from the blocked mounted-transform residual set. |
| Directory/inode fallback reads | `inode` | blocked | This path still recovers inode records directly from raw store keys. |
| Live dataset key administration | `live_dataset_seal_key`, `live_dataset_rotate_key` in `vfs_engine_impl.rs` plus `tidefs_encryption::secret_handle` lifecycle assessment | metadata/raw-only | These paths store sealed key records rather than file payloads. Issue #1823 adds source-owned key access states for active, rotating, revoked, quarantined, retired, missing, stale, and recovery-after-crash evidence, and it refuses cryptographic-erase claim review unless transform metadata, stored-frame reachability, media/remanence limits, and fully encrypted payload classification are present. The row remains metadata/raw-only and non-enabling for mounted device-level encryption while production blocked rows remain. |
| Directory/inode fallback reads | `inode_record_only`, `ensure_inode_loaded_for_write` in `src/lib.rs` plus `committed_inode_record` | metadata/raw-only through transform-aware authority | `inode_record_only`, `ensure_inode_loaded_for_write`, and `committed_inode_record` now route inode and directory fallback reads through `MountedMetadataFallbackAuthority` which records the `RawMetadataOnlyNoDeviceTransforms` mode. Focused invariant coverage preserves missing inode/directory `CorruptState` errors, mismatched inode-id rejection, and typed inode/directory decode errors at this fallback boundary. Device-level compression/encryption claims remain blocked while any production `blocked` row remains. The `inode()` path still reads inode objects through the raw store and needs a follow-up slice. |
| Crash-matrix boundary staging | `CrashMatrixRawStagingAuthority` in `src/crash_recovery.rs` | validation-only raw staging | This private helper stages raw commit-boundary objects for crash-matrix validation only. It is not a mounted product write path and does not authorize mounted device-level compression or encryption claims while production `blocked` rows remain. |
| Placement, locator, rebuild, and default pool-media writes | #17, #18, #91 surfaces | later receipt/placement issue | This issue deliberately does not edit those write paths. |

## Scrub/Repair Identity Boundary

Issue #637 reviewed this inventory, the deleted scrub/repair/resilver
historical lineage,
`crates/tidefs-local-filesystem/src/scrub.rs`,
`crates/tidefs-local-filesystem/src/repair.rs`, active stale-generation repair
issue #591, and placement/rebuild issue #18.

The current local scrub source routes inline and chunk block reads through
`read_mounted_content_scrub_block`, records mounted plaintext identity plus
checksum-layer evidence, and keeps missing, stale, unavailable, and unbound
receipt evidence visible in the scrub report. The current repair source still
reconstructs repair jobs from scrub findings, then dispatches
truncate/mark-corrupt/reconstruct behavior against the existing content keys.
The bridge already records missing or stale receipt evidence as blocked
scheduling state, but repair dispatch has not yet consumed the mounted scrub
evidence as a writeback precondition.

The mounted product boundary is:

```text
ScrubBlockId + current data_version + plaintext content identity
  + checksum-layer evidence
  + placement/receipt evidence status
```

Plaintext content identity is the logical mounted file/extent bytes after the
content reader has applied every mounted content and device transform needed to
interpret the committed object. Checksum-layer evidence remains attached to the
exact encoded or transformed bytes owned by that layer; it is evidence for the
finding, not the repair identity. Raw media bytes, compression frames, and
encryption frames may be lower-device diagnostics, but they cannot authorize a
mounted content repair.

Implementation is split so the write sets do not overlap:

| Issue | Slice | Expected write set |
|---|---|---|
| #650 | Add the transform-aware mounted content scrub/read authority. | `crates/tidefs-local-filesystem/src/content.rs`, a local helper/type module if needed, and focused local-filesystem tests. |
| #651 | Route local scrub through that authority and keep findings non-writeback. | `crates/tidefs-local-filesystem/src/scrub.rs` and focused scrub tests. |
| #652 | Require transform-aware scrub evidence before repair dispatch can write or mark mounted content. | `crates/tidefs-local-filesystem/src/scrub_repair_integration.rs`, `crates/tidefs-local-filesystem/src/repair.rs`, and scrub-core evidence/result types only if needed. |

Issue #591 remains the active stale-generation repair gate. Issue #18 remains
the placement receipt, rebuild, and source-selection gate. The scrub/repair
identity work in #637, #650, #651, and #652 is deliberately non-enabling for
mounted device-level transforms while any production `blocked` row remains in
this inventory. In that state:

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
