# Mounted Transform Authority Raw-Store Inventory

Maturity: current guardrail for TFR-006 and GitHub issue #218.

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
- blocked: the path still handles mounted filesystem data or recovery state
  through a raw handle and blocks device-level mounted transforms.
- later receipt/placement issue: the path belongs to placement receipt,
  locator, rebuild, or default media work and is deliberately outside this
  slice.

## Checked Raw-Store Counts

Current `raw_primary_store()` and `raw_primary_store_mut()` matches:

| Path | Current matches | Inventory note |
|---|---:|---|
| `crates/tidefs-local-object-store/src/pool/mod.rs` | 7 | Pool accessors and `PoolStore` escape hatches. This is the lower object-store authority, not a mounted-filesystem proof. |
| `crates/tidefs-local-filesystem/src/lib.rs` | 64 | 63 mounted production matches plus one in-file test raw drain assertion. |
| `crates/tidefs-local-filesystem/src/crash_recovery.rs` | 21 | Crash-matrix validation helpers stage raw commit-boundary objects. |
| `crates/tidefs-local-filesystem/src/journal_cleaner.rs` | 7 | One production key-scan path plus six unit-test assertions. |
| `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` | 7 | Five live mounted VFS/admin paths plus two encryption-feature tests. |

The check intentionally fails when these counts change. Any new raw-store
access must update this inventory with a status classification before the
branch can pass the guard.

## Production Classification

| Mounted path group | Source surface | Status | Classification |
|---|---|---|---|
| Open, committed-root selection, v0.390 import, intent-log load, commit-group recovery, allocator scan | `MountedOpenRecoveryAuthority` in `src/lib.rs` | transform-aware in raw-only mode | The mounted open path now rejects configured device transforms before pool creation, then routes committed-root selection, v0.390 import, intent-log load, commit-group recovery, txg replay, quota/space/orphan metadata, and allocator scan through one raw-only/no-device-transforms authority. Raw primary-store trust in this group is scoped to the current fail-closed transform mode and remains a non-claim for mounted device-level compression/encryption while any other production blocked row remains. |
| Recovery probe, audit, online verifier, root retention, and selected committed-root summary | `MountedCommittedRootRepairAuthority` behind `probe_recovery*`, `recovery_audit`, `online_verifier_report`, `root_retention_plan`, `safe_root_retention_plan`, `reclaim_unprotected_objects`, and `selected_current_root_summary` in `src/lib.rs` | metadata/raw-only through transform-aware authority | These operator repair/probe paths inspect committed-root slots, transaction manifests, protected root-slot locations, and storage metadata through `MetadataRawOnlyNoDeviceTransforms`. The authority names `plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes`, deliberately handles no mounted file plaintext, compression frame, encryption frame, or content checksum state, and remains a non-claim for mounted device-level compression/encryption while any production `blocked` row remains. |
| Public/raw internal store exposure | `object_store`, `store_ref` in `src/lib.rs` | blocked | These expose the bypass directly to mounted callers and tests, so they cannot coexist with mounted device-transform claims. |
| Reclaim and snapshot-protection key scans | `record_reclaim_delta`, `collect_snapshot_protected_content_keys`, `drain_local_reclaim_queue_into_store`, `reclaim_unprotected_objects`, `commit_space_delta`, and journal cleaner key scans | metadata/raw-only for keys; blocked for content-layout reads | Reclaim identity is an object-key/locator lifetime concern, but several scans still read mounted content layouts through the raw store. |
| Scrub and repair | `schedule_scrub_repairs`, `scrub_repair_pass`, `dispatch_scheduled_repairs` | blocked | Scrub must know whether it is checking plaintext identity, compression frame, encryption frame, checksum, or raw media bytes before mounted device transforms can be enabled. |
| File content reads, writes, sparse operations, reflink, copy-file-range, truncate, punch-hole, zero-range, read overlay | `create_file_like`, `replace_content`, `rewrite_content_*`, `read_content*`, `reflink_*`, `truncate_file`, `free_extent_range`, `punch_hole`, `zero_range`, and related helpers in `src/lib.rs` plus anonymous tmpfile reads and whole-file copy fast paths in `vfs_engine_impl.rs` | transform-aware for mounted content compression, plaintext dedup, and receipt-producing content writes; blocked for remaining device-level compression/encryption reads and raw paths | The main content-write population paths now route durable chunk writes through `PoolStoreMut::put_with_receipt`, but mounted content still has raw read, layout, reclaim, sparse, commit, recovery, and whole-file copy raw paths before device-level transforms can become a product claim. |
| Snapshot export/import and send/receive | `rollback_to_snapshot`, `export_changed_records`, `export_incremental_changed_records` | blocked | Export/import currently serializes raw mounted records and is not yet one ordered transform contract. |
| Intent log, fsync, commit, rollback | `sync_write_intent`, `flush_intent_log_if_needed`, `fsync_*`, `sync_*`, `fdatasync_inode`, `do_commit`, `rollback_mutation_delta`, `selected_current_root_summary` | blocked | Durability barriers and replay anchors still write and clear raw state/log objects. |
| Directory/inode fallback reads | `inode`, `ensure_inode_loaded_for_write` | blocked | These paths recover inode and directory records directly from raw store keys. |
| Live dataset key administration | `live_dataset_seal_key`, `live_dataset_rotate_key` in `vfs_engine_impl.rs` | metadata/raw-only | These paths store sealed key records rather than file payloads, but the format still needs transform-authority review before it becomes a product encryption claim. |
| Crash-matrix boundary staging | `src/crash_recovery.rs` | blocked validation fixture | This is not a mounted product write path, but it proves raw state construction is still required by validation. |
| Placement, locator, rebuild, and default pool-media writes | #17, #18, #91 surfaces | later receipt/placement issue | This issue deliberately does not edit those write paths. |

## Current Mounted Transform Claim

Mounted local-filesystem device-level compression and encryption are blocked
behind this inventory. The lower object-store stack may still expose transform
wrappers, but a mounted filesystem open with device compression or encryption
must fail closed while any production `blocked` row remains.
