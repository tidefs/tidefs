// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VFSSEND2 bridge: convert local-filesystem changed-record exports into
//! the canonical VFSSEND2 stream format defined in [`tidefs_send_stream`].
//!
//! # Authority
//!
//! This module is the **single integration point** between the
//! local-filesystem VFSSEND1 changed-record export path and the VFSSEND2
//! protocol crate. It converts [`ChangedRecordExport`] data into the
//! [`tidefs_send_stream::SendBuilder`] stream format.
//!
//! The live storage-node daemon (`tidefs-storage-node`) uses this bridge for
//! `Frame::Send` exports. `Frame::Receive` remains on the VFSSEND1
//! [`ChangedRecordExport`] path until the receive-side wiring lands.
//!
//! ## Conversion mapping
//!
//! | VFSSEND1 role                    | VFSSEND2 ObjectKind |
//! |----------------------------------|---------------------|
//! | TransactionInode                 | Inode               |
//! | TransactionDirectory             | Directory           |
//! | TransactionExtentMap             | Extent              |
//! | TransactionSnapshotCatalogEntry  | SnapshotCatalog     |
//! | TransactionManifest              | DatasetProperty     |
//! | TransactionSuperblock            | DatasetProperty     |
//! | VersionedContent                 | DatasetProperty     |
//! | VersionedContentChunk            | DatasetProperty     |
//!
//! ## Nonclaim boundaries
//!
//! - This module does **not** own pool-id or dataset-id authority; callers
//!   must provide those from pool/dataset metadata.
//! - VFSSEND1 [`ChangedRecordExport`] streams remain local-only. Distributed
//!   senders must attach [`SenderAuthority`] while converting to VFSSEND2, and
//!   VFSSEND2 streams carrying sender authority are rejected by the current
//!   receive-to-VFSSEND1 bridge until receive authorization is implemented.
//! - Storage-node send responses can wrap VFSSEND2 bytes in
//!   [`tidefs_send_stream::SendTransportBridge`] frames, while dedicated
//!   sender lifecycle and resumable session negotiation remain separate
//!   follow-up work.
//! - Incremental send (VFSSEND2 `SendBuilder::incremental`) is bridged via
//!   [`export_incremental_vfssend2_from_changed_records`].
//! - Receive (VFSSEND2 → local-filesystem) is **not** yet bridged; tracked
//!   by Review debt TFR-010 (historical issues #5949 / #6328).

use std::collections::{BTreeMap, BTreeSet};

use tidefs_send_stream::{
    Bytes32, DeltaObject, Id128, ObjectKind, PinnedBaseRoot, SendBuilder, SendStreamHeader,
    SenderAuthority, SnapshotDelta,
};

use tidefs_local_object_store::IntegrityDigest64;

use crate::error::FileSystemError;
use crate::types::{
    ChangedObjectRecord, ChangedRecordExport, ChangedRecordObjectRole, ChangedRecordRoot,
    CommittedRootSummary,
};

const CHANGED_RECORD_METADATA_MAGIC: [u8; 8] = *b"VFS1META";
const CHANGED_RECORD_METADATA_VERSION: u16 = 1;
const CHANGED_RECORD_METADATA_HAS_FROM_ROOT: u16 = 1 << 0;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChangedRecordObjectMetadata {
    role: ChangedRecordObjectRole,
    checksum: IntegrityDigest64,
    source_root: CommittedRootSummary,
    from_root: Option<CommittedRootSummary>,
}

/// Convert a VFSSEND1 [`ChangedRecordExport`] into a VFSSEND2-encoded stream.
///
/// Returns the fully-encoded VFSSEND2 byte stream ready for transport or
/// storage.  This is a full export (not incremental).
pub fn export_vfssend2_from_changed_records(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
) -> crate::Result<Vec<u8>> {
    encode_full_changed_records_as_vfssend2(export, pool_id, dataset_id, None)
}

/// Convert a local VFSSEND1 export into a VFSSEND2 stream carrying sender
/// authority evidence.
pub fn export_vfssend2_from_changed_records_with_sender_authority(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
    sender_authority: SenderAuthority,
) -> crate::Result<Vec<u8>> {
    encode_full_changed_records_as_vfssend2(export, pool_id, dataset_id, Some(sender_authority))
}

fn encode_full_changed_records_as_vfssend2(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
    sender_authority: Option<SenderAuthority>,
) -> crate::Result<Vec<u8>> {
    let (header, snapshots) =
        build_header_and_snapshots(export, pool_id, dataset_id, sender_authority)?;

    let builder =
        SendBuilder::full(header, snapshots).map_err(|e| FileSystemError::LifecycleError {
            reason: format!("VFSSEND2 SendBuilder::full: {e}"),
        })?;

    builder
        .encode()
        .map_err(|e| FileSystemError::LifecycleError {
            reason: format!("VFSSEND2 SendBuilder::encode: {e}"),
        })
}

/// Convert a VFSSEND1 incremental [`ChangedRecordExport`] into a VFSSEND2
/// incremental stream.
///
/// The export **must** have `incremental: true` and a `from_root`.  Only
/// changed objects are included; the VFSSEND2 header carries the
/// `INCREMENTAL` flag and `from_snapshot_id` so the receiver can validate
/// the baseline against the base snapshot it already holds.
///
/// Object filtering is done at the VFSSEND1 export layer
/// ([`crate::send_receive::export_incremental_changed_records`]), so the
/// base-object-digest map passed to
/// [`SendBuilder::incremental_from_base`] is empty while the lineage manifest
/// still carries a pinned base-root identity.
pub fn export_incremental_vfssend2_from_changed_records(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
) -> crate::Result<Vec<u8>> {
    encode_incremental_changed_records_as_vfssend2(export, pool_id, dataset_id, None)
}

/// Convert a local incremental VFSSEND1 export into a VFSSEND2 stream carrying
/// sender authority evidence.
pub fn export_incremental_vfssend2_from_changed_records_with_sender_authority(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
    sender_authority: SenderAuthority,
) -> crate::Result<Vec<u8>> {
    encode_incremental_changed_records_as_vfssend2(
        export,
        pool_id,
        dataset_id,
        Some(sender_authority),
    )
}

fn encode_incremental_changed_records_as_vfssend2(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
    sender_authority: Option<SenderAuthority>,
) -> crate::Result<Vec<u8>> {
    if !export.incremental {
        return Err(FileSystemError::LifecycleError {
            reason: "export_incremental_vfssend2: export is not incremental".into(),
        });
    }
    let from_root = export
        .from_root
        .as_ref()
        .ok_or_else(|| FileSystemError::LifecycleError {
            reason: "export_incremental_vfssend2: from_root is missing".into(),
        })?;

    let from_snapshot_id = make_snapshot_id(from_root.transaction_id, from_root.generation);

    let (header, snapshots) =
        build_header_and_snapshots(export, pool_id, dataset_id, sender_authority)?;
    let header = header.incremental_from(from_snapshot_id);

    let base_root = PinnedBaseRoot::new(
        dataset_id,
        from_snapshot_id,
        changed_record_root_digest(dataset_id, from_snapshot_id, from_root),
        BTreeMap::new(),
        true,
    );

    let builder =
        SendBuilder::incremental_from_base(header, snapshots, base_root).map_err(|e| {
            FileSystemError::LifecycleError {
                reason: format!("VFSSEND2 SendBuilder::incremental: {e}"),
            }
        })?;

    builder
        .encode()
        .map_err(|e| FileSystemError::LifecycleError {
            reason: format!("VFSSEND2 SendBuilder::encode: {e}"),
        })
}

/// Shared helper: build the VFSSEND2 header and snapshot delta vec from a
/// changed-record export.
fn build_header_and_snapshots(
    export: &ChangedRecordExport,
    pool_id: Id128,
    dataset_id: Id128,
    sender_authority: Option<SenderAuthority>,
) -> crate::Result<(SendStreamHeader, Vec<SnapshotDelta>)> {
    let to_snapshot_id = make_snapshot_id(
        export.current_root.transaction_id,
        export.current_root.generation,
    );
    let mut header = SendStreamHeader::new(pool_id, dataset_id, to_snapshot_id);
    if let Some(sender_authority) = sender_authority {
        header = header.with_sender_authority(sender_authority);
    }
    let mut snapshots: Vec<SnapshotDelta> = Vec::with_capacity(export.roots.len());
    for root in &export.roots {
        let delta = changed_record_root_to_snapshot_delta(root, export.from_root.as_ref())?;
        snapshots.push(delta);
    }
    Ok((header, snapshots))
}

fn changed_record_root_to_snapshot_delta(
    root: &ChangedRecordRoot,
    from_root: Option<&CommittedRootSummary>,
) -> crate::Result<SnapshotDelta> {
    let summary = &root.source_root;
    let snapshot_id = make_snapshot_id(summary.transaction_id, summary.generation);
    let snapshot_name = format!("tx-{}", summary.transaction_id);

    let mut delta = SnapshotDelta::new(snapshot_id, snapshot_name, summary.generation);

    for record in &root.records {
        let delta_obj = changed_record_to_delta_object(record, summary, from_root)?;
        delta.objects.push(delta_obj);
    }

    delta.removed_objects = BTreeSet::new();

    Ok(delta)
}

fn changed_record_to_delta_object(
    record: &ChangedObjectRecord,
    source_root: &CommittedRootSummary,
    from_root: Option<&CommittedRootSummary>,
) -> crate::Result<DeltaObject> {
    let object_id: Bytes32 = *record.object_key.as_bytes();
    let kind = role_to_object_kind(record.role);

    let mut obj = DeltaObject::new(object_id, kind, record.payload.clone());
    obj.metadata = encode_changed_record_metadata(source_root, from_root, record);
    obj.birth_commit_group = source_root.generation;

    Ok(obj)
}

fn encode_changed_record_metadata(
    source_root: &CommittedRootSummary,
    from_root: Option<&CommittedRootSummary>,
    record: &ChangedObjectRecord,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CHANGED_RECORD_METADATA_MAGIC);
    crate::encoding::push_u16(&mut out, CHANGED_RECORD_METADATA_VERSION);
    let flags = if from_root.is_some() {
        CHANGED_RECORD_METADATA_HAS_FROM_ROOT
    } else {
        0
    };
    crate::encoding::push_u16(&mut out, flags);
    crate::encoding::push_u16(&mut out, record.role.as_u16());
    crate::encoding::push_u16(&mut out, 0);
    crate::encoding::push_u64(&mut out, record.checksum.get());
    crate::encoding::encode_committed_root_summary(&mut out, source_root);
    if let Some(from_root) = from_root {
        crate::encoding::encode_committed_root_summary(&mut out, from_root);
    }
    out
}

fn decode_changed_record_metadata(bytes: &[u8]) -> crate::Result<ChangedRecordObjectMetadata> {
    let mut decoder = crate::encoding::Decoder::new("VFSSEND2 changed-record metadata", bytes);
    decoder.expect_magic(CHANGED_RECORD_METADATA_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != CHANGED_RECORD_METADATA_VERSION {
        return Err(FileSystemError::Decode {
            object: "VFSSEND2 changed-record metadata",
            reason: "unsupported metadata version",
        });
    }
    let flags = decoder.read_u16()?;
    if flags & !CHANGED_RECORD_METADATA_HAS_FROM_ROOT != 0 {
        return Err(FileSystemError::Decode {
            object: "VFSSEND2 changed-record metadata",
            reason: "reserved metadata flags are set",
        });
    }
    let role = ChangedRecordObjectRole::try_from(decoder.read_u16()?).map_err(|_| {
        FileSystemError::Decode {
            object: "VFSSEND2 changed-record metadata",
            reason: "unknown changed-record role",
        }
    })?;
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "VFSSEND2 changed-record metadata",
            reason: "reserved metadata field is non-zero",
        });
    }
    let checksum = IntegrityDigest64(decoder.read_u64()?);
    let source_root = crate::encoding::decode_committed_root_summary(&mut decoder)?;
    let from_root = if flags & CHANGED_RECORD_METADATA_HAS_FROM_ROOT != 0 {
        Some(crate::encoding::decode_committed_root_summary(
            &mut decoder,
        )?)
    } else {
        None
    };
    decoder.finish()?;
    Ok(ChangedRecordObjectMetadata {
        role,
        checksum,
        source_root,
        from_root,
    })
}

fn role_to_object_kind(role: ChangedRecordObjectRole) -> ObjectKind {
    match role {
        ChangedRecordObjectRole::TransactionInode => ObjectKind::Inode,
        ChangedRecordObjectRole::TransactionDirectory => ObjectKind::Directory,
        ChangedRecordObjectRole::TransactionExtentMap => ObjectKind::Extent,
        ChangedRecordObjectRole::TransactionSnapshotCatalogEntry => ObjectKind::SnapshotCatalog,
        // VFSSEND2 has no direct equivalents; use DatasetProperty as generic.
        ChangedRecordObjectRole::TransactionManifest
        | ChangedRecordObjectRole::TransactionSuperblock
        | ChangedRecordObjectRole::VersionedContent
        | ChangedRecordObjectRole::VersionedContentChunk => ObjectKind::DatasetProperty,
    }
}

/// Derive a deterministic snapshot id from transaction metadata.
fn make_snapshot_id(transaction_id: u64, generation: u64) -> Id128 {
    let mut id = [0u8; 16];
    id[0..8].copy_from_slice(&transaction_id.to_le_bytes());
    id[8..16].copy_from_slice(&generation.to_le_bytes());
    id
}

fn changed_record_root_digest(
    dataset_id: Id128,
    snapshot_id: Id128,
    root: &CommittedRootSummary,
) -> Bytes32 {
    let mut hasher = blake3::Hasher::new_derive_key("TideFS VFSSEND2 local root summary digest v1");
    hasher.update(&dataset_id);
    hasher.update(&snapshot_id);
    hasher.update(&root.slot.to_le_bytes());
    hasher.update(&root.transaction_id.to_le_bytes());
    hasher.update(&root.generation.to_le_bytes());
    hasher.update(&root.superblock_checksum.0.to_le_bytes());
    hasher.update(&root.manifest_checksum.0.to_le_bytes());
    hasher.update(&root.manifest_entry_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ChangedRecordExport, ChangedRecordRoot, CommittedRootSummary, RootAuthenticationCode,
        RootAuthenticationDigest,
    };
    use tidefs_local_object_store::{IntegrityDigest64, ObjectKey};

    fn make_test_root_summary(tx: u64, gen: u64) -> CommittedRootSummary {
        CommittedRootSummary {
            slot: 0,
            transaction_id: tx,
            generation: gen,
            next_inode_id: 0,
            inode_count: 0,
            superblock_checksum: IntegrityDigest64::ZERO,
            has_transaction_manifest: false,
            manifest_checksum: IntegrityDigest64::ZERO,
            manifest_entry_count: 0,
            has_root_authentication: false,
            root_authentication_policy_epoch: None,
            root_authentication_algorithm_suite_id: None,
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        }
    }

    fn make_authenticated_root_summary(tx: u64, gen: u64) -> CommittedRootSummary {
        CommittedRootSummary {
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(tx + gen + 10),
            manifest_entry_count: 3,
            has_root_authentication: true,
            root_authentication_policy_epoch: Some(1),
            root_authentication_algorithm_suite_id: Some(1),
            superblock_digest: Some(RootAuthenticationDigest::from_bytes32([0x11; 32])),
            manifest_digest: Some(RootAuthenticationDigest::from_bytes32([0x22; 32])),
            root_authentication_code: Some(RootAuthenticationCode::from_bytes32([0x33; 32])),
            ..make_test_root_summary(tx, gen)
        }
    }

    #[test]
    fn empty_export_rejected_by_send_builder() {
        let summary = make_test_root_summary(1, 1);
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 1,
            current_root: summary.clone(),
            roots: vec![],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
        };
        let pool_id = [1u8; 16];
        let dataset_id = [2u8; 16];
        let result = export_vfssend2_from_changed_records(&export, pool_id, dataset_id);
        assert!(result.is_err());
    }

    #[test]
    fn single_inode_record_round_trips_through_vfssend2() {
        let summary = make_test_root_summary(1, 100);
        let object_key = ObjectKey::from_bytes32([3u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionInode,
            object_key,
            checksum: IntegrityDigest64(42),
            payload: vec![10, 20, 30],
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![record],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 1,
            current_root: summary,
            roots: vec![root],
            total_records: 1,
            payload_bytes: 3,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
        };
        let pool_id = [1u8; 16];
        let dataset_id = [2u8; 16];
        let result = export_vfssend2_from_changed_records(&export, pool_id, dataset_id);
        assert!(result.is_ok(), "expected ok, got {result:?}");
        let encoded = result.unwrap();
        assert!(!encoded.is_empty());

        // Verify VFSSEND2 magic bytes at stream start
        assert_eq!(&encoded[0..8], tidefs_send_stream::STREAM_MAGIC);
    }

    #[test]
    fn sender_authority_is_carried_in_vfssend2_header() {
        let summary = make_test_root_summary(1, 100);
        let object_key = ObjectKey::from_bytes32([3u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionInode,
            object_key,
            checksum: IntegrityDigest64(42),
            payload: vec![10, 20, 30],
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![record],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 1,
            current_root: summary,
            roots: vec![root],
            total_records: 1,
            payload_bytes: 3,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
        };
        assert!(export.sender_authority().is_absent_local_only());

        let pool_id = [1u8; 16];
        let dataset_id = [2u8; 16];
        let sender_authority = tidefs_send_stream::SenderAuthority::new(pool_id, 7, 11).unwrap();
        let encoded = export_vfssend2_from_changed_records_with_sender_authority(
            &export,
            pool_id,
            dataset_id,
            sender_authority,
        )
        .unwrap();

        let (header, _records) = tidefs_send_stream::SendStreamHeader::decode(&encoded).unwrap();
        assert_eq!(
            header.sender_authority.distributed(),
            Some(sender_authority)
        );
    }

    #[test]
    fn receive_bridge_rejects_vfssend2_sender_authority_before_conversion() {
        let summary = make_test_root_summary(1, 100);
        let object_key = ObjectKey::from_bytes32([3u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionInode,
            object_key,
            checksum: IntegrityDigest64(42),
            payload: vec![10, 20, 30],
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![record],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 1,
            current_root: summary,
            roots: vec![root],
            total_records: 1,
            payload_bytes: 3,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
        };
        let pool_id = [1u8; 16];
        let dataset_id = [2u8; 16];
        let sender_authority = tidefs_send_stream::SenderAuthority::new(pool_id, 7, 11).unwrap();
        let encoded = export_vfssend2_from_changed_records_with_sender_authority(
            &export,
            pool_id,
            dataset_id,
            sender_authority,
        )
        .unwrap();

        let err = receive_vfssend2_to_changed_records(&encoded).unwrap_err();
        assert!(matches!(
            err,
            crate::FileSystemError::LifecycleError { reason }
                if reason.contains("sender authority")
        ));
    }

    #[test]
    fn receive_bridge_preserves_changed_record_metadata() {
        let summary = make_authenticated_root_summary(7, 700);
        let object_key = ObjectKey::from_bytes32([9u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionSuperblock,
            object_key,
            checksum: IntegrityDigest64(0x1234),
            payload: vec![1, 2, 3, 4, 5],
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![record.clone()],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 1,
            current_root: summary.clone(),
            roots: vec![root],
            total_records: 1,
            payload_bytes: 5,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
        };
        let encoded = export_vfssend2_from_changed_records(&export, [1u8; 16], [2u8; 16]).unwrap();

        let decoded = receive_vfssend2_to_changed_records(&encoded).expect("decode");

        assert!(!decoded.incremental);
        assert_eq!(decoded.from_root, None);
        assert_eq!(decoded.current_root, summary);
        assert_eq!(decoded.roots.len(), 1);
        assert_eq!(decoded.roots[0].source_root, summary);
        assert_eq!(decoded.roots[0].records, vec![record]);
    }

    #[test]
    fn receive_bridge_preserves_incremental_base_metadata() {
        let from_summary = make_authenticated_root_summary(7, 700);
        let to_summary = make_authenticated_root_summary(8, 800);
        let object_key = ObjectKey::from_bytes32([10u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionInode,
            object_key,
            checksum: IntegrityDigest64(0x5678),
            payload: vec![6, 7, 8],
        };
        let root = ChangedRecordRoot {
            source_root: to_summary.clone(),
            records: vec![record.clone()],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 2,
            current_root: to_summary.clone(),
            roots: vec![root],
            total_records: 1,
            payload_bytes: 3,
            production_fsck_required: false,
            from_root: Some(from_summary.clone()),
            incremental: true,
            placement_epoch: None,
        };
        let encoded =
            export_incremental_vfssend2_from_changed_records(&export, [1u8; 16], [2u8; 16])
                .unwrap();

        let decoded = receive_vfssend2_to_changed_records(&encoded).expect("decode");

        assert!(decoded.incremental);
        assert_eq!(decoded.from_root, Some(from_summary));
        assert_eq!(decoded.current_root, to_summary);
        assert_eq!(decoded.roots.len(), 1);
        assert_eq!(decoded.roots[0].records, vec![record]);
    }

    #[test]
    fn role_to_kind_maps_all_variants() {
        use ChangedRecordObjectRole::*;
        // Every role must map without panic
        for role in [
            TransactionManifest,
            TransactionSuperblock,
            TransactionInode,
            TransactionDirectory,
            VersionedContent,
            VersionedContentChunk,
            TransactionSnapshotCatalogEntry,
            TransactionExtentMap,
        ] {
            let _kind = role_to_object_kind(role);
        }
    }

    #[test]
    fn incremental_export_produces_vfssend2_magic() {
        let from_summary = make_test_root_summary(1, 100);
        let to_summary = make_test_root_summary(2, 200);
        let object_key = ObjectKey::from_bytes32([7u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionInode,
            object_key,
            checksum: IntegrityDigest64(99),
            payload: vec![1, 2, 3, 4],
        };
        let root = ChangedRecordRoot {
            source_root: to_summary.clone(),
            records: vec![record],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 2,
            current_root: to_summary,
            roots: vec![root],
            total_records: 1,
            payload_bytes: 4,
            production_fsck_required: false,
            from_root: Some(from_summary.clone()),
            incremental: true,
            placement_epoch: None,
        };
        let pool_id = [11u8; 16];
        let dataset_id = [22u8; 16];
        let expected_from_snapshot_id =
            make_snapshot_id(from_summary.transaction_id, from_summary.generation);
        let result = export_incremental_vfssend2_from_changed_records(&export, pool_id, dataset_id);
        assert!(result.is_ok(), "expected ok, got {result:?}");
        let encoded = result.unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(
            &encoded[0..8],
            tidefs_send_stream::STREAM_MAGIC,
            "VFSSEND2 magic bytes must be present"
        );
        let (header, _tail) = tidefs_send_stream::SendStreamHeader::decode(&encoded).unwrap();
        assert!(header
            .flags
            .contains(tidefs_send_stream::StreamFlags::INCREMENTAL));
        assert_eq!(header.from_snapshot_id, expected_from_snapshot_id);
    }

    #[test]
    fn incremental_rejects_non_incremental_export() {
        let summary = make_test_root_summary(1, 100);
        let object_key = ObjectKey::from_bytes32([3u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionInode,
            object_key,
            checksum: IntegrityDigest64(42),
            payload: vec![10, 20, 30],
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![record],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 1,
            current_root: summary,
            roots: vec![root],
            total_records: 1,
            payload_bytes: 3,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
        };
        let pool_id = [1u8; 16];
        let dataset_id = [2u8; 16];
        let result = export_incremental_vfssend2_from_changed_records(&export, pool_id, dataset_id);
        assert!(result.is_err(), "non-incremental export must be rejected");
    }

    #[test]
    fn incremental_rejects_missing_from_root() {
        let summary = make_test_root_summary(2, 200);
        let object_key = ObjectKey::from_bytes32([5u8; 32]);
        let record = ChangedObjectRecord {
            role: ChangedRecordObjectRole::TransactionDirectory,
            object_key,
            checksum: IntegrityDigest64(77),
            payload: vec![8, 9],
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![record],
        };
        let export = ChangedRecordExport {
            spec: "test",
            stream_version: 2,
            current_root: summary,
            roots: vec![root],
            total_records: 1,
            payload_bytes: 2,
            production_fsck_required: false,
            from_root: None,
            placement_epoch: None,
            incremental: true, // flagged incremental but missing from_root
        };
        let pool_id = [1u8; 16];
        let dataset_id = [2u8; 16];
        let result = export_incremental_vfssend2_from_changed_records(&export, pool_id, dataset_id);
        assert!(
            result.is_err(),
            "missing from_root on incremental export must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// VFSSEND2 receive bridge: convert VFSSEND2 stream -> ChangedRecordExport
// ---------------------------------------------------------------------------

/// Receive a VFSSEND2-encoded byte stream and convert it into a
/// VFSSEND1 [`ChangedRecordExport`] suitable for the existing
/// `receive_changed_records_into_empty_root` pipeline.
///
/// # Errors
///
/// Returns [`FileSystemError`] when the stream is malformed, contains
/// records that cannot be mapped, or the VFSSEND2 header is invalid.
pub fn receive_vfssend2_to_changed_records(
    stream_bytes: &[u8],
) -> crate::Result<crate::types::ChangedRecordExport> {
    let (header, dataset) = receive_vfssend2_dataset(stream_bytes)?;
    let incremental = header
        .flags
        .contains(tidefs_send_stream::StreamFlags::INCREMENTAL);
    let mut snapshots: Vec<_> = dataset.snapshots.values().collect();
    snapshots.sort_by_key(|snapshot| snapshot.commit_group);
    let mut roots = Vec::with_capacity(snapshots.len());
    let mut total_records = 0_u64;
    let mut payload_bytes = 0_u64;
    let mut from_root: Option<CommittedRootSummary> = None;
    let mut referenced_objects = BTreeSet::new();

    for snapshot in snapshots {
        let mut source_root: Option<CommittedRootSummary> = None;
        let mut records: Vec<crate::types::ChangedObjectRecord> =
            Vec::with_capacity(snapshot.object_ids.len());

        for object_id in &snapshot.object_ids {
            let object = dataset.objects.get(object_id).ok_or_else(|| {
                crate::FileSystemError::LifecycleError {
                    reason: "VFSSEND2 snapshot references a missing object".into(),
                }
            })?;
            referenced_objects.insert(*object_id);

            let metadata = decode_changed_record_metadata(&object.metadata)?;
            if role_to_object_kind(metadata.role) != object.kind {
                return Err(crate::FileSystemError::Decode {
                    object: "VFSSEND2 changed-record metadata",
                    reason: "changed-record role does not match VFSSEND2 object kind",
                });
            }
            if make_snapshot_id(
                metadata.source_root.transaction_id,
                metadata.source_root.generation,
            ) != snapshot.snapshot_id
                || metadata.source_root.generation != snapshot.commit_group
            {
                return Err(crate::FileSystemError::Decode {
                    object: "VFSSEND2 changed-record metadata",
                    reason: "committed root summary does not match snapshot boundary",
                });
            }
            match &source_root {
                Some(existing) if existing != &metadata.source_root => {
                    return Err(crate::FileSystemError::Decode {
                        object: "VFSSEND2 changed-record metadata",
                        reason: "snapshot objects carry inconsistent committed roots",
                    });
                }
                Some(_) => {}
                None => source_root = Some(metadata.source_root.clone()),
            }
            match (&from_root, &metadata.from_root) {
                (Some(existing), Some(candidate)) if existing != candidate => {
                    return Err(crate::FileSystemError::Decode {
                        object: "VFSSEND2 changed-record metadata",
                        reason: "snapshot objects carry inconsistent incremental base roots",
                    });
                }
                (None, Some(candidate)) => from_root = Some(candidate.clone()),
                (Some(_), None) if incremental => {
                    return Err(crate::FileSystemError::Decode {
                        object: "VFSSEND2 changed-record metadata",
                        reason: "incremental object is missing base-root metadata",
                    });
                }
                _ => {}
            }

            payload_bytes = payload_bytes
                .checked_add(object.payload.len() as u64)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            total_records = total_records
                .checked_add(1)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            records.push(crate::types::ChangedObjectRecord {
                role: metadata.role,
                object_key: tidefs_local_object_store::ObjectKey::from_bytes(object.object_id),
                checksum: metadata.checksum,
                payload: object.payload.clone(),
            });
        }

        let source_root = source_root.ok_or_else(|| crate::FileSystemError::LifecycleError {
            reason: "VFSSEND2 snapshot contained no changed-record objects".into(),
        })?;
        roots.push(crate::types::ChangedRecordRoot {
            source_root,
            records,
        });
    }

    if roots.is_empty() {
        return Err(crate::FileSystemError::LifecycleError {
            reason: "VFSSEND2 stream contained no changed-record roots".into(),
        });
    }
    if dataset
        .objects
        .keys()
        .any(|object_id| !referenced_objects.contains(object_id))
    {
        return Err(crate::FileSystemError::Decode {
            object: "VFSSEND2 changed-record metadata",
            reason: "stream contains objects outside snapshot boundaries",
        });
    }

    let from_root = if incremental {
        let from_root = from_root.ok_or(crate::FileSystemError::Decode {
            object: "VFSSEND2 changed-record metadata",
            reason: "incremental stream is missing base-root metadata",
        })?;
        if make_snapshot_id(from_root.transaction_id, from_root.generation)
            != header.from_snapshot_id
        {
            return Err(crate::FileSystemError::Decode {
                object: "VFSSEND2 changed-record metadata",
                reason: "base-root metadata does not match VFSSEND2 header",
            });
        }
        Some(from_root)
    } else {
        if from_root.is_some() {
            return Err(crate::FileSystemError::Decode {
                object: "VFSSEND2 changed-record metadata",
                reason: "full stream carries incremental base-root metadata",
            });
        }
        None
    };

    let current_root = roots
        .last()
        .expect("roots checked non-empty")
        .source_root
        .clone();

    Ok(crate::types::ChangedRecordExport {
        spec: crate::constants::SEND_RECEIVE_CHANGED_RECORD_SPEC,
        stream_version: crate::constants::SEND_RECEIVE_STREAM_VERSION,
        current_root,
        roots,
        total_records,
        payload_bytes,
        production_fsck_required: false,
        from_root,
        placement_epoch: None,
        incremental,
    })
}

fn receive_vfssend2_dataset(
    stream_bytes: &[u8],
) -> crate::Result<(
    tidefs_send_stream::SendStreamHeader,
    tidefs_send_stream::ReceivedDataset,
)> {
    use tidefs_send_stream::{ReceiveBuilder, ReceiveProgress, SendStreamHeader};

    let (header, _tail) = SendStreamHeader::decode(stream_bytes).map_err(|e| {
        crate::FileSystemError::LifecycleError {
            reason: format!("VFSSEND2 header decode: {e}"),
        }
    })?;
    if !header.sender_authority.is_absent_local_only() {
        return Err(crate::FileSystemError::LifecycleError {
            reason: "VFSSEND2 sender authority is not accepted by the local-only receive bridge"
                .into(),
        });
    }

    let dataset_id = header.source_dataset_id;
    let mut builder = ReceiveBuilder::new(dataset_id, stream_bytes).map_err(|e| {
        crate::FileSystemError::LifecycleError {
            reason: format!("VFSSEND2 ReceiveBuilder: {e}"),
        }
    })?;

    loop {
        match builder.next_record() {
            Ok(ReceiveProgress::StreamComplete(stats)) => {
                if !stats.validation_passed {
                    return Err(crate::FileSystemError::LifecycleError {
                        reason: "VFSSEND2 receive validation failed".into(),
                    });
                }
                break;
            }
            Ok(_) => continue,
            Err(e) => {
                return Err(crate::FileSystemError::LifecycleError {
                    reason: format!("VFSSEND2 receive record: {e}"),
                });
            }
        }
    }

    Ok((header, builder.staged_dataset().clone()))
}

/// Auto-detect stream format and convert to [`ChangedRecordExport`].
///
/// If the byte slice starts with `VFSSEND2` magic, it is decoded as
/// VFSSEND2; otherwise the bytes are interpreted as VFSSEND1.
pub fn decode_any_stream_to_changed_records(
    bytes: &[u8],
) -> crate::Result<crate::types::ChangedRecordExport> {
    if bytes.len() >= 8 && &bytes[0..8] == tidefs_send_stream::STREAM_MAGIC {
        receive_vfssend2_to_changed_records(bytes)
    } else {
        crate::types::ChangedRecordExport::decode(bytes)
    }
}
