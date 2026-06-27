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
//! The live storage-node daemon (`tidefs-storage-node`) does **not** yet
//! use this bridge; its `Frame::Send`/`Frame::Receive` handlers still use
//! VFSSEND1 [`ChangedRecordExport`] directly. When the daemon adopts this
//! bridge, the send/receive authority consolidates to VFSSEND2.
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
//! - The VFSSEND2 stream is **not** yet carried over transport; the
//!   send-stream session adapter (`tidefs-send-stream` with `transport`
//!   feature) handles network delivery separately (#6087).
//! - Incremental send (VFSSEND2 `SendBuilder::incremental`) is bridged via
//!   [`export_incremental_vfssend2_from_changed_records`].
//! - Receive (VFSSEND2 → local-filesystem) is **not** yet bridged; tracked
//!   by Review debt TFR-010 (historical issues #5949 / #6328).

use std::collections::BTreeSet;

use tidefs_send_stream::{
    Bytes32, DeltaObject, Id128, ObjectKind, SendBuilder, SendStreamHeader, SenderAuthority,
    SnapshotDelta,
};

use crate::error::FileSystemError;
use crate::types::{
    ChangedObjectRecord, ChangedRecordExport, ChangedRecordObjectRole, ChangedRecordRoot,
};

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
/// base-object-digest map passed to [`SendBuilder::incremental`] is empty.
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

    let builder = SendBuilder::incremental(header, snapshots, std::collections::BTreeMap::new())
        .map_err(|e| FileSystemError::LifecycleError {
            reason: format!("VFSSEND2 SendBuilder::incremental: {e}"),
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
        let delta = changed_record_root_to_snapshot_delta(root)?;
        snapshots.push(delta);
    }
    Ok((header, snapshots))
}

fn changed_record_root_to_snapshot_delta(root: &ChangedRecordRoot) -> crate::Result<SnapshotDelta> {
    let summary = &root.source_root;
    let snapshot_id = make_snapshot_id(summary.transaction_id, summary.generation);
    let snapshot_name = format!("tx-{}", summary.transaction_id);

    let mut delta = SnapshotDelta::new(snapshot_id, snapshot_name, summary.generation);

    for record in &root.records {
        let delta_obj = changed_record_to_delta_object(record, summary.generation)?;
        delta.objects.push(delta_obj);
    }

    delta.removed_objects = BTreeSet::new();

    Ok(delta)
}

fn changed_record_to_delta_object(
    record: &ChangedObjectRecord,
    birth_commit_group: u64,
) -> crate::Result<DeltaObject> {
    let object_id: Bytes32 = *record.object_key.as_bytes();
    let kind = role_to_object_kind(record.role);

    let mut obj = DeltaObject::new(object_id, kind, record.payload.clone());
    obj.birth_commit_group = birth_commit_group;

    Ok(obj)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChangedRecordExport, ChangedRecordRoot, CommittedRootSummary};
    use tidefs_local_object_store::{IntegrityDigest64, ObjectKey, StoreOptions};

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

    fn temp_dir(name: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tidefs-vfssend2-bridge-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn setup_auth_env() {
        std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "B".repeat(64));
    }

    fn root_id_from_summary(summary: &crate::types::SnapshotSummary) -> tidefs_send_stream::Id128 {
        let mut id = [0u8; 16];
        id[0..8].copy_from_slice(&summary.source_transaction_id.to_le_bytes());
        id[8..16].copy_from_slice(&summary.source_generation.to_le_bytes());
        id
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
    fn receive_bridge_applies_snapshot_mutation_stream() {
        setup_auth_env();
        let root = temp_dir("snapshot-mutation");
        let mut fs = crate::LocalFileSystem::open_with_options(&root, StoreOptions::default())
            .expect("open fs");
        fs.create_snapshot("origin").expect("snapshot");
        fs.create_clone("myclone", "origin").expect("clone");
        let root_id = root_id_from_summary(&fs.snapshot_summary("myclone").expect("clone summary"));
        let delta = tidefs_send_stream::SnapshotDelta::promote([3u8; 16], "myclone", 7, root_id);
        let header = tidefs_send_stream::SendStreamHeader::new([1u8; 16], [2u8; 16], [3u8; 16]);
        let stream = tidefs_send_stream::SendBuilder::full(header, vec![delta])
            .expect("builder")
            .encode()
            .expect("encode");

        let reports = receive_vfssend2_snapshot_mutations(&mut fs, &stream).expect("receive");

        assert_eq!(reports.len(), 1);
        assert!(matches!(
            &reports[0],
            crate::SnapshotMutationApplyReport::Promoted(report)
                if report.name == "myclone" && report.previous_origin == "origin"
        ));
        let entry = fs
            .list_snapshots_extended()
            .into_iter()
            .find(|entry| entry.name == "myclone")
            .expect("promoted entry");
        assert_eq!(entry.kind, crate::records::SnapshotKind::Snapshot);
        let _ = std::fs::remove_dir_all(&root);
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
            from_root: Some(from_summary),
            incremental: true,
            placement_epoch: None,
        };
        let pool_id = [11u8; 16];
        let dataset_id = [22u8; 16];
        let result = export_incremental_vfssend2_from_changed_records(&export, pool_id, dataset_id);
        assert!(result.is_ok(), "expected ok, got {result:?}");
        let encoded = result.unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(
            &encoded[0..8],
            tidefs_send_stream::STREAM_MAGIC,
            "VFSSEND2 magic bytes must be present"
        );
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

/// Map a VFSSEND2 [`ObjectKind`] to a VFSSEND1 [`ChangedRecordObjectRole`].
///
/// The reverse of the export mapping defined at the top of this module.
/// Multiple VFSSEND2 kinds map to `DatasetProperty`; callers that need
/// finer disambiguation should inspect the object payload or metadata.
fn vfssend2_kind_to_role(
    kind: tidefs_send_stream::ObjectKind,
) -> crate::types::ChangedRecordObjectRole {
    match kind {
        tidefs_send_stream::ObjectKind::Inode => {
            crate::types::ChangedRecordObjectRole::TransactionInode
        }
        tidefs_send_stream::ObjectKind::Directory => {
            crate::types::ChangedRecordObjectRole::TransactionDirectory
        }
        tidefs_send_stream::ObjectKind::Extent => {
            crate::types::ChangedRecordObjectRole::TransactionExtentMap
        }
        tidefs_send_stream::ObjectKind::SnapshotCatalog => {
            crate::types::ChangedRecordObjectRole::TransactionSnapshotCatalogEntry
        }
        tidefs_send_stream::ObjectKind::DatasetProperty | tidefs_send_stream::ObjectKind::Xattr => {
            crate::types::ChangedRecordObjectRole::TransactionManifest
        }
    }
}

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
    let mut records: Vec<crate::types::ChangedObjectRecord> = Vec::new();

    for object in dataset.objects.values() {
        let role = vfssend2_kind_to_role(object.kind);
        records.push(crate::types::ChangedObjectRecord {
            role,
            object_key: tidefs_local_object_store::ObjectKey::from_bytes(object.object_id),
            checksum: tidefs_local_object_store::IntegrityDigest64(object.birth_commit_group),
            payload: object.payload.clone(),
        });
    }

    if records.is_empty() {
        return Err(crate::FileSystemError::LifecycleError {
            reason: "VFSSEND2 stream contained no objects".into(),
        });
    }

    let total_records = records.len() as u64;
    let payload_bytes: u64 = records.iter().map(|r| r.payload.len() as u64).sum();

    // Derive commit group from max object birth_commit_group.
    let max_cg = dataset
        .objects
        .values()
        .map(|o| o.birth_commit_group)
        .max()
        .unwrap_or(1);

    // Build a synthetic root for the export.
    let current_root = crate::types::CommittedRootSummary {
        slot: 0,
        transaction_id: max_cg,
        generation: max_cg,
        next_inode_id: 1,
        inode_count: records.len() as u64,
        superblock_checksum: tidefs_local_object_store::IntegrityDigest64(0),
        has_transaction_manifest: true,
        manifest_checksum: tidefs_local_object_store::IntegrityDigest64(0),
        manifest_entry_count: 0,
        has_root_authentication: false,
        root_authentication_policy_epoch: None,
        root_authentication_algorithm_suite_id: None,
        superblock_digest: None,
        manifest_digest: None,
        root_authentication_code: None,
    };

    let changed_root = crate::types::ChangedRecordRoot {
        source_root: current_root.clone(),
        records,
    };

    Ok(crate::types::ChangedRecordExport {
        spec: crate::constants::SEND_RECEIVE_CHANGED_RECORD_SPEC,
        stream_version: crate::constants::SEND_RECEIVE_STREAM_VERSION,
        current_root,
        roots: vec![changed_root],
        total_records,
        payload_bytes,
        production_fsck_required: false,
        from_root: None,
        placement_epoch: None,
        incremental: header
            .flags
            .contains(tidefs_send_stream::StreamFlags::INCREMENTAL),
    })
}

/// Decode a VFSSEND2 stream and apply any snapshot-record mutations it carries.
pub fn receive_vfssend2_snapshot_mutations(
    fs: &mut crate::LocalFileSystem,
    stream_bytes: &[u8],
) -> crate::Result<Vec<crate::SnapshotMutationApplyReport>> {
    let (_header, dataset) = receive_vfssend2_dataset(stream_bytes)?;
    let mut reports = Vec::with_capacity(dataset.snapshot_mutations.len());
    for mutation in &dataset.snapshot_mutations {
        reports.push(fs.apply_vfssend2_snapshot_mutation(mutation)?);
    }
    Ok(reports)
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
