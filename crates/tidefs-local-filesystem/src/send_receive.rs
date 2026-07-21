// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_extent_map::ExtentMap;
use tidefs_local_object_store::pool::Pool;
use tidefs_local_object_store::{
    checksum64, IntegrityDigest64, LocalObjectStore, ObjectKey, StoreError, StoreOptions,
};
use tidefs_receive_stream::receive_persistence::{
    validate_receive_contract, BaseRootPinLookup, ReceiveContract, ReceivePersistenceError,
};
use tidefs_types_vfs_core::{InodeId, NodeKind};

use crate::constants::*;
use crate::content::*;
use crate::dedup::DedupIndex;
use crate::encoding::*;
use crate::encoding::{decode_dedup_redirect, is_dedup_redirect};
use crate::error::{
    FileSystemError, IncrementalReceiveBaseRootIdentity,
    INCREMENTAL_RECEIVE_BASE_ROOT_CONFLICT_OPERATOR_ACTIONS,
};
use crate::fs_io_error;
use crate::load_state_from_transaction;
use crate::object_keys::*;
use crate::persist_transaction_objects;
use crate::receive_merge_planner::{locate_common_ancestor, ReceiveMergeStreamLineageManifest};
use crate::receive_persistence::should_import_object;
use crate::records::*;
use crate::root_commit_from_summary;
use crate::roots_with_snapshot_roots;
use crate::types::*;
use crate::validate_namespace_invariants;
use crate::{
    DatasetInodeAuthority, FileSystemState, LocalFileSystem, QuotaTable, Result, ROOT_DATASET_ID,
};
use tidefs_space_accounting::SpaceAccounting;

type LoadedStateWithObjectMaps = (
    FileSystemState,
    BTreeMap<InodeId, ObjectKey>,
    BTreeMap<InodeId, ObjectKey>,
);

#[derive(Clone, Debug)]
pub(crate) struct PreparedChangedRecordExport {
    current_identity: RootIdentity,
    roots: Vec<PreparedChangedRecordRoot>,
    total_records: u64,
    payload_bytes: u64,
    stream_version: u16,
    /// Placement epoch from the decoded export; None when sender did not track it.
    placement_epoch: Option<u64>,
    transform_contract: ChangedRecordTransformContract,
}

pub(crate) fn export_changed_records_from_root(
    store: &mut LocalObjectStore,
    current_root: &CommittedRootSummary,
    current_state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
    placement_epoch: Option<u64>,
) -> Result<ChangedRecordExport> {
    let mut source_roots = roots_with_snapshot_roots(vec![current_root.clone()], current_state);
    source_roots.sort_by_key(|root| root.transaction_id);

    let mut seen = BTreeSet::new();
    let mut roots = Vec::new();
    for source_root in source_roots {
        if seen.insert(RootIdentity::from_summary(&source_root)) {
            roots.push(export_changed_record_root(
                store,
                &source_root,
                root_authentication_key,
            )?);
        }
    }

    let total_records = roots
        .iter()
        .map(|root| root.records.len() as u64)
        .sum::<u64>();
    let payload_bytes =
        roots
            .iter()
            .flat_map(|root| root.records.iter())
            .try_fold(0_u64, |sum, record| {
                sum.checked_add(record.payload.len() as u64)
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })
            })?;

    Ok(ChangedRecordExport {
        spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
        stream_version: SEND_RECEIVE_STREAM_VERSION,
        current_root: current_root.clone(),
        roots,
        total_records,
        payload_bytes,
        production_fsck_required: false,
        from_root: None,
        incremental: false,
        placement_epoch,
        transform_contract: ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
    })
}

/// Export only new or changed records between two committed roots.
///
/// Records present in both roots with the same key and checksum are omitted
/// from the stream, dramatically reducing bandwidth for large datasets with
/// small changes.  This mirrors ZFS `zfs send -i <base> <target>`.
///
/// The receiver must already possess the `from_root` state; only new or
/// modified objects (by object key + checksum) are included.
pub(crate) fn export_incremental_changed_records(
    store: &mut LocalObjectStore,
    from_root: &CommittedRootSummary,
    to_root: &CommittedRootSummary,
    current_state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
    placement_epoch: Option<u64>,
) -> Result<ChangedRecordExport> {
    if !from_root.has_transaction_manifest || !from_root.has_root_authentication {
        return Err(FileSystemError::Unsupported {
            operation: "incremental send/receive export",
            reason: "from_root must be manifest-backed and authenticated",
        });
    }
    if !to_root.has_transaction_manifest || !to_root.has_root_authentication {
        return Err(FileSystemError::Unsupported {
            operation: "incremental send/receive export",
            reason: "to_root must be manifest-backed and authenticated",
        });
    }
    if to_root.transaction_id <= from_root.transaction_id {
        return Err(FileSystemError::Unsupported {
            operation: "incremental send/receive export",
            reason: "to_root transaction_id must be greater than from_root transaction_id",
        });
    }

    // Build the set of (object_key, checksum) pairs from the base root.
    let from_root_commit = root_commit_from_summary(from_root);
    let from_manifest_key = transaction_manifest_object_key(from_root_commit.transaction_id);
    let from_manifest_bytes =
        store
            .get(from_manifest_key)?
            .ok_or(FileSystemError::CorruptState {
                reason: "incremental send: from_root is missing its transaction manifest",
            })?;
    let from_manifest = decode_transaction_manifest(&from_manifest_bytes)?;
    let from_object_set: BTreeSet<(ObjectKey, IntegrityDigest64)> = from_manifest
        .entries
        .iter()
        .map(|e| (e.object_key, e.checksum))
        .collect();

    // Export all roots (including snapshot roots) then filter each.
    let mut source_roots =
        roots_with_snapshot_roots(vec![from_root.clone(), to_root.clone()], current_state);
    source_roots.sort_by_key(|root| root.transaction_id);

    let mut seen_root_ids = BTreeSet::new();
    let mut incremental_roots: Vec<ChangedRecordRoot> = Vec::new();

    for source_root in &source_roots {
        if !seen_root_ids.insert(RootIdentity::from_summary(source_root)) {
            continue;
        }
        let root_export = export_changed_record_root(store, source_root, root_authentication_key)?;
        let mut filtered_records: Vec<ChangedObjectRecord> = Vec::new();

        for record in &root_export.records {
            // Always include the transaction manifest and structural records
            // (inodes, directories, superblock, etc.) that the receiver needs
            // for state reconstruction.  Only content records (VersionedContent,
            // VersionedContentChunk) can be omitted when unchanged.
            let is_content = matches!(
                record.role,
                ChangedRecordObjectRole::VersionedContent
                    | ChangedRecordObjectRole::VersionedContentChunk
            );
            if !is_content {
                filtered_records.push(record.clone());
                continue;
            }
            let pair = (record.object_key, record.checksum);
            if !from_object_set.contains(&pair) {
                filtered_records.push(record.clone());
            }
        }

        // Always include each root so the receiver can validate the snapshot
        // catalog, even if no records changed for that root.
        incremental_roots.push(ChangedRecordRoot {
            source_root: source_root.clone(),
            records: filtered_records,
        });
    }

    let total_records = incremental_roots
        .iter()
        .map(|root| root.records.len() as u64)
        .sum::<u64>();
    if total_records <= 1 {
        return Err(FileSystemError::Unsupported {
            operation: "incremental send",
            reason: "no changed records between base and target snapshots",
        });
    }
    let payload_bytes = incremental_roots
        .iter()
        .flat_map(|root| root.records.iter())
        .try_fold(0_u64, |sum, record| {
            sum.checked_add(record.payload.len() as u64)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })
        })?;

    Ok(ChangedRecordExport {
        spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
        stream_version: 2,
        from_root: Some(from_root.clone()),
        current_root: to_root.clone(),
        roots: incremental_roots,
        total_records,
        payload_bytes,
        production_fsck_required: false,
        incremental: true,
        placement_epoch,
        transform_contract: ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
    })
}

pub(crate) fn export_changed_record_root(
    store: &mut LocalObjectStore,
    source_root: &CommittedRootSummary,
    root_authentication_key: RootAuthenticationKey,
) -> Result<ChangedRecordRoot> {
    if !source_root.has_transaction_manifest || !source_root.has_root_authentication {
        return Err(FileSystemError::Unsupported {
            operation: "send/receive export",
            reason: "only manifest-backed authenticated committed roots can be exported",
        });
    }

    let root = root_commit_from_summary(source_root);
    let _validated_state = load_state_from_transaction(store, &root, root_authentication_key)?;
    let manifest_key = transaction_manifest_object_key(root.transaction_id);
    let manifest_bytes = store
        .get(manifest_key)?
        .ok_or(FileSystemError::CorruptState {
            reason: "send/receive export root is missing its transaction manifest",
        })?;
    if checksum64(&manifest_bytes) != root.manifest_checksum {
        return Err(FileSystemError::CorruptState {
            reason: "send/receive export manifest checksum does not match root",
        });
    }
    let manifest = decode_transaction_manifest(&manifest_bytes)?;
    if manifest.transaction_id != root.transaction_id || manifest.generation != root.generation {
        return Err(FileSystemError::CorruptState {
            reason: "send/receive export manifest does not match root",
        });
    }

    let mut records = vec![ChangedObjectRecord {
        role: ChangedRecordObjectRole::TransactionManifest,
        object_key: manifest_key,
        checksum: checksum64(&manifest_bytes),
        payload: manifest_bytes,
    }];
    let mut canonical_dedup_keys: BTreeSet<ObjectKey> = BTreeSet::new();
    for entry in manifest.entries {
        let payload = store
            .get(entry.object_key)?
            .ok_or(FileSystemError::CorruptState {
                reason: "send/receive export manifest references a missing object",
            })?;
        if checksum64(&payload) != entry.checksum {
            return Err(FileSystemError::CorruptState {
                reason: "send/receive export object checksum does not match manifest",
            });
        }
        // Collect canonical dedup targets so they are included in the
        // export even though the transaction manifest only tracks
        // per-inode keys (not content-addressed canonical keys).
        if entry.role == TransactionManifestObjectRole::VersionedContentChunk
            && is_dedup_redirect(&payload)
        {
            if let Ok(canonical_key) = decode_dedup_redirect(&payload) {
                canonical_dedup_keys.insert(canonical_key);
            }
        }
        records.push(ChangedObjectRecord {
            role: ChangedRecordObjectRole::from_manifest_role(entry.role),
            object_key: entry.object_key,
            checksum: entry.checksum,
            payload,
        });
    }

    // Include canonical dedup objects in the export.  These are not
    // tracked by the transaction manifest because they are content-
    // addressed and may be shared across files/versions.  Without
    // them the receive side cannot resolve dedup redirects.
    for canonical_key in &canonical_dedup_keys {
        if let Some(payload) = store.get(*canonical_key)? {
            records.push(ChangedObjectRecord {
                role: ChangedRecordObjectRole::VersionedContentChunk,
                object_key: *canonical_key,
                checksum: checksum64(&payload),
                payload,
            });
        }
    }

    Ok(ChangedRecordRoot {
        source_root: source_root.clone(),
        records,
    })
}

/// Validate sender authority evidence carried by a receive stream.
///
/// VFSSEND1 changed-record streams always carry [`SenderAuthorityEvidence::AbsentLocalOnly`]
/// and pass through this gate unchanged.  When VFSSEND2 streams arrive with
/// [`SenderAuthorityEvidence::Distributed`] evidence, this function performs the
/// fail-closed cross-pool authorization check:
///
/// 1. Same-pool: sender UUID matches the local pool → proceed.
/// 2. Cross-pool with authorization: every field must match the provided
///    [`CrossPoolReceiveAuthorization`] exactly → proceed.
/// 3. Cross-pool without authorization → [`FileSystemError::CrossPoolReceiveUnauthorized`].
/// 4. Authorization mismatch → [`FileSystemError::CrossPoolReceiveAuthorizationMismatch`].
///
/// This check does not replace the existing full/incremental target classification,
/// base-root, omitted-content, root-authentication, checksum, namespace, or publish
/// validation — all of those remain required after authorization passes.
pub(crate) fn validate_sender_authority_for_receive(
    authority_evidence: SenderAuthorityEvidence,
    target_pool_uuid: Id128,
    target_dataset_uuid: Id128,
    authorization: Option<&CrossPoolReceiveAuthorization>,
) -> Result<()> {
    match authority_evidence {
        SenderAuthorityEvidence::AbsentLocalOnly => {
            // Legacy local-only stream: no distributed claim, no authorization
            // needed.  Proceed directly to existing receive validation.
            Ok(())
        }
        SenderAuthorityEvidence::Distributed(sender) => {
            // Same-pool shortcut: sender is the local pool.
            if sender.sender_pool_uuid == target_pool_uuid {
                return Ok(());
            }
            // Cross-pool: require exact per-receive authorization.
            let auth = authorization.ok_or(FileSystemError::CrossPoolReceiveUnauthorized {
                sender_pool_uuid: sender.sender_pool_uuid,
            })?;
            if !auth.matches(&sender) {
                // Determine which field mismatched for operator diagnostics.
                let mismatch_field = if auth.sender_pool_uuid != sender.sender_pool_uuid {
                    "sender_pool_uuid"
                } else if auth.sender_pool_epoch != sender.sender_pool_epoch {
                    "sender_pool_epoch"
                } else {
                    "sender_membership_generation"
                };
                return Err(FileSystemError::CrossPoolReceiveAuthorizationMismatch {
                    field: mismatch_field,
                });
            }
            // Cross-pool authorization matches; proceed to existing validation.
            let _ = target_dataset_uuid;
            Ok(())
        }
    }
}

pub(crate) fn validate_changed_record_transform_contract(
    contract: ChangedRecordTransformContract,
) -> Result<()> {
    ChangedRecordTypedTransformMetadata::for_contract(contract).validate_import()
}

const CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON: &str =
    "mounted device transforms require typed transform metadata before changed-record streams can be imported";

impl ChangedRecordTypedTransformMetadata {
    fn validate_import(self) -> Result<()> {
        if self.refusal_state == ChangedRecordTransformRefusalState::MissingTypedTransformMetadata {
            return Err(FileSystemError::Unsupported {
                operation: "send/receive transform contract",
                reason: CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON,
            });
        }

        debug_assert_eq!(
            self,
            ChangedRecordTypedTransformMetadata::for_contract(
                ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
            )
        );

        if self.stored_frame_contract
            != ChangedRecordStoredFrameContract::StoredFrameNoDeviceTransforms
        {
            return Err(FileSystemError::Unsupported {
                operation: "send/receive transform contract",
                reason: CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON,
            });
        }

        if self.plaintext_identity
            != ChangedRecordPlaintextIdentity::StoredFrameBytesAreMountedPlaintext
            || self.transform_frame_identity
                != ChangedRecordTransformFrameIdentity::NotApplicableNoDeviceTransforms
            || self.checksum_layer != ChangedRecordChecksumLayer::StoredFrameBytes
        {
            return Err(FileSystemError::Unsupported {
                operation: "send/receive transform contract",
                reason: CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON,
            });
        }

        Ok(())
    }
}

pub(crate) fn validate_changed_record_export(
    export: &ChangedRecordExport,
    is_incremental: bool,
) -> Result<PreparedChangedRecordExport> {
    if export.spec != SEND_RECEIVE_CHANGED_RECORD_SPEC {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "unsupported stream spec",
        });
    }
    // stream_version: 1=full, 2=incremental, 3=full+epoch, 4=incremental+epoch
    if export.stream_version > 4 || export.stream_version == 0 {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "unsupported stream version",
        });
    }
    validate_changed_record_transform_contract(export.transform_contract)?;
    if export.roots.is_empty() {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "stream contains no committed roots",
        });
    }

    let current_identity = RootIdentity::from_summary(&export.current_root);
    if is_incremental {
        if !export.incremental {
            return Err(FileSystemError::Unsupported {
                operation: "incremental receive",
                reason: "stream is a full export; use full receive into a fresh target",
            });
        }
        let from_root = export.from_root.as_ref().ok_or(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "incremental stream is missing from_root",
        })?;
        if !from_root.has_transaction_manifest || !from_root.has_root_authentication {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "incremental from_root is not manifest-backed and authenticated",
            });
        }
        if export.current_root.transaction_id <= from_root.transaction_id {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "incremental current root is not newer than from_root",
            });
        }
        if RootIdentity::from_summary(from_root) == current_identity {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "incremental current root matches from_root",
            });
        }
        if !export
            .roots
            .iter()
            .any(|root| committed_root_stream_identity_matches(&root.source_root, from_root))
        {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "incremental from_root is not present in stream roots",
            });
        }
    } else if export.incremental || export.from_root.is_some() {
        return Err(FileSystemError::Unsupported {
            operation: "send/receive import",
            reason: "incremental stream requires incremental receive into an existing target",
        });
    }

    let mut seen_roots = BTreeSet::new();
    let mut prepared_roots = Vec::new();
    for root in &export.roots {
        let identity = RootIdentity::from_summary(&root.source_root);
        if !seen_roots.insert(identity) {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "duplicate committed root in stream",
            });
        }
        prepared_roots.push(prepare_changed_record_root(root, is_incremental)?);
    }

    let current = prepared_roots
        .iter()
        .find(|root| RootIdentity::from_summary(&root.source_root) == current_identity)
        .ok_or(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "current root is not present in stream roots",
        })?;

    for snapshot in current.state.snapshots.values() {
        if !crate::snapshot::snapshot_record_retains_data(snapshot) {
            continue;
        }
        let snapshot_identity = RootIdentity::from_summary(&snapshot.root);
        if snapshot.root.transaction_id >= export.current_root.transaction_id {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "current snapshot catalog references a future committed root",
            });
        }
        if !seen_roots.contains(&snapshot_identity) {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "current snapshot catalog references a root missing from the stream",
            });
        }
    }

    let total_records = prepared_roots
        .iter()
        .map(|root| root.records.len() as u64)
        .sum::<u64>();
    let payload_bytes = prepared_roots
        .iter()
        .flat_map(|root| root.records.values())
        .try_fold(0_u64, |sum, record| {
            sum.checked_add(record.payload.len() as u64)
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })
        })?;
    if total_records != export.total_records || payload_bytes != export.payload_bytes {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive stream",
            reason: "stream record totals do not match encoded roots",
        });
    }

    Ok(PreparedChangedRecordExport {
        current_identity,
        roots: prepared_roots,
        total_records,
        payload_bytes,
        stream_version: export.stream_version,
        placement_epoch: export.placement_epoch,
        transform_contract: export.transform_contract,
    })
}

fn committed_root_stream_identity_matches(
    candidate: &CommittedRootSummary,
    expected: &CommittedRootSummary,
) -> bool {
    candidate.transaction_id == expected.transaction_id
        && candidate.generation == expected.generation
        && candidate.next_inode_id == expected.next_inode_id
        && candidate.inode_count == expected.inode_count
        && candidate.superblock_checksum == expected.superblock_checksum
        && candidate.has_transaction_manifest
        && expected.has_transaction_manifest
        && candidate.manifest_checksum == expected.manifest_checksum
        && candidate.manifest_entry_count == expected.manifest_entry_count
        && candidate.has_root_authentication
        && expected.has_root_authentication
        && candidate.root_authentication_policy_epoch == expected.root_authentication_policy_epoch
        && candidate.root_authentication_algorithm_suite_id
            == expected.root_authentication_algorithm_suite_id
        && candidate.superblock_digest == expected.superblock_digest
        && candidate.manifest_digest == expected.manifest_digest
        && candidate.root_authentication_code == expected.root_authentication_code
}

fn manifest_role_is_content(role: TransactionManifestObjectRole) -> bool {
    matches!(
        role,
        TransactionManifestObjectRole::VersionedContent
            | TransactionManifestObjectRole::VersionedContentChunk
    )
}

fn committed_root_incremental_base_identity_matches(
    candidate: &CommittedRootSummary,
    expected: &CommittedRootSummary,
) -> bool {
    candidate.transaction_id == expected.transaction_id
        && candidate.generation == expected.generation
        && candidate.next_inode_id == expected.next_inode_id
        && candidate.inode_count == expected.inode_count
        && candidate.superblock_checksum == expected.superblock_checksum
        && candidate.has_transaction_manifest
        && expected.has_transaction_manifest
        && candidate.has_root_authentication
        && expected.has_root_authentication
        && candidate.root_authentication_policy_epoch == expected.root_authentication_policy_epoch
        && candidate.root_authentication_algorithm_suite_id
            == expected.root_authentication_algorithm_suite_id
        && candidate.superblock_digest == expected.superblock_digest
}

fn receive_base_root_identity(root: &CommittedRootSummary) -> [u8; 32] {
    *blake3::hash(&encode_root_commit(&root_commit_from_summary(root))).as_bytes()
}

fn receive_dataset_lineage_identity(
    existing: &LocalFileSystem,
    record: &SnapshotRecord,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tidefs.local.receive.dataset-lineage.v1");
    hasher.update(&existing.mounted_dataset_id());
    hasher.update(crate::snapshot::snapshot_record_catalog_name(record).as_bytes());
    hasher.update(crate::snapshot::snapshot_record_dataset_id(record).as_bytes());
    hasher.update(&record.root.transaction_id.to_le_bytes());
    hasher.update(&record.root.generation.to_le_bytes());
    hasher.update(&record.root.superblock_checksum.0.to_le_bytes());
    hasher.update(&record.root.manifest_checksum.0.to_le_bytes());
    *hasher.finalize().as_bytes()
}

struct LocalReceiveBaseRootPinLookup<'a> {
    existing: &'a LocalFileSystem,
    authorized_base: &'a CommittedRootSummary,
    completed_generation: Option<u64>,
}

impl LocalReceiveBaseRootPinLookup<'_> {
    fn authorized_record_for_identity(
        &self,
        base_root_identity: &[u8; 32],
    ) -> Option<&SnapshotRecord> {
        if *base_root_identity != receive_base_root_identity(self.authorized_base) {
            return None;
        }
        if self
            .existing
            .ensure_snapshot_authority_consistent()
            .is_err()
        {
            return None;
        }
        self.existing.state.snapshots.values().find(|record| {
            crate::snapshot::snapshot_record_retains_data(record)
                && committed_root_incremental_base_identity_matches(
                    &record.root,
                    self.authorized_base,
                )
                && self
                    .existing
                    .ensure_snapshot_record_authority(record)
                    .is_ok()
        })
    }
}

impl BaseRootPinLookup for LocalReceiveBaseRootPinLookup<'_> {
    fn is_base_root_pinned(&self, base_root_identity: &[u8; 32]) -> bool {
        self.authorized_record_for_identity(base_root_identity)
            .is_some()
    }

    fn dataset_lineage_for_base_root(&self, base_root_identity: &[u8; 32]) -> Option<[u8; 32]> {
        self.authorized_record_for_identity(base_root_identity)
            .map(|record| receive_dataset_lineage_identity(self.existing, record))
    }

    fn latest_completed_receive_generation(
        &self,
        base_root_identity: &[u8; 32],
        dataset_lineage_identity: &[u8; 32],
    ) -> Option<u64> {
        let actual_lineage = self.dataset_lineage_for_base_root(base_root_identity)?;
        if &actual_lineage == dataset_lineage_identity {
            self.completed_generation
        } else {
            None
        }
    }
}

fn receive_contract_error(error: ReceivePersistenceError) -> FileSystemError {
    if matches!(error, ReceivePersistenceError::Store(_)) {
        return FileSystemError::CorruptState {
            reason: "receive contract validation unexpectedly reached object-store persistence",
        };
    }
    FileSystemError::ReceiveStreamRefused {
        reason: error.receiver_refusal_reason(),
    }
}

fn validate_local_incremental_receive_contract(
    existing: &LocalFileSystem,
    audit: &RecoveryAuditReport,
    authorized_base: &CommittedRootSummary,
    export: &ChangedRecordExport,
) -> Result<()> {
    let pin_lookup = LocalReceiveBaseRootPinLookup {
        existing,
        authorized_base,
        completed_generation: audit
            .selected_root
            .as_ref()
            .map(|selected| selected.transaction_id),
    };
    let base_root_identity = receive_base_root_identity(authorized_base);
    let dataset_lineage_identity = pin_lookup
        .dataset_lineage_for_base_root(&base_root_identity)
        .ok_or_else(|| {
            receive_contract_error(ReceivePersistenceError::DatasetLineageUnavailable {
                base_root_identity,
            })
        })?;
    let contract = ReceiveContract {
        base_root_identity,
        dataset_lineage_identity,
        receive_generation: export.current_root.transaction_id,
    };
    validate_receive_contract(contract, &pin_lookup).map_err(receive_contract_error)
}

fn verify_incremental_base_root_authority(
    existing: &LocalFileSystem,
    audit: &RecoveryAuditReport,
    from_root: &CommittedRootSummary,
) -> Result<CommittedRootSummary> {
    existing.ensure_snapshot_authority_consistent()?;
    for record in existing.state.snapshots.values() {
        if !crate::snapshot::snapshot_record_retains_data(record) {
            continue;
        }
        if committed_root_incremental_base_identity_matches(&record.root, from_root) {
            existing.ensure_snapshot_record_authority(record)?;
            return Ok(record.root.clone());
        }
    }

    let found_in_recovery_audit = audit
        .valid_committed_roots
        .iter()
        .any(|candidate| committed_root_incremental_base_identity_matches(candidate, from_root));

    Err(FileSystemError::IncrementalReceiveBaseRootConflict {
        from_root: IncrementalReceiveBaseRootIdentity::from_summary(from_root),
        found_in_recovery_audit,
        protected_by_data_retaining_snapshot_or_clone: false,
        operator_action_guidance: INCREMENTAL_RECEIVE_BASE_ROOT_CONFLICT_OPERATOR_ACTIONS,
    })
}

pub(crate) fn prepare_changed_record_root(
    root: &ChangedRecordRoot,
    is_incremental: bool,
) -> Result<PreparedChangedRecordRoot> {
    if !root.source_root.has_transaction_manifest || !root.source_root.has_root_authentication {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "root is not manifest-backed and authenticated",
        });
    }
    let mut records = BTreeMap::new();
    for record in &root.records {
        if checksum64(&record.payload) != record.checksum {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "changed-record checksum does not match payload",
            });
        }
        if records.insert(record.object_key, record.clone()).is_some() {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "duplicate changed-record object key",
            });
        }
    }

    let root_commit = root_commit_from_summary(&root.source_root);
    let manifest_key = transaction_manifest_object_key(root_commit.transaction_id);
    let manifest_record = records.get(&manifest_key).ok_or(FileSystemError::Decode {
        object: "local filesystem send/receive root",
        reason: "root is missing its transaction manifest record",
    })?;
    if manifest_record.role != ChangedRecordObjectRole::TransactionManifest
        || manifest_record.checksum != root_commit.manifest_checksum
    {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "transaction manifest record does not match root",
        });
    }
    let manifest = decode_transaction_manifest(&manifest_record.payload)?;
    if manifest.transaction_id != root_commit.transaction_id
        || manifest.generation != root_commit.generation
        || manifest.entries.len() as u64 != root_commit.manifest_entry_count
    {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "transaction manifest does not match root",
        });
    }

    for entry in &manifest.entries {
        let record = records.get(&entry.object_key);
        let record = match record {
            Some(r) => r,
            None => {
                // Incremental send/receive omits unchanged content records
                // (VersionedContent / VersionedContentChunk) from the stream.
                // The receiver already has them from the baseline state, so
                // skipping them here is correct.
                if is_incremental && manifest_role_is_content(entry.role) {
                    continue;
                }
                return Err(FileSystemError::Decode {
                    object: "local filesystem send/receive root",
                    reason: "manifest entry is missing from changed-record stream",
                });
            }
        };
        if record.role.to_manifest_role() != Some(entry.role) || record.checksum != entry.checksum {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "changed-record role or checksum does not match manifest",
            });
        }
    }
    // TFR-010: canonical dedup records are extra send/receive state.
    // The transaction manifest tracks per-inode chunk keys, but
    // content-addressed dedup redirects reference canonical keys
    // that are not part of the manifest.  The sender includes
    // them so the receiver can resolve dedup redirects.
    let min_expected_records = if is_incremental {
        // Incremental streams omit unchanged content records, so
        // the record count may be lower than manifest entry count.
        1 // at minimum: the manifest itself plus any structural records
    } else {
        manifest.entries.len().saturating_add(1)
    };
    if records.len() < min_expected_records {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "stream root is missing records referenced by the transaction manifest",
        });
    }

    let (state, inode_key_map, dir_key_map) =
        load_state_from_changed_records(&records, &root_commit, &manifest, is_incremental)?;
    validate_transaction_manifest_matches_changed_records(
        &records,
        &root_commit,
        &state,
        &manifest,
        &inode_key_map,
        &dir_key_map,
        is_incremental,
    )?;
    Ok(PreparedChangedRecordRoot {
        source_root: root.source_root.clone(),
        state,
        records,
    })
}

pub(crate) fn load_state_from_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    root: &RootCommitRecord,
    manifest: &TransactionManifestRecord,
    is_incremental: bool,
) -> Result<LoadedStateWithObjectMaps> {
    let superblock_key = transaction_superblock_object_key(root.transaction_id);
    let superblock_bytes = changed_record_payload(records, superblock_key)?;
    if checksum64(superblock_bytes) != root.superblock_checksum {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "superblock checksum does not match root",
        });
    }
    let root_authentication = root.root_authentication.ok_or(FileSystemError::Decode {
        object: "local filesystem send/receive root",
        reason: "root authentication record is missing",
    })?;
    let actual_superblock_digest =
        root_authentication_digest(ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN, superblock_bytes);
    if Some(actual_superblock_digest) != root.summary().superblock_digest {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "superblock digest does not match root authentication record",
        });
    }
    let manifest_bytes = changed_record_payload(
        records,
        transaction_manifest_object_key(root.transaction_id),
    )?;
    if checksum64(manifest_bytes) != root.manifest_checksum {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "manifest checksum does not match root",
        });
    }
    let actual_manifest_digest =
        root_authentication_digest(ROOT_AUTHENTICATION_MANIFEST_DOMAIN, manifest_bytes);
    if actual_manifest_digest != root_authentication.manifest_digest {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "manifest digest does not match root authentication record",
        });
    }

    let (superblock, _legacy_snapshots) = decode_superblock(superblock_bytes)?;
    if superblock.generation != root.generation
        || superblock.next_inode_id != root.next_inode_id
        || superblock.inode_count != root.inode_count
    {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "superblock fields do not match root",
        });
    }
    if manifest.transaction_id != root.transaction_id || manifest.generation != root.generation {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "manifest fields do not match root",
        });
    }
    let (state, inode_key_map, dir_key_map) = load_state_from_superblock_changed_records(
        records,
        &superblock,
        root.transaction_id,
        &manifest.entries,
        is_incremental,
    )?;
    Ok((state, inode_key_map, dir_key_map))
}

pub(crate) fn load_state_from_superblock_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    superblock: &SuperblockRecord,
    transaction_id: u64,
    manifest_entries: &[TransactionManifestEntry],
    is_incremental: bool,
) -> Result<LoadedStateWithObjectMaps> {
    // Build inode_id → object_key mappings from the manifest entries.
    // This is necessary because clean (unchanged) inodes and directories
    // may reference keys from previous transactions, not the current one.
    // The manifest is the authoritative source for which keys belong to
    // which logical objects.
    let mut inode_key_map: BTreeMap<InodeId, ObjectKey> = BTreeMap::new();
    let mut dir_key_map: BTreeMap<InodeId, ObjectKey> = BTreeMap::new();
    for entry in manifest_entries {
        match entry.role {
            TransactionManifestObjectRole::TransactionInode => {
                let record = records
                    .get(&entry.object_key)
                    .ok_or(FileSystemError::Decode {
                        object: "local filesystem send/receive root",
                        reason: "manifest inode entry is missing from changed-record stream",
                    })?;
                let inode = decode_inode(&record.payload)?;
                inode_key_map.insert(inode.inode_id, entry.object_key);
            }
            TransactionManifestObjectRole::TransactionDirectory => {
                // Decode the directory payload to find its owning inode_id.
                let record = records
                    .get(&entry.object_key)
                    .ok_or(FileSystemError::Decode {
                        object: "local filesystem send/receive root",
                        reason: "manifest directory entry is missing from changed-record stream",
                    })?;
                let dir_inode_id = decode_directory_inode_id(&record.payload)?;
                dir_key_map.insert(dir_inode_id, entry.object_key);
            }
            _ => {}
        }
    }

    let mut inodes = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut extent_maps = BTreeMap::new();
    let mut last_extent_map_write_tx = BTreeMap::new();
    for (word_idx, word) in superblock.inode_allocation_bitmap.iter().enumerate() {
        let mut bits = *word;
        while bits != 0 {
            let bit = bits.trailing_zeros();
            bits &= bits - 1;
            let inode_id = InodeId::new((word_idx * 64 + bit as usize + 1) as u64);
            let inode_key =
                inode_key_map
                    .get(&inode_id)
                    .copied()
                    .ok_or(FileSystemError::Decode {
                        object: "local filesystem send/receive root",
                        reason: "inode allocated in superblock has no corresponding manifest entry",
                    })?;
            let inode = decode_inode(changed_record_payload(records, inode_key)?)?;
            if inode.inode_id != inode_id {
                return Err(FileSystemError::Decode {
                    object: "local filesystem send/receive root",
                    reason: "inode record id does not match superblock",
                });
            }
            if inode.kind() == NodeKind::Dir {
                let directory_key =
                    dir_key_map
                        .get(&inode_id)
                        .copied()
                        .ok_or(FileSystemError::Decode {
                            object: "local filesystem send/receive root",
                            reason: "directory inode has no corresponding directory manifest entry",
                        })?;
                directories.insert(
                    inode_id,
                    decode_directory(changed_record_payload(records, directory_key)?)?,
                );
            }
            inodes.insert(inode_id, inode);
        }
    }
    for entry in manifest_entries {
        if entry.role != TransactionManifestObjectRole::TransactionExtentMap {
            continue;
        }
        let record = records
            .get(&entry.object_key)
            .ok_or(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "manifest extent-map entry is missing from changed-record stream",
            })?;
        if record.role != ChangedRecordObjectRole::TransactionExtentMap {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "extent-map changed-record role does not match manifest",
            });
        }
        let inode_id = inodes
            .keys()
            .copied()
            .find(|inode_id| {
                transaction_extent_map_object_key(transaction_id, *inode_id) == entry.object_key
            })
            .ok_or(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "extent-map manifest key does not match a received inode",
            })?;
        let mut cursor = Cursor::new(record.payload.as_slice());
        let extent_map =
            ExtentMap::deserialize(&mut cursor).map_err(|_| FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "extent-map payload did not decode",
            })?;
        extent_maps.insert(inode_id, extent_map);
        last_extent_map_write_tx.insert(inode_id, transaction_id);
    }
    validate_loaded_state_changed_records(records, &inodes, &directories, is_incremental)?;
    // v3+: snapshots are stored as separate catalog objects, not in the superblock.
    // Send/receive transports the catalog entries separately via changed records.
    let mut snapshots = BTreeMap::new();
    for record in records.values() {
        // Snapshot catalog entries have object keys matching the snapshot catalog prefix.
        // We detect them by checking the changed record role.
        if record.role == ChangedRecordObjectRole::TransactionSnapshotCatalogEntry {
            let snapshot = decode_snapshot_record(&record.payload)?;
            if snapshots.insert(snapshot.name.clone(), snapshot).is_some() {
                return Err(FileSystemError::Decode {
                    object: "local filesystem send/receive root",
                    reason: "duplicate snapshot name in changed records",
                });
            }
        }
    }
    let known_inode_ids: BTreeSet<InodeId> = inodes.keys().cloned().collect();
    let state = FileSystemState {
        inode_authority: DatasetInodeAuthority::from_recovered_inode_ids(
            ROOT_DATASET_ID,
            superblock.next_inode_id,
            known_inode_ids.iter().copied(),
        ),
        generation: superblock.generation.max(1),
        inodes: Arc::new(inodes),
        directories: Arc::new(directories),
        snapshots,
        dirty_content: BTreeSet::new(),
        dirty_inodes: BTreeSet::new(),
        dirty_dirs: BTreeSet::new(),
        last_inode_write_tx: BTreeMap::new(),
        last_dir_write_tx: BTreeMap::new(),
        quota_table: QuotaTable::new(),
        space_accounting: SpaceAccounting::empty(),
        known_inode_ids,
        change_streams: BTreeMap::new(),
        extent_maps: Arc::new(Mutex::new(extent_maps)),
        dirty_extent_maps: BTreeSet::new(),
        last_extent_map_write_tx,
        content_compression_policy: ContentCompressionPolicy::default(),
    };
    Ok((state, inode_key_map, dir_key_map))
}

pub(crate) fn validate_loaded_state_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    is_incremental: bool,
) -> Result<()> {
    validate_namespace_invariants(inodes, directories)?;
    for inode in inodes.values() {
        if inode.is_file_like() {
            // Incremental streams omit content records for
            // unchanged objects; skip validation when the
            // content key is absent from the stream.
            let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
            if is_incremental && !records.contains_key(&content_key) {
                continue;
            }
            let _ = read_content_from_changed_records(records, inode.inode_id, inode)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_transaction_manifest_matches_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    root: &RootCommitRecord,
    state: &FileSystemState,
    manifest: &TransactionManifestRecord,
    inode_key_map: &BTreeMap<InodeId, ObjectKey>,
    dir_key_map: &BTreeMap<InodeId, ObjectKey>,
    is_incremental: bool,
) -> Result<()> {
    let mut expected = Vec::new();
    for inode in state.inodes.values() {
        if inode.is_file_like() {
            expected.extend(transaction_manifest_entries_for_content_changed_records(
                records,
                inode,
                is_incremental,
            )?);
        }

        let inode_key =
            inode_key_map
                .get(&inode.inode_id)
                .copied()
                .ok_or(FileSystemError::Decode {
                    object: "local filesystem send/receive root",
                    reason: "inode has no corresponding key in manifest",
                })?;
        expected.push(TransactionManifestEntry {
            role: TransactionManifestObjectRole::TransactionInode,
            object_key: inode_key,
            checksum: checksum64(changed_record_payload(records, inode_key)?),
        });

        if inode.kind() == NodeKind::Dir {
            let directory_key =
                dir_key_map
                    .get(&inode.inode_id)
                    .copied()
                    .ok_or(FileSystemError::Decode {
                        object: "local filesystem send/receive root",
                        reason: "directory inode has no corresponding key in manifest",
                    })?;
            expected.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::TransactionDirectory,
                object_key: directory_key,
                checksum: checksum64(changed_record_payload(records, directory_key)?),
            });
        }
    }

    for entry in manifest
        .entries
        .iter()
        .filter(|entry| entry.role == TransactionManifestObjectRole::TransactionExtentMap)
    {
        expected.push(TransactionManifestEntry {
            role: TransactionManifestObjectRole::TransactionExtentMap,
            object_key: entry.object_key,
            checksum: checksum64(changed_record_payload(records, entry.object_key)?),
        });
    }

    let superblock_key = transaction_superblock_object_key(root.transaction_id);
    expected.push(TransactionManifestEntry {
        role: TransactionManifestObjectRole::TransactionSuperblock,
        object_key: superblock_key,
        checksum: checksum64(changed_record_payload(records, superblock_key)?),
    });

    // Include snapshot catalog entries in the expected manifest.
    // v3+ snapshots are stored as separate catalog objects per
    // transaction; the manifest must account for them.
    for (snapshot_name, _snapshot) in state.snapshots.iter() {
        let snap_key =
            transaction_snapshot_catalog_entry_object_key(root.transaction_id, snapshot_name);
        expected.push(TransactionManifestEntry {
            role: TransactionManifestObjectRole::TransactionSnapshotCatalogEntry,
            object_key: snap_key,
            checksum: checksum64(changed_record_payload(records, snap_key)?),
        });
    }

    // For incremental streams, the expected set excludes content
    // entries for unchanged objects (which the sender omitted).
    // Filter the manifest to match the expected scope before comparing.
    let compare_entries: Vec<&TransactionManifestEntry> = if is_incremental {
        manifest
            .entries
            .iter()
            .filter(|e| {
                !matches!(
                    e.role,
                    TransactionManifestObjectRole::VersionedContent
                        | TransactionManifestObjectRole::VersionedContentChunk
                ) || expected.iter().any(|x| x.object_key == e.object_key)
            })
            .collect()
    } else {
        manifest.entries.iter().collect()
    };
    if compare_entries.len() != expected.len()
        || compare_entries
            .iter()
            .zip(expected.iter())
            .any(|(a, b)| *a != b)
    {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "manifest does not exactly match changed-record payloads",
        });
    }
    Ok(())
}

pub(crate) fn transaction_manifest_entries_for_content_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    inode: &InodeRecord,
    is_incremental: bool,
) -> Result<Vec<TransactionManifestEntry>> {
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    let content_bytes = match records.get(&content_key) {
        Some(record) => record.payload.as_slice(),
        None => {
            if inode.size == 0 {
                return Ok(Vec::new());
            }
            // Incremental streams omit unchanged content records.
            // Return an empty manifest entry set for this inode.
            if is_incremental {
                return Ok(Vec::new());
            }
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "changed-record object is missing",
            });
        }
    };
    let layout = decode_content_layout(content_bytes)?;
    validate_content_layout(inode.inode_id, inode, &layout)?;

    let mut entries = vec![TransactionManifestEntry {
        role: TransactionManifestObjectRole::VersionedContent,
        object_key: content_key,
        checksum: checksum64(content_bytes),
    }];
    if let ContentLayout::Chunked(manifest) = layout {
        for chunk_ref in &manifest.chunks {
            let object_key = content_chunk_object_key_for_version(
                manifest.inode_id,
                chunk_ref.data_version,
                chunk_ref.chunk_index,
            );
            let _chunk =
                read_content_chunk_from_changed_records(records, manifest.inode_id, chunk_ref)?;
            // read_content_chunk_from_changed_records already performs
            // dedup-aware metadata validation (inode_id, data_version,
            // chunk_index checks are skipped for dedup-resolved chunks).
            entries.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::VersionedContentChunk,
                object_key,
                checksum: chunk_ref.checksum,
            });
        }
    }
    Ok(entries)
}

pub(crate) fn read_content_from_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    inode_id: InodeId,
    record: &InodeRecord,
) -> Result<Vec<u8>> {
    match read_content_layout_from_changed_records(records, inode_id, record)? {
        ContentLayout::Inline(content) => Ok(content.bytes),
        ContentLayout::Chunked(manifest) => {
            let capacity =
                usize::try_from(record.size).map_err(|_| FileSystemError::SizeOverflow {
                    requested: record.size,
                })?;
            let mut out = Vec::with_capacity(capacity);
            for chunk_ref in &manifest.chunks {
                let chunk =
                    read_content_chunk_from_changed_records(records, manifest.inode_id, chunk_ref)?;
                out.extend_from_slice(&chunk.bytes);
            }
            if u64::try_from(out.len()).unwrap_or(u64::MAX) != record.size {
                return Err(FileSystemError::Decode {
                    object: "local filesystem send/receive root",
                    reason: "chunked content size does not match inode",
                });
            }
            Ok(out)
        }
    }
}

pub(crate) fn read_content_layout_from_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    inode_id: InodeId,
    record: &InodeRecord,
) -> Result<ContentLayout> {
    let bytes = changed_record_payload(
        records,
        content_object_key_for_version(inode_id, record.data_version),
    )?;
    let layout = decode_content_layout(bytes)?;
    validate_content_layout(inode_id, record, &layout)?;
    Ok(layout)
}

pub(crate) fn read_content_chunk_from_changed_records(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    inode_id: InodeId,
    chunk_ref: &ContentChunkRef,
) -> Result<ContentChunkObject> {
    // Hole (sparse) chunks have no backing data in the changed-record stream.
    if chunk_ref.is_hole() {
        let bytes = vec![0_u8; chunk_ref.len as usize];
        return Ok(ContentChunkObject {
            inode_id,
            data_version: 0,
            chunk_index: chunk_ref.chunk_index,
            bytes,
        });
    }
    let key = content_chunk_object_key_for_version(
        inode_id,
        chunk_ref.data_version,
        chunk_ref.chunk_index,
    );
    let bytes = changed_record_payload(records, key)?;
    if checksum64(bytes) != chunk_ref.checksum {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "content chunk checksum does not match manifest",
        });
    }
    let chunk_bytes: &[u8] = if is_dedup_redirect(bytes) {
        let canonical_key = decode_dedup_redirect(bytes)?;
        records
            .get(&canonical_key)
            .map(|rec| rec.payload.as_slice())
            .ok_or(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "dedup redirect references a missing canonical changed-record object",
            })?
    } else {
        bytes
    };
    let chunk = decode_content_chunk(chunk_bytes)?;
    // For dedup-resolved chunks, skip inode_id, data_version, and
    // chunk_index checks: the canonical data may differ on all three
    // fields from the redirect reference (#841).
    let dedup_resolved = is_dedup_redirect(bytes);
    if (!dedup_resolved
        && (chunk.inode_id != inode_id
            || chunk.data_version != chunk_ref.data_version
            || chunk.chunk_index != chunk_ref.chunk_index))
        || chunk.bytes.len() != chunk_ref.len as usize
    {
        return Err(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "content chunk fields do not match manifest",
        });
    }
    Ok(chunk)
}

pub(crate) fn changed_record_payload(
    records: &BTreeMap<ObjectKey, ChangedObjectRecord>,
    key: ObjectKey,
) -> Result<&[u8]> {
    records
        .get(&key)
        .map(|record| record.payload.as_slice())
        .ok_or(FileSystemError::Decode {
            object: "local filesystem send/receive root",
            reason: "changed-record object is missing",
        })
}

fn validate_incremental_content_entry_payload(
    store: &LocalObjectStore,
    entry: &TransactionManifestEntry,
    missing_reason: &'static str,
    checksum_reason: &'static str,
) -> Result<()> {
    let payload = store
        .get(entry.object_key)?
        .ok_or(FileSystemError::Decode {
            object: "local filesystem incremental receive target",
            reason: missing_reason,
        })?;
    if checksum64(&payload) != entry.checksum {
        return Err(FileSystemError::Decode {
            object: "local filesystem incremental receive target",
            reason: checksum_reason,
        });
    }
    Ok(())
}

fn validate_omitted_incremental_content_manifest(
    store: &LocalObjectStore,
    root: &PreparedChangedRecordRoot,
    entry: &TransactionManifestEntry,
) -> Result<()> {
    let inode = root
        .state
        .inodes
        .values()
        .find(|inode| {
            inode.is_file_like()
                && content_object_key_for_version(inode.inode_id, inode.data_version)
                    == entry.object_key
        })
        .ok_or(FileSystemError::Decode {
            object: "local filesystem incremental receive target",
            reason: "omitted content manifest has no matching file inode",
        })?;

    let _content =
        read_untrusted_raw_content_from_store_for_integrity(store, inode.inode_id, inode, true)?;
    Ok(())
}

fn validate_incremental_content_objects(
    store: &LocalObjectStore,
    prepared: &PreparedChangedRecordExport,
    omitted_only: bool,
) -> Result<()> {
    for root in &prepared.roots {
        let manifest_key = transaction_manifest_object_key(root.source_root.transaction_id);
        let manifest_record = root
            .records
            .get(&manifest_key)
            .ok_or(FileSystemError::Decode {
                object: "local filesystem send/receive root",
                reason: "incremental receive root is missing its transaction manifest record",
            })?;
        let manifest = decode_transaction_manifest(&manifest_record.payload)?;

        for entry in manifest
            .entries
            .iter()
            .filter(|entry| manifest_role_is_content(entry.role))
        {
            let stream_carries_entry = root.records.contains_key(&entry.object_key);
            if stream_carries_entry {
                if omitted_only {
                    continue;
                }
                validate_incremental_content_entry_payload(
                    store,
                    entry,
                    "content object required by incoming manifest is missing from target",
                    "content object required by incoming manifest failed checksum validation",
                )?;
                continue;
            }

            match entry.role {
                TransactionManifestObjectRole::VersionedContent => {
                    validate_omitted_incremental_content_manifest(store, root, entry)?;
                }
                TransactionManifestObjectRole::VersionedContentChunk => {
                    validate_incremental_content_entry_payload(
                        store,
                        entry,
                        "omitted content object required by incremental base is missing from target",
                        "omitted content object required by incremental base failed checksum validation",
                    )?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_incremental_target_content_objects(
    store: &LocalObjectStore,
    prepared: &PreparedChangedRecordExport,
) -> Result<()> {
    validate_incremental_content_objects(store, prepared, false)
}

fn validate_incremental_omitted_content_objects(
    store: &LocalObjectStore,
    prepared: &PreparedChangedRecordExport,
) -> Result<()> {
    validate_incremental_content_objects(store, prepared, true)
}

fn target_has_incremental_base_root_slot(
    store: &LocalObjectStore,
    from_root: &CommittedRootSummary,
) -> Result<bool> {
    for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        let slot_key = root_slot_object_key(slot);
        for location in store.version_locations_of(slot_key).into_iter().rev() {
            let bytes = match store.get_at_location(location) {
                Ok(bytes) => bytes,
                Err(err) if crate::is_skippable_store_error(&err) => continue,
                Err(err) => return Err(FileSystemError::from(err)),
            };
            let root = match decode_root_commit(&bytes) {
                Ok(root) => root,
                Err(_) => continue,
            };
            if root.slot != slot {
                continue;
            }
            if committed_root_incremental_base_identity_matches(&root.summary(), from_root) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn incremental_receive_placement_verified_stable(
    local_epoch: Option<u64>,
    stream_epoch: Option<u64>,
) -> Result<bool> {
    match (local_epoch, stream_epoch) {
        (Some(local_epoch), Some(stream_epoch)) if local_epoch == stream_epoch => Ok(true),
        (Some(_), Some(_)) => Err(FileSystemError::Unsupported {
            operation: "incremental receive",
            reason: "stream placement epoch does not match target placement epoch",
        }),
        _ => Ok(false),
    }
}

pub(crate) fn receive_changed_records_into_empty_root(
    root: &Path,
    options: StoreOptions,
    export: &ChangedRecordExport,
    root_authentication_key: RootAuthenticationKey,
    target_pool_uuid: Id128,
    target_dataset_uuid: Id128,
    authorization: Option<&CrossPoolReceiveAuthorization>,
) -> Result<ChangedRecordImportReport> {
    if export.incremental || export.from_root.is_some() {
        return Err(FileSystemError::Unsupported {
            operation: "send/receive import",
            reason: "incremental stream requires incremental receive into an existing target",
        });
    }
    if root.exists() {
        return Err(FileSystemError::Unsupported {
            operation: "send/receive import",
            reason: "receive target root must not already exist",
        });
    }
    let prepared = validate_changed_record_export(export, false)?;

    // Validate sender authority before staging any object payloads.
    // VFSSEND1 streams are always AbsentLocalOnly and pass through.
    validate_sender_authority_for_receive(
        export.sender_authority(),
        target_pool_uuid,
        target_dataset_uuid,
        authorization,
    )?;
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| fs_io_error("create_dir_all", parent, source))?;
    let staging = receive_staging_root(root)?;

    // Try to resume from an interrupted prior attempt.
    let skip_keys = if staging.exists() {
        let export_id = compute_export_identity(export);
        match try_load_checkpoint_for_resume(&staging, &options, export_id) {
            Ok(Some(cp)) => {
                // Matching checkpoint found: resume from completed keys.
                cp.completed_keys
            }
            Ok(None) | Err(_) => {
                // No usable checkpoint: clean staging and start fresh.
                let _ = fs::remove_dir_all(&staging);
                BTreeSet::new()
            }
        }
    } else {
        BTreeSet::new()
    };

    let result = receive_changed_records_into_staging_with_skip(
        root,
        &staging,
        options,
        prepared,
        root_authentication_key,
        &skip_keys,
    );
    match result {
        Ok((report, _newly_persisted)) => Ok(report),
        Err(e) => {
            // Per RECEIVE_STREAM_MERGE_POLICY §2.2: preserve staging
            // and checkpoint on retryable errors so a retry can resume;
            // remove staging on non-retryable errors that make the
            // checkpoint unrecoverable (export identity mismatch,
            // decode failure, target pool corruption).
            if !is_receive_error_retryable(&e) {
                let _ = fs::remove_dir_all(&staging);
            }
            // Return the original error unchanged regardless of cleanup;
            // the caller decides whether to retry.
            Err(e)
        }
    }
}

pub(crate) fn rewrite_snapshot_roots_for_import(
    state: &mut FileSystemState,
    imported_summaries: &BTreeMap<RootIdentity, CommittedRootSummary>,
    require_all: bool,
) -> Result<()> {
    for snapshot in state.snapshots.values_mut() {
        if !crate::snapshot::snapshot_record_retains_data(snapshot) {
            continue;
        }
        let identity = RootIdentity::from_summary(&snapshot.root);
        if let Some(imported) = imported_summaries.get(&identity) {
            snapshot.root = imported.clone();
        } else if require_all {
            return Err(FileSystemError::Decode {
                object: "local filesystem send/receive stream",
                reason: "current snapshot root was not imported before the current root",
            });
        }
    }
    Ok(())
}

fn receive_completed_content_record_is_valid(
    store: &LocalObjectStore,
    record: &ChangedObjectRecord,
) -> Result<bool> {
    let Some(payload) = store.get(record.object_key)? else {
        return Ok(false);
    };
    Ok(checksum64(&payload) == record.checksum)
}

fn normalize_received_content_receipts(
    pool: &mut Pool,
    state: &FileSystemState,
    normalized_content: &mut BTreeSet<ObjectKey>,
) -> Result<()> {
    let mut dedup_index = DedupIndex::new();
    for inode in state.inodes.values() {
        if !inode.is_file_like() || inode.size == 0 {
            continue;
        }
        let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
        if !normalized_content.insert(content_key) {
            continue;
        }
        // Decode imported bytes without trusting the sender's placement receipt,
        // then rewrite once through the target pool so root manifests stay stable.
        let content = read_untrusted_raw_content_from_store_for_integrity(
            pool.raw_primary_store(),
            inode.inode_id,
            inode,
            true,
        )?;
        let mut store = pool.pool_store_mut();
        write_chunked_content(
            false,
            &mut store,
            inode,
            &content,
            &mut dedup_index,
            None,
            &state.content_compression_policy,
        )?;
    }
    Ok(())
}

pub(crate) fn receive_staging_root(root: &Path) -> Result<PathBuf> {
    let parent = root.parent().unwrap_or_else(|| Path::new("."));
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tidefs-receive");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FileSystemError::Unsupported {
            operation: "send/receive import",
            reason: "system clock is before unix epoch",
        })?
        .as_nanos();
    Ok(parent.join(format!(
        ".{name}.receive-staging-{}-{nanos}",
        std::process::id()
    )))
}

pub(crate) fn sync_directory_path(path: &Path) -> Result<()> {
    let directory = fs::File::open(path).map_err(|source| fs_io_error("open", path, source))?;
    directory
        .sync_all()
        .map_err(|source| fs_io_error("sync_all", path, source))
}

/// Classify a receive error as retryable (staging checkpoint preserved)
/// or non-retryable (staging checkpoint discarded).
///
/// Retryable errors include transient storage failures that can plausibly
/// succeed on retry. Non-retryable errors include export identity mismatches,
/// stream decode failures, deterministic store/configuration failures, and
/// target pool corruption that permanently invalidates the receive checkpoint.
///
/// Per `docs/RECEIVE_STREAM_MERGE_POLICY.md` §2.2.
fn is_receive_error_retryable(err: &FileSystemError) -> bool {
    match err {
        FileSystemError::Store(store_err) => is_receive_store_error_retryable(store_err),
        // I/O errors during the publish step are retryable.
        FileSystemError::PublishOutcomeUncertain { .. } => true,
        // Decode errors mean the stream is malformed — not retryable.
        FileSystemError::Decode { .. } => false,
        // Unsupported operations mean the stream is structurally wrong.
        FileSystemError::Unsupported { .. } => false,
        // Target pool corruption invalidates the base root.
        FileSystemError::CorruptState { .. } => false,
        // All other errors default to non-retryable (fail closed).
        _ => false,
    }
}

fn is_receive_store_error_retryable(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::Io { .. } | StoreError::NoSpace | StoreError::PressureRefused { .. }
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_incremental_changed_records(
    root: &Path,
    options: StoreOptions,
    export: &ChangedRecordExport,
    root_authentication_key: RootAuthenticationKey,
    target_pool_uuid: Id128,
    target_dataset_uuid: Id128,
    authorization: Option<&CrossPoolReceiveAuthorization>,
    merge_plan: Option<&crate::receive_merge_planner::ReceiveMergePlan>,
) -> Result<ChangedRecordImportReport> {
    // No staging directory and no checkpoint — this function persists
    // directly to the target object store.  Errors propagate without
    // cleanup because partial object puts are unreferenced until a root
    // slot is published.  See `is_receive_error_retryable` for error
    // classification shared with the empty-target staging path.
    if !export.incremental {
        return Err(FileSystemError::Unsupported {
            operation: "incremental receive",
            reason: "stream is not an incremental export",
        });
    }
    let from_root = export.from_root.as_ref().ok_or(FileSystemError::Decode {
        object: "local filesystem send/receive stream",
        reason: "incremental stream is missing from_root",
    })?;
    if !root.exists() {
        return Err(FileSystemError::Unsupported {
            operation: "incremental receive",
            reason: "target filesystem must already exist (containing the base snapshot)",
        });
    }

    let prepared = validate_changed_record_export(export, true)?;

    // Validate sender authority before staging any object payloads.
    // VFSSEND1 streams are always AbsentLocalOnly and pass through.
    validate_sender_authority_for_receive(
        export.sender_authority(),
        target_pool_uuid,
        target_dataset_uuid,
        authorization,
    )?;

    let mut preflight_pool = LocalFileSystem::default_development_pool(root, &options, None, None)?;
    let preflight_store = preflight_pool.raw_primary_store_mut();
    if target_has_incremental_base_root_slot(preflight_store, from_root)? {
        validate_incremental_omitted_content_objects(preflight_store, &prepared)?;
    }
    drop(preflight_pool);

    // Determine whether the merge plan relaxes the fail-closed gate
    // (`docs/RECEIVE_STREAM_MERGE_POLICY.md` §1.3).  When a merge plan is
    // present, the receive proceeds with per-object decisions instead of
    // requiring a pinned base root on the target.
    let (authorized_base, placement_verified_stable) = if merge_plan.is_some() {
        // Gate relaxed: use the merge plan's common-ancestor identity.
        // The receive does not require the base root to be pinned on the
        // target; per-object decisions from the merge plan govern which
        // stream objects are imported.
        let existing = LocalFileSystem::open_with_root_authentication_key(
            root,
            options.clone(),
            root_authentication_key,
        )?;
        let placement_verified_stable = incremental_receive_placement_verified_stable(
            existing.placement_epoch,
            export.placement_epoch,
        )?;
        drop(existing);
        // Use from_root from the export as the nominal base.  When the base
        // root does not exist on the target, the import skips base-state
        // validation and proceeds with merge-plan object-level control.
        (from_root.clone(), placement_verified_stable)
    } else {
        // Fail-closed gate: verify the base root exists in the target
        // filesystem and is protected by the local snapshot/catalog/
        // lifecycle-pin authority.
        let mut existing = LocalFileSystem::open_with_root_authentication_key(
            root,
            options.clone(),
            root_authentication_key,
        )?;
        let audit = existing.recovery_audit()?;
        let stream_lineage = ReceiveMergeStreamLineageManifest::from_changed_record_export(export);
        let _common_ancestor = locate_common_ancestor(&stream_lineage, &audit)?;
        let authorized_base = verify_incremental_base_root_authority(&existing, &audit, from_root)?;
        validate_local_incremental_receive_contract(&existing, &audit, &authorized_base, export)?;
        let placement_verified_stable = incremental_receive_placement_verified_stable(
            existing.placement_epoch,
            export.placement_epoch,
        )?;
        drop(existing);
        (authorized_base, placement_verified_stable)
    };

    // Prove base content first, then apply changed content and prove every
    // incoming manifest content reference before publishing a new root slot.
    let mut pool = LocalFileSystem::default_development_pool(root, &options, None, None)?;

    // When the merge plan is present, the target may not hold the base root;
    // base-state loading and omitted-content validation are skipped.  Object-
    // level import decisions come from the merge plan instead.
    let has_merge_plan = merge_plan.is_some();
    {
        let store = pool.raw_primary_store_mut();
        if !has_merge_plan {
            let base_root = root_commit_from_summary(&authorized_base);
            let _base_state =
                load_state_from_transaction(store, &base_root, root_authentication_key)?;
        }

        for root_rec in &prepared.roots {
            for record in root_rec.records.values() {
                if matches!(
                    record.role,
                    ChangedRecordObjectRole::VersionedContent
                        | ChangedRecordObjectRole::VersionedContentChunk
                ) {
                    // When a merge plan is present, consult it for per-object
                    // import decisions: skip objects marked KeepLocal so the
                    // target's existing version is preserved.
                    if !should_import_object(merge_plan, &record.object_key) {
                        continue;
                    }
                    store.put(record.object_key, &record.payload)?;
                }
            }
        }
        if !has_merge_plan {
            validate_incremental_target_content_objects(store, &prepared)?;
        }
    }

    // Persist all roots (re-signing with the target's authentication key).
    let mut roots = prepared.roots.clone();
    roots.sort_by_key(|r| r.source_root.transaction_id);
    let mut imported_summaries = BTreeMap::new();
    let mut normalized_content = BTreeSet::new();
    let mut selected_summary = None;
    let mut snapshot_catalog_entries = 0_usize;

    for root_rec in roots {
        let identity = RootIdentity::from_summary(&root_rec.source_root);
        let mut state = root_rec.state.clone();
        rewrite_snapshot_roots_for_import(
            &mut state,
            &imported_summaries,
            identity == prepared.current_identity,
        )?;
        normalize_received_content_receipts(&mut pool, &state, &mut normalized_content)?;
        let unsigned_root = persist_transaction_objects(
            pool.raw_primary_store_mut(),
            &state,
            root_rec.source_root.transaction_id,
        )?;
        let signed_root = sign_root_commit(&unsigned_root, root_authentication_key)?;
        pool.raw_primary_store_mut().put(
            root_slot_object_key(signed_root.slot),
            &encode_root_commit(&signed_root),
        )?;
        let summary = signed_root.summary();
        if identity == prepared.current_identity {
            snapshot_catalog_entries = state.snapshots.len();
            selected_summary = Some(summary.clone());
        }
        imported_summaries.insert(identity, summary);
    }
    let final_audit = {
        let store = pool.raw_primary_store_mut();
        store.sync_all()?;
        crate::recovery::audit_recovery_store(store, root_authentication_key)?
    };
    drop(pool);

    let selected = selected_summary.ok_or(FileSystemError::CorruptState {
        reason: "incremental receive did not publish the selected root",
    })?;
    if final_audit.selected_root.as_ref() != Some(&selected) {
        return Err(FileSystemError::CorruptState {
            reason: "incremental receive selected a root other than the received current root",
        });
    }

    Ok(ChangedRecordImportReport {
        spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
        target_root: root.to_path_buf(),
        imported_roots: imported_summaries.len() as u64,
        imported_records: prepared.total_records,
        imported_payload_bytes: prepared.payload_bytes,
        selected_generation: selected.generation,
        selected_transaction_id: selected.transaction_id,
        snapshot_catalog_entries,
        stream_version: prepared.stream_version,
        staging_validated_before_publish: true,
        destination_root_reauthentication: true,
        production_fsck_required: false,
        placement_epoch: export.placement_epoch,
        placement_verified_stable,
    })
}

/// Verify that the placement epoch in an import report matches the
/// local placement epoch.  Returns `true` when the stream was exported
/// under the same placement version that the receiver currently holds.
///
/// Callers should check this after every receive to detect placement
/// changes that occurred between export and import.
#[must_use]
pub fn verify_placement_stable(
    local_epoch: Option<u64>,
    report: &ChangedRecordImportReport,
) -> bool {
    matches!(
        (local_epoch, report.placement_epoch),
        (Some(local_epoch), Some(stream_epoch)) if local_epoch == stream_epoch
    )
}

// ── Receive checkpoint: durable resume for interrupted streams ──────────────

/// Persistent checkpoint written to the staging store during receive so that
/// a crashed or interrupted stream can resume from the last persisted object
/// without duplicating or dropping records.
///
/// The checkpoint records the export identity (a digest of spec, stream
/// version, and root identities) plus the set of [`ObjectKey`]s already
/// persisted. On resume the receiver loads the checkpoint, verifies the export
/// matches, and skips keys already present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveCheckpoint {
    /// Digest that uniquely identifies the export being received.
    pub export_identity: IntegrityDigest64,
    /// Total number of changed-object records expected across all roots.
    pub total_records: u64,
    /// Object keys already successfully persisted.
    pub completed_keys: BTreeSet<ObjectKey>,
}

/// Compute a stable export-identity digest from the key fields of a
/// [`ChangedRecordExport`].  Two exports with the same spec, stream version,
/// current-root identity, and root-identity set produce the same digest.
pub(crate) fn compute_export_identity(export: &ChangedRecordExport) -> IntegrityDigest64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(export.spec.as_bytes());
    hasher.update(&export.stream_version.to_le_bytes());
    hasher.update(&export.transform_contract.as_u16().to_le_bytes());
    // Hash the sorted root identities so order does not matter.
    let mut root_ids: Vec<RootIdentity> = export
        .roots
        .iter()
        .map(|r| RootIdentity::from_summary(&r.source_root))
        .collect();
    root_ids.sort_by_key(|r| r.transaction_id);
    for id in &root_ids {
        hasher.update(&id.transaction_id.to_le_bytes());
        hasher.update(&id.generation.to_le_bytes());
        hasher.update(&id.superblock_checksum.to_le_bytes());
    }
    checksum64(hasher.finalize().as_bytes())
}

/// Encode a [`ReceiveCheckpoint`] to bytes for persistent storage.
///
/// Wire format:
/// ```text
/// magic         [u8; 8]  = "VFSRCPT1"
/// version       u16 LE
/// export_id     u64 LE
/// total_records u64 LE
/// key_count     u32 LE
/// keys          [u8; 32] × key_count
/// ```
pub(crate) fn encode_receive_checkpoint(checkpoint: &ReceiveCheckpoint) -> Vec<u8> {
    let key_count = u32::try_from(checkpoint.completed_keys.len())
        .expect("receive checkpoint key count overflow");
    let mut buf = Vec::with_capacity(8 + 2 + 8 + 8 + 4 + (checkpoint.completed_keys.len() * 32));
    buf.extend_from_slice(&RECEIVE_CHECKPOINT_MAGIC_BYTES);
    buf.extend_from_slice(&RECEIVE_CHECKPOINT_VERSION.to_le_bytes());
    buf.extend_from_slice(&checkpoint.export_identity.0.to_le_bytes());
    buf.extend_from_slice(&checkpoint.total_records.to_le_bytes());
    buf.extend_from_slice(&key_count.to_le_bytes());
    for key in &checkpoint.completed_keys {
        buf.extend_from_slice(key.as_bytes());
    }
    buf
}

/// Error decoding a receive checkpoint.
#[derive(Debug)]
pub(crate) enum ReceiveCheckpointDecodeError {
    Truncated,
    BadMagic { got: [u8; 8] },
    BadVersion { got: u16 },
    KeyCountOverflow,
}

impl std::fmt::Display for ReceiveCheckpointDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "receive checkpoint truncated"),
            Self::BadMagic { got } => {
                write!(f, "receive checkpoint bad magic: {got:02X?}")
            }
            Self::BadVersion { got } => {
                write!(f, "receive checkpoint unsupported version: {got}")
            }
            Self::KeyCountOverflow => {
                write!(f, "receive checkpoint key count overflow")
            }
        }
    }
}

/// Decode a [`ReceiveCheckpoint`] from bytes.
pub(crate) fn decode_receive_checkpoint(
    data: &[u8],
) -> std::result::Result<ReceiveCheckpoint, ReceiveCheckpointDecodeError> {
    let min_len = 8 + 2 + 8 + 8 + 4; // magic + version + export_id + total + key_count
    if data.len() < min_len {
        return Err(ReceiveCheckpointDecodeError::Truncated);
    }
    let magic: [u8; 8] = data[0..8].try_into().unwrap();
    if magic != RECEIVE_CHECKPOINT_MAGIC_BYTES {
        return Err(ReceiveCheckpointDecodeError::BadMagic { got: magic });
    }
    let version = u16::from_le_bytes(data[8..10].try_into().unwrap());
    if version != RECEIVE_CHECKPOINT_VERSION {
        return Err(ReceiveCheckpointDecodeError::BadVersion { got: version });
    }
    let export_id = u64::from_le_bytes(data[10..18].try_into().unwrap());
    let total_records = u64::from_le_bytes(data[18..26].try_into().unwrap());
    let key_count = u32::from_le_bytes(data[26..30].try_into().unwrap()) as usize;

    let keys_end = 30_usize
        .checked_add(
            key_count
                .checked_mul(32)
                .ok_or(ReceiveCheckpointDecodeError::KeyCountOverflow)?,
        )
        .ok_or(ReceiveCheckpointDecodeError::KeyCountOverflow)?;
    if data.len() < keys_end {
        return Err(ReceiveCheckpointDecodeError::Truncated);
    }

    let mut completed_keys = BTreeSet::new();
    for i in 0..key_count {
        let start = 30 + i * 32;
        let key_bytes: [u8; 32] = data[start..start + 32].try_into().unwrap();
        completed_keys.insert(ObjectKey::from_bytes32(key_bytes));
    }

    Ok(ReceiveCheckpoint {
        export_identity: IntegrityDigest64(export_id),
        total_records,
        completed_keys,
    })
}

/// Public wrapper for fuzz testing: feed arbitrary bytes to the receive
/// checkpoint decoder. Must never panic; the fuzz crate calls this directly.
#[doc(hidden)]
pub fn fuzz_decode_receive_checkpoint(data: &[u8]) {
    let _ = decode_receive_checkpoint(data);
}

/// Persist a receive checkpoint to the staging store under the well-known
/// named key.
pub(crate) fn write_receive_checkpoint(
    store: &mut LocalObjectStore,
    checkpoint: &ReceiveCheckpoint,
) -> Result<()> {
    let encoded = encode_receive_checkpoint(checkpoint);
    store
        .put_named(RECEIVE_CHECKPOINT_NAMED_KEY, &encoded)
        .map_err(FileSystemError::Store)?;
    Ok(())
}

/// Load a receive checkpoint from the staging store, returning `None` when
/// no checkpoint has been written yet.
pub(crate) fn load_receive_checkpoint(
    store: &mut LocalObjectStore,
) -> Result<Option<ReceiveCheckpoint>> {
    match store.get_named(RECEIVE_CHECKPOINT_NAMED_KEY) {
        Ok(Some(data)) => {
            let checkpoint =
                decode_receive_checkpoint(&data).map_err(|_| FileSystemError::Decode {
                    object: "receive checkpoint",
                    reason: "checkpoint decode failed",
                })?;
            Ok(Some(checkpoint))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(FileSystemError::Store(e)),
    }
}

/// Try to load a receive checkpoint from a staging directory for resume.
///
/// Opens the staging store, reads the checkpoint, and verifies the export
/// identity matches. Returns `Ok(Some(cp))` when a valid matching checkpoint
/// exists, `Ok(None)` when no checkpoint or a mismatched checkpoint is found.
fn try_load_checkpoint_for_resume(
    staging_root: &Path,
    options: &StoreOptions,
    expected_export_id: IntegrityDigest64,
) -> Result<Option<ReceiveCheckpoint>> {
    let mut pool = LocalFileSystem::default_development_pool(staging_root, options, None, None)?;
    let store = pool.raw_primary_store_mut();
    match load_receive_checkpoint(store)? {
        Some(cp) if cp.export_identity == expected_export_id => Ok(Some(cp)),
        _ => Ok(None),
    }
}

/// Remove the receive checkpoint from the staging store after a successful
/// receive.
pub(crate) fn remove_receive_checkpoint(store: &mut LocalObjectStore) -> Result<()> {
    store
        .delete_named(RECEIVE_CHECKPOINT_NAMED_KEY)
        .map_err(FileSystemError::Store)?;
    Ok(())
}

/// Modified version of [`receive_changed_records_into_staging`] that supports
/// resume via a set of already-persisted [`ObjectKey`]s.  Keys present in
/// `skip_keys` are not re-written, avoiding duplicate writes after a crash.
///
/// Returns the set of keys that were actually persisted during this call
/// (new keys not already in `skip_keys`).
pub(crate) fn receive_changed_records_into_staging_with_skip(
    target_root: &Path,
    staging_root: &Path,
    options: StoreOptions,
    prepared: PreparedChangedRecordExport,
    root_authentication_key: RootAuthenticationKey,
    skip_keys: &BTreeSet<ObjectKey>,
) -> Result<(ChangedRecordImportReport, BTreeSet<ObjectKey>)> {
    let mut pool = LocalFileSystem::default_development_pool(staging_root, &options, None, None)?;
    let export_identity = compute_export_identity_from_prepared(&prepared);

    // Load any existing checkpoint and merge with caller-provided skip set.
    let mut completed = skip_keys.clone();
    let mut newly_persisted = BTreeSet::new();
    {
        let store = pool.raw_primary_store_mut();
        if let Some(existing_cp) = load_receive_checkpoint(store)? {
            if existing_cp.export_identity == export_identity {
                completed.extend(existing_cp.completed_keys);
            }
        }

        // Phase 1: write content objects, skipping only verified staged keys.
        for root in &prepared.roots {
            for record in root.records.values() {
                if !matches!(
                    record.role,
                    ChangedRecordObjectRole::VersionedContent
                        | ChangedRecordObjectRole::VersionedContentChunk
                ) {
                    continue;
                }
                if completed.contains(&record.object_key)
                    && receive_completed_content_record_is_valid(store, record)?
                {
                    continue;
                }
                store.put(record.object_key, &record.payload)?;
                completed.insert(record.object_key);
                newly_persisted.insert(record.object_key);
            }
        }

        // Persist checkpoint after all content objects are written.
        let checkpoint = ReceiveCheckpoint {
            export_identity,
            total_records: prepared.total_records,
            completed_keys: completed.clone(),
        };
        write_receive_checkpoint(store, &checkpoint)?;
    }

    // Phase 2: persist transaction objects and roots.
    let mut roots = prepared.roots.clone();
    roots.sort_by_key(|r| r.source_root.transaction_id);
    let mut imported_summaries = BTreeMap::new();
    let mut normalized_content = BTreeSet::new();
    let mut selected_summary = None;
    let mut snapshot_catalog_entries = 0_usize;

    for root in roots {
        let identity = RootIdentity::from_summary(&root.source_root);
        let mut state = root.state.clone();
        rewrite_snapshot_roots_for_import(
            &mut state,
            &imported_summaries,
            identity == prepared.current_identity,
        )?;
        normalize_received_content_receipts(&mut pool, &state, &mut normalized_content)?;
        let unsigned_root = persist_transaction_objects(
            pool.raw_primary_store_mut(),
            &state,
            root.source_root.transaction_id,
        )?;
        let signed_root = sign_root_commit(&unsigned_root, root_authentication_key)?;
        pool.raw_primary_store_mut().put(
            root_slot_object_key(signed_root.slot),
            &encode_root_commit(&signed_root),
        )?;
        let summary = signed_root.summary();
        if identity == prepared.current_identity {
            snapshot_catalog_entries = state.snapshots.len();
            selected_summary = Some(summary.clone());
        }
        imported_summaries.insert(identity, summary);
    }

    // Remove the checkpoint now that all roots are persisted.
    let audit = {
        let store = pool.raw_primary_store_mut();
        store.sync_all()?;
        let _ = remove_receive_checkpoint(store);
        crate::recovery::audit_recovery_store(store, root_authentication_key)?
    };
    drop(pool);

    let selected = selected_summary.ok_or(FileSystemError::CorruptState {
        reason: "send/receive import did not publish the selected root",
    })?;
    if audit.selected_root.as_ref() != Some(&selected) {
        return Err(FileSystemError::CorruptState {
            reason: "send/receive import selected a root other than the received current root",
        });
    }

    if target_root.exists() {
        return Err(FileSystemError::Unsupported {
            operation: "send/receive import",
            reason: "receive target root appeared before publication",
        });
    }
    fs::rename(staging_root, target_root)
        .map_err(|source| fs_io_error("rename", staging_root, source))?;
    sync_directory_path(target_root.parent().unwrap_or_else(|| Path::new(".")))?;

    Ok((
        ChangedRecordImportReport {
            spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
            target_root: target_root.to_path_buf(),
            imported_roots: imported_summaries.len() as u64,
            imported_records: prepared.total_records,
            imported_payload_bytes: prepared.payload_bytes,
            selected_generation: selected.generation,
            selected_transaction_id: selected.transaction_id,
            snapshot_catalog_entries,
            stream_version: prepared.stream_version,
            staging_validated_before_publish: true,
            destination_root_reauthentication: true,
            production_fsck_required: false,
            placement_epoch: prepared.placement_epoch,
            placement_verified_stable: false,
        },
        newly_persisted,
    ))
}

/// Compute export identity from a prepared export (avoids re-deriving from
/// the export struct when it's already been validated).
fn compute_export_identity_from_prepared(
    prepared: &PreparedChangedRecordExport,
) -> IntegrityDigest64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEND_RECEIVE_CHANGED_RECORD_SPEC.as_bytes());
    hasher.update(&prepared.stream_version.to_le_bytes());
    hasher.update(&prepared.transform_contract.as_u16().to_le_bytes());
    let mut root_ids: Vec<RootIdentity> = prepared
        .roots
        .iter()
        .map(|r| RootIdentity::from_summary(&r.source_root))
        .collect();
    root_ids.sort_by_key(|r| r.transaction_id);
    for id in &root_ids {
        hasher.update(&id.transaction_id.to_le_bytes());
        hasher.update(&id.generation.to_le_bytes());
        hasher.update(&id.superblock_checksum.to_le_bytes());
    }
    checksum64(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Round-trip encode/decode of an empty ReceiveCheckpoint.
    #[test]
    fn checkpoint_encode_decode_empty_roundtrip() {
        let cp = ReceiveCheckpoint {
            export_identity: IntegrityDigest64(0xABCD_EF01_2345_6789),
            total_records: 42,
            completed_keys: BTreeSet::new(),
        };
        let encoded = encode_receive_checkpoint(&cp);
        let decoded = decode_receive_checkpoint(&encoded).unwrap();
        assert_eq!(decoded.export_identity, cp.export_identity);
        assert_eq!(decoded.total_records, cp.total_records);
        assert!(decoded.completed_keys.is_empty());
    }

    /// Round-trip encode/decode of a ReceiveCheckpoint with completed keys.
    #[test]
    fn checkpoint_encode_decode_with_keys_roundtrip() {
        let key1 = ObjectKey::from_bytes32([0x01; 32]);
        let key2 = ObjectKey::from_bytes32([0x42; 32]);
        let key3 = ObjectKey::from_bytes32([0xFF; 32]);
        let mut completed = BTreeSet::new();
        completed.insert(key1);
        completed.insert(key2);
        completed.insert(key3);

        let cp = ReceiveCheckpoint {
            export_identity: IntegrityDigest64(0xDEAD_BEEF_CAFE_BABE),
            total_records: 100,
            completed_keys: completed,
        };
        let encoded = encode_receive_checkpoint(&cp);
        let decoded = decode_receive_checkpoint(&encoded).unwrap();
        assert_eq!(decoded.export_identity, cp.export_identity);
        assert_eq!(decoded.total_records, cp.total_records);
        assert_eq!(decoded.completed_keys.len(), 3);
        assert!(decoded.completed_keys.contains(&key1));
        assert!(decoded.completed_keys.contains(&key2));
        assert!(decoded.completed_keys.contains(&key3));
    }

    /// Different export identities produce different checkpoints.
    #[test]
    fn checkpoint_export_identity_differs() {
        let cp_a = ReceiveCheckpoint {
            export_identity: IntegrityDigest64(1),
            total_records: 1,
            completed_keys: BTreeSet::new(),
        };
        let cp_b = ReceiveCheckpoint {
            export_identity: IntegrityDigest64(2),
            total_records: 1,
            completed_keys: BTreeSet::new(),
        };
        let enc_a = encode_receive_checkpoint(&cp_a);
        let enc_b = encode_receive_checkpoint(&cp_b);
        assert_ne!(enc_a, enc_b);

        let dec_a = decode_receive_checkpoint(&enc_a).unwrap();
        let dec_b = decode_receive_checkpoint(&enc_b).unwrap();
        assert_ne!(dec_a.export_identity, dec_b.export_identity);
    }

    /// Decoding truncated data returns an error.
    #[test]
    fn checkpoint_decode_truncated() {
        assert!(decode_receive_checkpoint(&[0u8; 10]).is_err());
        // Header (8+2+8+8+4=30 bytes) with key_count=1 but no key data
        let mut header = Vec::new();
        header.extend_from_slice(&RECEIVE_CHECKPOINT_MAGIC_BYTES);
        header.extend_from_slice(&RECEIVE_CHECKPOINT_VERSION.to_le_bytes());
        header.extend_from_slice(&0u64.to_le_bytes()); // export_id
        header.extend_from_slice(&1u64.to_le_bytes()); // total_records
        header.extend_from_slice(&1u32.to_le_bytes()); // key_count=1
                                                       // no key bytes
        assert!(decode_receive_checkpoint(&header).is_err());
    }

    /// Decoding with bad magic returns an error.
    #[test]
    fn checkpoint_decode_bad_magic() {
        let mut buf = vec![0u8; 30];
        buf[0] = 0xFF;
        assert!(decode_receive_checkpoint(&buf).is_err());
    }

    /// Decoding with unsupported version returns an error.
    #[test]
    fn checkpoint_decode_bad_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&RECEIVE_CHECKPOINT_MAGIC_BYTES);
        buf.extend_from_slice(&99u16.to_le_bytes()); // wrong version
        buf.extend_from_slice(&0u64.to_le_bytes()); // export_id
        buf.extend_from_slice(&0u64.to_le_bytes()); // total_records
        buf.extend_from_slice(&0u32.to_le_bytes()); // key_count=0
        assert!(decode_receive_checkpoint(&buf).is_err());
    }

    /// compute_export_identity produces stable output.
    #[test]
    fn export_identity_stable_for_same_export() {
        use crate::types::CommittedRootSummary;
        let summary = CommittedRootSummary {
            slot: 0,
            transaction_id: 1,
            generation: 1,
            next_inode_id: 2,
            inode_count: 1,
            superblock_checksum: IntegrityDigest64(0xABCD),
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(0x1234),
            manifest_entry_count: 2,
            has_root_authentication: true,
            root_authentication_policy_epoch: Some(1),
            root_authentication_algorithm_suite_id: Some(1),
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        };
        let root = ChangedRecordRoot {
            source_root: summary.clone(),
            records: vec![],
        };
        let export = ChangedRecordExport {
            spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: SEND_RECEIVE_STREAM_VERSION,
            current_root: summary.clone(),
            roots: vec![root.clone()],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
            transform_contract: ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };
        let id1 = compute_export_identity(&export);
        let id2 = compute_export_identity(&export);
        assert_eq!(id1, id2, "same export must produce same identity");

        let mut transform_required = export.clone();
        transform_required.transform_contract =
            ChangedRecordTransformContract::MountedDeviceTransformsRequireTypedMetadata;
        assert_ne!(
            compute_export_identity(&export),
            compute_export_identity(&transform_required),
            "receive checkpoint identity must include the transform contract"
        );
    }

    #[test]
    fn transform_disabled_changed_record_contract_uses_stored_frame_metadata() {
        let metadata = ChangedRecordTypedTransformMetadata::for_contract(
            ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        );

        assert_eq!(
            metadata,
            ChangedRecordTypedTransformMetadata {
                plaintext_identity:
                    ChangedRecordPlaintextIdentity::StoredFrameBytesAreMountedPlaintext,
                transform_frame_identity:
                    ChangedRecordTransformFrameIdentity::NotApplicableNoDeviceTransforms,
                checksum_layer: ChangedRecordChecksumLayer::StoredFrameBytes,
                stored_frame_contract:
                    ChangedRecordStoredFrameContract::StoredFrameNoDeviceTransforms,
                refusal_state: ChangedRecordTransformRefusalState::ReplayReady,
            }
        );
        validate_changed_record_transform_contract(
            ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        )
        .expect("stored-frame/no-device-transform streams remain importable");
    }

    #[test]
    fn transform_required_changed_record_contract_records_typed_refusal() {
        let metadata = ChangedRecordTypedTransformMetadata::for_contract(
            ChangedRecordTransformContract::MountedDeviceTransformsRequireTypedMetadata,
        );

        assert_eq!(
            metadata,
            ChangedRecordTypedTransformMetadata {
                plaintext_identity: ChangedRecordPlaintextIdentity::RequiresTypedMountedContentIdentity,
                transform_frame_identity:
                    ChangedRecordTransformFrameIdentity::MissingTypedCompressionEncryptionFrameIdentity,
                checksum_layer: ChangedRecordChecksumLayer::RequiresTypedMountedTransformChecksum,
                stored_frame_contract:
                    ChangedRecordStoredFrameContract::RawMediaBytesNotMountedContentAuthority,
                refusal_state: ChangedRecordTransformRefusalState::MissingTypedTransformMetadata,
            }
        );

        let err = validate_changed_record_transform_contract(
            ChangedRecordTransformContract::MountedDeviceTransformsRequireTypedMetadata,
        )
        .expect_err("transform-required streams must fail without typed metadata");
        assert!(matches!(
            err,
            FileSystemError::Unsupported {
                operation: "send/receive transform contract",
                reason: CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON,
            }
        ));
    }

    #[test]
    fn transform_required_changed_record_streams_fail_closed() {
        use crate::types::CommittedRootSummary;

        let summary = CommittedRootSummary {
            slot: 0,
            transaction_id: 1,
            generation: 1,
            next_inode_id: 2,
            inode_count: 1,
            superblock_checksum: IntegrityDigest64(0xABCD),
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(0x1234),
            manifest_entry_count: 0,
            has_root_authentication: true,
            root_authentication_policy_epoch: Some(1),
            root_authentication_algorithm_suite_id: Some(1),
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        };
        let export = ChangedRecordExport {
            spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: SEND_RECEIVE_STREAM_VERSION,
            current_root: summary,
            roots: Vec::new(),
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
            transform_contract:
                ChangedRecordTransformContract::MountedDeviceTransformsRequireTypedMetadata,
        };

        let encoded = export.encode();
        let decoded = ChangedRecordExport::decode(&encoded)
            .expect("typed transform refusal metadata must survive the stream codec");

        let err = validate_changed_record_export(&decoded, false)
            .expect_err("transform-required stream must fail before import");
        assert!(matches!(
            err,
            FileSystemError::Unsupported {
                operation: "send/receive transform contract",
                reason: CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON,
            }
        ));

        let mut incremental_without_base = decoded;
        incremental_without_base.roots = vec![ChangedRecordRoot {
            source_root: incremental_without_base.current_root.clone(),
            records: Vec::new(),
        }];
        incremental_without_base.incremental = true;

        let err = validate_changed_record_export(&incremental_without_base, true)
            .expect_err("transform-required stream must fail before incremental base checks");
        assert!(matches!(
            err,
            FileSystemError::Unsupported {
                operation: "send/receive transform contract",
                reason: CHANGED_RECORD_MOUNTED_TRANSFORM_METADATA_REQUIRED_REASON,
            }
        ));
    }

    /// compute_export_identity differs for different exports.
    #[test]
    fn export_identity_differs_for_different_export() {
        use crate::types::CommittedRootSummary;
        let summary1 = CommittedRootSummary {
            slot: 0,
            transaction_id: 1,
            generation: 1,
            next_inode_id: 2,
            inode_count: 1,
            superblock_checksum: IntegrityDigest64(0xAAAA),
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(0x1111),
            manifest_entry_count: 1,
            has_root_authentication: true,
            root_authentication_policy_epoch: Some(1),
            root_authentication_algorithm_suite_id: Some(1),
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        };
        let summary2 = CommittedRootSummary {
            slot: 0,
            transaction_id: 2, // different tx
            generation: 1,
            next_inode_id: 2,
            inode_count: 1,
            superblock_checksum: IntegrityDigest64(0xBBBB),
            has_transaction_manifest: true,
            manifest_checksum: IntegrityDigest64(0x2222),
            manifest_entry_count: 1,
            has_root_authentication: true,
            root_authentication_policy_epoch: Some(1),
            root_authentication_algorithm_suite_id: Some(1),
            superblock_digest: None,
            manifest_digest: None,
            root_authentication_code: None,
        };
        let root1 = ChangedRecordRoot {
            source_root: summary1.clone(),
            records: vec![],
        };
        let root2 = ChangedRecordRoot {
            source_root: summary2.clone(),
            records: vec![],
        };
        let export1 = ChangedRecordExport {
            spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: SEND_RECEIVE_STREAM_VERSION,
            current_root: summary1,
            roots: vec![root1],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
            transform_contract: ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };
        let export2 = ChangedRecordExport {
            spec: SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: SEND_RECEIVE_STREAM_VERSION,
            current_root: summary2,
            roots: vec![root2],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
            transform_contract: ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };
        assert_ne!(
            compute_export_identity(&export1),
            compute_export_identity(&export2),
            "different exports must produce different identities"
        );
    }

    #[test]
    fn receive_error_retryability_preserves_staging_for_transient_store_errors() {
        use tidefs_local_object_store::IoClass;

        let io_error = FileSystemError::Store(StoreError::Io {
            operation: "write",
            path: std::path::PathBuf::from("segment"),
            source: std::io::Error::from(std::io::ErrorKind::Interrupted),
        });
        assert!(is_receive_error_retryable(&io_error));
        assert!(is_receive_error_retryable(&FileSystemError::Store(
            StoreError::NoSpace
        )));
        assert!(is_receive_error_retryable(&FileSystemError::Store(
            StoreError::PressureRefused {
                class: IoClass::Metadata,
            }
        )));
    }

    #[test]
    fn receive_error_retryability_discards_staging_for_deterministic_store_errors() {
        assert!(!is_receive_error_retryable(&FileSystemError::Store(
            StoreError::PayloadTooLarge {
                len: 65_536,
                max: 16_384,
            }
        )));
        assert!(!is_receive_error_retryable(&FileSystemError::Store(
            StoreError::InvalidOptions {
                reason: "bad receive store options",
            }
        )));
        assert!(!is_receive_error_retryable(&FileSystemError::Store(
            StoreError::ReadOnly { operation: "write" }
        )));
        assert!(!is_receive_error_retryable(&FileSystemError::Store(
            StoreError::CorruptHeader {
                segment_id: 1,
                offset: 0,
                reason: "bad header",
            }
        )));
    }

    // ── Tier 3: mounted userspace resume validation ────────────────────────

    /// End-to-end test: receive resume from a durable checkpoint.
    ///
    /// 1. Create a source filesystem with files and a snapshot.
    /// 2. Export changed records and validate.
    /// 3. Manually pre-populate a staging directory with partial content
    ///    objects and a receive checkpoint, simulating an interrupted receive.
    /// 4. Call the resume-aware receive function with the completed-key
    ///    skip set, proving the receive completes without duplication or drops.
    /// 5. Open the received filesystem and verify all files match.
    #[test]
    fn receive_resume_from_checkpoint_skips_completed_keys() {
        let source_root = std::env::temp_dir().join(format!(
            "tidefs-resume-test-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let target_root = std::env::temp_dir().join(format!(
            "tidefs-resume-test-target-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let source_key = crate::types::RootAuthenticationKey::from_bytes32(
            [0xAA_u8; crate::constants::ROOT_AUTHENTICATION_KEY_LEN],
        );
        let target_key = crate::types::RootAuthenticationKey::from_bytes32(
            [0xBB_u8; crate::constants::ROOT_AUTHENTICATION_KEY_LEN],
        );

        let opts = StoreOptions {
            max_segment_bytes: 256 * 1024,
            sync_on_write: false,
            repair_torn_tail: true,
            mirror_path: None,
            replica_paths: Vec::new(),
            segment_rotation_interval_secs: 0,
            segment_rotation_write_limit: 0,
            fault_injection_config: None,
            background_scrub_interval_secs: 0,
            segment_count: 65536,
            reclaim_enabled: true,
            write_throttle_enabled: false,
            durability_layout: None,
            verify_read_checksums: true,
        };

        // 1. Create source filesystem with data large enough to produce
        //    content objects (exceeding content_chunk_size so content is
        //    stored externally, not inline in the inode).
        let chunk_sz = crate::constants::content_chunk_size() as usize;
        let mut source = crate::LocalFileSystem::open_with_root_authentication_key(
            &source_root,
            opts.clone(),
            source_key,
        )
        .expect("open source fs");
        source.create_dir("/data", 0o755).expect("create /data");
        source
            .create_file("/data/big.bin", 0o644)
            .expect("create big.bin");
        let data_big = vec![0x41_u8; chunk_sz * 2 + 17];
        source
            .write_file("/data/big.bin", 0, &data_big)
            .expect("write big.bin");
        source.sync_all().expect("sync source");
        source.create_snapshot("snap1").expect("create snapshot");
        drop(source);

        // 2. Export.
        let mut source2 = crate::LocalFileSystem::open_with_root_authentication_key(
            &source_root,
            opts.clone(),
            source_key,
        )
        .expect("reopen source");
        let export = source2.export_changed_records().expect("export");
        assert!(export.total_records > 0, "export must have records");
        drop(source2);

        // 3. Validate and compute export identity.
        let prepared = validate_changed_record_export(&export, false).expect("validate export");
        let export_id = compute_export_identity(&export);

        // 4. Collect all content-object keys and their payloads.
        let all_content: Vec<(ObjectKey, Vec<u8>)> = prepared
            .roots
            .iter()
            .flat_map(|r| r.records.values())
            .filter(|rec| {
                matches!(
                    rec.role,
                    crate::types::ChangedRecordObjectRole::VersionedContent
                        | crate::types::ChangedRecordObjectRole::VersionedContentChunk
                )
            })
            .map(|rec| (rec.object_key, rec.payload.clone()))
            .collect();

        assert!(
            all_content.len() >= 2,
            "need at least 2 content objects; chunk file should produce them"
        );

        // 5. Create staging, pre-populate with ALL content objects plus a
        //    checkpoint that lists ALL of them as completed.
        let staging = receive_staging_root(&target_root).expect("staging root");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        let all_keys: BTreeSet<ObjectKey> = all_content.iter().map(|(k, _)| *k).collect();
        {
            let mut pool = LocalFileSystem::default_development_pool(&staging, &opts, None, None)
                .expect("open staging pool");
            let store = pool.raw_primary_store_mut();
            for (key, payload) in &all_content {
                store.put(*key, payload).expect("put content");
            }
            let cp = ReceiveCheckpoint {
                export_identity: export_id,
                total_records: prepared.total_records,
                completed_keys: all_keys.clone(),
            };
            write_receive_checkpoint(store, &cp).expect("write checkpoint");
        }

        // 6. Call the resume-aware receive with all keys as skip set.
        //    The function should skip all content writes (they are already
        //    persisted and in the checkpoint) and proceed to root commits.
        let (report, newly_persisted) = receive_changed_records_into_staging_with_skip(
            &target_root,
            &staging,
            opts.clone(),
            prepared,
            target_key,
            &all_keys,
        )
        .expect("resume receive");

        // Since all content objects were already in the completed set and
        // already written to the store, nothing new should be persisted.
        assert!(
            newly_persisted.is_empty(),
            "all content keys already persisted; newly_persisted must be empty, got {newly_persisted:?}"
        );

        assert_eq!(report.imported_records, export.total_records);
        assert_eq!(report.imported_payload_bytes, export.payload_bytes);
        assert!(report.staging_validated_before_publish);
        assert!(report.destination_root_reauthentication);

        // 7. Open the received filesystem and verify content.
        let received = crate::LocalFileSystem::open_with_root_authentication_key(
            &target_root,
            opts,
            target_key,
        )
        .expect("open received fs");
        let stat = received.stat("/data/big.bin").expect("stat big.bin");
        assert_eq!(stat.size, data_big.len() as u64, "file size must match");
        let read_back = received.read_file("/data/big.bin").expect("read big.bin");
        assert_eq!(read_back, data_big, "content must match");
        let snapshots = received.list_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "snap1");
        drop(received);

        let _ = std::fs::remove_dir_all(&source_root);
        let _ = std::fs::remove_dir_all(&target_root);
    }

    #[test]
    fn receive_accepts_bookmark_without_retained_snapshot_root() {
        let source_root = std::env::temp_dir().join(format!(
            "tidefs-bookmark-send-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let target_root = std::env::temp_dir().join(format!(
            "tidefs-bookmark-send-target-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let auth_key = crate::types::RootAuthenticationKey::from_bytes32(
            [0xEE_u8; crate::constants::ROOT_AUTHENTICATION_KEY_LEN],
        );
        let opts = StoreOptions::test_fast();

        let mut source = crate::LocalFileSystem::open_with_root_authentication_key(
            &source_root,
            opts.clone(),
            auth_key,
        )
        .expect("open source fs");
        source.create_dir("/data", 0o755).expect("create /data");
        source
            .create_file("/data/f", 0o644)
            .expect("create /data/f");
        source
            .write_file("/data/f", 0, b"bookmark-only-send")
            .expect("write /data/f");
        source.sync_all().expect("sync source");
        let snapshot = source.create_snapshot("snap1").expect("create snapshot");
        source
            .create_bookmark("bookmark1", "snap1")
            .expect("create bookmark");
        source
            .delete_snapshot("snap1")
            .expect("delete bookmarked snapshot");

        let export = source
            .export_changed_records()
            .expect("export changed records");
        let bookmark_root = RootIdentity::from_summary(&snapshot.source_root);
        assert!(
            export
                .roots
                .iter()
                .all(|root| RootIdentity::from_summary(&root.source_root) != bookmark_root),
            "bookmark roots must not be exported as data-retaining roots"
        );
        validate_changed_record_export(&export, false).expect("validate bookmark-only export");
        drop(source);

        crate::LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            opts.clone(),
            &export,
            auth_key,
        [0; 16], [0; 16], None)
        .expect("receive bookmark-only export");

        let received =
            crate::LocalFileSystem::open_with_root_authentication_key(&target_root, opts, auth_key)
                .expect("open received fs");
        let bookmarks = received.list_bookmarks();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].name, "bookmark1");
        assert_eq!(bookmarks[0].source_snapshot, "snap1");
        let descriptors = received.list_snapshots_extended();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].kind, crate::records::SnapshotKind::Bookmark);
        drop(received);

        let _ = std::fs::remove_dir_all(&source_root);
        let _ = std::fs::remove_dir_all(&target_root);
    }

    #[test]
    fn resume_ignores_stale_checkpoint_from_different_export() {
        let source_root = std::env::temp_dir().join(format!(
            "tidefs-stale-cp-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let target_root = std::env::temp_dir().join(format!(
            "tidefs-stale-cp-target-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let source_key = crate::types::RootAuthenticationKey::from_bytes32(
            [0xCC_u8; crate::constants::ROOT_AUTHENTICATION_KEY_LEN],
        );
        let target_key = crate::types::RootAuthenticationKey::from_bytes32(
            [0xDD_u8; crate::constants::ROOT_AUTHENTICATION_KEY_LEN],
        );

        let opts = StoreOptions {
            max_segment_bytes: 16 * 1024,
            sync_on_write: false,
            repair_torn_tail: true,
            mirror_path: None,
            replica_paths: Vec::new(),
            segment_rotation_interval_secs: 0,
            segment_rotation_write_limit: 0,
            fault_injection_config: None,
            background_scrub_interval_secs: 0,
            segment_count: 65536,
            reclaim_enabled: true,
            write_throttle_enabled: false,
            durability_layout: None,
            verify_read_checksums: true,
        };

        // Create source filesystem and export.
        let mut source = crate::LocalFileSystem::open_with_root_authentication_key(
            &source_root,
            opts.clone(),
            source_key,
        )
        .expect("open source fs");
        source.create_dir("/d", 0o755).expect("create /d");
        source.create_file("/d/f", 0o644).expect("create /d/f");
        source.write_file("/d/f", 0, b"hello").expect("write f");
        source.sync_all().expect("sync");
        source.create_snapshot("s1").expect("snapshot");
        drop(source);

        let mut source2 = crate::LocalFileSystem::open_with_root_authentication_key(
            &source_root,
            opts.clone(),
            source_key,
        )
        .expect("reopen source");
        let export = source2.export_changed_records().expect("export");
        drop(source2);

        // Pre-populate a staging directory with a checkpoint that has a WRONG
        // export identity (different from the real export).
        let staging = receive_staging_root(&target_root).expect("staging root");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        {
            let mut store = LocalObjectStore::open_with_options(&staging, opts.clone())
                .expect("open staging store");
            let stale_cp = ReceiveCheckpoint {
                export_identity: IntegrityDigest64(0xDEAD_BEEF_CAFE_BABE),
                total_records: 999,
                completed_keys: BTreeSet::new(),
            };
            write_receive_checkpoint(&mut store, &stale_cp).expect("write stale cp");
            drop(store);
        }

        // The public receive API should detect the stale checkpoint (identity
        // mismatch) and still complete successfully by starting fresh.
        let report =
            crate::LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
                &target_root,
                opts.clone(),
                &export,
                target_key,
            [0; 16], [0; 16], None)
            .expect("receive with stale checkpoint must succeed");

        assert_eq!(report.imported_records, export.total_records);
        assert!(report.staging_validated_before_publish);

        // Verify received filesystem integrity.
        let received = crate::LocalFileSystem::open_with_root_authentication_key(
            &target_root,
            opts,
            target_key,
        )
        .expect("open received fs");
        let read = received.read_file("/d/f").expect("read /d/f");
        assert_eq!(read, b"hello");
        let snapshots = received.list_snapshots();
        assert_eq!(snapshots.len(), 1);
        drop(received);

        let _ = std::fs::remove_dir_all(&source_root);
        let _ = std::fs::remove_dir_all(&target_root);
    }
    #[test]
    fn placement_epoch_encodes_and_decodes_roundtrip() {
        use crate::encoding::{decode_changed_record_export, encode_changed_record_export};

        fn make_summary(txid: u64) -> crate::types::CommittedRootSummary {
            crate::types::CommittedRootSummary {
                slot: 0,
                transaction_id: txid,
                generation: 1,
                next_inode_id: 2,
                inode_count: 1,
                superblock_checksum: crate::IntegrityDigest64(0xABCD + txid),
                has_transaction_manifest: true,
                manifest_checksum: crate::IntegrityDigest64(0x1234 + txid),
                manifest_entry_count: 2,
                has_root_authentication: true,
                root_authentication_policy_epoch: Some(1),
                root_authentication_algorithm_suite_id: Some(1),
                superblock_digest: None,
                manifest_digest: None,
                root_authentication_code: None,
            }
        }

        let root = crate::ChangedRecordRoot {
            source_root: make_summary(1),
            records: vec![],
        };
        let export = crate::ChangedRecordExport {
            spec: crate::SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: 1,
            current_root: make_summary(1),
            roots: vec![root],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: Some(7),
            transform_contract:
                crate::ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };

        let encoded = encode_changed_record_export(&export);
        assert!(!encoded.is_empty());

        let decoded = decode_changed_record_export(&encoded)
            .expect("decode full export with placement_epoch");
        assert_eq!(decoded.placement_epoch, Some(7));
        assert_eq!(decoded.stream_version, 3);
        assert!(!decoded.incremental);
    }

    #[test]
    fn placement_epoch_none_keeps_base_stream_version() {
        use crate::encoding::{decode_changed_record_export, encode_changed_record_export};

        fn make_summary(txid: u64) -> crate::types::CommittedRootSummary {
            crate::types::CommittedRootSummary {
                slot: 0,
                transaction_id: txid,
                generation: 1,
                next_inode_id: 2,
                inode_count: 1,
                superblock_checksum: crate::IntegrityDigest64(0xABCD + txid),
                has_transaction_manifest: true,
                manifest_checksum: crate::IntegrityDigest64(0x1234 + txid),
                manifest_entry_count: 2,
                has_root_authentication: true,
                root_authentication_policy_epoch: Some(1),
                root_authentication_algorithm_suite_id: Some(1),
                superblock_digest: None,
                manifest_digest: None,
                root_authentication_code: None,
            }
        }

        let root = crate::ChangedRecordRoot {
            source_root: make_summary(1),
            records: vec![],
        };
        let export = crate::ChangedRecordExport {
            spec: crate::SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: 1,
            current_root: make_summary(1),
            roots: vec![root],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: None,
            transform_contract:
                crate::ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };

        let encoded = encode_changed_record_export(&export);
        let decoded = decode_changed_record_export(&encoded)
            .expect("decode full export without placement_epoch");
        assert_eq!(decoded.placement_epoch, None);
        assert_eq!(decoded.stream_version, 1);
        assert!(!decoded.incremental);
    }

    #[test]
    fn placement_epoch_roundtrip_incremental() {
        use crate::encoding::{decode_changed_record_export, encode_changed_record_export};

        fn make_summary(txid: u64) -> crate::types::CommittedRootSummary {
            crate::types::CommittedRootSummary {
                slot: 0,
                transaction_id: txid,
                generation: 1,
                next_inode_id: 2,
                inode_count: 1,
                superblock_checksum: crate::IntegrityDigest64(0xABCD + txid),
                has_transaction_manifest: true,
                manifest_checksum: crate::IntegrityDigest64(0x1234 + txid),
                manifest_entry_count: 2,
                has_root_authentication: true,
                root_authentication_policy_epoch: Some(1),
                root_authentication_algorithm_suite_id: Some(1),
                superblock_digest: None,
                manifest_digest: None,
                root_authentication_code: None,
            }
        }

        let base = make_summary(1);
        let target = make_summary(2);
        let root = crate::ChangedRecordRoot {
            source_root: target.clone(),
            records: vec![],
        };
        let export = crate::ChangedRecordExport {
            spec: crate::SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: 2,
            current_root: target,
            roots: vec![root],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: Some(base),
            incremental: true,
            placement_epoch: Some(42),
            transform_contract:
                crate::ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };

        let encoded = encode_changed_record_export(&export);
        let decoded = decode_changed_record_export(&encoded)
            .expect("decode incremental export with placement_epoch");
        assert_eq!(decoded.placement_epoch, Some(42));
        assert_eq!(decoded.stream_version, 4);
        assert!(decoded.incremental);
        assert!(decoded.from_root.is_some());
    }

    #[test]
    fn placement_epoch_mismatch_not_silently_dropped() {
        use crate::encoding::encode_changed_record_export;

        fn make_summary(txid: u64) -> crate::types::CommittedRootSummary {
            crate::types::CommittedRootSummary {
                slot: 0,
                transaction_id: txid,
                generation: 1,
                next_inode_id: 2,
                inode_count: 1,
                superblock_checksum: crate::IntegrityDigest64(0xABCD + txid),
                has_transaction_manifest: true,
                manifest_checksum: crate::IntegrityDigest64(0x1234 + txid),
                manifest_entry_count: 2,
                has_root_authentication: true,
                root_authentication_policy_epoch: Some(1),
                root_authentication_algorithm_suite_id: Some(1),
                superblock_digest: None,
                manifest_digest: None,
                root_authentication_code: None,
            }
        }

        let root = crate::ChangedRecordRoot {
            source_root: make_summary(1),
            records: vec![],
        };
        let export = crate::ChangedRecordExport {
            spec: crate::SEND_RECEIVE_CHANGED_RECORD_SPEC,
            stream_version: 1,
            current_root: make_summary(1),
            roots: vec![root],
            total_records: 0,
            payload_bytes: 0,
            production_fsck_required: false,
            from_root: None,
            incremental: false,
            placement_epoch: Some(100),
            transform_contract:
                crate::ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
        };

        let encoded = encode_changed_record_export(&export);
        let decoded = crate::ChangedRecordExport::decode(&encoded).expect("decode via public API");
        assert_eq!(decoded.placement_epoch, Some(100));
    }

    #[test]
    fn placement_epoch_end_to_end_export_import_roundtrip() {
        let source_root = std::env::temp_dir().join(format!(
            "tidefs-pe-send-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let target_root = std::env::temp_dir().join(format!(
            "tidefs-pe-recv-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let auth_key = crate::types::RootAuthenticationKey::from_bytes32(
            [0xEE_u8; crate::constants::ROOT_AUTHENTICATION_KEY_LEN],
        );
        let opts = crate::StoreOptions {
            max_segment_bytes: 64 * 1024,
            sync_on_write: false,
            repair_torn_tail: true,
            mirror_path: None,
            replica_paths: Vec::new(),
            segment_rotation_interval_secs: 0,
            segment_rotation_write_limit: 0,
            fault_injection_config: None,
            background_scrub_interval_secs: 0,
            segment_count: 65536,
            reclaim_enabled: true,
            write_throttle_enabled: false,
            durability_layout: None,
            verify_read_checksums: true,
        };

        // 1. Create source filesystem and populate with data.
        let mut source = crate::LocalFileSystem::open_with_root_authentication_key(
            &source_root,
            opts.clone(),
            auth_key,
        )
        .expect("open source fs");
        source.create_dir("/data", 0o755).expect("mkdir /data");
        source.create_file("/data/f1", 0o644).expect("create f1");
        source
            .write_file("/data/f1", 0, b"epoch-tracked stream")
            .expect("write f1");
        source.sync_all().expect("sync source");

        // 2. Set placement epoch on the source before export.
        source.set_placement_epoch(99);
        assert!(
            source.placement_epoch == Some(99),
            "placement_epoch should be set on source"
        );

        // 3. Export and verify placement_epoch is in the export.
        let export = source.export_changed_records().expect("export");
        assert_eq!(export.placement_epoch, Some(99));
        assert!(!export.incremental);
        // Encoding should produce stream version 3 (full + epoch)
        let encoded = export.encode();
        assert!(!encoded.is_empty());
        drop(source);

        // 4. Decode and verify placement_epoch survives wire encoding.
        let decoded = crate::ChangedRecordExport::decode(&encoded).expect("decode export");
        assert_eq!(decoded.placement_epoch, Some(99));
        assert_eq!(decoded.stream_version, 3);

        // 5. Import into target filesystem.
        let report = crate::LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            opts.clone(),
            &decoded,
            auth_key,
        [0; 16], [0; 16], None)
        .expect("import");

        // 6. Verify the import report carries placement_epoch.
        assert_eq!(report.placement_epoch, Some(99));
        assert!(
            !report.placement_verified_stable,
            "placement_verified_stable is false (caller must compare)"
        );
        assert!(report.staging_validated_before_publish);
        assert!(report.destination_root_reauthentication);

        // 7. Open the received filesystem and verify data integrity.
        let received =
            crate::LocalFileSystem::open_with_root_authentication_key(&target_root, opts, auth_key)
                .expect("open received fs");
        let data = received.read_file("/data/f1").expect("read f1");
        assert_eq!(data, b"epoch-tracked stream");
        let stat = received.stat("/data/f1").expect("stat f1");
        assert_eq!(stat.size, 20);
        drop(received);

        // Cleanup.
        let _ = std::fs::remove_dir_all(&source_root);
        let _ = std::fs::remove_dir_all(&target_root);
    }

    #[test]
    fn verify_placement_stable_match() {
        let report = crate::ChangedRecordImportReport {
            spec: crate::SEND_RECEIVE_CHANGED_RECORD_SPEC,
            target_root: std::path::PathBuf::from("/tmp/test"),
            imported_roots: 1,
            imported_records: 1,
            imported_payload_bytes: 0,
            selected_generation: 1,
            selected_transaction_id: 1,
            snapshot_catalog_entries: 0,
            stream_version: 3,
            staging_validated_before_publish: true,
            destination_root_reauthentication: true,
            production_fsck_required: false,
            placement_epoch: Some(7),
            placement_verified_stable: false,
        };
        assert!(verify_placement_stable(Some(7), &report));
        assert!(!verify_placement_stable(Some(8), &report));
        assert!(!verify_placement_stable(None, &report));
    }

    #[test]
    fn incremental_receive_placement_match_reports_stable() {
        let stable = incremental_receive_placement_verified_stable(Some(7), Some(7))
            .expect("matching placement epochs should be stable");
        assert!(stable);
    }

    #[test]
    fn incremental_receive_placement_mismatch_refuses() {
        let err = incremental_receive_placement_verified_stable(Some(7), Some(8))
            .expect_err("mismatched placement epochs must fail closed");
        assert!(
            err.to_string()
                .contains("stream placement epoch does not match target placement epoch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn incremental_receive_placement_absent_is_unknown() {
        assert!(!incremental_receive_placement_verified_stable(None, None)
            .expect("absent placement epochs should be reported as unknown"));
        assert!(
            !incremental_receive_placement_verified_stable(Some(7), None)
                .expect("missing stream placement epoch should be reported as unknown")
        );
        assert!(
            !incremental_receive_placement_verified_stable(None, Some(7))
                .expect("missing target placement epoch should be reported as unknown")
        );
    }

    #[test]
    fn verify_placement_stable_none_is_unknown() {
        let report = crate::ChangedRecordImportReport {
            spec: crate::SEND_RECEIVE_CHANGED_RECORD_SPEC,
            target_root: std::path::PathBuf::from("/tmp/test"),
            imported_roots: 1,
            imported_records: 1,
            imported_payload_bytes: 0,
            selected_generation: 1,
            selected_transaction_id: 1,
            snapshot_catalog_entries: 0,
            stream_version: 1,
            staging_validated_before_publish: true,
            destination_root_reauthentication: true,
            production_fsck_required: false,
            placement_epoch: None,
            placement_verified_stable: false,
        };
        // Missing placement evidence is unknown/unstable, not proof of stability.
        assert!(!verify_placement_stable(None, &report));
        assert!(!verify_placement_stable(Some(1), &report));
    }
}
