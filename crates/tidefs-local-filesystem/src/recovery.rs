// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use tidefs_local_object_store::{
    checksum64,
    pool::{is_strict_read_authority_error, Pool},
    CrashInjectionPoint, DeviceIoClass, IntegrityDigest64, LocalObjectStore, ObjectKey,
    ObjectLocation, StoreError,
};
use tidefs_types_vfs_core::{Generation, InodeId, NodeKind, ROOT_INODE_ID};

use crate::allocation_bytes;
use crate::constants::*;
use crate::content_allocation_entries_for_state;
use crate::crash_hooks::check_crash_hook;
use crate::encoding::*;
use crate::error::FileSystemError;
use crate::helpers::*;
use crate::intent_log::{
    replay_uncommitted, replay_uncommitted_with_pool, IntentLog, IntentLogRootAnchor,
};
use crate::merge_allocation_entries;
use crate::object_keys::*;
use crate::persistence::{persist_state_with_pool, root_slot_for_transaction};
use crate::read_content_from_store;
use crate::read_content_layout_from_store;
use crate::records::*;
use crate::types::*;
use crate::{is_skippable_recovery_error, is_skippable_store_error};
use crate::{
    transaction_manifest_entries_for_existing_content,
    transaction_manifest_entries_for_pool_content,
};
use crate::{DatasetInodeAuthority, FileSystemState, QuotaTable, Result, ROOT_DATASET_ID};
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_space_accounting::SpaceAccounting;
pub(crate) fn initial_state() -> FileSystemState {
    let inode_authority = DatasetInodeAuthority::fresh_root(ROOT_DATASET_ID);
    let root_inode_id = inode_authority.root_inode_id();
    let root = InodeRecord {
        rdev: 0,
        inode_id: root_inode_id,
        generation: Generation::new(1),
        facets: NodeKind::Dir.to_facets(),
        mode: mode_for_kind(NodeKind::Dir, DEFAULT_DIRECTORY_PERMISSIONS),
        uid: 0,
        gid: 0,
        nlink: 2,
        size: 0,
        data_version: 1,
        metadata_version: 1,
        posix_time: PosixTimeRecord::now(),
        xattrs: BTreeMap::new(),
        dir_storage_kind: 0,
        xattr_storage_kind: 0,
        dir_rev: 0,
        subtree_rev: 0,
    };
    let mut inodes = BTreeMap::new();
    inodes.insert(root_inode_id, root);
    let mut directories = BTreeMap::new();
    directories.insert(root_inode_id, BTreeMap::new());
    FileSystemState {
        inode_authority,
        generation: 1,
        inodes: Arc::new(inodes),
        directories: Arc::new(directories),
        snapshots: BTreeMap::new(),
        dirty_content: BTreeSet::new(),
        dirty_inodes: BTreeSet::new(),
        dirty_dirs: BTreeSet::new(),
        quota_table: QuotaTable::new(),
        space_accounting: SpaceAccounting::empty(),
        last_inode_write_tx: BTreeMap::new(),
        last_dir_write_tx: BTreeMap::new(),
        known_inode_ids: {
            let mut ids = BTreeSet::new();
            ids.insert(root_inode_id);
            ids
        },
        corrupted_inodes: BTreeSet::new(),
        change_streams: BTreeMap::new(),
        extent_maps: Arc::new(Mutex::new(BTreeMap::new())),
        dirty_extent_maps: BTreeSet::new(),
        last_extent_map_write_tx: BTreeMap::new(),
        content_compression_policy: ContentCompressionPolicy::default(),
    }
}

fn namespace_entry_matches_target_inode(entry: &NamespaceEntry, target: &InodeRecord) -> bool {
    entry.inode_id == target.inode_id
        && entry.facets() == target.facets()
        && entry.kind() == target.kind()
}

pub(crate) struct RootSelection {
    report: RecoveryProbeReport,
    state: Option<FileSystemState>,
    selected_root: Option<CommittedRootSummary>,
}

#[derive(Clone)]
struct QuorumRootCandidate {
    root: RootCommitRecord,
    supporting_store_indices: BTreeSet<usize>,
}

struct QuorumRootCandidateScan {
    roots_by_transaction: BTreeMap<u64, Vec<QuorumRootCandidate>>,
    root_slots_seen: u64,
    root_candidate_locations_seen: u64,
    skipped_root_candidates: u64,
    checked_transaction_manifests: u64,
    first_candidate_io_error: Option<FileSystemError>,
}

#[derive(Clone)]
struct ValidatedCommittedRoot {
    candidate: QuorumRootCandidate,
    state: FileSystemState,
}

struct RecoveryAuditDetails {
    report: RecoveryAuditReport,
    validated_roots: Vec<ValidatedCommittedRoot>,
    quorum_candidates: Vec<QuorumRootCandidate>,
}

trait CommittedRootRecoverySource {
    fn raw_store(&self) -> &LocalObjectStore;

    fn load_committed_state(
        &mut self,
        root: &RootCommitRecord,
        supporting_store_indices: &BTreeSet<usize>,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<FileSystemState>;

    fn read_current_content_for_retention(&self, key: ObjectKey) -> Result<Option<Vec<u8>>>;
}

impl CommittedRootRecoverySource for LocalObjectStore {
    fn raw_store(&self) -> &LocalObjectStore {
        self
    }

    fn load_committed_state(
        &mut self,
        root: &RootCommitRecord,
        supporting_store_indices: &BTreeSet<usize>,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<FileSystemState> {
        load_state_from_transaction_store_candidate(
            self,
            root,
            supporting_store_indices,
            root_authentication_key,
        )
    }

    fn read_current_content_for_retention(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key)?)
    }
}

impl CommittedRootRecoverySource for Pool {
    fn raw_store(&self) -> &LocalObjectStore {
        self.raw_primary_store()
    }

    fn load_committed_state(
        &mut self,
        root: &RootCommitRecord,
        supporting_store_indices: &BTreeSet<usize>,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<FileSystemState> {
        load_state_from_transaction_pool_candidate(
            self,
            root,
            supporting_store_indices,
            root_authentication_key,
        )
        .map_err(pool_candidate_content_error)
    }

    fn read_current_content_for_retention(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        self.get_with_current_receipt(DeviceIoClass::Data, key)
            .map(|content| content.map(|(bytes, _receipt)| bytes))
            .map_err(FileSystemError::from)
            .map_err(pool_candidate_content_error)
    }
}

fn pool_candidate_content_error(error: FileSystemError) -> FileSystemError {
    let is_content_authority_failure = match &error {
        FileSystemError::Store(store_error) => is_strict_read_authority_error(store_error),
        FileSystemError::ReceiptAuthorityUnavailable { .. }
        | FileSystemError::ReceiptAuthorityMissing { .. }
        | FileSystemError::ReceiptAuthorityStale { .. }
        | FileSystemError::ReceiptAuthoritySynthetic { .. }
        | FileSystemError::ReceiptAuthorityMalformedPolicy { .. }
        | FileSystemError::ReceiptAuthorityUnderWidth { .. }
        | FileSystemError::ReceiptAuthorityOverWidth { .. } => true,
        _ => false,
    };
    if is_content_authority_failure {
        FileSystemError::CorruptState {
            reason: "committed root content lacks current Pool placement authority",
        }
    } else {
        error
    }
}

fn is_candidate_local_store_io(error: &StoreError) -> bool {
    matches!(error, StoreError::Io { .. })
}

fn validate_superblock_format_compatibility(superblock: &SuperblockRecord) -> Result<()> {
    if superblock.format_version_min == 0
        || superblock.format_version_max == 0
        || superblock.format_version_min > superblock.format_version_max
    {
        return Err(FileSystemError::CorruptState {
            reason: "superblock contains an invalid format-version range",
        });
    }
    if CURRENT_FORMAT_VERSION < superblock.format_version_min
        || CURRENT_FORMAT_VERSION < superblock.format_version_max
    {
        return Err(FileSystemError::FormatVersionIncompatible {
            running_version: CURRENT_FORMAT_VERSION,
            filesystem_min: superblock.format_version_min,
            filesystem_max: superblock.format_version_max,
        });
    }
    Ok(())
}

fn retired_v0390_fixed_superblock_marker_present(store: &LocalObjectStore) -> Result<bool> {
    Ok(store
        .get(retired_v0390_fixed_superblock_object_key())?
        .is_some())
}

fn retired_v0390_fixed_superblock_error() -> FileSystemError {
    FileSystemError::CorruptState {
        reason: RETIRED_V0390_FIXED_SUPERBLOCK_REFUSAL_REASON,
    }
}

pub(crate) fn load_latest_committed_state(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
    policy: RecoveryPolicy,
) -> Result<Option<FileSystemState>> {
    let selection = select_latest_committed_root(store, root_authentication_key)?;
    match selection.report.outcome {
        RecoveryProbeOutcome::SelectedCommittedRoot => {
            let mut state = selection.state.ok_or(FileSystemError::CorruptState {
                reason: "recovery selected a committed root without decoded state",
            })?;
            // After selecting the newest valid committed root, replay any
            // uncommitted intent log entries (fsynced data that survived
            // a crash but was never promoted to a transaction group commit).
            let since_tx = selection.report.selected_transaction_id.unwrap_or(0);
            if policy.allows_replay() {
                let log = IntentLog::load(store)?;
                check_crash_hook(CrashInjectionPoint::RecoveryBeforeReplay);
                if log.replay_is_needed(since_tx) {
                    let count = replay_uncommitted(&log, &mut state, store, since_tx)?;
                    check_crash_hook(CrashInjectionPoint::RecoveryAfterReplay);
                    if count > 0 {
                        eprintln!(
                            "recovery: replayed {count} uncommitted intent log entries after transaction {since_tx}"
                        );
                    }
                }
            } else {
                eprintln!(
                    "recovery: policy={} skips intent-log replay after tx {since_tx}",
                    policy.label(),
                );
            }
            Ok(Some(state))
        }
        RecoveryProbeOutcome::EmptyStore => {
            if retired_v0390_fixed_superblock_marker_present(store)? {
                Err(retired_v0390_fixed_superblock_error())
            } else {
                Ok(None)
            }
        }
        RecoveryProbeOutcome::ExplicitIntegrityOrMediaError => Err(FileSystemError::CorruptState {
            reason: "root slots exist but no valid committed root could be selected",
        }),
    }
}

/// Select a mounted recovery root only when its committed content remains
/// readable through current Pool placement authority.
pub(crate) fn load_latest_committed_state_pool(
    pool: &mut Pool,
    root_authentication_key: RootAuthenticationKey,
    policy: RecoveryPolicy,
) -> Result<Option<FileSystemState>> {
    let selection = select_latest_committed_root_from_source(pool, root_authentication_key)?;
    match selection.report.outcome {
        RecoveryProbeOutcome::SelectedCommittedRoot => {
            let mut state = selection.state.ok_or(FileSystemError::CorruptState {
                reason: "recovery selected a committed root without decoded state",
            })?;
            if !policy.allows_replay() {
                return Ok(Some(state));
            }
            let selected_root =
                selection
                    .selected_root
                    .as_ref()
                    .ok_or(FileSystemError::CorruptState {
                        reason: "recovery selected state without exact committed-root identity",
                    })?;
            let committed_base = IntentLogRootAnchor::from_committed_root_summary(selected_root);
            let since_tx = committed_base.transaction_id;
            let mut log = IntentLog::load(pool.raw_primary_store())?;
            if log.replay_is_needed(since_tx) {
                check_crash_hook(CrashInjectionPoint::RecoveryBeforeReplay);
                let count = replay_uncommitted_with_pool(&log, &mut state, pool, &committed_base)?;
                check_crash_hook(CrashInjectionPoint::RecoveryAfterReplay);
                if count > 0 {
                    persist_state_with_pool(pool, &state, root_authentication_key)?;
                    let generation = state.generation;
                    for inode_id in state.dirty_inodes.iter().copied() {
                        state.last_inode_write_tx.insert(inode_id, generation);
                    }
                    for inode_id in state.dirty_dirs.iter().copied() {
                        state.last_dir_write_tx.insert(inode_id, generation);
                    }
                    state.dirty_content.clear();
                    state.dirty_inodes.clear();
                    state.dirty_dirs.clear();
                    eprintln!(
                        "recovery: replayed {count} intent log entries through Pool authority after transaction {since_tx}"
                    );
                }
            }
            // A selected root at or beyond every remaining anchor already
            // contains those intents. Clearing after root publication is
            // retry-safe when a prior mount crashed between the two steps.
            if !log.is_empty() {
                log.clear(pool.raw_primary_store_mut())?;
            }
            Ok(Some(state))
        }
        RecoveryProbeOutcome::EmptyStore => {
            if retired_v0390_fixed_superblock_marker_present(pool.raw_primary_store())? {
                Err(retired_v0390_fixed_superblock_error())
            } else {
                Ok(None)
            }
        }
        RecoveryProbeOutcome::ExplicitIntegrityOrMediaError => Err(FileSystemError::CorruptState {
            reason: "root slots exist but no Pool-authorized committed root could be selected",
        }),
    }
}

pub(crate) fn recovery_probe_from_store(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RecoveryProbeReport> {
    let mut report = select_latest_committed_root(store, root_authentication_key)?.report;
    if report.outcome == RecoveryProbeOutcome::EmptyStore
        && retired_v0390_fixed_superblock_marker_present(store)?
    {
        report.outcome = RecoveryProbeOutcome::ExplicitIntegrityOrMediaError;
    }
    Ok(report)
}

pub(crate) fn audit_recovery_store(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RecoveryAuditReport> {
    Ok(audit_recovery_source_details(store, root_authentication_key)?.report)
}

pub(crate) fn audit_recovery_pool(
    pool: &mut Pool,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RecoveryAuditReport> {
    Ok(audit_recovery_source_details(pool, root_authentication_key)?.report)
}

fn audit_recovery_source_details<S: CommittedRootRecoverySource>(
    source: &mut S,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RecoveryAuditDetails> {
    let scan = scan_quorum_root_candidates(source)?;
    if let Some(error) = scan.first_candidate_io_error {
        return Err(error);
    }
    let mut report = RecoveryAuditReport::empty();
    report.root_slots_seen = scan.root_slots_seen;
    report.root_candidates_seen = scan.root_candidate_locations_seen;
    report.invalid_root_candidates = scan.skipped_root_candidates;
    report.checked_transaction_manifests = scan.checked_transaction_manifests;

    let mut protected_slots = BTreeSet::new();
    let mut validated_roots = Vec::new();
    let mut quorum_candidates = Vec::new();

    for (_transaction_id, candidates) in scan.roots_by_transaction.into_iter().rev() {
        quorum_candidates.extend(candidates.iter().cloned());
        if candidates
            .first()
            .is_some_and(|candidate| protected_slots.contains(&candidate.root.slot))
        {
            continue;
        }

        let mut validated_for_transaction = Vec::new();
        for candidate in candidates {
            match source.load_committed_state(
                &candidate.root,
                &candidate.supporting_store_indices,
                root_authentication_key,
            ) {
                Ok(state) => {
                    validated_for_transaction.push(ValidatedCommittedRoot { candidate, state })
                }
                Err(err) if is_skippable_recovery_error(&err) => {
                    report.invalid_root_candidates =
                        report.invalid_root_candidates.saturating_add(1);
                }
                Err(err) => return Err(err),
            }
        }
        if validated_for_transaction.len() > 1 {
            return Err(FileSystemError::CorruptState {
                reason: "conflicting authenticated committed roots share a transaction id",
            });
        }
        if let Some(validated) = validated_for_transaction.pop() {
            let summary = validated.candidate.root.summary();
            protected_slots.insert(validated.candidate.root.slot);
            if report.selected_root.is_none() {
                report.selected_root = Some(summary.clone());
            }
            report.valid_committed_roots.push(summary);
            validated_roots.push(validated);
        }
    }

    if report.selected_root.is_some() {
        report.outcome = RecoveryAuditOutcome::SelectedCommittedRoot;
    } else if report.root_slots_seen > 0
        || retired_v0390_fixed_superblock_marker_present(source.raw_store())?
    {
        report.outcome = RecoveryAuditOutcome::ExplicitIntegrityOrMediaError;
    }
    Ok(RecoveryAuditDetails {
        report,
        validated_roots,
        quorum_candidates,
    })
}

pub fn verify_online_store(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
) -> Result<OnlineVerifierReport> {
    let mut report = OnlineVerifierReport::empty();
    let mut selected: Option<CommittedRootSummary> = None;

    for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        let slot_key = root_slot_object_key(slot);
        let locations = store.version_locations_of(slot_key);
        if locations.is_empty() {
            continue;
        }
        let mut slot_issues = Vec::new();
        let mut slot_verified = false;
        report.root_slots_seen = report.root_slots_seen.saturating_add(1);
        report.root_slot_records_seen = report
            .root_slot_records_seen
            .saturating_add(locations.len() as u64);

        for location in locations.into_iter().rev() {
            report.root_candidates_seen = report.root_candidates_seen.saturating_add(1);
            let bytes = match store.get_at_location(location) {
                Ok(bytes) => bytes,
                Err(err) => {
                    report.invalid_root_candidates =
                        report.invalid_root_candidates.saturating_add(1);
                    slot_issues.push(online_verifier_issue(
                        OnlineVerifierIssueKind::RootSlotRead,
                        Some(slot),
                        Some(location),
                        None,
                        format!("could not read root-slot candidate: {err}"),
                    ));
                    continue;
                }
            };
            let root = match decode_root_commit(&bytes) {
                Ok(root) => root,
                Err(err) => {
                    report.invalid_root_candidates =
                        report.invalid_root_candidates.saturating_add(1);
                    slot_issues.push(online_verifier_issue(
                        OnlineVerifierIssueKind::RootCommitDecode,
                        Some(slot),
                        Some(location),
                        None,
                        err.to_string(),
                    ));
                    continue;
                }
            };
            if root.slot != slot || root.transaction_id < ROOT_COMMIT_MIN_TRANSACTION_ID {
                report.invalid_root_candidates = report.invalid_root_candidates.saturating_add(1);
                slot_issues.push(online_verifier_issue(
                    OnlineVerifierIssueKind::RootCommitIdentity,
                    Some(slot),
                    Some(location),
                    Some(&root),
                    "root commit slot or transaction id does not match the root-slot ring",
                ));
                continue;
            }

            match online_verifier_root_report(store, &root, root_authentication_key) {
                Ok(root_report) => {
                    if selected
                        .as_ref()
                        .map(|current| root_report.root.transaction_id > current.transaction_id)
                        .unwrap_or(true)
                    {
                        selected = Some(root_report.root.clone());
                    }
                    report.checked_transaction_manifests = report
                        .checked_transaction_manifests
                        .saturating_add(if root.has_manifest() { 1 } else { 0 });
                    report.checked_content_objects = report
                        .checked_content_objects
                        .saturating_add(root_report.checked_content_objects);
                    report.checked_content_chunks = report
                        .checked_content_chunks
                        .saturating_add(root_report.checked_content_chunks);
                    report.verified_snapshot_roots = report
                        .verified_snapshot_roots
                        .saturating_add(root_report.verified_snapshot_roots);
                    report.verified_committed_roots.push(root_report);
                    for mut issue in slot_issues.drain(..) {
                        issue.severity = OnlineVerifierIssueSeverity::Warning;
                        issue.reason = format!(
                            "stale same-slot root candidate ignored after validating fallback root: {}",
                            issue.reason
                        );
                        report.issues.push(issue);
                    }
                    slot_verified = true;
                    // Only validate the latest (most recent) root commit per slot.
                    // Older overwritten entries are stale; their superblocks may
                    // have been cleaned up by segment rotation.
                    break;
                }
                Err(err) => {
                    report.invalid_root_candidates =
                        report.invalid_root_candidates.saturating_add(1);
                    let kind = if matches!(&err, FileSystemError::SnapshotNotFound { .. }) {
                        OnlineVerifierIssueKind::SnapshotRootValidation
                    } else {
                        OnlineVerifierIssueKind::RootCommitValidation
                    };
                    slot_issues.push(online_verifier_issue(
                        kind,
                        Some(slot),
                        Some(location),
                        Some(&root),
                        err.to_string(),
                    ));
                }
            }
        }
        if !slot_verified {
            report.issues.extend(slot_issues);
        }
    }

    if selected.is_none()
        && report.root_slot_records_seen == 0
        && retired_v0390_fixed_superblock_marker_present(store)?
    {
        report.issues.push(online_verifier_issue(
            OnlineVerifierIssueKind::RootCommitValidation,
            None,
            None,
            None,
            RETIRED_V0390_FIXED_SUPERBLOCK_REFUSAL_REASON,
        ));
    }

    let has_error_issue = report
        .issues
        .iter()
        .any(|issue| issue.severity == OnlineVerifierIssueSeverity::Error);
    report.selected_root = selected;
    report.outcome = if has_error_issue {
        OnlineVerifierOutcome::IssuesFound
    } else if report.root_slot_records_seen == 0 {
        OnlineVerifierOutcome::EmptyStore
    } else {
        OnlineVerifierOutcome::Clean
    };
    Ok(report)
}

pub fn online_verifier_root_report(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
) -> Result<OnlineVerifierRootReport> {
    if !root.has_manifest() {
        return Err(FileSystemError::CorruptState {
            reason: "online verifier requires manifest-backed committed roots",
        });
    }
    if root.root_authentication.is_none() {
        return Err(FileSystemError::CorruptState {
            reason: "online verifier requires authenticated committed roots",
        });
    }
    let state = load_state_from_transaction(store, root, root_authentication_key)?;
    let mount_invariant = mount_invariant_report_from_state(&state)?;
    let (checked_content_objects, checked_content_chunks) =
        online_verifier_content_counts(store, &state)?;
    let verified_snapshot_roots =
        online_verifier_snapshot_roots(store, root, &state, root_authentication_key)?;
    Ok(OnlineVerifierRootReport {
        root: root.summary(),
        mount_invariant,
        snapshot_catalog_entries: state.snapshots.len(),
        verified_snapshot_roots,
        checked_manifest_entries: root.manifest_entry_count,
        checked_content_objects,
        checked_content_chunks,
    })
}

pub fn online_verifier_content_counts(
    store: &LocalObjectStore,
    state: &FileSystemState,
) -> Result<(u64, u64)> {
    let mut checked_content_objects = 0_u64;
    let mut checked_content_chunks = 0_u64;
    for inode in state.inodes.values() {
        if inode.is_file_like() {
            let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
            if inode.size == 0 && !store.contains_key(content_key) {
                continue;
            }
            let layout = read_content_layout_from_store(store, inode.inode_id, inode)?;
            let _ = read_content_from_store(store, inode.inode_id, inode, None)?;
            checked_content_objects = checked_content_objects.saturating_add(1);
            if let ContentLayout::Chunked(manifest) = layout {
                checked_content_chunks =
                    checked_content_chunks.saturating_add(manifest.chunks.len() as u64);
            }
        }
    }
    Ok((checked_content_objects, checked_content_chunks))
}

pub fn inspect_filesystem_content_objects_store(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
    pool: Option<&Pool>,
) -> Result<FilesystemContentInspectionReport> {
    let mut report = FilesystemContentInspectionReport::empty();
    let Some((selected_root, state)) =
        load_newest_content_inspection_state(store, root_authentication_key)?
    else {
        return Ok(report);
    };
    report.selected_root = Some(selected_root);

    for inode in state.inodes.values() {
        if !inode.is_file_like() {
            continue;
        }
        report.file_like_inodes = report.file_like_inodes.saturating_add(1);
        inspect_inode_content_objects(store, inode, &mut report, pool)?;
    }
    Ok(report)
}

fn load_newest_content_inspection_state(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
) -> Result<Option<(CommittedRootSummary, FileSystemState)>> {
    let mut best: Option<(CommittedRootSummary, FileSystemState)> = None;

    for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        let slot_key = root_slot_object_key(slot);
        let locations = store.version_locations_of(slot_key);
        if locations.is_empty() {
            continue;
        }

        for location in locations.into_iter().rev() {
            let bytes = match store.get_at_location(location) {
                Ok(bytes) => bytes,
                Err(err) if is_skippable_store_error(&err) => continue,
                Err(err) => return Err(FileSystemError::from(err)),
            };
            let root = match decode_root_commit(&bytes) {
                Ok(root) => root,
                Err(_) => continue,
            };
            if root.slot != slot || root.transaction_id < ROOT_COMMIT_MIN_TRANSACTION_ID {
                continue;
            }
            let state = match load_state_from_transaction_for_content_inspection(
                store,
                &root,
                root_authentication_key,
            ) {
                Ok(state) => state,
                Err(err) if is_skippable_recovery_error(&err) => continue,
                Err(err) => return Err(err),
            };
            let summary = root.summary();
            if best
                .as_ref()
                .is_none_or(|(current, _)| summary.transaction_id > current.transaction_id)
            {
                best = Some((summary, state));
            }
            break;
        }
    }

    Ok(best)
}

fn inspect_inode_content_objects(
    store: &LocalObjectStore,
    inode: &InodeRecord,
    report: &mut FilesystemContentInspectionReport,
    pool: Option<&Pool>,
) -> Result<()> {
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);
    let content_bytes = store.get(content_key)?;
    let missing = content_bytes.is_none();
    if missing && inode.size == 0 {
        return Ok(());
    }
    let zero_length_record = content_bytes
        .as_ref()
        .map(|bytes| bytes.is_empty())
        .unwrap_or(false);
    if missing {
        report.observe(FilesystemContentObjectRef {
            kind: FilesystemContentObjectKind::InlineContent,
            inode_id: inode.inode_id,
            data_version: inode.data_version,
            chunk_index: None,
            key: content_key,
            expected_logical_len: Some(inode.size),
            observed_logical_len: None,
            observed_encoded_len: None,
            missing,
            zero_length_record,
            missing_receipt: false,
            receipt_mismatch: false,
            malformed_reason: None,
        });
        return Ok(());
    }

    match read_content_layout_from_store(store, inode.inode_id, inode) {
        Ok(ContentLayout::Inline(content)) => {
            report.observe(FilesystemContentObjectRef {
                kind: FilesystemContentObjectKind::InlineContent,
                inode_id: inode.inode_id,
                data_version: inode.data_version,
                chunk_index: None,
                key: content_key,
                expected_logical_len: Some(inode.size),
                observed_logical_len: Some(content.bytes.len() as u64),
                observed_encoded_len: content_bytes.as_ref().map(|bytes| bytes.len() as u64),
                missing,
                zero_length_record,
                missing_receipt: false,
                receipt_mismatch: false,
                malformed_reason: None,
            });
        }
        Ok(ContentLayout::Chunked(manifest)) => {
            report.observe(FilesystemContentObjectRef {
                kind: FilesystemContentObjectKind::ContentManifest,
                inode_id: inode.inode_id,
                data_version: inode.data_version,
                chunk_index: None,
                key: content_key,
                expected_logical_len: Some(inode.size),
                observed_logical_len: Some(manifest.file_size),
                observed_encoded_len: content_bytes.as_ref().map(|bytes| bytes.len() as u64),
                missing,
                zero_length_record,
                missing_receipt: false,
                receipt_mismatch: false,
                malformed_reason: None,
            });
            for chunk_ref in &manifest.chunks {
                if chunk_ref.is_hole() {
                    continue;
                }
                inspect_chunk_object(store, inode, chunk_ref, report, pool)?;
            }
        }
        Err(err) => {
            report.observe(FilesystemContentObjectRef {
                kind: FilesystemContentObjectKind::InlineContent,
                inode_id: inode.inode_id,
                data_version: inode.data_version,
                chunk_index: None,
                key: content_key,
                expected_logical_len: Some(inode.size),
                observed_logical_len: None,
                observed_encoded_len: content_bytes.as_ref().map(|bytes| bytes.len() as u64),
                missing,
                zero_length_record,
                missing_receipt: false,
                receipt_mismatch: false,
                malformed_reason: Some(err.to_string()),
            });
        }
    }
    Ok(())
}

fn inspect_chunk_object(
    store: &LocalObjectStore,
    inode: &InodeRecord,
    chunk_ref: &ContentChunkRef,
    report: &mut FilesystemContentInspectionReport,
    pool: Option<&Pool>,
) -> Result<()> {
    let key = content_chunk_object_key_for_version(
        inode.inode_id,
        chunk_ref.data_version,
        chunk_ref.chunk_index,
    );
    let bytes = store.get(key)?;
    let missing = bytes.is_none();
    let zero_length_record = bytes
        .as_ref()
        .map(|bytes| bytes.is_empty())
        .unwrap_or(false);
    let (observed_logical_len, malformed_reason) = match bytes.as_deref() {
        None => (None, None),
        Some(raw) if is_dedup_redirect(raw) => match decode_dedup_redirect(raw) {
            Ok(_) => (Some(chunk_ref.len as u64), None),
            Err(err) => (None, Some(err.to_string())),
        },
        Some(raw) => match decode_content_chunk(raw) {
            Ok(chunk) => (Some(chunk.bytes.len() as u64), None),
            Err(err) => (None, Some(err.to_string())),
        },
    };
    report.observe(FilesystemContentObjectRef {
        kind: FilesystemContentObjectKind::ContentChunk,
        inode_id: inode.inode_id,
        data_version: chunk_ref.data_version,
        chunk_index: Some(chunk_ref.chunk_index),
        key,
        expected_logical_len: Some(chunk_ref.len as u64),
        observed_logical_len,
        observed_encoded_len: bytes.as_ref().map(|bytes| bytes.len() as u64),
        missing,
        zero_length_record,
        missing_receipt: !chunk_ref.is_hole() && chunk_ref.placement_receipt_generation == 0,
        receipt_mismatch: false,
        malformed_reason,
    });

    // Validate stored receipt generation against pool when pool is available.
    // Uses chunk_receipt_is_durable from allocation.rs for authoritative
    // receipt-authority gating: hole chunks and zero-generation (pre-v6)
    // chunks return durable-trivial, while non-zero chunks must match the
    // pool's current durable receipt.
    if let Some(pool) = pool {
        if !crate::allocation::chunk_receipt_is_durable(pool, chunk_ref, key) {
            if let Some(last) = report.referenced_objects.last_mut() {
                if !last.receipt_mismatch {
                    last.receipt_mismatch = true;
                    report.receipt_mismatches = report.receipt_mismatches.saturating_add(1);
                }
            }
        }
    }

    Ok(())
}

pub fn online_verifier_snapshot_roots(
    store: &mut LocalObjectStore,
    current_root: &RootCommitRecord,
    state: &FileSystemState,
    root_authentication_key: RootAuthenticationKey,
) -> Result<u64> {
    let mut verified = 0_u64;
    for snapshot in state.snapshots.values() {
        if snapshot.root.transaction_id >= current_root.transaction_id {
            return Err(FileSystemError::CorruptState {
                reason: "online verifier found a snapshot root at or after the current root",
            });
        }
        let _locations = root_slot_locations_for_summary(store, &snapshot.root)?;
        let root = root_commit_from_summary(&snapshot.root);
        let _state = load_state_from_transaction(store, &root, root_authentication_key)?;
        verified = verified.saturating_add(1);
    }
    Ok(verified)
}

pub fn online_verifier_issue(
    kind: OnlineVerifierIssueKind,
    slot: Option<u64>,
    location: Option<ObjectLocation>,
    root: Option<&RootCommitRecord>,
    reason: impl Into<String>,
) -> OnlineVerifierIssue {
    OnlineVerifierIssue {
        severity: OnlineVerifierIssueSeverity::Error,
        kind,
        slot,
        location,
        transaction_id: root.map(|root| root.transaction_id),
        generation: root.map(|root| root.generation),
        reason: reason.into(),
    }
}

#[cfg(test)]
pub(crate) fn plan_root_retention_store(
    store: &mut LocalObjectStore,
    policy: RootRetentionPolicy,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootRetentionPlan> {
    plan_root_retention_source(store, policy, root_authentication_key)
}

pub(crate) fn plan_root_retention_pool(
    pool: &mut Pool,
    policy: RootRetentionPolicy,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootRetentionPlan> {
    plan_root_retention_source(pool, policy, root_authentication_key)
}

fn plan_root_retention_source<S: CommittedRootRecoverySource>(
    source: &mut S,
    policy: RootRetentionPolicy,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootRetentionPlan> {
    policy.validate()?;
    let RecoveryAuditDetails {
        report: audit,
        validated_roots,
        quorum_candidates,
    } = audit_recovery_source_details(source, root_authentication_key)?;
    let retention_debt = RootRetentionDebt {
        policy_required_committed_roots: policy.protected_committed_roots,
        valid_committed_roots_available: audit.valid_committed_roots.len(),
        missing_committed_roots: policy
            .protected_committed_roots
            .saturating_sub(audit.valid_committed_roots.len()),
    };
    let mut protected_roots = audit.valid_committed_roots.clone();
    protected_roots.sort_by(|lhs, rhs| rhs.transaction_id.cmp(&lhs.transaction_id));
    protected_roots.truncate(policy.protected_committed_roots);

    let mut protected_candidates = Vec::with_capacity(protected_roots.len());
    for summary in &protected_roots {
        let validated = validated_roots
            .iter()
            .find(|validated| validated.candidate.root.summary() == *summary)
            .cloned()
            .ok_or(FileSystemError::CorruptState {
                reason: "retention planner lost a Pool-mountable committed-root candidate",
            })?;
        protected_candidates.push(validated);
    }
    expand_data_retaining_snapshot_roots(
        source,
        &quorum_candidates,
        &mut protected_candidates,
        root_authentication_key,
    )?;
    protected_roots = protected_candidates
        .iter()
        .map(|validated| validated.candidate.root.summary())
        .collect();

    let mut protected_keys = BTreeSet::new();
    let mut protected_root_slot_locations = Vec::new();
    for validated in &protected_candidates {
        let summary = validated.candidate.root.summary();
        // Exact locations currently identify primary-store segments only.
        // If a mountable root exists solely on non-primary supporters, refuse
        // compaction rather than preserving the wrong primary slot version.
        protected_root_slot_locations.extend(root_slot_locations_for_summary(
            source.raw_store(),
            &summary,
        )?);
        protected_keys.extend(object_keys_for_validated_root_candidate(
            source,
            &validated.candidate,
            root_authentication_key,
            false,
        )?);
    }

    let live_keys = source.raw_store().list_keys();
    let reclaimable_live_object_keys = live_keys
        .iter()
        .copied()
        .filter(|key| !protected_keys.contains(key))
        .collect();

    Ok(RootRetentionPlan {
        design_rule: PRODUCTION_RECOVERY_DOCTRINE,
        planner_is_not_fsck: RETENTION_RECLAMATION_IS_NOT_FSCK,
        policy,
        audit,
        retention_debt,
        protected_committed_roots: protected_roots,
        protected_object_keys: protected_keys.into_iter().collect(),
        protected_root_slot_locations,
        live_object_keys_seen: live_keys.len() as u64,
        reclaimable_live_object_keys,
        mutating_reclamation_allowed: false,
        production_fsck_required: false,
    })
}

fn validated_root_for_summary<S: CommittedRootRecoverySource>(
    source: &mut S,
    quorum_candidates: &[QuorumRootCandidate],
    summary: &CommittedRootSummary,
    root_authentication_key: RootAuthenticationKey,
) -> Result<ValidatedCommittedRoot> {
    let mut matching = quorum_candidates
        .iter()
        .filter(|candidate| candidate.root.summary() == *summary);
    let candidate = matching
        .next()
        .cloned()
        .ok_or(FileSystemError::CorruptState {
            reason: "retained snapshot root lacks committed-root quorum",
        })?;
    if matching.next().is_some() {
        return Err(FileSystemError::CorruptState {
            reason: "retained snapshot root has ambiguous committed-root quorum",
        });
    }
    let state = source.load_committed_state(
        &candidate.root,
        &candidate.supporting_store_indices,
        root_authentication_key,
    )?;
    Ok(ValidatedCommittedRoot { candidate, state })
}

fn expand_data_retaining_snapshot_roots<S: CommittedRootRecoverySource>(
    source: &mut S,
    quorum_candidates: &[QuorumRootCandidate],
    protected_roots: &mut Vec<ValidatedCommittedRoot>,
    root_authentication_key: RootAuthenticationKey,
) -> Result<()> {
    let mut cursor = 0;
    while cursor < protected_roots.len() {
        let parent_transaction_id = protected_roots[cursor].candidate.root.transaction_id;
        let snapshot_roots = snapshot_retained_roots(&protected_roots[cursor].state);
        for summary in snapshot_roots {
            if summary.transaction_id >= parent_transaction_id {
                return Err(FileSystemError::CorruptState {
                    reason:
                        "retention planner found a snapshot root at or after its containing root",
                });
            }
            if protected_roots
                .iter()
                .any(|validated| validated.candidate.root.summary() == summary)
            {
                continue;
            }
            protected_roots.push(validated_root_for_summary(
                source,
                quorum_candidates,
                &summary,
                root_authentication_key,
            )?);
        }
        cursor += 1;
    }
    Ok(())
}

fn require_primary_retention_bytes(
    store: &LocalObjectStore,
    key: ObjectKey,
    expected_checksum: IntegrityDigest64,
    missing_reason: &'static str,
) -> Result<Vec<u8>> {
    let location = store
        .location_of(key)
        .ok_or(FileSystemError::CorruptState {
            reason: missing_reason,
        })?;
    let bytes = store.read_location_from_store(0, location)?;
    if checksum64(&bytes) != expected_checksum {
        return Err(FileSystemError::CorruptState {
            reason: "retention planner: primary protected object checksum changed",
        });
    }
    Ok(bytes)
}

fn object_keys_for_validated_root_candidate<S: CommittedRootRecoverySource>(
    source: &S,
    candidate: &QuorumRootCandidate,
    root_authentication_key: RootAuthenticationKey,
    content_only: bool,
) -> Result<BTreeSet<ObjectKey>> {
    let transaction = read_transaction_candidate_objects(
        source.raw_store(),
        &candidate.root,
        &candidate.supporting_store_indices,
        root_authentication_key,
    )?;
    let mut keys = BTreeSet::new();
    if !content_only {
        keys.insert(root_slot_object_key(candidate.root.slot));
        keys.insert(transaction_superblock_object_key(
            candidate.root.transaction_id,
        ));
        keys.insert(transaction_manifest_object_key(
            candidate.root.transaction_id,
        ));
        require_primary_retention_bytes(
            source.raw_store(),
            transaction_superblock_object_key(candidate.root.transaction_id),
            candidate.root.superblock_checksum,
            "retention planner: primary cannot preserve the protected transaction superblock",
        )?;
        require_primary_retention_bytes(
            source.raw_store(),
            transaction_manifest_object_key(candidate.root.transaction_id),
            candidate.root.manifest_checksum,
            "retention planner: primary cannot preserve the protected transaction manifest",
        )?;
    }

    for entry in &transaction.manifest.entries {
        let is_content = matches!(
            entry.role,
            TransactionManifestObjectRole::VersionedContent
                | TransactionManifestObjectRole::VersionedContentChunk
        );
        if !content_only || is_content {
            keys.insert(entry.object_key);
        }
        if !content_only {
            require_primary_retention_bytes(
                source.raw_store(),
                entry.object_key,
                entry.checksum,
                "retention planner: primary cannot preserve a protected manifest object",
            )?;
        }
        if entry.role != TransactionManifestObjectRole::VersionedContentChunk {
            continue;
        }

        let chunk_bytes = source
            .read_current_content_for_retention(entry.object_key)?
            .ok_or(FileSystemError::CorruptState {
                reason: "retention planner: committed content chunk is missing",
            })?;
        if checksum64(&chunk_bytes) != entry.checksum {
            return Err(FileSystemError::CorruptState {
                reason: "retention planner: committed content chunk checksum changed",
            });
        }
        if !is_dedup_redirect(&chunk_bytes) {
            continue;
        }
        let canonical_key = decode_dedup_redirect(&chunk_bytes)?;
        let canonical_bytes = source
            .read_current_content_for_retention(canonical_key)?
            .ok_or(FileSystemError::CorruptState {
                reason: "retention planner: dedup redirect target is missing",
            })?;
        let canonical_chunk = decode_content_chunk(&canonical_bytes)?;
        let fingerprint = compute_content_fingerprint(&canonical_chunk.bytes);
        if content_dedup_object_key(&fingerprint) != canonical_key {
            return Err(FileSystemError::CorruptState {
                reason: "retention planner: dedup redirect target has the wrong content identity",
            });
        }
        if !content_only {
            let primary_location = source.raw_store().location_of(canonical_key).ok_or(
                FileSystemError::CorruptState {
                    reason: "retention planner: primary cannot preserve a dedup redirect target",
                },
            )?;
            let primary_bytes = source
                .raw_store()
                .read_location_from_store(0, primary_location)?;
            let primary_chunk = decode_content_chunk(&primary_bytes)?;
            let primary_fingerprint = compute_content_fingerprint(&primary_chunk.bytes);
            if content_dedup_object_key(&primary_fingerprint) != canonical_key {
                return Err(FileSystemError::CorruptState {
                    reason:
                        "retention planner: primary dedup target has the wrong content identity",
                });
            }
        }
        keys.insert(canonical_key);
    }
    Ok(keys)
}

pub(crate) fn reclaim_protected_content_keys_pool(
    pool: &mut Pool,
    root_authentication_key: RootAuthenticationKey,
    state: &FileSystemState,
) -> Result<BTreeSet<ObjectKey>> {
    let RecoveryAuditDetails {
        validated_roots: mut protected_roots,
        quorum_candidates,
        ..
    } = audit_recovery_source_details(pool, root_authentication_key)?;

    // Protect every current root-ring fallback, not only roots named by a
    // snapshot. A later valid candidate in the same physical slot replaces
    // its older overwritten location in this fallback floor; retention
    // compaction handles physical cleanup of those stale locations separately.
    for summary in snapshot_retained_roots(state) {
        if protected_roots
            .iter()
            .any(|validated: &ValidatedCommittedRoot| validated.candidate.root.summary() == summary)
        {
            continue;
        }
        if !quorum_candidates
            .iter()
            .any(|candidate| candidate.root.summary() == summary)
        {
            return Err(FileSystemError::CorruptState {
                reason: "live snapshot references a root outside current recovery authority",
            });
        }
        protected_roots.push(validated_root_for_summary(
            pool,
            &quorum_candidates,
            &summary,
            root_authentication_key,
        )?);
    }
    expand_data_retaining_snapshot_roots(
        pool,
        &quorum_candidates,
        &mut protected_roots,
        root_authentication_key,
    )?;

    let mut protected_keys = BTreeSet::new();
    for validated in protected_roots {
        protected_keys.extend(object_keys_for_validated_root_candidate(
            pool,
            &validated.candidate,
            root_authentication_key,
            true,
        )?);
    }
    Ok(protected_keys)
}

pub(crate) fn object_keys_for_committed_root_summary(
    store: &mut LocalObjectStore,
    summary: &CommittedRootSummary,
    root_authentication_key: RootAuthenticationKey,
) -> Result<BTreeSet<ObjectKey>> {
    let root = root_commit_from_summary(summary);
    let mut keys = BTreeSet::new();
    keys.insert(root_slot_object_key(root.slot));
    keys.insert(transaction_superblock_object_key(root.transaction_id));

    if root.has_manifest() {
        let manifest_key = transaction_manifest_object_key(root.transaction_id);
        keys.insert(manifest_key);
        let manifest_bytes = store
            .get(manifest_key)?
            .ok_or(FileSystemError::CorruptState {
                reason: "retention planner: committed root manifest is missing",
            })?;
        if checksum64(&manifest_bytes) != root.manifest_checksum {
            return Err(FileSystemError::CorruptState {
                reason: "retention planner: committed root manifest checksum changed",
            });
        }
        let manifest = decode_transaction_manifest(&manifest_bytes)?;
        if manifest.transaction_id != root.transaction_id
            || manifest.generation != root.generation
            || manifest.entries.len() as u64 != root.manifest_entry_count
        {
            return Err(FileSystemError::CorruptState {
                reason: "retention planner: manifest does not match committed root summary",
            });
        }
        for entry in &manifest.entries {
            keys.insert(entry.object_key);
        }
        // Protect canonical content-dedup keys. The transaction manifest
        // lists per-inode chunk keys (VersionedContentChunk) but never the
        // canonical content-dedup targets they redirect to.  Without explicit
        // protection, auto-compaction reclaims the shared canonical data,
        // silently corrupting every inode whose chunk redirects to it.
        for entry in &manifest.entries {
            if entry.role != TransactionManifestObjectRole::VersionedContentChunk {
                continue;
            }
            if let Ok(Some(chunk_bytes)) = store.get(entry.object_key) {
                if is_dedup_redirect(&chunk_bytes) {
                    if let Ok(canonical_key) = decode_dedup_redirect(&chunk_bytes) {
                        keys.insert(canonical_key);
                    }
                }
            }
        }
        return Ok(keys);
    }

    let state = load_state_from_transaction(store, &root, root_authentication_key)?;
    for inode in state.inodes.values() {
        keys.insert(transaction_inode_object_key(
            root.transaction_id,
            inode.inode_id,
        ));
        if inode.carries_child_namespace() {
            keys.insert(transaction_directory_object_key(
                root.transaction_id,
                inode.inode_id,
            ));
        }
        if inode.is_file_like() {
            let key = content_object_key_for_version(inode.inode_id, inode.data_version);
            if inode.size > 0 || store.contains_key(key) {
                keys.insert(key);
            }
        }
    }
    Ok(keys)
}

pub(crate) fn root_slot_locations_for_summary(
    store: &LocalObjectStore,
    summary: &CommittedRootSummary,
) -> Result<Vec<ObjectLocation>> {
    let slot_key = root_slot_object_key(summary.slot);
    let mut matches = Vec::new();
    for location in store.version_locations_of(slot_key) {
        let bytes = match store.get_at_location(location) {
            Ok(bytes) => bytes,
            Err(err) if is_skippable_store_error(&err) => continue,
            Err(err) => return Err(FileSystemError::from(err)),
        };
        let root = match decode_root_commit(&bytes) {
            Ok(root) => root,
            Err(_) => continue,
        };
        if root.summary() == *summary {
            matches.push(location);
        }
    }
    if matches.is_empty() {
        return Err(FileSystemError::CorruptState {
            reason: "retention planner: protected committed root slot location is missing",
        });
    }
    Ok(matches)
}

pub(crate) fn root_commit_from_summary(summary: &CommittedRootSummary) -> RootCommitRecord {
    RootCommitRecord {
        slot: summary.slot,
        transaction_id: summary.transaction_id,
        generation: summary.generation,
        next_inode_id: summary.next_inode_id,
        inode_count: summary.inode_count,
        superblock_checksum: summary.superblock_checksum,
        manifest_checksum: summary.manifest_checksum,
        manifest_entry_count: summary.manifest_entry_count,
        root_authentication: match (
            summary.root_authentication_policy_epoch,
            summary.root_authentication_algorithm_suite_id,
            summary.superblock_digest,
            summary.manifest_digest,
            summary.root_authentication_code,
        ) {
            (
                Some(policy_epoch),
                Some(algorithm_suite_id),
                Some(superblock_digest),
                Some(manifest_digest),
                Some(authentication_code),
            ) => Some(RootAuthenticationRecord {
                record_version: ROOT_AUTHENTICATION_RECORD_VERSION,
                algorithm_suite_id,
                policy_epoch,
                superblock_digest,
                manifest_digest,
                authentication_code,
            }),
            _ => None,
        },
    }
}

pub(crate) fn allocator_report_for_state(
    store: &mut LocalObjectStore,
    state: &FileSystemState,
    policy: LocalStorageAllocatorPolicy,
    root_authentication_key: RootAuthenticationKey,
) -> Result<LocalStorageAllocatorReport> {
    policy.validate()?;
    let current_entries = content_allocation_entries_for_state(store, state)?;
    let unique_current_content_objects = current_entries.len() as u64;
    let current_namespace_allocated_bytes = allocation_bytes(&current_entries)?;
    let protected_roots = snapshot_retained_roots(state);
    let mut protected_entries = BTreeMap::new();
    for summary in &protected_roots {
        let root = root_commit_from_summary(summary);
        let committed_state = load_state_from_transaction(store, &root, root_authentication_key)?;
        merge_allocation_entries(
            &mut protected_entries,
            content_allocation_entries_for_state(store, &committed_state)?,
        );
    }
    let protected_committed_root_allocated_bytes = allocation_bytes(&protected_entries)?;
    let mut reserved_entries = protected_entries.clone();
    merge_allocation_entries(&mut reserved_entries, current_entries);
    let allocator_reserved_bytes = allocation_bytes(&reserved_entries)?;
    let reusable_free_bytes = policy
        .content_capacity_bytes
        .saturating_sub(allocator_reserved_bytes);
    let inode_count = state.inodes.len() as u64;
    Ok(LocalStorageAllocatorReport {
        spec: LOCAL_STORAGE_ALLOCATOR_SPEC,
        policy,
        grain_bytes: content_chunk_size() as u64,
        current_namespace_allocated_bytes,
        protected_committed_root_allocated_bytes,
        protected_committed_roots: protected_roots.len() as u64,
        unique_current_content_objects,
        unique_protected_content_objects: protected_entries.len() as u64,
        allocator_reserved_bytes,
        pending_free_bytes: allocator_reserved_bytes
            .saturating_sub(current_namespace_allocated_bytes),
        reusable_free_bytes,
        inode_count,
        free_inodes: policy.inode_capacity.saturating_sub(inode_count),
        enospc_enforced: true,
        statfs_capacity_reporting: true,
        production_fsck_required: false,
    })
}

pub(crate) fn protected_committed_content_entries(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
    state: &FileSystemState,
) -> Result<BTreeMap<ObjectKey, u64>> {
    let protected_roots = snapshot_retained_roots(state);
    let mut entries = BTreeMap::new();
    for summary in &protected_roots {
        let root = root_commit_from_summary(summary);
        let committed_state = load_state_from_transaction(store, &root, root_authentication_key)?;
        let state_entries = content_allocation_entries_for_state(store, &committed_state)?;
        let _state_bytes: u64 = state_entries.values().sum();
        merge_allocation_entries(&mut entries, state_entries);
    }
    Ok(entries)
}

pub(crate) fn snapshot_retained_roots(state: &FileSystemState) -> Vec<CommittedRootSummary> {
    // Ordinary root-slot fallback roots are protected by retention/GC policy.
    // Logical content-capacity admission only reserves roots that a live
    // snapshot or clone keeps user-addressable.
    let mut roots = Vec::new();
    for snapshot in state.snapshots.values() {
        if crate::snapshot::snapshot_record_retains_data(snapshot)
            && !roots.contains(&snapshot.root)
        {
            roots.push(snapshot.root.clone());
        }
    }
    roots
}

pub(crate) fn roots_with_snapshot_roots(
    mut roots: Vec<CommittedRootSummary>,
    state: &FileSystemState,
) -> Vec<CommittedRootSummary> {
    for snapshot_root in snapshot_retained_roots(state) {
        if !roots.contains(&snapshot_root) {
            roots.push(snapshot_root);
        }
    }
    roots
}

pub(crate) fn select_latest_committed_root(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootSelection> {
    select_latest_committed_root_from_source(store, root_authentication_key)
}

pub(crate) fn selected_committed_root_summary_pool(
    pool: &mut Pool,
    root_authentication_key: RootAuthenticationKey,
) -> Result<Option<CommittedRootSummary>> {
    Ok(select_latest_committed_root_from_source(pool, root_authentication_key)?.selected_root)
}

fn scan_quorum_root_candidates<S: CommittedRootRecoverySource>(
    source: &S,
) -> Result<QuorumRootCandidateScan> {
    let quorum = (source.raw_store().stores_count() / 2) + 1;
    let mut encoded_candidates: BTreeMap<(u64, Vec<u8>), BTreeSet<usize>> = BTreeMap::new();
    let mut slots_with_records = BTreeSet::new();
    let mut root_candidate_locations_seen = 0_u64;
    let mut skipped_root_candidates = 0_u64;
    let mut checked_transaction_manifests = 0_u64;
    let mut first_candidate_io_error = None;

    // Retain one store vote per encoded candidate while scanning. The current
    // quorum contract aggregates those store votes by transaction ID below;
    // exact encoded-root vote identity is a separate follow-on boundary.
    for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        let slot_key = root_slot_object_key(slot);
        let all_store_locations = source.raw_store().version_locations_across_stores(slot_key);
        if all_store_locations
            .iter()
            .any(|locations| !locations.is_empty())
        {
            slots_with_records.insert(slot);
        }

        for (store_index, locations) in all_store_locations.iter().enumerate() {
            root_candidate_locations_seen =
                root_candidate_locations_seen.saturating_add(locations.len() as u64);
            for location in locations.iter().rev().copied() {
                let bytes = match source
                    .raw_store()
                    .read_location_from_store(store_index, location)
                {
                    Ok(bytes) => bytes,
                    Err(error)
                        if is_skippable_store_error(&error)
                            || is_candidate_local_store_io(&error) =>
                    {
                        skipped_root_candidates = skipped_root_candidates.saturating_add(1);
                        if is_candidate_local_store_io(&error) && first_candidate_io_error.is_none()
                        {
                            first_candidate_io_error = Some(FileSystemError::from(error));
                        }
                        continue;
                    }
                    Err(error) => return Err(FileSystemError::from(error)),
                };
                encoded_candidates
                    .entry((slot, bytes))
                    .or_default()
                    .insert(store_index);
            }
        }
    }

    let mut decoded_candidates = Vec::new();
    let mut supporting_stores_by_transaction: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
    for ((slot, bytes), supporting_store_indices) in encoded_candidates {
        let root = match decode_quorum_root_candidate(slot, &bytes) {
            Ok(root) => root,
            Err(error) if is_skippable_recovery_error(&error) => {
                skipped_root_candidates = skipped_root_candidates.saturating_add(1);
                continue;
            }
            Err(error) => return Err(error),
        };
        if root.slot != slot
            || root.slot != root_slot_for_transaction(root.transaction_id)
            || root.transaction_id < ROOT_COMMIT_MIN_TRANSACTION_ID
        {
            skipped_root_candidates = skipped_root_candidates.saturating_add(1);
            continue;
        }
        supporting_stores_by_transaction
            .entry(root.transaction_id)
            .or_default()
            .extend(supporting_store_indices.iter().copied());
        decoded_candidates.push(root);
    }

    let mut roots_by_transaction = BTreeMap::new();
    for root in decoded_candidates {
        let supporting_store_indices = supporting_stores_by_transaction
            .get(&root.transaction_id)
            .cloned()
            .unwrap_or_default();
        if supporting_store_indices.len() < quorum {
            skipped_root_candidates = skipped_root_candidates.saturating_add(1);
            continue;
        }
        if root.has_manifest() {
            checked_transaction_manifests = checked_transaction_manifests.saturating_add(1);
        }
        roots_by_transaction
            .entry(root.transaction_id)
            .or_insert_with(Vec::new)
            .push(QuorumRootCandidate {
                root,
                supporting_store_indices,
            });
    }

    Ok(QuorumRootCandidateScan {
        roots_by_transaction,
        root_slots_seen: slots_with_records.len() as u64,
        root_candidate_locations_seen,
        skipped_root_candidates,
        checked_transaction_manifests,
        first_candidate_io_error,
    })
}

fn select_latest_committed_root_from_source<S: CommittedRootRecoverySource>(
    source: &mut S,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootSelection> {
    let mut report = RecoveryProbeReport::empty_with_replay_tail(
        source.raw_store().replay_report().repaired_tail_bytes,
    );
    let scan = scan_quorum_root_candidates(source)?;
    if let Some(error) = scan.first_candidate_io_error {
        return Err(error);
    }
    report.root_slot_records_seen = scan.root_candidate_locations_seen;
    report.root_slot_candidates_seen = scan.root_candidate_locations_seen;
    report.skipped_root_candidates = scan.skipped_root_candidates;
    for (_transaction_id, roots) in scan.roots_by_transaction.into_iter().rev() {
        let mut selected = None;
        for candidate in roots {
            match source.load_committed_state(
                &candidate.root,
                &candidate.supporting_store_indices,
                root_authentication_key,
            ) {
                Ok(state) => {
                    report.valid_committed_roots_seen =
                        report.valid_committed_roots_seen.saturating_add(1);
                    if selected.is_some() {
                        return Err(FileSystemError::CorruptState {
                            reason:
                                "conflicting authenticated committed roots share a transaction id",
                        });
                    }
                    selected = Some((candidate.root, state));
                }
                Err(err) if is_skippable_recovery_error(&err) => {
                    report.skipped_root_candidates =
                        report.skipped_root_candidates.saturating_add(1);
                }
                Err(err) => return Err(err),
            }
        }
        if let Some((root, state)) = selected {
            let selected_root = root.summary();
            report.selected_slot = Some(root.slot);
            report.selected_transaction_id = Some(root.transaction_id);
            report.selected_generation = Some(root.generation);
            report.selected_inode_count = Some(root.inode_count);
            report.outcome = RecoveryProbeOutcome::SelectedCommittedRoot;
            return Ok(RootSelection {
                report,
                state: Some(state),
                selected_root: Some(selected_root),
            });
        }
    }

    if report.root_slot_records_seen > 0 {
        report.outcome = RecoveryProbeOutcome::ExplicitIntegrityOrMediaError;
    }
    Ok(RootSelection {
        report,
        state: None,
        selected_root: None,
    })
}

fn decode_quorum_root_candidate(physical_slot: u64, bytes: &[u8]) -> Result<RootCommitRecord> {
    const ENCODED_VERSION_OFFSET: usize = ROOT_COMMIT_MAGIC.len();
    const ENCODED_VERSION_END: usize = ENCODED_VERSION_OFFSET + 2;
    if bytes.get(..ROOT_COMMIT_MAGIC.len()) == Some(ROOT_COMMIT_MAGIC.as_slice()) {
        if let Some(version_bytes) = bytes.get(ENCODED_VERSION_OFFSET..ENCODED_VERSION_END) {
            let version = u16::from_le_bytes([version_bytes[0], version_bytes[1]]);
            if version > FILESYSTEM_FORMAT_VERSION {
                const RESERVED_END: usize = ENCODED_VERSION_END + 2;
                const SLOT_END: usize = RESERVED_END + 8;
                const TRANSACTION_END: usize = SLOT_END + 8;
                let prefix = bytes
                    .get(..TRANSACTION_END)
                    .ok_or(FileSystemError::Decode {
                        object: "local filesystem root commit",
                        reason: "future-format root candidate lacks the stable authority prefix",
                    })?;
                let reserved = u16::from_le_bytes(
                    prefix[ENCODED_VERSION_END..RESERVED_END]
                        .try_into()
                        .unwrap(),
                );
                let embedded_slot =
                    u64::from_le_bytes(prefix[RESERVED_END..SLOT_END].try_into().unwrap());
                let transaction_id =
                    u64::from_le_bytes(prefix[SLOT_END..TRANSACTION_END].try_into().unwrap());
                if reserved != ROOT_COMMIT_RESERVED
                    || embedded_slot >= FILESYSTEM_ROOT_SLOT_COUNT
                    || embedded_slot != physical_slot
                    || embedded_slot != root_slot_for_transaction(transaction_id)
                    || transaction_id < ROOT_COMMIT_MIN_TRANSACTION_ID
                {
                    return Err(FileSystemError::CorruptState {
                        reason: "future-format root candidate lacks admissible stable authority",
                    });
                }
                return Err(FileSystemError::FormatVersionIncompatible {
                    running_version: FILESYSTEM_FORMAT_VERSION,
                    filesystem_min: version,
                    filesystem_max: version,
                });
            }
        }
    }
    decode_root_commit(bytes)
}

pub(crate) fn load_state_from_transaction(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FileSystemState> {
    load_state_from_transaction_with_manifest_validation(store, root, root_authentication_key, true)
}

/// Load transaction metadata from its authenticated manifest, then validate
/// every nonempty committed file-like inode through current Pool authority.
pub(crate) fn load_state_from_transaction_pool(
    pool: &mut Pool,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FileSystemState> {
    let state = load_state_from_transaction_for_content_inspection(
        pool.raw_primary_store_mut(),
        root,
        root_authentication_key,
    )?;
    let superblock_bytes = pool
        .raw_primary_store()
        .get(transaction_superblock_object_key(root.transaction_id))?
        .ok_or(FileSystemError::CorruptState {
            reason: "root commit references a missing transaction superblock",
        })?;
    let root_authentication = validate_root_authentication_record(root, root_authentication_key)?;
    let manifest = validate_root_transaction_manifest(
        pool.raw_primary_store(),
        root,
        &superblock_bytes,
        &root_authentication,
    )?;
    validate_transaction_manifest_matches_loaded_state_pool(
        pool,
        root,
        &state,
        &manifest,
        &superblock_bytes,
        None,
    )?;
    Ok(state)
}

fn read_candidate_object_by_checksum(
    store: &LocalObjectStore,
    supporting_store_indices: &BTreeSet<usize>,
    key: ObjectKey,
    expected_checksum: IntegrityDigest64,
    expected_authentication: Option<(&'static [u8], RootAuthenticationDigest)>,
    missing_reason: &'static str,
) -> Result<Vec<u8>> {
    let locations_by_store = store.version_locations_across_stores(key);
    let mut first_io_error = None;
    for store_index in supporting_store_indices.iter().copied() {
        let Some(locations) = locations_by_store.get(store_index) else {
            continue;
        };
        for location in locations.iter().rev().copied() {
            match store.read_location_from_store(store_index, location) {
                Ok(bytes) if checksum64(&bytes) == expected_checksum => {
                    if expected_authentication.is_some_and(|(domain, expected_digest)| {
                        root_authentication_digest(domain, &bytes) != expected_digest
                    }) {
                        continue;
                    }
                    return Ok(bytes);
                }
                Ok(_) => {}
                Err(error) if is_skippable_store_error(&error) => {}
                Err(error) if is_candidate_local_store_io(&error) => {
                    if first_io_error.is_none() {
                        first_io_error = Some(error);
                    }
                }
                Err(error) => return Err(FileSystemError::from(error)),
            }
        }
    }
    if let Some(error) = first_io_error {
        return Err(FileSystemError::from(error));
    }
    Err(FileSystemError::CorruptState {
        reason: missing_reason,
    })
}

struct TransactionCandidateObjects {
    superblock_bytes: Vec<u8>,
    manifest: TransactionManifestRecord,
    objects: BTreeMap<ObjectKey, Vec<u8>>,
}

fn read_transaction_candidate_objects(
    store: &LocalObjectStore,
    root: &RootCommitRecord,
    supporting_store_indices: &BTreeSet<usize>,
    root_authentication_key: RootAuthenticationKey,
) -> Result<TransactionCandidateObjects> {
    // Reject an unauthenticated root before it can influence metadata I/O or
    // the error selected for fallback.
    let root_authentication = validate_root_authentication_record(root, root_authentication_key)?;
    if !root.has_manifest() {
        return Err(FileSystemError::CorruptState {
            reason: "candidate recovery requires a manifest-backed committed root",
        });
    }

    let superblock_key = transaction_superblock_object_key(root.transaction_id);
    let superblock_bytes = read_candidate_object_by_checksum(
        store,
        supporting_store_indices,
        superblock_key,
        root.superblock_checksum,
        Some((
            ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN,
            root_authentication.superblock_digest,
        )),
        "root candidate has no authenticated transaction superblock on its supporting stores",
    )?;
    let manifest_key = transaction_manifest_object_key(root.transaction_id);
    let manifest_bytes = read_candidate_object_by_checksum(
        store,
        supporting_store_indices,
        manifest_key,
        root.manifest_checksum,
        Some((
            ROOT_AUTHENTICATION_MANIFEST_DOMAIN,
            root_authentication.manifest_digest,
        )),
        "root candidate has no authenticated transaction manifest on its supporting stores",
    )?;
    let manifest =
        validate_root_transaction_manifest_bytes(root, &root_authentication, &manifest_bytes)?;

    let mut objects = BTreeMap::new();
    objects.insert(superblock_key, superblock_bytes.clone());
    for entry in &manifest.entries {
        match entry.role {
            TransactionManifestObjectRole::TransactionSuperblock => {
                if entry.object_key != superblock_key || entry.checksum != root.superblock_checksum
                {
                    return Err(FileSystemError::CorruptState {
                        reason: "candidate manifest superblock entry does not match its root",
                    });
                }
            }
            TransactionManifestObjectRole::TransactionInode
            | TransactionManifestObjectRole::TransactionDirectory
            | TransactionManifestObjectRole::TransactionSnapshotCatalogEntry
            | TransactionManifestObjectRole::TransactionExtentMap => {
                let bytes = read_candidate_object_by_checksum(
                    store,
                    supporting_store_indices,
                    entry.object_key,
                    entry.checksum,
                    None,
                    "candidate manifest object is absent from its supporting stores",
                )?;
                if objects.insert(entry.object_key, bytes).is_some() {
                    return Err(FileSystemError::CorruptState {
                        reason: "candidate manifest repeats a transaction metadata object key",
                    });
                }
            }
            TransactionManifestObjectRole::VersionedContent
            | TransactionManifestObjectRole::VersionedContentChunk => {}
        }
    }

    Ok(TransactionCandidateObjects {
        superblock_bytes,
        manifest,
        objects,
    })
}

fn decode_candidate_superblock(
    root: &RootCommitRecord,
    superblock_bytes: &[u8],
) -> Result<SuperblockRecord> {
    let superblock = decode_superblock(superblock_bytes)?;
    validate_superblock_format_compatibility(&superblock)?;
    if superblock.generation != root.generation
        || superblock.next_inode_id != root.next_inode_id
        || superblock.inode_count != root.inode_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "candidate transaction superblock does not match root commit",
        });
    }
    Ok(superblock)
}

fn load_state_from_transaction_store_candidate(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    supporting_store_indices: &BTreeSet<usize>,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FileSystemState> {
    let candidate = read_transaction_candidate_objects(
        store,
        root,
        supporting_store_indices,
        root_authentication_key,
    )?;
    let superblock = decode_candidate_superblock(root, &candidate.superblock_bytes)?;
    let state = load_state_from_superblock_with_content_validation(
        store,
        &superblock,
        Some(root.transaction_id),
        true,
        Some(&candidate.manifest.entries),
        Some(&candidate.objects),
    )?;
    validate_transaction_manifest_matches_loaded_state_with_content(
        store,
        root,
        &state,
        &candidate.manifest,
        &candidate.superblock_bytes,
        Some(&candidate.objects),
        |inode| transaction_manifest_entries_for_existing_content(store, inode),
    )?;
    Ok(state)
}

fn load_state_from_transaction_pool_candidate(
    pool: &mut Pool,
    root: &RootCommitRecord,
    supporting_store_indices: &BTreeSet<usize>,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FileSystemState> {
    let candidate = read_transaction_candidate_objects(
        pool.raw_primary_store(),
        root,
        supporting_store_indices,
        root_authentication_key,
    )?;
    let superblock = decode_candidate_superblock(root, &candidate.superblock_bytes)?;
    let state = load_state_from_superblock_for_content_inspection(
        pool.raw_primary_store_mut(),
        &superblock,
        root.transaction_id,
        &candidate.manifest.entries,
        Some(&candidate.objects),
    )?;
    validate_transaction_manifest_matches_loaded_state_pool(
        pool,
        root,
        &state,
        &candidate.manifest,
        &candidate.superblock_bytes,
        Some(&candidate.objects),
    )?;
    Ok(state)
}

fn load_state_from_transaction_for_content_inspection(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FileSystemState> {
    load_state_from_transaction_with_manifest_validation(
        store,
        root,
        root_authentication_key,
        false,
    )
}

fn load_state_from_transaction_with_manifest_validation(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
    validate_manifest_against_loaded_state: bool,
) -> Result<FileSystemState> {
    let superblock_bytes = store
        .get(transaction_superblock_object_key(root.transaction_id))?
        .ok_or(FileSystemError::CorruptState {
            reason: "root commit references a missing transaction superblock",
        })?;
    let actual = checksum64(&superblock_bytes);
    if actual != root.superblock_checksum {
        return Err(FileSystemError::CorruptState {
            reason: "transaction superblock checksum does not match root commit",
        });
    }
    let root_authentication = validate_root_authentication_record(root, root_authentication_key)?;
    let actual_superblock_digest =
        root_authentication_digest(ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN, &superblock_bytes);
    if actual_superblock_digest != root_authentication.superblock_digest {
        return Err(FileSystemError::CorruptState {
            reason: "transaction superblock digest does not match root authentication record",
        });
    }
    let manifest = if root.has_manifest() {
        Some(validate_root_transaction_manifest(
            store,
            root,
            &superblock_bytes,
            &root_authentication,
        )?)
    } else {
        if !root_authentication.manifest_digest.is_zero() {
            return Err(FileSystemError::CorruptState {
                reason: "root authentication manifest digest is non-zero for a root without a transaction manifest",
            });
        }
        None
    };
    let superblock = decode_superblock(&superblock_bytes)?;
    validate_superblock_format_compatibility(&superblock)?;
    if superblock.generation != root.generation
        || superblock.next_inode_id != root.next_inode_id
        || superblock.inode_count != root.inode_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "transaction superblock does not match root commit",
        });
    }
    let state = if validate_manifest_against_loaded_state {
        load_state_from_superblock_with_content_validation(
            store,
            &superblock,
            Some(root.transaction_id),
            true,
            manifest
                .as_ref()
                .map(|manifest| manifest.entries.as_slice()),
            None,
        )?
    } else {
        let manifest = manifest.as_ref().ok_or(FileSystemError::CorruptState {
            reason: "content inspection requires a manifest-backed committed root",
        })?;
        load_state_from_superblock_for_content_inspection(
            store,
            &superblock,
            root.transaction_id,
            &manifest.entries,
            None,
        )?
    };
    if validate_manifest_against_loaded_state {
        if let Some(manifest) = manifest {
            validate_transaction_manifest_matches_loaded_state(
                store,
                root,
                &state,
                &manifest,
                &superblock_bytes,
            )?;
        }
    }
    Ok(state)
}

pub(crate) fn validate_root_transaction_manifest(
    store: &LocalObjectStore,
    root: &RootCommitRecord,
    _superblock_bytes: &[u8],
    root_authentication: &RootAuthenticationRecord,
) -> Result<TransactionManifestRecord> {
    let manifest_bytes = store
        .get(transaction_manifest_object_key(root.transaction_id))?
        .ok_or(FileSystemError::CorruptState {
            reason: "root commit references a missing transaction manifest",
        })?;
    validate_root_transaction_manifest_bytes(root, root_authentication, &manifest_bytes)
}

fn validate_root_transaction_manifest_bytes(
    root: &RootCommitRecord,
    root_authentication: &RootAuthenticationRecord,
    manifest_bytes: &[u8],
) -> Result<TransactionManifestRecord> {
    let actual_manifest_checksum = checksum64(&manifest_bytes);
    if actual_manifest_checksum != root.manifest_checksum {
        return Err(FileSystemError::CorruptState {
            reason: "transaction manifest checksum does not match root commit",
        });
    }
    let actual_manifest_digest =
        root_authentication_digest(ROOT_AUTHENTICATION_MANIFEST_DOMAIN, &manifest_bytes);
    if actual_manifest_digest != root_authentication.manifest_digest {
        return Err(FileSystemError::CorruptState {
            reason: "transaction manifest digest does not match root authentication record",
        });
    }
    let manifest = decode_transaction_manifest(&manifest_bytes)?;
    validate_root_transaction_manifest_record(root, &manifest)?;
    Ok(manifest)
}

pub(crate) fn validate_root_transaction_manifest_record(
    root: &RootCommitRecord,
    manifest: &TransactionManifestRecord,
) -> Result<()> {
    if manifest.transaction_id != root.transaction_id
        || manifest.generation != root.generation
        || manifest.entries.len() as u64 != root.manifest_entry_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "transaction manifest does not match root commit",
        });
    }
    Ok(())
}

pub(crate) fn validate_transaction_manifest_matches_loaded_state(
    store: &LocalObjectStore,
    root: &RootCommitRecord,
    state: &FileSystemState,
    manifest: &TransactionManifestRecord,
    superblock_bytes: &[u8],
) -> Result<()> {
    validate_transaction_manifest_matches_loaded_state_with_content(
        store,
        root,
        state,
        manifest,
        superblock_bytes,
        None,
        |inode| transaction_manifest_entries_for_existing_content(store, inode),
    )
}

fn validate_transaction_manifest_matches_loaded_state_pool(
    pool: &Pool,
    root: &RootCommitRecord,
    state: &FileSystemState,
    manifest: &TransactionManifestRecord,
    superblock_bytes: &[u8],
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
) -> Result<()> {
    validate_transaction_manifest_matches_loaded_state_with_content(
        pool.raw_primary_store(),
        root,
        state,
        manifest,
        superblock_bytes,
        candidate_objects,
        |inode| transaction_manifest_entries_for_pool_content(pool, inode),
    )
}

fn validate_transaction_manifest_matches_loaded_state_with_content(
    store: &LocalObjectStore,
    root: &RootCommitRecord,
    state: &FileSystemState,
    manifest: &TransactionManifestRecord,
    superblock_bytes: &[u8],
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
    mut content_entries: impl FnMut(&InodeRecord) -> Result<Vec<TransactionManifestEntry>>,
) -> Result<()> {
    let (manifest_inode_keys, manifest_directory_keys) =
        manifest_transaction_object_key_maps(store, &manifest.entries, candidate_objects)?;
    let mut expected = Vec::new();
    for inode in state.inodes.values() {
        if inode.is_file_like() {
            expected.extend(content_entries(inode)?);
        }

        let inode_key =
            *manifest_inode_keys
                .get(&inode.inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "transaction manifest validation expected a missing inode object",
                })?;
        let inode_bytes = recovery_object_bytes(store, candidate_objects, inode_key)?.ok_or(
            FileSystemError::CorruptState {
                reason: "transaction manifest validation expected a missing inode object",
            },
        )?;
        if try_encode_inode(inode)? != inode_bytes {
            return Err(FileSystemError::CorruptState {
                reason: "transaction manifest inode object does not match loaded state",
            });
        }
        expected.push(TransactionManifestEntry {
            role: TransactionManifestObjectRole::TransactionInode,
            object_key: inode_key,
            checksum: checksum64(&inode_bytes),
        });

        if inode.carries_child_namespace() {
            let directory_key = *manifest_directory_keys.get(&inode.inode_id).ok_or(
                FileSystemError::CorruptState {
                    reason: "transaction manifest validation expected a missing directory object",
                },
            )?;
            let directory_bytes = recovery_object_bytes(store, candidate_objects, directory_key)?
                .ok_or(FileSystemError::CorruptState {
                reason: "transaction manifest validation expected a missing directory object",
            })?;
            let directory =
                state
                    .directories
                    .get(&inode.inode_id)
                    .ok_or(FileSystemError::CorruptState {
                        reason: "loaded directory inode has no directory table",
                    })?;
            if encode_directory(inode, directory) != directory_bytes {
                return Err(FileSystemError::CorruptState {
                    reason: "transaction manifest directory object does not match loaded state",
                });
            }
            expected.push(TransactionManifestEntry {
                role: TransactionManifestObjectRole::TransactionDirectory,
                object_key: directory_key,
                checksum: checksum64(&directory_bytes),
            });
        }
    }

    // v3+: extent map entries — read from the actual manifest and
    // add them to the expected set.  During mount, extent maps are loaded
    // in load_state_from_superblock once they are tracked in FileSystemState.
    for entry in &manifest.entries {
        if entry.role == TransactionManifestObjectRole::TransactionExtentMap {
            if let Some(ext_bytes) =
                recovery_object_bytes(store, candidate_objects, entry.object_key)?
            {
                expected.push(TransactionManifestEntry {
                    role: TransactionManifestObjectRole::TransactionExtentMap,
                    object_key: entry.object_key,
                    checksum: checksum64(&ext_bytes),
                });
            }
        }
    }
    expected.push(TransactionManifestEntry {
        role: TransactionManifestObjectRole::TransactionSuperblock,
        object_key: transaction_superblock_object_key(root.transaction_id),
        checksum: checksum64(superblock_bytes),
    });

    // v3+: snapshot catalog entries
    for snapshot in state.snapshots.values() {
        let snap_key =
            transaction_snapshot_catalog_entry_object_key(root.transaction_id, &snapshot.name);
        let snap_bytes = recovery_object_bytes(store, candidate_objects, snap_key)?.ok_or(
            FileSystemError::CorruptState {
                reason: "transaction manifest validation expected a missing snapshot catalog entry",
            },
        )?;
        expected.push(TransactionManifestEntry {
            role: TransactionManifestObjectRole::TransactionSnapshotCatalogEntry,
            object_key: snap_key,
            checksum: checksum64(&snap_bytes),
        });
    }

    if manifest.entries != expected {
        return Err(FileSystemError::CorruptState {
            reason: "transaction manifest does not exactly match the loaded committed root",
        });
    }
    Ok(())
}

/// Find the transaction key where an inode object currently resides,
/// scanning backwards from `transaction_id`. Needed because dirty-only
/// commits reference older transaction keys for clean inodes.
fn find_inode_key(
    store: &LocalObjectStore,
    transaction_id: u64,
    inode_id: InodeId,
) -> Option<ObjectKey> {
    let mut tx = transaction_id;
    while tx >= ROOT_COMMIT_MIN_TRANSACTION_ID {
        let key = transaction_inode_object_key(tx, inode_id);
        if store.get(key).ok()?.is_some() {
            return Some(key);
        }
        if tx == 1 {
            break;
        }
        tx -= 1;
    }
    None
}

/// Find the transaction key where a directory object currently resides,
/// scanning backwards from `transaction_id`.
fn find_directory_key(
    store: &LocalObjectStore,
    transaction_id: u64,
    inode_id: InodeId,
) -> Option<ObjectKey> {
    let mut tx = transaction_id;
    while tx >= ROOT_COMMIT_MIN_TRANSACTION_ID {
        let key = transaction_directory_object_key(tx, inode_id);
        if store.get(key).ok()?.is_some() {
            return Some(key);
        }
        if tx == 1 {
            break;
        }
        tx -= 1;
    }
    None
}

fn recovery_object_bytes(
    store: &LocalObjectStore,
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
    key: ObjectKey,
) -> Result<Option<Vec<u8>>> {
    match candidate_objects {
        Some(objects) => Ok(objects.get(&key).cloned()),
        None => Ok(store.get(key)?),
    }
}

fn manifest_transaction_object_key_maps(
    store: &LocalObjectStore,
    entries: &[TransactionManifestEntry],
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
) -> Result<(BTreeMap<InodeId, ObjectKey>, BTreeMap<InodeId, ObjectKey>)> {
    let mut inode_keys = BTreeMap::new();
    let mut directory_keys = BTreeMap::new();
    for entry in entries {
        let target = match entry.role {
            TransactionManifestObjectRole::TransactionInode => &mut inode_keys,
            TransactionManifestObjectRole::TransactionDirectory => &mut directory_keys,
            _ => continue,
        };
        let bytes = recovery_object_bytes(store, candidate_objects, entry.object_key)?.ok_or(
            FileSystemError::CorruptState {
                reason: "transaction manifest references a missing namespace object",
            },
        )?;
        if checksum64(&bytes) != entry.checksum {
            return Err(FileSystemError::CorruptState {
                reason: "transaction manifest namespace object checksum mismatch",
            });
        }
        let inode_id = match entry.role {
            TransactionManifestObjectRole::TransactionInode => decode_inode(&bytes)?.inode_id,
            TransactionManifestObjectRole::TransactionDirectory => {
                decode_directory_inode_id(&bytes)?
            }
            _ => unreachable!("non-namespace roles were skipped"),
        };
        if target.insert(inode_id, entry.object_key).is_some() {
            return Err(FileSystemError::CorruptState {
                reason: "transaction manifest contains duplicate namespace objects for an inode",
            });
        }
    }
    Ok((inode_keys, directory_keys))
}

fn manifest_snapshot_records(
    store: &LocalObjectStore,
    entries: &[TransactionManifestEntry],
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
) -> Result<BTreeMap<Vec<u8>, SnapshotRecord>> {
    let mut snapshots = BTreeMap::new();
    for entry in entries {
        if entry.role != TransactionManifestObjectRole::TransactionSnapshotCatalogEntry {
            continue;
        }
        let bytes = recovery_object_bytes(store, candidate_objects, entry.object_key)?.ok_or(
            FileSystemError::CorruptState {
                reason: "manifest references missing snapshot catalog entry",
            },
        )?;
        if checksum64(&bytes) != entry.checksum {
            return Err(FileSystemError::CorruptState {
                reason: "transaction manifest snapshot object checksum mismatch",
            });
        }
        let snapshot = decode_snapshot_record(&bytes)?;
        if snapshots.insert(snapshot.name.clone(), snapshot).is_some() {
            return Err(FileSystemError::Decode {
                object: "local filesystem superblock",
                reason: "duplicate snapshot name",
            });
        }
    }
    Ok(snapshots)
}

fn load_state_from_superblock_for_content_inspection(
    store: &mut LocalObjectStore,
    superblock: &SuperblockRecord,
    transaction_id: u64,
    manifest_entries: &[TransactionManifestEntry],
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
) -> Result<FileSystemState> {
    load_state_from_superblock_with_content_validation(
        store,
        superblock,
        Some(transaction_id),
        false,
        Some(manifest_entries),
        candidate_objects,
    )
}

fn load_state_from_superblock_with_content_validation(
    store: &mut LocalObjectStore,
    superblock: &SuperblockRecord,
    transaction_id: Option<u64>,
    validate_file_content: bool,
    manifest_entries: Option<&[TransactionManifestEntry]>,
    candidate_objects: Option<&BTreeMap<ObjectKey, Vec<u8>>>,
) -> Result<FileSystemState> {
    let (manifest_inode_keys, manifest_directory_keys) = manifest_entries
        .map(|entries| manifest_transaction_object_key_maps(store, entries, candidate_objects))
        .transpose()?
        .map_or((None, None), |(inode_keys, directory_keys)| {
            (Some(inode_keys), Some(directory_keys))
        });
    let mut known_inode_ids = BTreeSet::new();
    let mut inodes = BTreeMap::new();
    let mut directories = BTreeMap::new();
    for (word_idx, word) in superblock.inode_allocation_bitmap.iter().enumerate() {
        let mut bits = *word;
        while bits != 0 {
            let bit = bits.trailing_zeros();
            bits &= bits - 1;
            let inode_id = InodeId::new((word_idx * 64 + bit as usize + 1) as u64);
            known_inode_ids.insert(inode_id);
            let inode_key = match manifest_inode_keys.as_ref() {
                Some(keys) => *keys.get(&inode_id).ok_or(FileSystemError::CorruptState {
                    reason: "superblock references an inode id not present in the manifest",
                })?,
                None => match transaction_id {
                    Some(tx) => find_inode_key(store, tx, inode_id)
                        .unwrap_or_else(|| inode_object_key(inode_id)),
                    None => inode_object_key(inode_id),
                },
            };
            let bytes = recovery_object_bytes(store, candidate_objects, inode_key)?.ok_or(
                FileSystemError::CorruptState {
                    reason: "superblock references a missing inode object",
                },
            )?;
            let inode = decode_inode(&bytes)?;
            if inode.inode_id != inode_id {
                return Err(FileSystemError::CorruptState {
                    reason: "inode object id does not match superblock",
                });
            }
            if inode.carries_child_namespace() {
                let dir_key = match manifest_directory_keys.as_ref() {
                    Some(keys) => *keys.get(&inode_id).ok_or(FileSystemError::CorruptState {
                        reason: "directory inode id is not present in the manifest",
                    })?,
                    None => match transaction_id {
                        Some(tx) => find_directory_key(store, tx, inode_id)
                            .unwrap_or_else(|| directory_object_key(inode_id)),
                        None => directory_object_key(inode_id),
                    },
                };
                let dir_bytes = recovery_object_bytes(store, candidate_objects, dir_key)?.ok_or(
                    FileSystemError::CorruptState {
                        reason: "directory inode is missing its directory object",
                    },
                )?;
                let directory = decode_directory(&dir_bytes)?;
                directories.insert(inode_id, directory);
            }
            inodes.insert(inode_id, inode);
        }
    }
    if validate_file_content {
        validate_loaded_state(store, &inodes, &directories)?;
    } else {
        validate_loaded_namespace_state(&inodes, &directories)?;
    }
    let mut snapshots = match manifest_entries {
        Some(entries) => manifest_snapshot_records(store, entries, candidate_objects)?,
        None => BTreeMap::new(),
    };
    if manifest_entries.is_none() {
        if let Some(cg_id) = transaction_id {
            // Load current snapshot records from transaction manifest entries.
            let manifest_key = transaction_manifest_object_key(cg_id);
            if let Some(manifest_bytes) = store.get(manifest_key)? {
                let manifest = decode_transaction_manifest(&manifest_bytes)?;
                for entry in manifest.entries {
                    if entry.role == TransactionManifestObjectRole::TransactionExtentMap {
                        // Extent maps are now tracked within FileSystemState; skip here.
                        // They are loaded and validated separately during mount.
                    }
                    if entry.role == TransactionManifestObjectRole::TransactionSnapshotCatalogEntry
                    {
                        let snap_bytes =
                            store
                                .get(entry.object_key)?
                                .ok_or(FileSystemError::CorruptState {
                                    reason: "manifest references missing snapshot catalog entry",
                                })?;
                        let snapshot = decode_snapshot_record(&snap_bytes)?;
                        if snapshots.insert(snapshot.name.clone(), snapshot).is_some() {
                            return Err(FileSystemError::Decode {
                                object: "local filesystem superblock",
                                reason: "duplicate snapshot name",
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(FileSystemState {
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
        quota_table: QuotaTable::new(),
        space_accounting: SpaceAccounting::empty(),
        known_inode_ids,
        corrupted_inodes: BTreeSet::new(),
        last_inode_write_tx: BTreeMap::new(),
        last_dir_write_tx: BTreeMap::new(),
        change_streams: BTreeMap::new(),
        extent_maps: Arc::new(Mutex::new(BTreeMap::new())),
        dirty_extent_maps: BTreeSet::new(),
        last_extent_map_write_tx: BTreeMap::new(),
        content_compression_policy: ContentCompressionPolicy::default(),
    })
}

/// Load FileSystemState from a snapshot superblock, reusing unchanged
/// inodes and directories from an already-validated in-memory state.
///
/// ZFS rollback is O(1) — it swaps a block pointer.  Without incremental
/// reload, TideFS would deserialise every inode and directory object from
/// the object store even when only a handful were touched since the
/// snapshot was created.  This function avoids that by comparing each
/// inode's `metadata_version` and `data_version` against
/// `snapshot_generation`: inodes that were not mutated after the snapshot
/// are simply cloned from `current_state`.
///
/// Inodes that *were* mutated (or that no longer exist in the current
/// state — they were deleted after the snapshot) are loaded from the
/// snapshot's transaction objects.  Inodes that exist in the current
/// state but not in the snapshot bitmap (created after the snapshot) are
/// silently dropped.
pub(crate) fn load_state_from_superblock_incremental(
    store: &mut LocalObjectStore,
    superblock: &SuperblockRecord,
    transaction_id: u64,
    current_state: &FileSystemState,
    snapshot_generation: u64,
    manifest_entries: Option<&[TransactionManifestEntry]>,
) -> Result<FileSystemState> {
    // Collect known inode IDs from bitmap without eager loading.
    // Build inode_id -> object_key and directory inode_id -> object_key
    // mappings from the transaction manifest (format v2+).
    // The manifest is the authoritative source for which keys belong to which
    // logical objects. Using it avoids linear backward scans via
    // find_inode_key/find_directory_key and correctly handles clean (unchanged)
    // inodes whose object keys live in prior transactions.
    let inode_key_map: Option<BTreeMap<InodeId, ObjectKey>>;
    let dir_key_map: Option<BTreeMap<InodeId, ObjectKey>>;
    let mut snapshots = BTreeMap::new();
    if let Some(entries) = manifest_entries {
        let mut ikm: BTreeMap<InodeId, ObjectKey> = BTreeMap::new();
        let mut dkm: BTreeMap<InodeId, ObjectKey> = BTreeMap::new();
        for entry in entries {
            match entry.role {
                TransactionManifestObjectRole::TransactionInode => {
                    let bytes =
                        store
                            .get(entry.object_key)?
                            .ok_or(FileSystemError::CorruptState {
                                reason: "manifest inode entry references missing object",
                            })?;
                    let inode = decode_inode(&bytes)?;
                    ikm.insert(inode.inode_id, entry.object_key);
                }
                TransactionManifestObjectRole::TransactionDirectory => {
                    let bytes =
                        store
                            .get(entry.object_key)?
                            .ok_or(FileSystemError::CorruptState {
                                reason: "manifest directory entry references missing object",
                            })?;
                    let dir_inode_id = decode_directory_inode_id(&bytes)?;
                    dkm.insert(dir_inode_id, entry.object_key);
                }
                TransactionManifestObjectRole::TransactionSnapshotCatalogEntry => {
                    let snap_bytes =
                        store
                            .get(entry.object_key)?
                            .ok_or(FileSystemError::CorruptState {
                                reason: "manifest references missing snapshot catalog entry",
                            })?;
                    let snapshot = decode_snapshot_record(&snap_bytes)?;
                    if snapshots.insert(snapshot.name.clone(), snapshot).is_some() {
                        return Err(FileSystemError::Decode {
                            object: "local filesystem superblock",
                            reason: "duplicate snapshot name",
                        });
                    }
                }
                _ => {}
            }
        }
        inode_key_map = Some(ikm);
        dir_key_map = Some(dkm);
    } else {
        inode_key_map = None;
        dir_key_map = None;
        let manifest_key = transaction_manifest_object_key(transaction_id);
        if let Some(manifest_bytes) = store.get(manifest_key)? {
            let manifest = decode_transaction_manifest(&manifest_bytes)?;
            for entry in manifest.entries {
                if entry.role == TransactionManifestObjectRole::TransactionSnapshotCatalogEntry {
                    let snap_bytes =
                        store
                            .get(entry.object_key)?
                            .ok_or(FileSystemError::CorruptState {
                                reason: "manifest references missing snapshot catalog entry",
                            })?;
                    let snapshot = decode_snapshot_record(&snap_bytes)?;
                    if snapshots.insert(snapshot.name.clone(), snapshot).is_some() {
                        return Err(FileSystemError::Decode {
                            object: "local filesystem superblock",
                            reason: "duplicate snapshot name",
                        });
                    }
                }
            }
        }
    }
    let mut known_inode_ids = BTreeSet::new();
    known_inode_ids.insert(ROOT_INODE_ID);
    for (word_idx, word) in superblock.inode_allocation_bitmap.iter().enumerate() {
        let mut bits = *word;
        while bits != 0 {
            let bit = bits.trailing_zeros();
            bits &= bits - 1;
            let inode_id = InodeId::new((word_idx * 64 + bit as usize + 1) as u64);
            known_inode_ids.insert(inode_id);
        }
    }
    // Load all inodes eagerly from the snapshot superblock.
    // Incremental rollback validates structural invariants across all
    // loaded inodes, so we cannot defer loading like at mount time.
    let mut inodes = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut reloaded_inode_ids: Vec<InodeId> = Vec::new();
    let _root_id = ROOT_INODE_ID;
    for &inode_id in &known_inode_ids {
        if let Some(current_inode) = current_state.inodes.get(&inode_id) {
            if current_inode.metadata_version <= snapshot_generation
                && current_inode.data_version <= snapshot_generation
            {
                inodes.insert(inode_id, current_inode.clone());
                if let Some(dir) = current_state.directories.get(&inode_id) {
                    directories.insert(inode_id, dir.clone());
                }
                continue;
            }
        }
        load_incremental_inode(IncrementalInodeLoad {
            store,
            transaction_id,
            inode_id,
            inode_key_map: inode_key_map.as_ref(),
            dir_key_map: dir_key_map.as_ref(),
            inodes: &mut inodes,
            directories: &mut directories,
            reloaded_inode_ids: &mut reloaded_inode_ids,
        })?;
    }

    // Structural validation covers the reloaded subset + invariants.
    validate_loaded_state_incremental(store, &inodes, &directories, &reloaded_inode_ids)?;

    Ok(FileSystemState {
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
        quota_table: QuotaTable::new(),
        space_accounting: SpaceAccounting::empty(),
        known_inode_ids,
        corrupted_inodes: BTreeSet::new(),
        last_inode_write_tx: BTreeMap::new(),
        last_dir_write_tx: BTreeMap::new(),
        change_streams: BTreeMap::new(),
        extent_maps: Arc::new(Mutex::new(BTreeMap::new())),
        dirty_extent_maps: BTreeSet::new(),
        last_extent_map_write_tx: BTreeMap::new(),
        content_compression_policy: ContentCompressionPolicy::default(),
    })
}

/// Helper: load a single inode (and its directory) from a snapshot transaction.
struct IncrementalInodeLoad<'a> {
    store: &'a mut LocalObjectStore,
    transaction_id: u64,
    inode_id: InodeId,
    inode_key_map: Option<&'a BTreeMap<InodeId, ObjectKey>>,
    dir_key_map: Option<&'a BTreeMap<InodeId, ObjectKey>>,
    inodes: &'a mut BTreeMap<InodeId, InodeRecord>,
    directories: &'a mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    reloaded_inode_ids: &'a mut Vec<InodeId>,
}

fn load_incremental_inode(request: IncrementalInodeLoad<'_>) -> Result<()> {
    let IncrementalInodeLoad {
        store,
        transaction_id,
        inode_id,
        inode_key_map,
        dir_key_map,
        inodes,
        directories,
        reloaded_inode_ids,
    } = request;
    let inode_key = if let Some(map) = inode_key_map {
        *map.get(&inode_id).ok_or(FileSystemError::CorruptState {
            reason: "superblock references an inode id not present in the manifest",
        })?
    } else {
        find_inode_key(store, transaction_id, inode_id).ok_or(FileSystemError::CorruptState {
            reason: "superblock references a missing inode object",
        })?
    };
    let bytes = store.get(inode_key)?.ok_or(FileSystemError::CorruptState {
        reason: "inode key resolved but object is missing",
    })?;
    let inode = decode_inode(&bytes)?;
    if inode.inode_id != inode_id {
        return Err(FileSystemError::CorruptState {
            reason: "inode object id does not match superblock",
        });
    }
    if inode.carries_child_namespace() {
        let dir_key = if let Some(map) = dir_key_map {
            *map.get(&inode_id).ok_or(FileSystemError::CorruptState {
                reason: "directory inode id is not present in the manifest",
            })?
        } else {
            find_directory_key(store, transaction_id, inode_id).ok_or(
                FileSystemError::CorruptState {
                    reason: "directory inode is missing its directory object",
                },
            )?
        };
        let dir_bytes = store.get(dir_key)?.ok_or(FileSystemError::CorruptState {
            reason: "directory inode is missing its directory object",
        })?;
        let directory = decode_directory(&dir_bytes)?;
        directories.insert(inode_id, directory);
    }
    reloaded_inode_ids.push(inode_id);
    inodes.insert(inode_id, inode);
    Ok(())
}

/// Like `load_state_from_transaction`, but uses the incremental
/// superblock loader so that only inodes modified since the snapshot
/// are re-read from the object store.
pub(crate) fn load_state_from_transaction_incremental(
    store: &mut LocalObjectStore,
    root: &RootCommitRecord,
    root_authentication_key: RootAuthenticationKey,
    current_state: &FileSystemState,
) -> Result<FileSystemState> {
    let superblock_bytes = store
        .get(transaction_superblock_object_key(root.transaction_id))?
        .ok_or(FileSystemError::CorruptState {
            reason: "root commit references a missing transaction superblock",
        })?;
    let actual = checksum64(&superblock_bytes);
    if actual != root.superblock_checksum {
        return Err(FileSystemError::CorruptState {
            reason: "transaction superblock checksum does not match root commit",
        });
    }
    let root_authentication = validate_root_authentication_record(root, root_authentication_key)?;
    let actual_superblock_digest =
        root_authentication_digest(ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN, &superblock_bytes);
    if actual_superblock_digest != root_authentication.superblock_digest {
        return Err(FileSystemError::CorruptState {
            reason: "transaction superblock digest does not match root authentication record",
        });
    }
    let manifest = if root.has_manifest() {
        Some(validate_root_transaction_manifest(
            store,
            root,
            &superblock_bytes,
            &root_authentication,
        )?)
    } else {
        if !root_authentication.manifest_digest.is_zero() {
            return Err(FileSystemError::CorruptState {
                reason: "root authentication manifest digest is non-zero for a root without a transaction manifest",
            });
        }
        None
    };
    let superblock = decode_superblock(&superblock_bytes)?;
    validate_superblock_format_compatibility(&superblock)?;
    if superblock.generation != root.generation
        || superblock.next_inode_id != root.next_inode_id
        || superblock.inode_count != root.inode_count
    {
        return Err(FileSystemError::CorruptState {
            reason: "transaction superblock does not match root commit",
        });
    }
    let state = load_state_from_superblock_incremental(
        store,
        &superblock,
        root.transaction_id,
        current_state,
        root.generation,
        manifest.as_ref().map(|m| m.entries.as_slice()),
    )?;
    if let Some(manifest) = manifest {
        validate_transaction_manifest_matches_loaded_state(
            store,
            root,
            &state,
            &manifest,
            &superblock_bytes,
        )?;
    }
    Ok(state)
}

/// Like `validate_loaded_state`, but only reads content from the store
/// for inodes that were reloaded from the snapshot.  Inodes that were
/// carried over from an already-validated in-memory state are assumed
/// structurally sound and their content is not re-read.
fn validate_loaded_state_incremental(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    reloaded_inode_ids: &[InodeId],
) -> Result<()> {
    validate_loaded_namespace_state(inodes, directories)?;
    // Only read content for inodes that were reloaded from the
    // snapshot; unchanged inodes carried from current_state were
    // already validated when they were originally loaded.
    for &inode_id in reloaded_inode_ids {
        if let Some(inode) = inodes.get(&inode_id) {
            if inode.is_file_like() {
                let _ = read_content_from_store(store, inode.inode_id, inode, None)?;
            }
        }
    }
    Ok(())
}

fn validate_loaded_namespace_state(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
) -> Result<()> {
    if !inodes.contains_key(&ROOT_INODE_ID) {
        return Err(FileSystemError::CorruptState {
            reason: "root inode is missing",
        });
    }
    if !directories.contains_key(&ROOT_INODE_ID) {
        return Err(FileSystemError::CorruptState {
            reason: "root directory object is missing",
        });
    }
    validate_namespace_invariants(inodes, directories)?;
    for (dir_id, directory) in directories {
        let dir_inode = inodes.get(dir_id).ok_or(FileSystemError::CorruptState {
            reason: "directory table has no matching inode",
        })?;
        if !dir_inode.is_directory() {
            return Err(FileSystemError::CorruptState {
                reason: "non-directory inode owns a directory table",
            });
        }
        for entry in directory.values() {
            let target = inodes
                .get(&entry.inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "directory entry references a missing inode",
                })?;
            if !namespace_entry_matches_target_inode(entry, target) {
                return Err(FileSystemError::CorruptState {
                    reason: "directory entry does not match target inode",
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_loaded_state(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
) -> Result<()> {
    validate_loaded_namespace_state(inodes, directories)?;
    validate_loaded_file_content(store, inodes)
}

fn validate_loaded_file_content(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
) -> Result<()> {
    for inode in inodes.values() {
        if inode.is_file_like() {
            let _ = read_content_from_store(store, inode.inode_id, inode, None)?;
        }
    }
    Ok(())
}

pub(crate) fn mount_invariant_report_from_state(
    state: &FileSystemState,
) -> Result<MountInvariantReport> {
    validate_namespace_invariants(&state.inodes, &state.directories)
}

pub(crate) fn validate_namespace_invariants(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
) -> Result<MountInvariantReport> {
    let root = inodes
        .get(&ROOT_INODE_ID)
        .ok_or(FileSystemError::CorruptState {
            reason: "mount invariant gate: root inode is missing",
        })?;
    if !root.carries_child_namespace() {
        return Err(FileSystemError::CorruptState {
            reason: "mount invariant gate: root inode is not a directory",
        });
    }
    if !directories.contains_key(&ROOT_INODE_ID) {
        return Err(FileSystemError::CorruptState {
            reason: "mount invariant gate: root directory table is missing",
        });
    }

    let mut directory_count = 0_u64;
    let mut file_like_count = 0_u64;
    let mut directory_entry_count = 0_u64;
    let mut hard_link_edge_count = 0_u64;
    let mut reference_counts: BTreeMap<InodeId, u64> = BTreeMap::new();
    let mut directory_parent_counts: BTreeMap<InodeId, u64> = BTreeMap::new();

    for inode in inodes.values() {
        reference_counts.entry(inode.inode_id).or_insert(0);
        if inode.carries_child_namespace() {
            directory_count = directory_count.saturating_add(1);
            directory_parent_counts.entry(inode.inode_id).or_insert(0);
            let directory =
                directories
                    .get(&inode.inode_id)
                    .ok_or(FileSystemError::CorruptState {
                        reason: "mount invariant gate: directory inode has no directory table",
                    })?;
            if inode.size != directory.len() as u64 {
                return Err(FileSystemError::CorruptState {
                    reason: "mount invariant gate: directory size does not match entry count",
                });
            }
        } else {
            if directories.contains_key(&inode.inode_id) {
                return Err(FileSystemError::CorruptState {
                    reason: "mount invariant gate: non-directory inode owns a directory table",
                });
            }
            if inode.is_file_like() {
                file_like_count = file_like_count.saturating_add(1);
            }
        }
    }

    for (parent_id, directory) in directories {
        let parent = inodes.get(parent_id).ok_or(FileSystemError::CorruptState {
            reason: "mount invariant gate: directory table has no parent inode",
        })?;
        if !parent.carries_child_namespace() {
            return Err(FileSystemError::CorruptState {
                reason: "mount invariant gate: directory table parent is not a directory",
            });
        }
        for (name, entry) in directory {
            validate_name(name)?;
            if entry.name.as_slice() != name.as_slice() {
                return Err(FileSystemError::CorruptState {
                    reason: "mount invariant gate: directory entry key and stored name differ",
                });
            }
            let target = inodes
                .get(&entry.inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "mount invariant gate: directory entry references a missing inode",
                })?;
            if !namespace_entry_matches_target_inode(entry, target) {
                return Err(FileSystemError::CorruptState {
                    reason: "mount invariant gate: directory entry does not match target inode",
                });
            }
            directory_entry_count = directory_entry_count.saturating_add(1);
            let refs = reference_counts.entry(entry.inode_id).or_insert(0);
            *refs = (*refs).saturating_add(1);
            if entry.carries_child_namespace() {
                if entry.inode_id == ROOT_INODE_ID {
                    return Err(FileSystemError::CorruptState {
                        reason: "mount invariant gate: root inode appears as a child directory",
                    });
                }
                let parents = directory_parent_counts.entry(entry.inode_id).or_insert(0);
                *parents = (*parents).saturating_add(1);
                if *parents > 1 {
                    return Err(FileSystemError::CorruptState {
                        reason: "mount invariant gate: directory has more than one parent",
                    });
                }
            } else {
                hard_link_edge_count = hard_link_edge_count.saturating_add(1);
            }
        }
    }

    for (inode_id, inode) in inodes {
        let refs = reference_counts.get(inode_id).copied().unwrap_or(0);
        if inode.carries_child_namespace() {
            let parent_refs = directory_parent_counts.get(inode_id).copied().unwrap_or(0);
            if *inode_id == ROOT_INODE_ID {
                if parent_refs != 0 {
                    return Err(FileSystemError::CorruptState {
                        reason: "mount invariant gate: root directory has a parent entry",
                    });
                }
            } else if parent_refs != 1 {
                return Err(FileSystemError::CorruptState {
                    reason:
                        "mount invariant gate: non-root directory does not have exactly one parent",
                });
            }
            let child_directory_count = directories
                .get(inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "mount invariant gate: directory inode has no directory table",
                })?
                .values()
                .filter(|entry| entry.carries_child_namespace())
                .count() as u64;
            let expected_nlink = 2_u64.saturating_add(child_directory_count);
            if u64::from(inode.nlink) != expected_nlink {
                return Err(FileSystemError::CorruptState { reason: "mount invariant gate: directory link count does not match child-directory topology" });
            }
        } else {
            if refs == 0 {
                return Err(FileSystemError::CorruptState {
                    reason: "mount invariant gate: non-directory inode is unreachable",
                });
            }
            if u64::from(inode.nlink) != refs {
                return Err(FileSystemError::CorruptState { reason: "mount invariant gate: file-like link count does not match directory references" });
            }
        }
    }

    let reachable = reachable_inodes_from_root(inodes, directories)?;
    if reachable.len() != inodes.len() {
        return Err(FileSystemError::CorruptState {
            reason: "mount invariant gate: committed root contains unreachable inode records",
        });
    }

    Ok(MountInvariantReport {
        design_rule: PRODUCTION_RECOVERY_DOCTRINE,
        invariant_gate_is_not_fsck: MOUNT_INVARIANT_GATE_IS_NOT_FSCK,
        inode_count: inodes.len() as u64,
        directory_count,
        file_like_count,
        directory_entry_count,
        hard_link_edge_count,
        reachable_inode_count: reachable.len() as u64,
        checked_link_counts: inodes.len() as u64,
        production_fsck_required: false,
    })
}

pub(crate) fn reachable_inodes_from_root(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
) -> Result<BTreeSet<InodeId>> {
    let mut reachable = BTreeSet::new();
    let mut stack = vec![ROOT_INODE_ID];
    while let Some(inode_id) = stack.pop() {
        if !reachable.insert(inode_id) {
            continue;
        }
        let inode = inodes.get(&inode_id).ok_or(FileSystemError::CorruptState {
            reason: "mount invariant gate: reachability walk found a missing inode",
        })?;
        if inode.carries_child_namespace() {
            let directory = directories
                .get(&inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "mount invariant gate: reachability walk found a missing directory",
                })?;
            for entry in directory.values() {
                stack.push(entry.inode_id);
            }
        }
    }
    Ok(reachable)
}

#[cfg(test)]
mod selection_authority_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct ScriptedRecoverySource {
        store: LocalObjectStore,
        io_fail_transactions: BTreeSet<u64>,
        strict_content_io_fail_transactions: BTreeSet<u64>,
        operational_fail_transactions: BTreeSet<u64>,
        invalid_generations: BTreeSet<u64>,
        load_calls: Vec<u64>,
    }

    impl CommittedRootRecoverySource for ScriptedRecoverySource {
        fn raw_store(&self) -> &LocalObjectStore {
            &self.store
        }

        fn load_committed_state(
            &mut self,
            root: &RootCommitRecord,
            _supporting_store_indices: &BTreeSet<usize>,
            _root_authentication_key: RootAuthenticationKey,
        ) -> Result<FileSystemState> {
            self.load_calls.push(root.transaction_id);
            if self.invalid_generations.contains(&root.generation) {
                return Err(FileSystemError::CorruptState {
                    reason: "scripted invalid committed-root candidate",
                });
            }
            if self.io_fail_transactions.contains(&root.transaction_id) {
                return Err(FileSystemError::Store(StoreError::Io {
                    operation: "scripted candidate read",
                    path: self.store.root().join("scripted-candidate"),
                    source: std::io::Error::other("scripted candidate-local I/O failure"),
                }));
            }
            if self
                .strict_content_io_fail_transactions
                .contains(&root.transaction_id)
            {
                return Err(pool_candidate_content_error(FileSystemError::Store(
                    StoreError::InvalidOptions {
                        reason: "strict read could not inspect every placement receipt copy",
                    },
                )));
            }
            if self
                .operational_fail_transactions
                .contains(&root.transaction_id)
            {
                return Err(pool_candidate_content_error(FileSystemError::Store(
                    StoreError::InvalidOptions {
                        reason: "pool is locked: encryption key required for I/O",
                    },
                )));
            }
            Ok(initial_state())
        }

        fn read_current_content_for_retention(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
            Ok(self.store.get(key)?)
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-root-selection-{label}-{nonce}"))
    }

    fn scripted_source(label: &str) -> (PathBuf, ScriptedRecoverySource) {
        let root = temp_root(label);
        let _ = std::fs::remove_dir_all(&root);
        let store = LocalObjectStore::open(&root).expect("open scripted recovery store");
        (
            root,
            ScriptedRecoverySource {
                store,
                io_fail_transactions: BTreeSet::new(),
                strict_content_io_fail_transactions: BTreeSet::new(),
                operational_fail_transactions: BTreeSet::new(),
                invalid_generations: BTreeSet::new(),
                load_calls: Vec::new(),
            },
        )
    }

    fn root_for_transaction(transaction_id: u64, generation: u64) -> RootCommitRecord {
        RootCommitRecord {
            slot: root_slot_for_transaction(transaction_id),
            transaction_id,
            generation,
            next_inode_id: 2,
            inode_count: 1,
            superblock_checksum: IntegrityDigest64(1),
            manifest_checksum: IntegrityDigest64::ZERO,
            manifest_entry_count: 0,
            root_authentication: None,
        }
    }

    fn append_root_bytes(source: &mut ScriptedRecoverySource, slot: u64, bytes: &[u8]) {
        source
            .store
            .put(root_slot_object_key(slot), bytes)
            .expect("append root candidate");
        source.store.sync_all().expect("sync root candidate");
    }

    #[test]
    fn candidate_local_io_is_terminal_before_older_candidate() {
        let (root, mut source) = scripted_source("candidate-io-fallback");
        let older = root_for_transaction(2, 2);
        let newer = root_for_transaction(3, 3);
        append_root_bytes(&mut source, older.slot, &encode_root_commit(&older));
        append_root_bytes(&mut source, newer.slot, &encode_root_commit(&newer));
        source.io_fail_transactions.insert(newer.transaction_id);

        let error = match select_latest_committed_root_from_source(
            &mut source,
            RootAuthenticationKey::demo_key(),
        ) {
            Ok(_) => panic!("unresolved candidate I/O must prevent writable older-root fallback"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            FileSystemError::Store(StoreError::Io { .. })
        ));
        assert_eq!(source.load_calls, vec![newer.transaction_id]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn strict_content_read_io_is_skippable_before_older_candidate() {
        let (root, mut source) = scripted_source("strict-content-io-fallback");
        let older = root_for_transaction(2, 2);
        let newer = root_for_transaction(3, 3);
        append_root_bytes(&mut source, older.slot, &encode_root_commit(&older));
        append_root_bytes(&mut source, newer.slot, &encode_root_commit(&newer));
        source
            .strict_content_io_fail_transactions
            .insert(newer.transaction_id);

        let selection = select_latest_committed_root_from_source(
            &mut source,
            RootAuthenticationKey::demo_key(),
        )
        .expect("object-local strict-read I/O must not fence an older candidate");
        assert_eq!(
            selection.report.selected_transaction_id,
            Some(older.transaction_id)
        );
        assert_eq!(selection.report.selected_generation, Some(older.generation));
        assert_eq!(
            source.load_calls,
            vec![newer.transaction_id, older.transaction_id]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn operational_pool_failure_is_terminal_before_older_root_fallback() {
        let (root, mut source) = scripted_source("candidate-operational-failure");
        let older = root_for_transaction(2, 2);
        let newer = root_for_transaction(3, 3);
        append_root_bytes(&mut source, older.slot, &encode_root_commit(&older));
        append_root_bytes(&mut source, newer.slot, &encode_root_commit(&newer));
        source
            .operational_fail_transactions
            .insert(newer.transaction_id);

        assert!(matches!(
            select_latest_committed_root_from_source(
                &mut source,
                RootAuthenticationKey::demo_key()
            ),
            Err(FileSystemError::Store(StoreError::InvalidOptions {
                reason: "pool is locked: encryption key required for I/O"
            }))
        ));
        assert_eq!(source.load_calls, vec![newer.transaction_id]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn divergent_quorum_roots_with_same_transaction_fail_closed() {
        let (root, mut source) = scripted_source("same-transaction-divergence");
        let first = root_for_transaction(2, 2);
        let mut second = first.clone();
        second.generation = 3;
        append_root_bytes(&mut source, first.slot, &encode_root_commit(&first));
        append_root_bytes(&mut source, second.slot, &encode_root_commit(&second));

        assert!(matches!(
            select_latest_committed_root_from_source(
                &mut source,
                RootAuthenticationKey::demo_key()
            ),
            Err(FileSystemError::CorruptState {
                reason: "conflicting authenticated committed roots share a transaction id"
            })
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_same_transaction_candidate_does_not_veto_valid_authority() {
        let (root, mut source) = scripted_source("same-transaction-invalid-candidate");
        let valid = root_for_transaction(2, 2);
        let mut invalid = valid.clone();
        invalid.generation = 3;
        append_root_bytes(&mut source, valid.slot, &encode_root_commit(&valid));
        append_root_bytes(&mut source, invalid.slot, &encode_root_commit(&invalid));
        source.invalid_generations.insert(invalid.generation);

        let selection = select_latest_committed_root_from_source(
            &mut source,
            RootAuthenticationKey::demo_key(),
        )
        .expect("an invalid peer record must not veto valid same-transaction authority");
        assert_eq!(
            selection.report.selected_transaction_id,
            Some(valid.transaction_id)
        );
        assert_eq!(selection.report.selected_generation, Some(valid.generation));
        assert_eq!(source.load_calls, vec![valid.transaction_id; 2]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn quorum_future_root_version_is_terminal_before_older_fallback() {
        let (root, mut source) = scripted_source("future-version-terminal");
        let older = root_for_transaction(2, 2);
        let future = root_for_transaction(3, 3);
        append_root_bytes(&mut source, older.slot, &encode_root_commit(&older));
        let mut future_bytes = encode_root_commit(&future);
        let future_version = FILESYSTEM_FORMAT_VERSION.checked_add(1).unwrap();
        future_bytes[ROOT_COMMIT_MAGIC.len()..ROOT_COMMIT_MAGIC.len() + 2]
            .copy_from_slice(&future_version.to_le_bytes());
        append_root_bytes(&mut source, future.slot, &future_bytes);

        assert!(matches!(
            select_latest_committed_root_from_source(
                &mut source,
                RootAuthenticationKey::demo_key()
            ),
            Err(FileSystemError::FormatVersionIncompatible {
                running_version: FILESYSTEM_FORMAT_VERSION,
                filesystem_min,
                filesystem_max,
            }) if filesystem_min == future_version && filesystem_max == future_version
        ));
        assert!(source.load_calls.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn retired_lower_root_version_does_not_fence_newer_current_root() {
        let (root, mut source) = scripted_source("retired-version-skipped");
        let retired = root_for_transaction(2, 2);
        let current = root_for_transaction(3, 3);
        let mut retired_bytes = encode_root_commit(&retired);
        let retired_version = FILESYSTEM_FORMAT_VERSION.checked_sub(1).unwrap();
        retired_bytes[ROOT_COMMIT_MAGIC.len()..ROOT_COMMIT_MAGIC.len() + 2]
            .copy_from_slice(&retired_version.to_le_bytes());
        append_root_bytes(&mut source, retired.slot, &retired_bytes);
        append_root_bytes(&mut source, current.slot, &encode_root_commit(&current));

        let selection = select_latest_committed_root_from_source(
            &mut source,
            RootAuthenticationKey::demo_key(),
        )
        .expect("retired lower-version history should be skippable");
        assert_eq!(
            selection.report.selected_transaction_id,
            Some(current.transaction_id)
        );
        assert_eq!(source.load_calls, vec![current.transaction_id]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn inadmissible_future_version_prefix_cannot_fence_current_root() {
        let (root, mut source) = scripted_source("future-prefix-inadmissible");
        let current = root_for_transaction(2, 2);
        append_root_bytes(&mut source, current.slot, &encode_root_commit(&current));
        let mut inadmissible = root_for_transaction(0, 3);
        inadmissible.slot = root_slot_for_transaction(0);
        let mut inadmissible_bytes = encode_root_commit(&inadmissible);
        let future_version = FILESYSTEM_FORMAT_VERSION.checked_add(1).unwrap();
        inadmissible_bytes[ROOT_COMMIT_MAGIC.len()..ROOT_COMMIT_MAGIC.len() + 2]
            .copy_from_slice(&future_version.to_le_bytes());
        append_root_bytes(&mut source, inadmissible.slot, &inadmissible_bytes);

        let selection = select_latest_committed_root_from_source(
            &mut source,
            RootAuthenticationKey::demo_key(),
        )
        .expect("inadmissible future prefix should be skipped");
        assert_eq!(
            selection.report.selected_transaction_id,
            Some(current.transaction_id)
        );
        assert_eq!(source.load_calls, vec![current.transaction_id]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn root_candidate_stored_in_wrong_slot_is_never_loaded() {
        let (root, mut source) = scripted_source("wrong-slot");
        let candidate = root_for_transaction(2, 2);
        let wrong_slot = (candidate.slot + 1) % FILESYSTEM_ROOT_SLOT_COUNT;
        append_root_bytes(&mut source, wrong_slot, &encode_root_commit(&candidate));

        let selection = select_latest_committed_root_from_source(
            &mut source,
            RootAuthenticationKey::demo_key(),
        )
        .expect("wrong-slot candidate should be skipped");
        assert_eq!(
            selection.report.outcome,
            RecoveryProbeOutcome::ExplicitIntegrityOrMediaError
        );
        assert!(source.load_calls.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod candidate_history_tests {
    use super::*;
    use crate::persistence::{persist_transaction_objects, publish_root_commit};
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::{
        segment_file_name, DeviceBacking, DeviceClass, DeviceConfig, DeviceKind, PoolConfig,
        PoolProperties, StoreOptions,
    };

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-candidate-history-{label}-{nonce}"))
    }

    fn make_pool(label: &str) -> (PathBuf, Pool) {
        let root = temp_root(label);
        let data_root = root.join("pool");
        let replica_root = root.join("metadata-replica");
        // StoreOptions replicas are LocalObjectStore replicas. Use the
        // explicitly admitted single-store compatibility bridge so this
        // diagnostic fixture can exercise replicated candidate history; block
        // device admission is covered independently.
        let mut options = StoreOptions::test_fast();
        options.replica_paths = vec![replica_root];
        let config = PoolConfig {
            name: format!("candidate-history-{label}"),
            root_path: data_root.clone(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_root.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_root },
                encryption: None,
                compression: None,
            }],
        };
        let pool = Pool::create(config, PoolProperties::default(), &options)
            .expect("create candidate-history pool");
        (root, pool)
    }

    fn state_with_generation_uid_and_next_inode(
        generation: u64,
        uid: u32,
        next_inode_id: u64,
    ) -> FileSystemState {
        let mut state = initial_state();
        state.generation = generation;
        state.set_inode_authority_next_inode_id(next_inode_id);
        Arc::make_mut(&mut state.inodes)
            .get_mut(&ROOT_INODE_ID)
            .expect("root inode")
            .uid = uid;
        state
    }

    fn persist_candidate(
        pool: &mut Pool,
        state: &FileSystemState,
        key: RootAuthenticationKey,
    ) -> RootCommitRecord {
        let transaction_id = state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
        let root = persist_transaction_objects(pool.raw_primary_store_mut(), state, transaction_id)
            .expect("persist candidate transaction objects");
        pool.raw_primary_store_mut()
            .sync_all()
            .expect("sync candidate transaction objects");
        publish_root_commit(pool.raw_primary_store_mut(), &root, key)
            .expect("publish candidate root");
        pool.raw_primary_store_mut()
            .sync_all()
            .expect("sync candidate root");
        root
    }

    #[test]
    fn authenticated_same_transaction_candidates_conflict_only_after_candidate_binding() {
        let (root, mut pool) = make_pool("authenticated-conflict");
        let key = RootAuthenticationKey::demo_key();
        let first = persist_candidate(
            &mut pool,
            &state_with_generation_uid_and_next_inode(2, 1001, 2),
            key,
        );
        let second = persist_candidate(
            &mut pool,
            &state_with_generation_uid_and_next_inode(2, 1002, 3),
            key,
        );
        assert_ne!(first.superblock_checksum, second.superblock_checksum);

        let error = match select_latest_committed_root_from_source(&mut pool, key) {
            Ok(_) => panic!("two independently valid same-transaction roots must conflict"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            FileSystemError::CorruptState {
                reason: "conflicting authenticated committed roots share a transaction id"
            }
        ));

        drop(pool);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pool_candidate_metadata_falls_back_to_matching_replica_history() {
        let (root, mut pool) = make_pool("metadata-replica-fallback");
        let key = RootAuthenticationKey::demo_key();
        let expected_uid = 4242;
        let committed = persist_candidate(
            &mut pool,
            &state_with_generation_uid_and_next_inode(2, expected_uid, 2),
            key,
        );
        let superblock_key = transaction_superblock_object_key(committed.transaction_id);
        let location = pool
            .raw_primary_store()
            .version_locations_across_stores(superblock_key)[0]
            .last()
            .copied()
            .expect("primary superblock location");
        let segment_path = pool
            .raw_primary_store()
            .segments_dir()
            .join(segment_file_name(location.segment_id));
        let mut segment = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&segment_path)
            .expect("open primary segment for corruption injection");
        segment
            .seek(SeekFrom::Start(location.payload_offset))
            .expect("seek primary superblock payload");
        let mut byte = [0_u8; 1];
        segment
            .read_exact(&mut byte)
            .expect("read primary superblock byte");
        byte[0] ^= 0xff;
        segment
            .seek(SeekFrom::Start(location.payload_offset))
            .expect("rewind primary superblock payload");
        segment
            .write_all(&byte)
            .expect("corrupt primary superblock payload");
        segment.sync_all().expect("sync primary corruption");
        drop(segment);

        let selection = select_latest_committed_root_from_source(&mut pool, key)
            .expect("matching replica metadata history should recover the candidate");
        assert_eq!(
            selection.report.selected_transaction_id,
            Some(committed.transaction_id)
        );
        assert_eq!(
            selection
                .state
                .expect("selected state")
                .inodes
                .get(&ROOT_INODE_ID)
                .expect("recovered root inode")
                .uid,
            expected_uid
        );

        drop(pool);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod mounted_pool_audit_retention_tests {
    use super::*;
    use crate::LocalFileSystem;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::{DeviceIoClass, StoreOptions};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-pool-recovery-{label}-{nonce}"))
    }

    fn options() -> StoreOptions {
        StoreOptions::test_fast()
    }

    fn cleanup(paths: &[&PathBuf]) {
        for path in paths {
            let _ = std::fs::remove_dir_all(path);
        }
    }

    #[test]
    fn pool_retention_preserves_older_mountable_root_after_newer_content_loses_authority() {
        let primary = temp_root("older-retained");
        cleanup(&[&primary]);
        let root_authentication_key = RootAuthenticationKey::demo_key();
        let store_options = options();
        let old_payload = b"older Pool-authorized payload";

        let (older_root, newer_root, older_content_key, newer_content_key) = {
            let mut fs = LocalFileSystem::open_with_root_authentication_key(
                &primary,
                store_options.clone(),
                root_authentication_key,
            )
            .expect("open filesystem");
            fs.set_auto_commit(false)
                .expect("test setup mutation must be admitted");
            fs.create_file("/data", 0o644).expect("create file");
            fs.replace_file("/data", old_payload)
                .expect("write older payload");
            fs.sync_all().expect("commit older payload");

            for index in 0..FILESYSTEM_ROOT_SLOT_COUNT.saturating_add(1) {
                fs.create_dir(format!("/stable-{index}"), 0o755)
                    .expect("advance stable root ring");
                fs.sync_all().expect("commit stable root");
            }
            fs.create_snapshot("retain-older-root")
                .expect("pin older content authority");
            fs.sync_all().expect("commit snapshot pin");
            let inode_id = fs.lookup("/data").expect("lookup data file");
            let older_record = fs.state.inodes.get(&inode_id).expect("older inode");
            let older_content_key =
                content_object_key_for_version(inode_id, older_record.data_version);
            let older_root = fs
                .selected_current_root_summary()
                .expect("capture older root");

            fs.replace_file("/data", b"newer payload without retained authority")
                .expect("write newer payload");
            fs.sync_all().expect("commit newer root");
            let newer_record = fs.state.inodes.get(&inode_id).expect("newer inode");
            let newer_content_key =
                content_object_key_for_version(inode_id, newer_record.data_version);
            let newer_root = fs
                .selected_current_root_summary()
                .expect("capture newer root");
            assert_ne!(older_content_key, newer_content_key);
            (older_root, newer_root, older_content_key, newer_content_key)
        };

        {
            let mut pool =
                LocalFileSystem::default_development_pool(&primary, &store_options, None, None)
                    .expect("open pool for authority loss");
            assert!(pool
                .delete(DeviceIoClass::Data, newer_content_key)
                .expect("remove newer payload and receipt"));
            pool.sync_all().expect("sync newer authority loss");
        }

        let mut fs = LocalFileSystem::open_with_root_authentication_key(
            &primary,
            store_options,
            root_authentication_key,
        )
        .expect("reopen through older mountable root");
        let plan = fs
            .safe_root_retention_plan()
            .expect("plan Pool-backed root retention");
        assert_eq!(plan.audit.selected_root, Some(older_root.clone()));
        assert_ne!(plan.audit.selected_root, Some(newer_root));
        assert!(plan.protected_committed_roots.contains(&older_root));
        assert!(plan.protected_object_keys.contains(&older_content_key));
        assert!(plan.retention_policy_satisfied());

        fs.safe_reclaim_unprotected_objects()
            .expect("compact while preserving the older mountable root");
        assert_eq!(
            fs.read_file("/data").expect("read retained older payload"),
            old_payload
        );
        assert_eq!(
            fs.recovery_audit()
                .expect("audit after retention compaction")
                .selected_root,
            Some(older_root)
        );
        drop(fs);

        cleanup(&[&primary]);
    }
}

// ── cross-device committed-root quorum tests ─────────────────────

#[cfg(test)]
mod cross_device_quorum_tests {
    use super::*;
    use crate::object_keys::root_slot_object_key;
    use std::path::PathBuf;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    fn make_store_opts(replica_paths: Vec<PathBuf>) -> StoreOptions {
        let mut opts = StoreOptions::test_fast();
        opts.replica_paths = replica_paths;
        opts
    }

    fn make_store(root: &PathBuf) -> LocalObjectStore {
        let _ = std::fs::remove_dir_all(root);
        LocalObjectStore::open(root).expect("open store")
    }

    fn write_root_slot_bytes(store: &mut LocalObjectStore, slot: u64, bytes: &[u8]) {
        let key = root_slot_object_key(slot);
        store.put(key, bytes).expect("put root slot bytes");
        store.sync_all().expect("sync");
    }

    fn cleanup_all(dirs: &[&PathBuf]) {
        for d in dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// Single store: quorum=1 always satisfied.
    #[test]
    fn single_store_quorum_satisfied() {
        let dir = PathBuf::from("/tmp/tidefs-workers/s3/test-single-quorum");
        let mut store = make_store(&dir);
        let slot = 0;
        write_root_slot_bytes(&mut store, slot, b"root-data");
        let key = root_slot_object_key(slot);
        let all_locs = store.version_locations_across_stores(key);
        assert_eq!(all_locs.len(), 1, "one store entry vector");
        assert!(!all_locs[0].is_empty(), "primary has history");
        assert_eq!(store.stores_count(), 1);
        cleanup_all(&[&dir]);
    }

    /// Two stores: across-stores aggregation.
    #[test]
    fn two_stores_version_locations_across_stores() {
        let primary = PathBuf::from("/tmp/tidefs-workers/s3/test-across-p");
        let rep = PathBuf::from("/tmp/tidefs-workers/s3/test-across-r");
        cleanup_all(&[&primary, &rep]);

        let opts = make_store_opts(vec![rep.clone()]);
        let mut store =
            LocalObjectStore::open_with_options(&primary, opts).expect("open with replica");
        assert_eq!(store.stores_count(), 2);

        let slot = 0;
        write_root_slot_bytes(&mut store, slot, b"root-data");

        let key = root_slot_object_key(slot);
        let all_locs = store.version_locations_across_stores(key);
        assert_eq!(all_locs.len(), 2, "primary + 1 replica");
        assert!(!all_locs[0].is_empty(), "primary history non-empty");
        assert!(
            !all_locs[1].is_empty(),
            "replica history non-empty after fan-out"
        );

        cleanup_all(&[&primary, &rep]);
    }

    /// stores_count reflects replica configuration.
    #[test]
    fn stores_count_with_replicas() {
        let primary = PathBuf::from("/tmp/tidefs-workers/s3/test-sc-p");
        let r1 = PathBuf::from("/tmp/tidefs-workers/s3/test-sc-r1");
        let r2 = PathBuf::from("/tmp/tidefs-workers/s3/test-sc-r2");
        cleanup_all(&[&primary, &r1, &r2]);

        let opts = make_store_opts(vec![r1.clone(), r2.clone()]);
        let store =
            LocalObjectStore::open_with_options(&primary, opts).expect("open with 2 replicas");
        assert_eq!(store.stores_count(), 3);

        cleanup_all(&[&primary, &r1, &r2]);
    }

    /// Minority copy: root only on primary, replica empty -> select_latest_committed_root
    /// must return ExplicitIntegrityOrMediaError (no root with quorum).
    #[test]
    fn minority_copy_on_one_of_two_stores_rejected() {
        let primary = PathBuf::from("/tmp/tidefs-workers/s3/test-minority-p");
        let rep = PathBuf::from("/tmp/tidefs-workers/s3/test-minority-r");
        cleanup_all(&[&primary, &rep]);

        // First, write a root into a primary-only store (no replica).
        {
            let mut primary_only = make_store(&primary);
            write_root_slot_bytes(&mut primary_only, 0, b"primary-only-root");
        }

        // Now open with replica configured (replica is empty = stale).
        let opts = make_store_opts(vec![rep.clone()]);
        let mut store =
            LocalObjectStore::open_with_options(&primary, opts).expect("open with stale replica");

        let selection = select_latest_committed_root(&mut store, RootAuthenticationKey::demo_key())
            .expect("select root");

        // Quorum=2 but only primary has a root.  The probe should not
        // find any valid root because the minority copy is rejected.
        assert_eq!(
            selection.report.outcome,
            RecoveryProbeOutcome::ExplicitIntegrityOrMediaError,
            "minority copy must be rejected"
        );

        cleanup_all(&[&primary, &rep]);
    }

    /// Majority copy: both stores have the root bytes.  Even though the
    /// test payload is not a valid RootCommitRecord (so state loading
    /// ultimately fails), both stores saw the same slot data, proving
    /// the fan-out and cross-store aggregation work together.
    #[test]
    fn majority_copy_on_two_stores_aggregates_both() {
        let primary = PathBuf::from("/tmp/tidefs-workers/s3/test-majority-p");
        let rep = PathBuf::from("/tmp/tidefs-workers/s3/test-majority-r");
        cleanup_all(&[&primary, &rep]);

        // Open with replica first; put data so both stores get it.
        {
            let opts = make_store_opts(vec![rep.clone()]);
            let mut store =
                LocalObjectStore::open_with_options(&primary, opts).expect("open with replica");
            write_root_slot_bytes(&mut store, 0, b"shared-root-data");
        }

        // Re-open: both stores have the root bytes.
        let opts = make_store_opts(vec![rep.clone()]);
        let store =
            LocalObjectStore::open_with_options(&primary, opts).expect("re-open with replica");

        // Verify that version_locations_across_stores sees both stores.
        let key = root_slot_object_key(0);
        let all_locs = store.version_locations_across_stores(key);
        assert_eq!(all_locs.len(), 2, "primary + 1 replica");
        assert!(!all_locs[0].is_empty(), "primary has root slot data");
        assert!(
            !all_locs[1].is_empty(),
            "replica has root slot data after fan-out"
        );

        cleanup_all(&[&primary, &rep]);
    }

    /// Two stores, live filesystem writes, commit, then recovery probe
    /// verifies committed-root quorum across primary+replica. Data is
    /// re-opened to confirm integrity after post-recovery open.
    #[test]
    fn two_store_committed_root_quorum_with_live_writes_and_recovery() {
        let primary = PathBuf::from("/tmp/tidefs-workers/s8/test-quorum-live-p");
        let replica = PathBuf::from("/tmp/tidefs-workers/s8/test-quorum-live-r");
        cleanup_all(&[&primary, &replica]);

        let root_auth_key = RootAuthenticationKey::demo_key();
        let file_data = b"committed-root-quorum-live-write-payload";
        let file_path = "/quorum-test-file";

        // Phase 1: open with replica, write file, commit.
        let recovery_report = {
            let mut opts = make_store_opts(vec![replica.clone()]);
            opts.sync_on_write = true;
            opts.max_segment_bytes = 65536;

            let mut fs = crate::LocalFileSystem::open_with_root_authentication_key(
                &primary,
                opts,
                root_auth_key,
            )
            .expect("open fs with replica");

            fs.create_file(file_path, 0o644).expect("create file");
            fs.write_file(file_path, 0, file_data).expect("write file");
            fs.commit().expect("commit");

            let got = fs.read_file(file_path).expect("read back");
            assert_eq!(got, file_data, "live readback must match");

            drop(fs);

            let probe_opts = make_store_opts(vec![replica.clone()]);
            crate::LocalFileSystem::probe_recovery_with_root_authentication_key(
                &primary,
                probe_opts,
                root_auth_key,
            )
            .expect("probe recovery")
        };

        // Phase 2: verify recovery probe found a valid committed root.
        // root_slot_records_seen counts across all slots and stores;
        // with 4 slots x 2 stores, we expect multiple records.
        assert!(
            recovery_report.root_slot_records_seen >= 1,
            "should see root slot records, got {}",
            recovery_report.root_slot_records_seen
        );
        assert!(
            recovery_report.valid_committed_roots_seen >= 1,
            "must see >= 1 valid committed root: {recovery_report:?}"
        );
        assert!(
            !matches!(
                recovery_report.outcome,
                RecoveryProbeOutcome::ExplicitIntegrityOrMediaError
            ),
            "quorum should succeed: both stores have the root"
        );

        // Phase 3: re-open and verify persisted data.
        let reopen_opts = make_store_opts(vec![replica.clone()]);
        let fs2 = crate::LocalFileSystem::open_with_root_authentication_key(
            &primary,
            reopen_opts,
            root_auth_key,
        )
        .expect("reopen fs");
        let got2 = fs2.read_file(file_path).expect("read after reopen");
        assert_eq!(got2, file_data, "data intact after recovery+reopen");
    }
}

#[cfg(test)]
mod receipt_validation_tests {
    use super::*;
    use crate::encoding::encode_content_chunk;
    use crate::types::PosixTimeRecord;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::pool::Pool;
    use tidefs_local_object_store::{
        DeviceBacking, DeviceClass, DeviceConfig, DeviceIoClass, DeviceKind, IntegrityDigest64,
        LocalObjectStore, PoolConfig, PoolProperties, StoreOptions,
    };
    use tidefs_types_vfs_core::S_IFREG;

    fn superblock_with_format_range(min: u16, max: u16) -> SuperblockRecord {
        SuperblockRecord {
            next_inode_id: 2,
            generation: 1,
            inode_count: 1,
            inode_allocation_bitmap: vec![1],
            format_version_min: min,
            format_version_max: max,
        }
    }

    #[test]
    fn superblock_format_max_is_a_terminal_downgrade_fence() {
        let future = CURRENT_FORMAT_VERSION.checked_add(1).unwrap();
        let error = validate_superblock_format_compatibility(&superblock_with_format_range(
            CURRENT_FORMAT_VERSION,
            future,
        ))
        .expect_err("a newer last-writer version must fence this reader");
        assert!(matches!(
            error,
            FileSystemError::FormatVersionIncompatible {
                running_version: CURRENT_FORMAT_VERSION,
                filesystem_min: CURRENT_FORMAT_VERSION,
                filesystem_max,
            } if filesystem_max == future
        ));
    }

    #[test]
    fn superblock_format_range_must_be_nonzero_and_ordered() {
        for (min, max) in [
            (0, CURRENT_FORMAT_VERSION),
            (CURRENT_FORMAT_VERSION, 0),
            (2, 1),
        ] {
            assert!(matches!(
                validate_superblock_format_compatibility(&superblock_with_format_range(min, max)),
                Err(FileSystemError::CorruptState {
                    reason: "superblock contains an invalid format-version range"
                })
            ));
        }
        validate_superblock_format_compatibility(&superblock_with_format_range(
            CURRENT_FORMAT_VERSION,
            CURRENT_FORMAT_VERSION,
        ))
        .expect("the running writer version is compatible");
    }

    fn temp_dir(label: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-recovery-receipt-test-{ts}-{label}"))
    }

    fn cleanup(dir: &PathBuf) {
        let _ = std::fs::remove_dir_all(dir);
    }

    fn make_store(root: &PathBuf) -> LocalObjectStore {
        let _ = std::fs::remove_dir_all(root);
        LocalObjectStore::open(root).expect("open store")
    }

    fn single_data_device_config(root: &PathBuf) -> PoolConfig {
        let data_dir = root.join("data");
        PoolConfig {
            name: "receipt-test-pool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                media_class: Default::default(),
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                class: DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        }
    }

    fn make_pool(root: &PathBuf) -> Pool {
        let _ = std::fs::remove_dir_all(root);
        let config = single_data_device_config(root);
        Pool::create(
            config,
            PoolProperties::default(),
            &StoreOptions::test_fast(),
        )
        .expect("create test pool")
    }

    fn make_file_inode(inode_id: u64, data_version: u64, size: u64) -> InodeRecord {
        InodeRecord {
            rdev: 0,
            inode_id: InodeId(inode_id),
            generation: Generation(1),
            facets: NodeKind::File.to_facets(),
            mode: S_IFREG | DEFAULT_FILE_PERMISSIONS,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version,
            metadata_version: 1,
            posix_time: PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        }
    }

    fn make_chunk_ref(
        chunk_index: u64,
        data_version: u64,
        len: u32,
        placement_receipt_generation: u64,
    ) -> ContentChunkRef {
        ContentChunkRef {
            chunk_index,
            data_version,
            len,
            checksum: IntegrityDigest64(0xCAFE),
            placement_receipt_generation,
        }
    }

    fn put_chunk_data(
        store: &mut LocalObjectStore,
        inode: &InodeRecord,
        chunk_ref: &ContentChunkRef,
    ) {
        let key = content_chunk_object_key_for_version(
            inode.inode_id,
            chunk_ref.data_version,
            chunk_ref.chunk_index,
        );
        let payload = b"test-chunk-payload-for-receipt-validation";
        let encoded =
            encode_content_chunk(inode, chunk_ref.chunk_index, payload, &Default::default());
        store.put(key, &encoded).expect("put chunk data");
        store.sync_all().expect("sync");
    }

    /// A chunk with zero placement_receipt_generation should have
    /// missing_receipt = true but receipt_mismatch = false (no pool
    /// validation is triggered).
    #[test]
    fn chunk_with_zero_receipt_generation_marks_missing_receipt() {
        let root = temp_dir("zero-receipt-gen");
        let mut store = make_store(&root);
        let inode = make_file_inode(2, 1, 4096);
        let chunk_ref = make_chunk_ref(0, 1, 4096, 0);
        put_chunk_data(&mut store, &inode, &chunk_ref);
        let mut report = FilesystemContentInspectionReport::empty();

        inspect_chunk_object(&store, &inode, &chunk_ref, &mut report, None)
            .expect("inspect_chunk_object success");

        assert_eq!(report.referenced_objects.len(), 1);
        let obj = &report.referenced_objects[0];
        assert!(
            obj.missing_receipt,
            "chunk with zero receipt generation must have missing_receipt=true"
        );
        assert!(
            !obj.receipt_mismatch,
            "chunk with zero receipt generation must not have receipt_mismatch=true"
        );
        assert_eq!(report.receipt_mismatches, 0);
        cleanup(&root);
    }

    /// A non-hole chunk with non-zero receipt generation and a matching
    /// pool receipt should not be flagged.
    #[test]
    fn chunk_with_matching_pool_receipt_not_flagged() {
        let store_root = temp_dir("matching-receipt-store");
        let pool_root = temp_dir("matching-receipt-pool");
        let mut store = make_store(&store_root);
        let mut pool = make_pool(&pool_root);
        let inode = make_file_inode(2, 1, 4096);

        let chunk_key = content_chunk_object_key_for_version(inode.inode_id, 1, 0);
        // Use put_with_receipt to get the pool-assigned generation, then
        // build a chunk_ref that carries that exact generation.
        let (_stored, receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, chunk_key, b"pool-chunk-data")
            .expect("put_with_receipt in pool");
        let receipt_generation = receipt.generation;

        // Verify the pool can find its own receipt before inspection.
        let pool_receipt = pool
            .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
            .expect("placement_receipt_for_key ok")
            .expect("pool must find its own receipt");
        assert_eq!(
            pool_receipt.generation,
            receipt_generation,
            "pool receipt gen {pool_gen} must match put_with_receipt return {receipt_generation}",
            pool_gen = pool_receipt.generation
        );

        let chunk_ref = make_chunk_ref(0, 1, 4096, receipt_generation);
        put_chunk_data(&mut store, &inode, &chunk_ref);

        let mut report = FilesystemContentInspectionReport::empty();
        inspect_chunk_object(&store, &inode, &chunk_ref, &mut report, Some(&pool))
            .expect("inspect_chunk_object success");

        assert_eq!(report.referenced_objects.len(), 1);
        let obj = &report.referenced_objects[0];
        assert!(
            !obj.receipt_mismatch,
            "matching receipt must not be flagged"
        );
        assert_eq!(report.receipt_mismatches, 0);
        cleanup(&store_root);
        cleanup(&pool_root);
    }

    /// A chunk with a non-zero receipt generation where the pool has no
    /// receipt for the key should be flagged as a receipt mismatch.
    #[test]
    fn chunk_with_missing_pool_receipt_flagged() {
        let store_root = temp_dir("missing-pool-receipt-store");
        let pool_root = temp_dir("missing-pool-receipt-pool");
        let mut store = make_store(&store_root);
        let pool = make_pool(&pool_root);
        let inode = make_file_inode(2, 1, 4096);
        let chunk_ref = make_chunk_ref(0, 1, 4096, 5);
        put_chunk_data(&mut store, &inode, &chunk_ref);

        let mut report = FilesystemContentInspectionReport::empty();
        inspect_chunk_object(&store, &inode, &chunk_ref, &mut report, Some(&pool))
            .expect("inspect_chunk_object success");

        assert_eq!(report.referenced_objects.len(), 1);
        let obj = &report.referenced_objects[0];
        assert!(
            obj.receipt_mismatch,
            "missing pool receipt must be flagged as mismatch"
        );
        assert_eq!(report.receipt_mismatches, 1);
        cleanup(&store_root);
        cleanup(&pool_root);
    }

    /// A chunk with no pool provided should never trigger receipt validation
    /// and should therefore never set receipt_mismatch.
    #[test]
    fn chunk_without_pool_never_flags_mismatch() {
        let root = temp_dir("no-pool-mismatch");
        let mut store = make_store(&root);
        let inode = make_file_inode(2, 1, 4096);
        let chunk_ref = make_chunk_ref(0, 1, 4096, 5);
        put_chunk_data(&mut store, &inode, &chunk_ref);
        let mut report = FilesystemContentInspectionReport::empty();

        inspect_chunk_object(&store, &inode, &chunk_ref, &mut report, None)
            .expect("inspect_chunk_object success");

        assert_eq!(report.referenced_objects.len(), 1);
        let obj = &report.referenced_objects[0];
        assert!(
            !obj.receipt_mismatch,
            "without pool no mismatch can be detected"
        );
        assert_eq!(report.receipt_mismatches, 0);
        cleanup(&root);
    }

    /// Receipt validation state accumulates across multiple chunk inspections
    /// with both matching and mismatching receipts.
    #[test]
    fn receipt_mismatch_counter_accumulates_across_chunks() {
        let store_root = temp_dir("accum-mismatch-store");
        let pool_root = temp_dir("accum-mismatch-pool");
        let mut store = make_store(&store_root);
        let mut pool = make_pool(&pool_root);
        let inode = make_file_inode(2, 1, 3 * 4096);

        // Chunk 0: match pool receipt generation -> no mismatch
        let key0 = content_chunk_object_key_for_version(inode.inode_id, 1, 0);
        let (_s0, r0) = pool
            .put_with_receipt(DeviceIoClass::Data, key0, b"pool-chunk-0")
            .expect("put chunk0");
        let chunk0 = make_chunk_ref(0, 1, 4096, r0.generation);
        put_chunk_data(&mut store, &inode, &chunk0);

        // Chunk 1: receipt gen 7, pool has NO receipt for this key -> mismatch
        let chunk1 = make_chunk_ref(1, 1, 4096, 7);
        put_chunk_data(&mut store, &inode, &chunk1);

        // Chunk 2: receipt gen mismatches pool gen -> mismatch
        let key2 = content_chunk_object_key_for_version(inode.inode_id, 1, 2);
        let (_s2, r2) = pool
            .put_with_receipt(DeviceIoClass::Data, key2, b"pool-chunk-2")
            .expect("put chunk2");
        // Deliberately use a generation that differs from the pool receipt.
        let mismatched_gen = r2.generation.saturating_add(1);
        let chunk2 = make_chunk_ref(2, 1, 4096, mismatched_gen);
        put_chunk_data(&mut store, &inode, &chunk2);

        let mut report = FilesystemContentInspectionReport::empty();
        inspect_chunk_object(&store, &inode, &chunk0, &mut report, Some(&pool)).expect("chunk0 ok");
        inspect_chunk_object(&store, &inode, &chunk1, &mut report, Some(&pool)).expect("chunk1 ok");
        inspect_chunk_object(&store, &inode, &chunk2, &mut report, Some(&pool)).expect("chunk2 ok");

        assert_eq!(report.referenced_objects.len(), 3);
        assert!(
            !report.referenced_objects[0].receipt_mismatch,
            "chunk0 matched"
        );
        assert!(
            report.referenced_objects[1].receipt_mismatch,
            "chunk1 missing pool receipt"
        );
        assert!(
            report.referenced_objects[2].receipt_mismatch,
            "chunk2 gen mismatch"
        );
        assert_eq!(report.receipt_mismatches, 2);
        cleanup(&store_root);
        cleanup(&pool_root);
    }
}
