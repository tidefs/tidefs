// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeSet;

use tidefs_local_object_store::LocalObjectStore;
use tidefs_orphan_index::OrphanIndex;
use tidefs_types_vfs_core::InodeId;

use crate::intent_log::{IntentLog, IntentLogEntryKind};
use crate::object_keys::*;
use crate::recovery::load_latest_committed_state;
use crate::types::*;
use crate::Result;
use tidefs_recovery_loop::RecoveryPolicy;

// ---------------------------------------------------------------------------
// fsck types
// ---------------------------------------------------------------------------

/// Category of filesystem integrity check performed by fsck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsckCategory {
    /// Cross-check between the orphan index B+tree and the inode table nlink
    /// values.
    OrphanIndexConsistency,
    /// Verify intent log entries reference valid inodes in the committed state.
    IntentLogCoherence,
    /// Authenticate committed root slots via keyed BLAKE3-256 hash.
    CommittedRootValidity,
    /// Verify extent map and content objects exist in the object store for each
    /// committed inode.
    ExtentReferenceIntegrity,
}

/// Severity of an individual fsck finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsckSeverity {
    /// A definite inconsistency; the filesystem should not be mounted.
    Error,
    /// A diagnostic observation that does not block mounting.
    Warning,
}

/// A single finding produced by an fsck integrity check pass.
#[derive(Clone, Debug)]
pub struct FsckFinding {
    /// Which check category produced this finding.
    pub category: FsckCategory,
    /// Severity of the finding.
    pub severity: FsckSeverity,
    /// The inode this finding relates to, if identifiable.
    pub inode_id: Option<InodeId>,
    /// Human-readable description of the finding.
    pub description: String,
}

/// Aggregated report produced by a full fsck run.
#[derive(Clone, Debug)]
pub struct FsckReport {
    /// `true` when no Error-severity findings were produced.
    pub passed: bool,
    /// All findings produced, in discovery order.
    pub findings: Vec<FsckFinding>,
    /// Count of Error-severity findings.
    pub error_count: usize,
    /// Count of Warning-severity findings.
    pub warning_count: usize,
}

impl FsckReport {
    /// Create an empty, passing report.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            passed: true,
            findings: Vec::new(),
            error_count: 0,
            warning_count: 0,
        }
    }

    fn add_finding(&mut self, finding: FsckFinding) {
        match finding.severity {
            FsckSeverity::Error => {
                self.error_count += 1;
                self.passed = false;
            }
            FsckSeverity::Warning => {
                self.warning_count += 1;
            }
        }
        self.findings.push(finding);
    }
}

// ---------------------------------------------------------------------------
// internal run_fsck
// ---------------------------------------------------------------------------

/// Run all fsck checks against an already-open store.
///
/// The caller must supply the [`RecoveryPolicy`] that controls whether state
/// loading may replay intents. Advisory diagnostic callers should prefer
/// [`RecoveryPolicy::ReadOnly`] to avoid mutating durable state.
pub(crate) fn run_fsck(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
    policy: RecoveryPolicy,
) -> Result<FsckReport> {
    let state: crate::FileSystemState =
        match load_latest_committed_state(store, root_authentication_key, policy)? {
            Some(s) => s,
            None => {
                // Empty store: nothing to check, passes trivially.
                return Ok(FsckReport::empty());
            }
        };

    let mut report = FsckReport::empty();

    check_orphan_index_consistency(store, &state, &mut report)?;
    check_intent_log_coherence(store, &state, &mut report)?;
    check_extent_reference_integrity(store, &state, &mut report)?;

    Ok(report)
}

// ---------------------------------------------------------------------------
// orphan index ↔ inode nlink consistency
// ---------------------------------------------------------------------------

fn check_orphan_index_consistency(
    store: &LocalObjectStore,
    state: &crate::FileSystemState,
    report: &mut FsckReport,
) -> Result<()> {
    let orphan_index = match store.get(orphan_index_object_key())? {
        Some(bytes) => match OrphanIndex::recover_from_log(&bytes) {
            Ok((idx, corrupted)) => {
                for &raw_id in &corrupted {
                    report.add_finding(FsckFinding {
                        category: FsckCategory::OrphanIndexConsistency,
                        severity: FsckSeverity::Error,
                        inode_id: Some(InodeId::new(raw_id)),
                        description: format!(
                            "orphan index entry for inode {raw_id} has invalid checksum"
                        ),
                    });
                }
                idx
            }
            Err(_) => {
                report.add_finding(FsckFinding {
                    category: FsckCategory::OrphanIndexConsistency,
                    severity: FsckSeverity::Error,
                    inode_id: None,
                    description: "orphan index failed to decode; cannot verify".into(),
                });
                return Ok(());
            }
        },
        None => OrphanIndex::new(),
    };

    let orphan_ids: BTreeSet<u64> = orphan_index.collect_inode_ids().into_iter().collect();

    // Forward check: every entry in the orphan index must reference an inode
    // that exists in the committed state with nlink == 0.
    for &raw_id in &orphan_ids {
        let inode_id = InodeId::new(raw_id);
        match state.inodes.get(&inode_id) {
            Some(rec) if rec.nlink == 0 => { /* consistent */ }
            Some(rec) => {
                report.add_finding(FsckFinding {
                    category: FsckCategory::OrphanIndexConsistency,
                    severity: FsckSeverity::Error,
                    inode_id: Some(inode_id),
                    description: format!(
                        "orphan index entry for inode {} but inode nlink is {} (expected 0)",
                        raw_id, rec.nlink
                    ),
                });
            }
            None => {
                report.add_finding(FsckFinding {
                    category: FsckCategory::OrphanIndexConsistency,
                    severity: FsckSeverity::Error,
                    inode_id: Some(inode_id),
                    description: format!(
                        "orphan index entry for inode {raw_id} points to missing inode"
                    ),
                });
            }
        }
    }

    // Reverse check: every inode in the committed state with nlink == 0 must
    // be present in the orphan index.
    for (&inode_id, rec) in state.inodes.iter() {
        if rec.nlink == 0 && !orphan_ids.contains(&inode_id.get()) {
            report.add_finding(FsckFinding {
                category: FsckCategory::OrphanIndexConsistency,
                severity: FsckSeverity::Error,
                inode_id: Some(inode_id),
                description: format!(
                    "inode {} has nlink=0 but is missing from orphan index",
                    inode_id.get()
                ),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// intent log coherence
// ---------------------------------------------------------------------------

fn check_intent_log_coherence(
    store: &LocalObjectStore,
    state: &crate::FileSystemState,
    report: &mut FsckReport,
) -> Result<()> {
    let intent_log = match IntentLog::load(store) {
        Ok(log) => log,
        Err(e) => {
            report.add_finding(FsckFinding {
                category: FsckCategory::IntentLogCoherence,
                severity: FsckSeverity::Warning,
                inode_id: None,
                description: format!("could not load intent log: {e}"),
            });
            return Ok(());
        }
    };

    if intent_log.is_empty() {
        return Ok(());
    }

    let orphan_ids: BTreeSet<u64> = match store.get(orphan_index_object_key())? {
        Some(bytes) => OrphanIndex::recover_from_log(&bytes)
            .map(|(idx, _corrupted)| idx.collect_inode_ids().into_iter().collect())
            .unwrap_or_default(),
        None => BTreeSet::new(),
    };

    for entry in intent_log.pending_entries() {
        for raw_id in referenced_inode_ids(&entry.entry_kind) {
            let inode_id = InodeId::new(raw_id);
            if state.inodes.contains_key(&inode_id) {
                continue; // inode exists in committed state
            }
            if orphan_ids.contains(&raw_id) {
                continue; // legitimately orphaned
            }
            report.add_finding(FsckFinding {
                category: FsckCategory::IntentLogCoherence,
                severity: FsckSeverity::Error,
                inode_id: Some(inode_id),
                description: format!(
                    "intent log entry {} references inode {} not in committed state or orphan index",
                    entry.entry_id, raw_id
                ),
            });
        }
    }

    Ok(())
}

/// Collect all distinct inode IDs referenced by an intent log entry kind.
fn referenced_inode_ids(kind: &IntentLogEntryKind) -> Vec<u64> {
    match kind {
        IntentLogEntryKind::SyncWriteRange { inode_id, .. }
        | IntentLogEntryKind::OdsyncDataRange { inode_id, .. }
        | IntentLogEntryKind::SharedMmapMsync { inode_id, .. } => {
            vec![inode_id.get()]
        }
        IntentLogEntryKind::FsyncDirtyDrain { inode_ids } => {
            inode_ids.iter().map(|id| id.get()).collect()
        }
        IntentLogEntryKind::NamespaceSyncIntent {
            affected_inode_ids, ..
        } => affected_inode_ids.iter().map(|id| id.get()).collect(),
        IntentLogEntryKind::NamespaceCreateIntent(intent) => {
            vec![intent.parent_inode_id.get()]
        }
        IntentLogEntryKind::PressureFallback | IntentLogEntryKind::CrashReplayReconcile => {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// committed root validity (standalone public function)
// ---------------------------------------------------------------------------

/// Verify committed root slot integrity independently of `run_fsck`.
///
/// Loads the latest committed state; if it fails, the root is corrupt or
/// unauthentic.
#[cfg(test)]
pub fn check_committed_root_validity(
    store: &mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
    policy: RecoveryPolicy,
) -> Result<FsckReport> {
    let mut report = FsckReport::empty();
    match load_latest_committed_state(store, root_authentication_key, policy) {
        Ok(Some(_)) => { /* valid committed root loaded */ }
        Ok(None) => { /* empty store */ }
        Err(e) => {
            report.add_finding(FsckFinding {
                category: FsckCategory::CommittedRootValidity,
                severity: FsckSeverity::Error,
                inode_id: None,
                description: format!("committed root validation failed: {e}"),
            });
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// extent reference integrity
// ---------------------------------------------------------------------------

fn check_extent_reference_integrity(
    store: &LocalObjectStore,
    state: &crate::FileSystemState,
    report: &mut FsckReport,
) -> Result<()> {
    let extent_maps = state.extent_maps.lock().unwrap();
    for (&inode_id, rec) in state.inodes.iter() {
        if rec.size == 0 && !extent_maps.contains_key(&inode_id) {
            continue;
        }

        let content_key = content_object_key(inode_id);
        let versioned_key = content_object_key_for_version(inode_id, rec.data_version);

        if !store.contains_key(content_key)
            && !store.contains_key(versioned_key)
            && (rec.size > 0 || extent_maps.contains_key(&inode_id))
        {
            report.add_finding(FsckFinding {
                category: FsckCategory::ExtentReferenceIntegrity,
                severity: FsckSeverity::Warning,
                inode_id: Some(inode_id),
                description: format!(
                    "inode {} (size={}) has no content object in store",
                    inode_id.get(),
                    rec.size
                ),
            });
        }
    }

    for &inode_id in extent_maps.keys() {
        let ext_key = transaction_extent_map_object_key(state.generation, inode_id);
        if !store.contains_key(ext_key) {
            report.add_finding(FsckFinding {
                category: FsckCategory::ExtentReferenceIntegrity,
                severity: FsckSeverity::Error,
                inode_id: Some(inode_id),
                description: format!(
                    "inode {} has an extent map but its transaction object is missing",
                    inode_id.get()
                ),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
    use tidefs_types_vfs_core::{Generation, NodeKind};

    fn open_store(dir: &TempDir) -> LocalObjectStore {
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::default())
            .expect("open store")
    }

    fn demo_key() -> RootAuthenticationKey {
        RootAuthenticationKey::demo_key()
    }

    fn minimal_state() -> crate::FileSystemState {
        use crate::recovery::initial_state;
        // initial_state() already provides a valid state with root inode,
        // root directory table, known_inode_ids, and all projection fields.
        // Just bump the generation so persist_state writes a fresh root.
        let mut state = initial_state();
        state.generation = 2;
        state
    }

    // ── empty filesystem ─────────────────────────────────────────────────

    #[test]
    fn empty_filesystem_passes_with_zero_findings() {
        let dir = TempDir::new().expect("tempdir");
        let mut store = open_store(&dir);
        let report = run_fsck(&mut store, demo_key(), RecoveryPolicy::default()).expect("fsck");
        assert!(report.passed);
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warning_count, 0);
        assert!(report.findings.is_empty());
    }

    // ── clean round-trip ────────────────────────────────────────────────

    #[test]
    fn clean_filesystem_roundtrip_passes() {
        use crate::persistence::persist_state;

        let dir = TempDir::new().expect("tempdir");
        let mut store = open_store(&dir);

        let state = minimal_state();
        persist_state(&mut store, &state, demo_key()).expect("persist");

        let mut store2 = open_store(&dir);
        let report = run_fsck(&mut store2, demo_key(), RecoveryPolicy::default()).expect("fsck");
        assert!(report.passed);
        assert_eq!(report.error_count, 0);
    }

    // ── orphan forward: nlink==0 inode missing from orphan index ─────────

    #[test]
    fn orphan_forward_nlink_zero_missing_from_orphan_index() {
        // Build a FileSystemState with an inode that has nlink=0 but no
        // corresponding orphan index entry.  The check runs directly against
        // the state and store (no persistence round-trip).
        let dir = TempDir::new().expect("tempdir");
        let store = open_store(&dir);

        let orphan_id = InodeId::new(10);
        let mut state = minimal_state();
        let orphan_rec = InodeRecord {
            rdev: 0,
            dir_storage_kind: 0,
            inode_id: orphan_id,
            generation: Generation::new(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o100644,
            uid: 0,
            gid: 0,
            nlink: 0,
            size: 0,
            data_version: 0,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
        };
        state.observe_explicit_inode_id(orphan_id);
        state.inodes = Arc::new({
            let mut m = (*state.inodes).clone();
            m.insert(orphan_id, orphan_rec);
            m
        });

        // No orphan index was written to the store.
        let mut report = FsckReport::empty();
        check_orphan_index_consistency(&store, &state, &mut report).expect("check");
        assert!(!report.passed);

        let finding = report
            .findings
            .iter()
            .find(|f| f.inode_id == Some(orphan_id))
            .expect("finding for orphan inode");
        assert_eq!(finding.category, FsckCategory::OrphanIndexConsistency);
        assert_eq!(finding.severity, FsckSeverity::Error);
        assert!(finding.description.contains("missing from orphan index"));
    }

    // ── orphan reverse: orphan entry points to live (nlink>0) inode ─────

    #[test]
    fn orphan_reverse_entry_for_live_inode_is_error() {
        // Build a state where an inode has nlink=1 (live), then write an
        // orphan index that incorrectly includes it.
        let dir = TempDir::new().expect("tempdir");
        let mut store = open_store(&dir);

        let live_id = InodeId::new(5);
        let mut state = minimal_state();
        let live_rec = InodeRecord {
            rdev: 0,
            dir_storage_kind: 0,
            inode_id: live_id,
            generation: Generation::new(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o100644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 0,
            data_version: 0,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
        };
        state.observe_explicit_inode_id(live_id);
        state.inodes = Arc::new({
            let mut m = (*state.inodes).clone();
            m.insert(live_id, live_rec);
            m
        });

        // Write an orphan index that includes the live inode.
        let mut orphan = OrphanIndex::new();
        let orphan_entry = tidefs_orphan_index::OrphanEntry::new(
            live_id.get(),
            1,
            1,
            tidefs_orphan_index::OrphanEntryFlags::NONE,
        );
        orphan.insert(live_id.get(), orphan_entry);
        store
            .put(orphan_index_object_key(), &orphan.encode_log())
            .expect("put orphan index");

        let mut report = FsckReport::empty();
        check_orphan_index_consistency(&store, &state, &mut report).expect("check");
        assert!(!report.passed);

        let finding = report
            .findings
            .iter()
            .find(|f| f.inode_id == Some(live_id))
            .expect("finding for live inode in orphan index");
        assert_eq!(finding.category, FsckCategory::OrphanIndexConsistency);
        assert_eq!(finding.severity, FsckSeverity::Error);
        assert!(finding.description.contains("nlink is 1 (expected 0)"));
    }

    // ── committed root corruption ───────────────────────────────────────

    #[test]
    fn committed_root_corruption_detected() {
        // Create a valid committed state, then verify it with a WRONG
        // root authentication key. Key mismatch is detected as a root
        // validity error.
        use crate::persistence::persist_state;

        let dir = TempDir::new().expect("tempdir");
        let mut store = open_store(&dir);

        let state = minimal_state();
        persist_state(&mut store, &state, demo_key()).expect("persist");

        // Use a different key for verification.
        let wrong_key = RootAuthenticationKey::from_bytes32([0xDEu8; 32]);

        let report =
            check_committed_root_validity(&mut store, wrong_key, RecoveryPolicy::default())
                .expect("check root");
        assert!(!report.passed);
        assert!(report.error_count > 0);
        let finding = report.findings.first().expect("finding");
        assert_eq!(finding.category, FsckCategory::CommittedRootValidity);
        assert_eq!(finding.severity, FsckSeverity::Error);
    }

    // ── intent log dangling reference ───────────────────────────────────

    #[test]
    fn intent_log_dangling_inode_reference_detected() {
        use crate::persistence::persist_state;

        let dir = TempDir::new().expect("tempdir");
        let mut store = open_store(&dir);

        let state = minimal_state();
        persist_state(&mut store, &state, demo_key()).expect("persist");

        let mut log = IntentLog::new();
        let dangling = InodeId::new(99);
        let entry = crate::intent_log::IntentLogEntry {
            entry_id: 0,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: dangling,
                offset: 0,
                length: 64,
                payload_digest: tidefs_local_object_store::IntegrityDigest64(0),
                data_version: 0,
            },
            root_anchor: crate::intent_log::IntentLogRootAnchor {
                transaction_id: 2,
                generation: 2,
                manifest_digest: tidefs_local_object_store::IntegrityDigest64(0),
            },
            timestamp_ns: 1,
        };
        log.append(
            &mut store,
            entry.entry_kind.clone(),
            entry.root_anchor,
            entry.timestamp_ns,
        )
        .expect("append");
        log.flush(&mut store).expect("flush");

        let mut store2 = open_store(&dir);
        let report = run_fsck(&mut store2, demo_key(), RecoveryPolicy::default()).expect("fsck");
        assert!(!report.passed);

        let finding = report
            .findings
            .iter()
            .find(|f| f.inode_id == Some(dangling))
            .expect("finding for dangling inode");
        assert_eq!(finding.category, FsckCategory::IntentLogCoherence);
        assert_eq!(finding.severity, FsckSeverity::Error);
    }

    // -- clean round-trip through LocalFileSystem::open --------------------

    #[test]
    fn open_clean_roundtrip_runs_fsck_and_passes() {
        let dir = TempDir::new().expect("tempdir");

        // Open fresh filesystem -- fsck runs internally and should pass.
        let mut fs = crate::LocalFileSystem::open_with_root_authentication_key(
            dir.path(),
            StoreOptions::default(),
            demo_key(),
        )
        .expect("first open should succeed (fsck passes)");

        // Create a file and write data through the filesystem API.
        crate::LocalFileSystem::create_file(&mut fs, "/test.txt", 0o644).expect("create file");
        crate::LocalFileSystem::write_file(&mut fs, "/test.txt", 0, b"hello fsck")
            .expect("write file");
        crate::LocalFileSystem::sync_all(&mut fs).expect("sync");

        // Close the filesystem.
        drop(fs);

        // Reopen -- fsck runs again internally and should pass.
        let fs2 = crate::LocalFileSystem::open_with_root_authentication_key(
            dir.path(),
            StoreOptions::default(),
            demo_key(),
        )
        .expect("reopen should succeed (fsck passes)");
        drop(fs2);
    }
}
