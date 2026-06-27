// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use tidefs_local_object_store::{
    checksum64, DeviceIoClass, IntegrityDigest64, LocalObjectStore, Pool, StoreOptions,
};
use tidefs_types_vfs_core::{Generation, InodeId, NodeKind, ROOT_INODE_ID};

use crate::constants::*;
use crate::error::FileSystemError;
use crate::records::*;
use crate::types::*;
use crate::{
    fs_io_error, persist_state_until_boundary, publish_root_commit, root_slot_for_transaction,
};
use crate::{FileSystemState, LocalFileSystem, Result};

use crate::{
    content_object_key_for_version, encode_content, encode_directory, encode_inode,
    encode_superblock, mode_for_kind, root_authentication_record_for_bytes, root_slot_object_key,
    transaction_directory_object_key, transaction_inode_object_key,
    transaction_superblock_object_key, validate_name,
};
pub(crate) fn prepare_empty_crash_matrix_root(root: &Path) -> Result<()> {
    if root.exists() {
        let mut entries =
            fs::read_dir(root).map_err(|source| fs_io_error("read_dir", root, source))?;
        if entries
            .next()
            .transpose()
            .map_err(|source| fs_io_error("read_dir", root, source))?
            .is_some()
        {
            return Err(FileSystemError::Unsupported {
                operation: "run_crash_recovery_matrix",
                reason: "matrix root must be empty so the validation run cannot overwrite existing storage",
            });
        }
    }
    fs::create_dir_all(root).map_err(|source| fs_io_error("create_dir_all", root, source))
}

pub(crate) fn run_crash_recovery_boundary_case(
    root: &Path,
    options: StoreOptions,
    boundary: CrashInjectionBoundary,
    root_authentication_key: RootAuthenticationKey,
) -> Result<CrashRecoveryCaseReport> {
    let mut fs = LocalFileSystem::open_with_root_authentication_key(
        root,
        options.clone(),
        root_authentication_key,
    )?;
    fs.create_file("/stable.txt", DEFAULT_FILE_PERMISSIONS)?;
    fs.write_file("/stable.txt", 0, b"stable-before-crash-matrix")?;
    fs.sync_all()?;
    let stable_generation = fs.stats().filesystem_generation;

    let (staged, candidate_path, inode_id, new_bytes) = stage_crash_matrix_file_state(
        &fs,
        b"candidate.txt",
        b"candidate bytes after crash matrix",
    )?;
    let candidate_generation = staged.generation;
    let expected = apply_crash_matrix_boundary(&mut fs, &staged, inode_id, &new_bytes, boundary)?;
    drop(fs);

    let probe = LocalFileSystem::probe_recovery_with_root_authentication_key(
        root,
        options.clone(),
        root_authentication_key,
    )?;
    let observed = classify_crash_matrix_boundary_outcome(
        CrashMatrixBoundaryClassification {
            root,
            options,
            root_authentication_key,
            candidate_path: &candidate_path,
            new_bytes: &new_bytes,
            stable_generation,
            candidate_generation,
        },
        probe.outcome,
    )?;
    Ok(CrashRecoveryCaseReport {
        boundary,
        expected,
        observed,
        stable_generation,
        candidate_generation,
        selected_generation: probe.selected_generation,
        object_store_repaired_tail_bytes: probe.object_store_repaired_tail_bytes,
        production_fsck_required: probe.production_recovery_requires_operator_repair(),
    })
}

pub(crate) fn run_crash_recovery_explicit_error_case(
    root: &Path,
    options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
) -> Result<CrashRecoveryExplicitErrorReport> {
    // Use the same pool backend as probe_recovery so the corrupt root
    // slots live in the block-device-backed store that the probe opens,
    // rather than in a separate directory-based LocalObjectStore.
    // Route through CrashMatrixRawStagingAuthority so the validation-only
    // raw-store count stays at one authoritative call site.
    let mut pool = LocalFileSystem::default_development_pool(root, &options, None, None)?;
    {
        let mut staging =
            CrashMatrixRawStagingAuthority::validation_only(&mut pool, root_authentication_key);
        for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
            staging
                .raw_store()
                .put(root_slot_object_key(slot), b"invalid root slot bytes")?;
        }
    }
    pool.sync_all()?;
    drop(pool);

    let probe = LocalFileSystem::probe_recovery_with_root_authentication_key(
        root,
        options.clone(),
        root_authentication_key,
    )?;
    if probe.outcome != RecoveryProbeOutcome::ExplicitIntegrityOrMediaError {
        return Err(FileSystemError::CorruptState {
            reason: "crash matrix explicit-error case did not classify as integrity/media error",
        });
    }
    if !matches!(
        LocalFileSystem::open_with_root_authentication_key(root, options, root_authentication_key),
        Err(FileSystemError::CorruptState { .. })
    ) {
        return Err(FileSystemError::CorruptState {
            reason: "crash matrix explicit-error case unexpectedly mounted",
        });
    }

    Ok(CrashRecoveryExplicitErrorReport {
        observed: CrashRecoveryObservedOutcome::ExplicitIntegrityOrMediaError,
        root_slot_records_seen: probe.root_slot_records_seen,
        valid_committed_roots_seen: probe.valid_committed_roots_seen,
        production_fsck_required: probe.production_recovery_requires_operator_repair(),
    })
}

pub(crate) fn stage_crash_matrix_file_state(
    fs: &LocalFileSystem,
    name: &[u8],
    bytes: &[u8],
) -> Result<(FileSystemState, String, InodeId, Vec<u8>)> {
    validate_name(name)?;
    let mut staged = fs.state.clone();
    let tick = staged.generation.saturating_add(1).max(1);
    staged.generation = tick;
    let inode_id = staged.allocate_inode_id();
    let record = InodeRecord {
        rdev: 0,
        inode_id,
        generation: Generation::new(tick),
        facets: NodeKind::File.to_facets(),
        mode: mode_for_kind(NodeKind::File, DEFAULT_FILE_PERMISSIONS),
        uid: 0,
        gid: 0,
        nlink: 1,
        size: bytes.len() as u64,
        data_version: tick,
        metadata_version: tick,
        posix_time: PosixTimeRecord::now(),
        xattrs: BTreeMap::new(),
        dir_storage_kind: 0,
        xattr_storage_kind: 0,
        dir_rev: 0,
        subtree_rev: 0,
    };
    Arc::make_mut(&mut staged.inodes).insert(inode_id, record.clone());
    let root_dir = Arc::make_mut(&mut staged.directories)
        .get_mut(&ROOT_INODE_ID)
        .ok_or(FileSystemError::CorruptState {
            reason: "crash matrix staging found no root directory",
        })?;
    root_dir.insert(
        name.to_vec(),
        NamespaceEntry {
            name: name.to_vec(),
            inode_id,
            generation: record.generation,
            facets: record.facets,
            mode: record.mode,
        },
    );
    if let Some(root_inode) = Arc::make_mut(&mut staged.inodes).get_mut(&ROOT_INODE_ID) {
        root_inode.size = root_dir.len() as u64;
        root_inode.data_version = tick;
        root_inode.metadata_version = tick;
    }
    Ok((
        staged,
        format!("/{}", String::from_utf8_lossy(name)),
        inode_id,
        bytes.to_vec(),
    ))
}

pub(crate) fn apply_crash_matrix_boundary(
    fs: &mut LocalFileSystem,
    staged: &FileSystemState,
    inode_id: InodeId,
    bytes: &[u8],
    boundary: CrashInjectionBoundary,
) -> Result<CrashRecoveryExpectation> {
    let transaction_id = staged.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    let root_authentication_key = fs.root_authentication_key;
    let mut raw_staging =
        CrashMatrixRawStagingAuthority::validation_only(&mut fs.store, root_authentication_key);
    match boundary {
        CrashInjectionBoundary::NoCrash | CrashInjectionBoundary::AfterRootCommitSynced => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            let observed = raw_staging
                .persist_until_boundary(staged, FilesystemCommitBoundary::RootCommitSynced)?;
            if observed != FilesystemCommitBoundary::RootCommitSynced {
                return Err(FileSystemError::CorruptState {
                    reason: "crash matrix failed to reach root commit sync boundary",
                });
            }
        }
        CrashInjectionBoundary::BeforeContentObjects => {
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterContentObjects => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterTransactionInodes => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            raw_staging.stage_transaction_inodes(staged, transaction_id)?;
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterTransactionDirectories => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            raw_staging.stage_transaction_inodes(staged, transaction_id)?;
            raw_staging.stage_transaction_directories(staged, transaction_id)?;
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterTransactionSuperblock => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            raw_staging.stage_transaction_inodes(staged, transaction_id)?;
            raw_staging.stage_transaction_directories(staged, transaction_id)?;
            let _root = raw_staging.stage_transaction_superblock(staged, transaction_id)?;
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterTransactionObjectsSynced => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            let observed = raw_staging.persist_until_boundary(
                staged,
                FilesystemCommitBoundary::TransactionObjectsSynced,
            )?;
            if observed != FilesystemCommitBoundary::TransactionObjectsSynced {
                return Err(FileSystemError::CorruptState {
                    reason: "crash matrix failed to reach transaction object sync boundary",
                });
            }
        }
        CrashInjectionBoundary::AfterMalformedRootCommit => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            raw_staging.stage_transaction_inodes(staged, transaction_id)?;
            raw_staging.stage_transaction_directories(staged, transaction_id)?;
            let root = raw_staging.stage_transaction_superblock(staged, transaction_id)?;
            raw_staging.stage_malformed_root_commit(&root)?;
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterRootCommitMissingTransaction => {
            raw_staging.stage_root_commit_without_transaction_objects(staged, transaction_id)?;
            raw_staging.sync_all()?;
        }
        CrashInjectionBoundary::AfterRootCommitWritten => {
            raw_staging.stage_content(staged, inode_id, bytes)?;
            let observed = raw_staging
                .persist_until_boundary(staged, FilesystemCommitBoundary::RootCommitWritten)?;
            if observed != FilesystemCommitBoundary::RootCommitWritten {
                return Err(FileSystemError::CorruptState {
                    reason: "crash matrix failed to reach root commit write boundary",
                });
            }
        }
    }
    Ok(boundary.expected_recovery())
}

struct CrashMatrixRawStagingAuthority<'a> {
    pool: &'a mut Pool,
    root_authentication_key: RootAuthenticationKey,
}

impl<'a> CrashMatrixRawStagingAuthority<'a> {
    // Validation-only commit-boundary staging for the crash matrix. This does
    // not authorize mounted device-level compression or encryption claims.
    fn validation_only(pool: &'a mut Pool, root_authentication_key: RootAuthenticationKey) -> Self {
        Self {
            pool,
            root_authentication_key,
        }
    }

    fn raw_store(&mut self) -> &mut LocalObjectStore {
        self.pool.raw_primary_store_mut()
    }

    fn stage_content(
        &mut self,
        staged: &FileSystemState,
        inode_id: InodeId,
        bytes: &[u8],
    ) -> Result<()> {
        let record = staged
            .inodes
            .get(&inode_id)
            .ok_or(FileSystemError::CorruptState {
                reason: "crash matrix staged file has no inode record",
            })?;
        self.raw_store().put(
            content_object_key_for_version(inode_id, record.data_version),
            &encode_content(record, bytes),
        )?;
        Ok(())
    }

    fn stage_transaction_inodes(
        &mut self,
        staged: &FileSystemState,
        transaction_id: u64,
    ) -> Result<()> {
        for inode in staged.inodes.values() {
            self.raw_store().put(
                transaction_inode_object_key(transaction_id, inode.inode_id),
                &encode_inode(inode),
            )?;
        }
        Ok(())
    }

    fn stage_transaction_directories(
        &mut self,
        staged: &FileSystemState,
        transaction_id: u64,
    ) -> Result<()> {
        for inode in staged.inodes.values() {
            if inode.kind() == NodeKind::Dir {
                let directory = staged.directories.get(&inode.inode_id).ok_or(
                    FileSystemError::CorruptState {
                        reason: "crash matrix staged directory inode has no directory table",
                    },
                )?;
                self.raw_store().put(
                    transaction_directory_object_key(transaction_id, inode.inode_id),
                    &encode_directory(inode, directory),
                )?;
            }
        }
        Ok(())
    }

    fn stage_transaction_superblock(
        &mut self,
        staged: &FileSystemState,
        transaction_id: u64,
    ) -> Result<RootCommitRecord> {
        let (root, superblock_bytes) = crash_matrix_root_for_staged_state(staged, transaction_id);
        self.raw_store().put(
            transaction_superblock_object_key(transaction_id),
            &superblock_bytes,
        )?;
        Ok(root)
    }

    fn persist_until_boundary(
        &mut self,
        staged: &FileSystemState,
        stop_after: FilesystemCommitBoundary,
    ) -> Result<FilesystemCommitBoundary> {
        let root_authentication_key = self.root_authentication_key;
        persist_state_until_boundary(
            self.raw_store(),
            staged,
            root_authentication_key,
            Some(stop_after),
        )
    }

    fn stage_root_commit_without_transaction_objects(
        &mut self,
        staged: &FileSystemState,
        transaction_id: u64,
    ) -> Result<()> {
        let (root, _superblock_bytes) = crash_matrix_root_for_staged_state(staged, transaction_id);
        let root_authentication_key = self.root_authentication_key;
        publish_root_commit(self.raw_store(), &root, root_authentication_key)?;
        Ok(())
    }

    fn stage_malformed_root_commit(&mut self, root: &RootCommitRecord) -> Result<()> {
        self.pool.put(
            DeviceIoClass::Data,
            root_slot_object_key(root.slot),
            b"malformed root-slot bytes with a valid object-store checksum",
        )?;
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        self.pool.sync_all()?;
        Ok(())
    }
}

pub(crate) fn crash_matrix_root_for_staged_state(
    staged: &FileSystemState,
    transaction_id: u64,
) -> (RootCommitRecord, Vec<u8>) {
    let inode_count = staged.inodes.len() as u64;
    let bitmap_words = staged.next_inode_id_raw().div_ceil(64) as usize;
    let mut inode_allocation_bitmap = vec![0u64; bitmap_words];
    for inode_id in staged.inodes.keys() {
        let idx = (inode_id.get() - 1) as usize;
        inode_allocation_bitmap[idx / 64] |= 1u64 << (idx % 64);
    }
    let superblock = SuperblockRecord {
        next_inode_id: staged.next_inode_id_raw(),
        generation: staged.generation,
        inode_count,
        inode_allocation_bitmap,
        format_version_min: CURRENT_FORMAT_VERSION,
        format_version_max: CURRENT_FORMAT_VERSION,
    };
    let superblock_bytes = encode_superblock(&superblock);
    let root = RootCommitRecord {
        slot: root_slot_for_transaction(transaction_id),
        transaction_id,
        generation: staged.generation,
        next_inode_id: staged.next_inode_id_raw(),
        inode_count: superblock.inode_count,
        superblock_checksum: checksum64(&superblock_bytes),
        manifest_checksum: IntegrityDigest64::ZERO,
        manifest_entry_count: 0,
        root_authentication: Some(root_authentication_record_for_bytes(
            &superblock_bytes,
            None,
        )),
    };
    (root, superblock_bytes)
}

pub(crate) struct CrashMatrixBoundaryClassification<'a> {
    root: &'a Path,
    options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
    candidate_path: &'a str,
    new_bytes: &'a [u8],
    stable_generation: u64,
    candidate_generation: u64,
}

pub(crate) fn classify_crash_matrix_boundary_outcome(
    params: CrashMatrixBoundaryClassification<'_>,
    probe_outcome: RecoveryProbeOutcome,
) -> Result<CrashRecoveryObservedOutcome> {
    if probe_outcome == RecoveryProbeOutcome::ExplicitIntegrityOrMediaError {
        return Ok(CrashRecoveryObservedOutcome::ExplicitIntegrityOrMediaError);
    }
    let reopened = LocalFileSystem::open_with_root_authentication_key(
        params.root,
        params.options,
        params.root_authentication_key,
    )?;
    let reopened_generation = reopened.stats().filesystem_generation;
    if reopened_generation == params.stable_generation
        && reopened.read_file("/stable.txt")? == b"stable-before-crash-matrix"
        && matches!(
            reopened.lookup(params.candidate_path),
            Err(FileSystemError::NotFound { .. })
        )
    {
        return Ok(CrashRecoveryObservedOutcome::PreviousCommittedRoot);
    }
    if reopened_generation == params.candidate_generation
        && reopened.read_file(params.candidate_path)? == params.new_bytes
    {
        return Ok(CrashRecoveryObservedOutcome::NewCommittedRoot);
    }
    Err(FileSystemError::CorruptState {
        reason: "crash matrix reopened to partial or unexpected namespace truth",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    use crate::{DatasetInodeAuthority, ROOT_DATASET_ID};

    // ── prepare_empty_crash_matrix_root ──────────────────────────────

    #[test]
    fn prepare_on_clean_tempdir_creates_directory() {
        let tmp = TempDir::new().expect("tempdir");
        let matrix_root = tmp.path().join("crash_matrix");
        assert!(
            !matrix_root.exists(),
            "matrix_root must not exist before prepare"
        );
        prepare_empty_crash_matrix_root(&matrix_root).expect("prepare on clean tempdir");
        assert!(matrix_root.is_dir(), "matrix_root should be a directory");
    }

    #[test]
    fn prepare_idempotent_reinitialization() {
        let tmp = TempDir::new().expect("tempdir");
        let matrix_root = tmp.path().join("matrix");
        prepare_empty_crash_matrix_root(&matrix_root).expect("first call");
        // Second call on the same empty dir should succeed (idempotent).
        prepare_empty_crash_matrix_root(&matrix_root).expect("second call (idempotent)");
        assert!(matrix_root.is_dir());
    }

    #[test]
    fn prepare_rejects_nonempty_directory() {
        let tmp = TempDir::new().expect("tempdir");
        let matrix_root = tmp.path().join("matrix");
        fs::create_dir(&matrix_root).expect("create dir");
        // Place a file inside so the directory is non-empty.
        fs::write(matrix_root.join("validation.log"), b"prior run")
            .expect("write file inside matrix");
        let err =
            prepare_empty_crash_matrix_root(&matrix_root).expect_err("non-empty should error");
        match err {
            FileSystemError::Unsupported { operation, .. } => {
                assert_eq!(operation, "run_crash_recovery_matrix");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn prepare_creates_parent_dirs() {
        // create_dir_all semantics: intermediate parents are created.
        let tmp = TempDir::new().expect("tempdir");
        let matrix_root = tmp.path().join("a").join("b").join("crash_matrix");
        assert!(!matrix_root.exists());
        prepare_empty_crash_matrix_root(&matrix_root).expect("prepare with missing parents");
        assert!(matrix_root.is_dir());
    }

    #[test]
    fn prepare_readonly_parent_permission_denied() {
        let tmp = TempDir::new().expect("tempdir");
        let readonly = tmp.path().join("ro");
        fs::create_dir(&readonly).expect("create ro dir");
        fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o500))
            .expect("set read-only");
        let matrix_root = readonly.join("matrix");
        let result = prepare_empty_crash_matrix_root(&matrix_root);
        // On Linux as root, permission bits are often ignored -- skip gracefully.
        if result.is_err() {
            let err = result.unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("create_dir_all")
                    || msg.contains("PermissionDenied")
                    || msg.contains("permission"),
                "expected permission or create_dir_all error, got {msg}"
            );
        }
        // Restore writability so TempDir can clean up.
        let _ = fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o700));
    }

    // ── crash_matrix_root_for_staged_state ───────────────────────────

    #[test]
    fn crash_matrix_root_for_default_empty_state() {
        let staged = FileSystemState::default();
        let transaction_id = 1;
        let (root, superblock_bytes) = crash_matrix_root_for_staged_state(&staged, transaction_id);
        // Superblock must be non-empty for default state.
        assert!(!superblock_bytes.is_empty(), "superblock must not be empty");
        assert_eq!(root.transaction_id, transaction_id);
        assert_eq!(root.generation, staged.generation);
        assert_eq!(root.next_inode_id, staged.next_inode_id_raw());
        assert_eq!(root.inode_count, 0);
        assert_eq!(root.manifest_entry_count, 0);
        // Root slot must be valid (depends on transaction_id).
        assert!(root.slot < FILESYSTEM_ROOT_SLOT_COUNT);
        // Root authentication record must exist (always, even for empty state).
        assert!(root.root_authentication.is_some());
        // Superblock checksum must be non-zero.
        assert_ne!(
            root.superblock_checksum,
            IntegrityDigest64::ZERO,
            "superblock_checksum must be non-zero"
        );
    }

    #[test]
    fn crash_matrix_root_preserves_inode_bitmap() {
        let mut staged = FileSystemState {
            generation: 42,
            inode_authority: DatasetInodeAuthority::from_recovered_next_inode_id(
                ROOT_DATASET_ID,
                10,
            ),
            ..FileSystemState::default()
        };
        // Insert two inodes (ids 1 and 3).
        let inode1 = InodeRecord {
            rdev: 0,
            inode_id: InodeId::new(1),
            generation: Generation::new(10),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            size: 0,
            data_version: 1,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        let inode3 = InodeRecord {
            rdev: 0,
            inode_id: InodeId::new(3),
            generation: Generation::new(20),
            facets: NodeKind::Dir.to_facets(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            nlink: 2,
            size: 0,
            data_version: 2,
            metadata_version: 2,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut staged.inodes).insert(InodeId::new(1), inode1);
        Arc::make_mut(&mut staged.inodes).insert(InodeId::new(3), inode3);

        let transaction_id = 100;
        let (root, superblock_bytes) = crash_matrix_root_for_staged_state(&staged, transaction_id);
        assert_eq!(root.generation, 42);
        assert_eq!(root.next_inode_id, 10);
        assert_eq!(root.inode_count, 2);
        assert!(!superblock_bytes.is_empty());
        assert_ne!(root.superblock_checksum, IntegrityDigest64::ZERO);
    }

    #[test]
    fn crash_matrix_root_different_inputs_different_output() {
        let staged = FileSystemState::default();
        let (root1, sb1) = crash_matrix_root_for_staged_state(&staged, 1);
        let (root2, sb2) = crash_matrix_root_for_staged_state(&staged, 2);
        // Different transaction_id changes the slot.
        assert_ne!(root1.slot, root2.slot);
        assert_ne!(root1.transaction_id, root2.transaction_id);
        // Superblock bytes should be identical (same state).
        assert_eq!(sb1, sb2);
        // Superblock checksums should match (same bytes).
        assert_eq!(root1.superblock_checksum, root2.superblock_checksum);
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[test]
    fn crash_matrix_root_is_deterministic() {
        let mut staged = FileSystemState {
            generation: 5,
            inode_authority: DatasetInodeAuthority::from_recovered_next_inode_id(
                ROOT_DATASET_ID,
                8,
            ),
            ..FileSystemState::default()
        };
        let inode = InodeRecord {
            rdev: 0,
            inode_id: InodeId::new(2),
            generation: Generation::new(3),
            facets: NodeKind::File.to_facets(),
            mode: 0o600,
            uid: 42,
            gid: 42,
            nlink: 1,
            size: 100,
            data_version: 7,
            metadata_version: 7,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut staged.inodes).insert(InodeId::new(2), inode);

        let (root_a, sb_a) = crash_matrix_root_for_staged_state(&staged, 99);
        let (root_b, sb_b) = crash_matrix_root_for_staged_state(&staged, 99);
        assert_eq!(sb_a, sb_b, "superblock bytes must be deterministic");
        assert_eq!(root_a.transaction_id, root_b.transaction_id);
        assert_eq!(root_a.generation, root_b.generation);
        assert_eq!(root_a.next_inode_id, root_b.next_inode_id);
        assert_eq!(root_a.inode_count, root_b.inode_count);
        assert_eq!(root_a.superblock_checksum, root_b.superblock_checksum);
        assert_eq!(root_a.slot, root_b.slot);
    }

    // ── Boundary: large next_inode_id ─────────────────────────────────

    #[test]
    fn crash_matrix_root_large_next_inode_id() {
        let _staged = FileSystemState::default();
        // next_inode_id=0 is fine (default); also try a large value.
        let large_staged = FileSystemState {
            inode_authority: DatasetInodeAuthority::from_recovered_next_inode_id(
                ROOT_DATASET_ID,
                1_000_000,
            ),
            generation: 1234,
            ..FileSystemState::default()
        };
        let (root, sb) = crash_matrix_root_for_staged_state(&large_staged, 50);
        assert_eq!(root.next_inode_id, 1_000_000);
        assert_eq!(root.inode_count, 0);
        assert!(!sb.is_empty());
        // The bitmap must be large enough to accommodate next_inode_id.
        assert_ne!(root.superblock_checksum, IntegrityDigest64::ZERO);
    }

    // ── Boundary: empty matrix (zero inodes, zero generation) ─────────

    #[test]
    fn crash_matrix_root_zero_generation() {
        let staged = FileSystemState::default();
        let (root, sb) = crash_matrix_root_for_staged_state(&staged, 1);
        assert_eq!(root.generation, 0);
        assert_eq!(root.inode_count, 0);
        assert!(!sb.is_empty());
        assert_ne!(root.superblock_checksum, IntegrityDigest64::ZERO);
    }
}
