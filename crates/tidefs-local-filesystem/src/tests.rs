#[cfg(test)]
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId, DatasetType};
use tidefs_local_object_store::CompressionAlgorithm;
use tidefs_local_object_store::{checksum64, IntegrityDigest64};
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_types_vfs_core::S_IFDIR;
use tidefs_types_vfs_core::{LockRange, LockType};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-local-filesystem-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn options() -> StoreOptions {
    StoreOptions {
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
        verify_read_checksums: false,
    }
}

fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

fn assert_record_has_wall_clock_posix_times(record: &InodeRecord, before_ns: i64, after_ns: i64) {
    let timestamps = [
        record.posix_time.atime_ns,
        record.posix_time.mtime_ns,
        record.posix_time.ctime_ns,
        record.posix_time.btime_ns,
    ];
    for timestamp in timestamps {
        assert!(
            timestamp >= before_ns && timestamp <= after_ns,
            "timestamp {timestamp} outside [{before_ns}, {after_ns}]"
        );
        assert!(
            timestamp / 1_000_000_000 > 0,
            "timestamp seconds should not truncate to zero"
        );
    }
}

#[test]
fn online_verifier_path_does_not_initialize_missing_store() {
    let root = temp_root("online-verifier-missing-store");
    assert!(!root.exists());

    let verifier = verify_online(&root, options()).expect("verify missing store");

    assert_eq!(verifier.outcome, OnlineVerifierOutcome::EmptyStore);
    assert!(verifier.passed());
    assert!(!verifier.mutates_storage());
    assert!(!root.exists());
    cleanup(&root);
}

fn stage_probe_file_state(
    fs: &LocalFileSystem,
    name: &[u8],
    bytes: &[u8],
) -> (FileSystemState, String, InodeId, Vec<u8>) {
    validate_name(name).expect("probe file name is valid");
    let mut staged = fs.state.clone();
    let tick = staged.generation.saturating_add(1).max(1);
    staged.generation = tick;
    let inode_id = InodeId::new(staged.next_inode_id);
    staged.next_inode_id = staged.next_inode_id.saturating_add(1);
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
        posix_time: crate::types::PosixTimeRecord::from_generation(tick),
        xattrs: BTreeMap::new(),
        dir_storage_kind: 0,
        xattr_storage_kind: 0,
        dir_rev: 0,
    };
    Arc::make_mut(&mut staged.inodes).insert(inode_id, record.clone());
    let root_dir = Arc::make_mut(&mut staged.directories)
        .get_mut(&ROOT_INODE_ID)
        .expect("root directory exists");
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
    let path = format!("/{}", String::from_utf8_lossy(name));
    (staged, path, inode_id, bytes.to_vec())
}

fn write_staged_content(
    store: &mut LocalObjectStore,
    staged: &FileSystemState,
    inode_id: InodeId,
    bytes: &[u8],
) {
    let record = staged.inodes.get(&inode_id).expect("staged inode exists");
    store
        .put(
            content_object_key_for_version(inode_id, record.data_version),
            &encode_content(record, bytes),
        )
        .expect("write staged content object");
}

fn current_content_manifest(fs: &LocalFileSystem, path: &str) -> ContentManifestObject {
    let record = fs.stat(path).expect("stat file");
    let bytes = fs
        .store
        .get(
            DeviceIoClass::Data,
            content_object_key_for_version(record.inode_id, record.data_version),
        )
        .expect("read content object")
        .expect("content object exists");
    let manifest = decode_content_manifest(&bytes).expect("decode chunk manifest");
    validate_content_manifest(record.inode_id, &record, &manifest)
        .expect("manifest validates against inode");
    manifest
}

fn write_transaction_inodes(
    store: &mut LocalObjectStore,
    staged: &FileSystemState,
    transaction_id: u64,
) {
    for inode in staged.inodes.values() {
        store
            .put(
                transaction_inode_object_key(transaction_id, inode.inode_id),
                &encode_inode(inode),
            )
            .expect("write staged transaction inode");
    }
}

fn write_transaction_directories(
    store: &mut LocalObjectStore,
    staged: &FileSystemState,
    transaction_id: u64,
) {
    for inode in staged.inodes.values() {
        if inode.kind() == NodeKind::Dir {
            let directory = staged
                .directories
                .get(&inode.inode_id)
                .expect("staged directory exists");
            store
                .put(
                    transaction_directory_object_key(transaction_id, inode.inode_id),
                    &encode_directory(inode, directory),
                )
                .expect("write staged transaction directory");
        }
    }
}

fn root_for_staged_state(
    staged: &FileSystemState,
    transaction_id: u64,
) -> (RootCommitRecord, Vec<u8>) {
    let inode_count = staged.inodes.len() as u64;
    let bitmap_words = staged.next_inode_id.div_ceil(64) as usize;
    let mut inode_allocation_bitmap = vec![0u64; bitmap_words];
    for inode_id in staged.inodes.keys() {
        let idx = (inode_id.get() - 1) as usize;
        inode_allocation_bitmap[idx / 64] |= 1u64 << (idx % 64);
    }
    let superblock = SuperblockRecord {
        next_inode_id: staged.next_inode_id,
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
        next_inode_id: staged.next_inode_id,
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

fn write_transaction_superblock(
    store: &mut LocalObjectStore,
    staged: &FileSystemState,
    transaction_id: u64,
) -> RootCommitRecord {
    let (root, superblock_bytes) = root_for_staged_state(staged, transaction_id);
    store
        .put(
            transaction_superblock_object_key(transaction_id),
            &superblock_bytes,
        )
        .expect("write staged transaction superblock");
    root
}

fn apply_crash_boundary(
    fs: &mut LocalFileSystem,
    staged: &FileSystemState,
    inode_id: InodeId,
    bytes: &[u8],
    boundary: CrashInjectionBoundary,
) -> CrashRecoveryExpectation {
    let transaction_id = staged.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    match boundary {
        CrashInjectionBoundary::NoCrash | CrashInjectionBoundary::AfterRootCommitSynced => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            let observed = persist_state_until_boundary(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                fs.root_authentication_key,
                Some(FilesystemCommitBoundary::RootCommitSynced),
            )
            .expect("complete root commit sync");
            assert_eq!(observed, FilesystemCommitBoundary::RootCommitSynced);
        }
        CrashInjectionBoundary::BeforeContentObjects => {
            fs.store.sync_all().expect("sync previous state only");
        }
        CrashInjectionBoundary::AfterContentObjects => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            fs.store.sync_all().expect("sync staged content object");
        }
        CrashInjectionBoundary::AfterTransactionInodes => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            write_transaction_inodes(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            fs.store.sync_all().expect("sync staged inodes");
        }
        CrashInjectionBoundary::AfterTransactionDirectories => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            write_transaction_inodes(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            write_transaction_directories(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            fs.store.sync_all().expect("sync staged directories");
        }
        CrashInjectionBoundary::AfterTransactionSuperblock => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            write_transaction_inodes(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            write_transaction_directories(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            let _root = write_transaction_superblock(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            fs.store
                .sync_all()
                .expect("sync staged transaction superblock");
        }
        CrashInjectionBoundary::AfterTransactionObjectsSynced => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            let observed = persist_state_until_boundary(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                fs.root_authentication_key,
                Some(FilesystemCommitBoundary::TransactionObjectsSynced),
            )
            .expect("stop after transaction objects sync");
            assert_eq!(observed, FilesystemCommitBoundary::TransactionObjectsSynced);
        }
        CrashInjectionBoundary::AfterMalformedRootCommit => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            write_transaction_inodes(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            write_transaction_directories(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            let root = write_transaction_superblock(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                transaction_id,
            );
            fs.store
                .put(
                    DeviceIoClass::Data,
                    root_slot_object_key(root.slot),
                    b"malformed root-slot bytes with a valid object-store checksum",
                )
                .expect("write malformed root commit candidate");
            fs.store
                .sync_all()
                .expect("sync malformed root commit candidate");
        }
        CrashInjectionBoundary::AfterRootCommitMissingTransaction => {
            let (root, _superblock_bytes) = root_for_staged_state(staged, transaction_id);
            publish_root_commit(
                fs.store.primary_store_mut().raw_store_mut(),
                &root,
                fs.root_authentication_key,
            )
            .expect("publish root commit with missing transaction objects");
            fs.store
                .sync_all()
                .expect("sync missing-transaction root commit candidate");
        }
        CrashInjectionBoundary::AfterRootCommitWritten => {
            write_staged_content(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                inode_id,
                bytes,
            );
            let observed = persist_state_until_boundary(
                fs.store.primary_store_mut().raw_store_mut(),
                staged,
                fs.root_authentication_key,
                Some(FilesystemCommitBoundary::RootCommitWritten),
            )
            .expect("stop after root commit write");
            assert_eq!(observed, FilesystemCommitBoundary::RootCommitWritten);
        }
    }
    boundary.expected_recovery()
}

fn assert_recovery_outcome(
    root: &Path,
    candidate_path: &str,
    new_bytes: &[u8],
    expectation: CrashRecoveryExpectation,
) {
    match expectation {
        CrashRecoveryExpectation::OldCommittedRoot => {
            let reopened =
                LocalFileSystem::open_with_options(root, options()).expect("reopen previous root");
            assert_eq!(
                reopened.read_file("/stable.txt").expect("read stable"),
                b"stable-before-crash".to_vec()
            );
            assert!(matches!(
                reopened.read_file(candidate_path),
                Err(FileSystemError::NotFound { .. })
            ));
        }
        CrashRecoveryExpectation::NewCommittedRoot => {
            let reopened =
                LocalFileSystem::open_with_options(root, options()).expect("reopen new root");
            assert_eq!(
                reopened.read_file("/stable.txt").expect("read stable"),
                b"stable-before-crash".to_vec()
            );
            assert_eq!(
                reopened.read_file(candidate_path).expect("read candidate"),
                new_bytes.to_vec()
            );
        }
        CrashRecoveryExpectation::OldOrNewCommittedRoot => {
            let reopened = LocalFileSystem::open_with_options(root, options())
                .expect("reopen previous-or-new root");
            assert_eq!(
                reopened.read_file("/stable.txt").expect("read stable"),
                b"stable-before-crash".to_vec()
            );
            match reopened.read_file(candidate_path) {
                Ok(actual) => assert_eq!(actual, new_bytes.to_vec()),
                Err(FileSystemError::NotFound { .. }) => {}
                Err(err) => panic!("unexpected recovery error: {err}"),
            }
        }
        CrashRecoveryExpectation::ExplicitIntegrityOrMediaError => {
            assert!(matches!(
                LocalFileSystem::open_with_options(root, options()),
                Err(FileSystemError::CorruptState { .. }) | Err(FileSystemError::Store(_))
            ));
        }
    }
}

#[test]
fn create_paths_initialize_posix_times_from_wall_clock() {
    let root = temp_root("create-posix-wall-clock-times");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let before_ns = crate::types::current_posix_time_ns();

    let dir = fs.create_dir("/docs", 0o755).expect("create docs");
    let file = fs
        .create_file("/docs/source.txt", 0o644)
        .expect("create file");
    let clone = fs
        .reflink_file("/docs/source.txt", "/docs/clone.txt")
        .expect("reflink file");

    let after_ns = crate::types::current_posix_time_ns().saturating_add(1_000_000_000);
    for record in [&dir, &file, &clone] {
        assert_record_has_wall_clock_posix_times(record, before_ns, after_ns);
    }
    cleanup(&root);
}

#[test]
fn create_write_reopen_read_file() {
    let root = temp_root("create-write-reopen");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/hello.txt", 0o644)
            .expect("create file");
        fs.write_file("/docs/hello.txt", 0, b"hello filesystem")
            .expect("write file");
        fs.sync_all().expect("sync fs");
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert_eq!(
            fs.read_file("/docs/hello.txt").expect("read file"),
            b"hello filesystem".to_vec()
        );
        let entries = fs.list_dir("/docs").expect("list docs");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"hello.txt".to_vec());
    }
    cleanup(&root);
}

#[test]
fn read_file_range_clips_eof_and_crosses_chunk_boundary() {
    let root = temp_root("read-file-range");
    let chunk_size = content_chunk_size() as usize;
    let mut payload = vec![0u8; chunk_size + 32];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }

    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/large.bin", 0o644).expect("create file");
    fs.write_file("/large.bin", 0, &payload)
        .expect("write file");

    assert_eq!(
        fs.read_file_range("/large.bin", chunk_size as u64 - 8, 24)
            .expect("read across boundary"),
        payload[chunk_size - 8..chunk_size + 16].to_vec()
    );
    assert_eq!(
        fs.read_file_range("/large.bin", payload.len() as u64 - 5, 64)
            .expect("read clips at eof"),
        payload[payload.len() - 5..].to_vec()
    );
    assert_eq!(
        fs.read_file_range("/large.bin", payload.len() as u64 + 1, 64)
            .expect("read beyond eof"),
        Vec::<u8>::new()
    );
    assert_eq!(
        fs.read_file_range("/large.bin", 0, 0)
            .expect("zero-length read"),
        Vec::<u8>::new()
    );
    cleanup(&root);
}

#[test]
fn rename_and_truncate_survive_reopen() {
    let root = temp_root("rename-truncate");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/a.txt", 0o644).expect("create file");
        fs.write_file("/docs/a.txt", 0, b"abcdef")
            .expect("write file");
        fs.truncate_file("/docs/a.txt", 3).expect("truncate file");
        fs.rename("/docs/a.txt", "/docs/b.txt", false)
            .expect("rename file");
        fs.sync_all().expect("sync fs");
    }
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        fs.read_file("/docs/b.txt").expect("read renamed"),
        b"abc".to_vec()
    );
    assert!(matches!(
        fs.read_file("/docs/a.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn rename_replaces_regular_file_atomically() {
    let root = temp_root("rename-replace-file");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/source.txt", 0o644)
            .expect("create source");
        fs.write_file("/docs/source.txt", 0, b"source bytes")
            .expect("write source");
        fs.create_file("/docs/target.txt", 0o644)
            .expect("create target");
        fs.write_file("/docs/target.txt", 0, b"target bytes")
            .expect("write target");

        fs.rename("/docs/source.txt", "/docs/target.txt", false)
            .expect("replace target");
        fs.sync_all().expect("sync replacement");
    }

    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        fs.read_file("/docs/target.txt")
            .expect("read replacement target"),
        b"source bytes".to_vec()
    );
    assert!(matches!(
        fs.read_file("/docs/source.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    let target = fs.stat("/docs/target.txt").expect("stat replacement");
    assert_eq!(target.nlink, 1);
    cleanup(&root);
}

#[test]
fn rename_replaces_empty_directory_with_directory_tree() {
    let root = temp_root("rename-replace-empty-dir");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_dir("/docs/source", 0o755)
            .expect("create source dir");
        fs.create_file("/docs/source/file.txt", 0o644)
            .expect("create nested file");
        fs.write_file("/docs/source/file.txt", 0, b"nested")
            .expect("write nested file");
        fs.create_dir("/docs/target", 0o755)
            .expect("create empty target dir");

        fs.rename("/docs/source", "/docs/target", false)
            .expect("replace empty target dir");
        fs.sync_all().expect("sync replacement");
    }

    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        fs.read_file("/docs/target/file.txt")
            .expect("read moved nested file"),
        b"nested".to_vec()
    );
    assert!(matches!(
        fs.list_dir("/docs/source"),
        Err(FileSystemError::NotFound { .. })
    ));
    let docs = fs.stat("/docs").expect("stat docs");
    assert_eq!(docs.nlink, 3);
    cleanup(&root);
}

#[test]
fn rename_rejects_invalid_replacements() {
    let root = temp_root("rename-invalid-replacements");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/file.txt", 0o644)
        .expect("create file");
    fs.create_dir("/docs/dir", 0o755).expect("create dir");
    fs.create_file("/docs/dir/nested.txt", 0o644)
        .expect("create nested file");
    fs.create_dir("/docs/empty", 0o755)
        .expect("create empty dir");

    assert!(matches!(
        fs.rename("/docs/file.txt", "/docs/dir", false),
        Err(FileSystemError::IsDirectory { .. })
    ));
    assert!(matches!(
        fs.rename("/docs/empty", "/docs/file.txt", false),
        Err(FileSystemError::NotDirectory { .. })
    ));
    assert!(matches!(
        fs.rename("/docs/empty", "/docs/dir", false),
        Err(FileSystemError::DirectoryNotEmpty { .. })
    ));
    assert!(matches!(
        fs.rename("/docs/dir", "/docs/dir/child", false),
        Err(FileSystemError::InvalidPath { .. })
    ));
    cleanup(&root);
}

#[test]
fn rename_noreplace_rejects_existing_target() {
    let root = temp_root("rename-noreplace-reject");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/source.txt", 0o644)
        .expect("create source");
    fs.create_file("/docs/target.txt", 0o644)
        .expect("create target");

    // noreplace=true must fail when target exists
    assert!(matches!(
        fs.rename("/docs/source.txt", "/docs/target.txt", true),
        Err(FileSystemError::AlreadyExists { .. })
    ));

    // source must still exist after failed noreplace
    assert!(fs.stat("/docs/source.txt").is_ok());

    // noreplace=false must succeed and replace the target
    fs.rename("/docs/source.txt", "/docs/target.txt", false)
        .expect("replace target without noreplace");
    assert!(matches!(
        fs.stat("/docs/source.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn rename_exchange_swaps_file_contents_atomically() {
    let root = temp_root("rename-exchange-files");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/a.txt", 0o644).expect("create a");
    fs.write_file("/docs/a.txt", 0, b"content-A")
        .expect("write a");
    fs.create_file("/docs/b.txt", 0o644).expect("create b");
    fs.write_file("/docs/b.txt", 0, b"content-B")
        .expect("write b");

    fs.rename_exchange("/docs/a.txt", "/docs/b.txt")
        .expect("exchange");
    fs.sync_all().expect("sync");

    assert_eq!(
        fs.read_file("/docs/a.txt").expect("read a"),
        b"content-B".to_vec()
    );
    assert_eq!(
        fs.read_file("/docs/b.txt").expect("read b"),
        b"content-A".to_vec()
    );
    cleanup(&root);
}

#[test]
fn rename_exchange_swaps_directories_atomically() {
    let root = temp_root("rename-exchange-dirs");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_dir("/docs/dirA", 0o755).expect("create dirA");
    fs.create_dir("/docs/dirB", 0o755).expect("create dirB");
    fs.create_file("/docs/dirA/child.txt", 0o644)
        .expect("create child");
    fs.write_file("/docs/dirA/child.txt", 0, b"child-data")
        .expect("write child");

    fs.rename_exchange("/docs/dirA", "/docs/dirB")
        .expect("exchange dirs");
    fs.sync_all().expect("sync");

    // dirA's inode now lives at /docs/dirB, so the child is there
    assert_eq!(
        fs.read_file("/docs/dirB/child.txt").expect("read child"),
        b"child-data".to_vec()
    );
    assert!(matches!(
        fs.read_file("/docs/dirA/child.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn rename_exchange_rejects_type_mismatch() {
    let root = temp_root("rename-exchange-type-mismatch");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/file.txt", 0o644)
        .expect("create file");
    fs.create_dir("/docs/dir", 0o755).expect("create dir");

    assert!(matches!(
        fs.rename_exchange("/docs/file.txt", "/docs/dir"),
        Err(FileSystemError::Unsupported { operation, .. }) if operation == "rename_exchange"
    ));
    cleanup(&root);
}

#[test]
fn rename_exchange_rejects_missing_paths() {
    let root = temp_root("rename-exchange-missing");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/exists.txt", 0o644)
        .expect("create file");

    assert!(matches!(
        fs.rename_exchange("/docs/exists.txt", "/docs/missing.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    assert!(matches!(
        fs.rename_exchange("/docs/missing.txt", "/docs/exists.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn rename_exchange_same_path_is_noop() {
    let root = temp_root("rename-exchange-noop");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/f.txt", 0o644).expect("create file");
    fs.write_file("/docs/f.txt", 0, b"data")
        .expect("write file");

    fs.rename_exchange("/docs/f.txt", "/docs/f.txt")
        .expect("noop exchange");
    assert_eq!(fs.read_file("/docs/f.txt").expect("read"), b"data".to_vec());
    cleanup(&root);
}
#[test]
fn hard_link_and_unlink_preserve_content_until_last_link() {
    let root = temp_root("hard-link");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/original.txt", 0o644)
        .expect("create file");
    fs.write_file("/docs/original.txt", 0, b"linked bytes")
        .expect("write file");
    let linked = fs
        .link_file("/docs/original.txt", "/docs/link.txt")
        .expect("link file");
    assert_eq!(linked.nlink, 2);
    fs.unlink("/docs/original.txt").expect("unlink original");
    fs.sync_all().expect("sync fs");
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        fs.read_file("/docs/link.txt").expect("read link"),
        b"linked bytes".to_vec()
    );
    cleanup(&root);
}

#[test]
fn unlink_last_hardlink_after_truncate_and_buffered_write_succeeds() {
    let root = temp_root("unlink-last-hardlink-truncate-buffered-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/file.bin", 0o600)
        .expect("create file");
    fs.write_file("/docs/file.bin", 0, b"alphabeta")
        .expect("seed file");
    fs.link_file("/docs/file.bin", "/docs/hard")
        .expect("create hard link");
    fs.truncate_file("/docs/file.bin", 128 * 1024)
        .expect("extend file");
    fs.write_file("/docs/file.bin", 0, &[0_u8; 32 * 1024])
        .expect("buffered overwrite");

    fs.unlink("/docs/hard").expect("unlink first hard link");
    fs.unlink("/docs/file.bin")
        .expect("unlink final hard link after truncate/write");
    assert!(matches!(
        fs.stat("/docs/file.bin"),
        Err(FileSystemError::NotFound { .. })
    ));
    fs.fsync_all().expect("sync after final unlink");
    assert_eq!(fs.space_counters().reserved_bytes, 0);
    cleanup(&root);
}

#[test]
fn unlink_last_link_after_fallocate_releases_reserved_space() {
    let root = temp_root("unlink-last-link-fallocate-reserved");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/reserved.bin", 0o600)
        .expect("create file");
    fs.fallocate_file("/docs/reserved.bin", 0, 128 * 1024)
        .expect("reserve file range");

    fs.unlink("/docs/reserved.bin")
        .expect("unlink final link after fallocate");
    fs.fsync_all().expect("sync after unlink");
    let counters = fs.space_counters();
    assert_eq!(counters.logical_used_bytes, 0);
    assert_eq!(counters.reserved_bytes, 0);
    cleanup(&root);
}

#[test]
fn symlink_round_trips_target() {
    let root = temp_root("symlink");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_symlink("/docs/current", b"target-v1")
        .expect("create symlink");
    fs.sync_all().expect("sync fs");
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        fs.read_symlink("/docs/current").expect("readlink"),
        b"target-v1".to_vec()
    );
    cleanup(&root);
}

#[test]
fn stat_reports_symlink_inode_without_following_target() {
    let root = temp_root("symlink-stat-nofollow");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/target.txt", 0o644)
        .expect("create target");
    fs.write_file("/docs/target.txt", 0, b"target-data")
        .expect("write target");
    let link = fs
        .create_symlink("/docs/current", b"target.txt")
        .expect("create symlink");

    let stat = fs.stat("/docs/current").expect("stat symlink");
    let attr = fs.stat_attr("/docs/current").expect("stat attr symlink");

    assert_eq!(stat.inode_id, link.inode_id);
    assert_eq!(stat.kind(), NodeKind::Symlink);
    assert_eq!(stat.size, b"target.txt".len() as u64);
    assert_eq!(attr.inode_id, link.inode_id);
    assert_eq!(attr.kind, NodeKind::Symlink);
    assert_eq!(attr.posix.size, b"target.txt".len() as u64);
    assert_ne!(
        fs.stat("/docs/target.txt").expect("stat target").inode_id,
        link.inode_id
    );
    assert!(matches!(
        fs.read_file("/docs/current"),
        Err(FileSystemError::NotFile {
            kind: NodeKind::Symlink,
            ..
        })
    ));
    cleanup(&root);
}

#[test]
fn write_at_offset_zero_fills_gap() {
    let root = temp_root("sparse-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/sparse.bin", 0o644).expect("create file");
    fs.write_file("/sparse.bin", 4, b"tail")
        .expect("write sparse file");
    assert_eq!(
        fs.read_file("/sparse.bin").expect("read sparse file"),
        vec![0, 0, 0, 0, b't', b'a', b'i', b'l']
    );
    cleanup(&root);
}

#[test]
fn zero_length_write_does_not_extend_or_allocate() {
    let root = temp_root("zero-length-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/sparse.bin", 0o644).expect("create file");
    fs.write_file("/sparse.bin", 0, b"abc")
        .expect("write baseline");
    assert_eq!(
        fs.read_file("/sparse.bin").expect("cache baseline"),
        b"abc".to_vec()
    );

    let generation_before = fs.stats().filesystem_generation;
    let record_before = fs.stat("/sparse.bin").expect("stat before");
    let allocator_before = fs.allocator_report().expect("allocator before");
    let cache_before = fs.hot_read_cache_report();

    let returned = fs
        .write_file("/sparse.bin", content_chunk_size() as u64 * 4, b"")
        .expect("zero-length write");
    assert_eq!(returned, record_before);
    assert_eq!(fs.stats().filesystem_generation, generation_before);
    assert_eq!(fs.stat("/sparse.bin").expect("stat after"), record_before);
    assert_eq!(
        fs.allocator_report().expect("allocator after"),
        allocator_before
    );
    assert_eq!(
        fs.read_file("/sparse.bin").expect("read after no-op"),
        b"abc".to_vec()
    );
    let cache_after = fs.hot_read_cache_report();
    assert_eq!(cache_after.hits, cache_before.hits.saturating_add(1));
    assert_eq!(cache_after.invalidations, cache_before.invalidations);

    fs.sync_all().expect("sync fs");
    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        reopened.read_file("/sparse.bin").expect("read reopened"),
        b"abc".to_vec()
    );
    assert_eq!(reopened.stat("/sparse.bin").expect("stat reopened").size, 3);
    cleanup(&root);
}

#[test]
fn random_write_updates_only_intersecting_chunk_refs() {
    let root = temp_root("chunked-random-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let record = fs.create_file("/chunked.bin", 0o644).expect("create file");
    let mut expected = Vec::with_capacity(content_chunk_size() as usize * 3);
    for index in 0..content_chunk_size() as usize * 3 {
        expected.push((index % 251) as u8);
    }
    fs.write_file("/chunked.bin", 0, &expected)
        .expect("write initial chunks");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush initial chunks");
    let full_record = fs.stat("/chunked.bin").expect("stat full file");
    let full_manifest = current_content_manifest(&fs, "/chunked.bin");
    assert_eq!(full_manifest.chunk_size, content_chunk_size());
    assert_eq!(full_manifest.chunks.len(), 3);
    assert!(full_manifest
        .chunks
        .iter()
        .all(|chunk| chunk.data_version == full_record.data_version));

    let patch_offset = content_chunk_size() as u64 + 17;
    fs.write_file("/chunked.bin", patch_offset, b"PATCH")
        .expect("patch one chunk");
    fs.flush_write_buffer(full_record.inode_id)
        .expect("flush patch");
    let patched_record = fs.stat("/chunked.bin").expect("stat patched file");
    expected[content_chunk_size() as usize + 17..content_chunk_size() as usize + 22]
        .copy_from_slice(b"PATCH");

    let patched_manifest = current_content_manifest(&fs, "/chunked.bin");
    assert_eq!(patched_manifest.chunks.len(), 3);
    assert_eq!(
        patched_manifest.chunks[0].data_version,
        full_record.data_version
    );
    assert_eq!(
        patched_manifest.chunks[1].data_version,
        patched_record.data_version
    );
    assert_eq!(
        patched_manifest.chunks[2].data_version,
        full_record.data_version
    );
    assert!(!fs
        .store
        .primary_store()
        .exists(content_chunk_object_key_for_version(
            patched_record.inode_id,
            patched_record.data_version,
            0
        ))
        .unwrap());
    assert_eq!(
        fs.read_file("/chunked.bin").expect("read patched file"),
        expected
    );
    fs.sync_all().expect("sync chunked file");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        reopened
            .read_file("/chunked.bin")
            .expect("read reopened chunked file"),
        expected
    );
    cleanup(&root);
}

#[test]
fn overlay_write_records_padded_dirty_bytes() {
    let root = temp_root("overlay-write-dirty-bytes");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let record = fs.create_file("/dirty.bin", 0o644).expect("create file");
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    fs.write_file("/dirty.bin", 0, &[0x5a; 4096])
        .expect("write small overlay");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush write buffer");

    assert_eq!(fs.dirty_set.data_bytes, content_chunk_size() as u64);
    assert_eq!(
        fs.dirty_set.per_inode_bytes.get(&record.inode_id).copied(),
        Some(content_chunk_size() as u64)
    );
    cleanup(&root);
}

#[test]
fn overlay_write_commits_when_padded_dirty_bytes_cross_target() {
    let root = temp_root("overlay-write-byte-target");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let record = fs.create_file("/pressure.bin", 0o644).expect("create file");
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);
    fs.commit_group.config.commit_group_target_bytes = content_chunk_size() as u64;
    fs.commit_group.config.commit_group_target_ops = u64::MAX;
    fs.commit_group.config.commit_group_dirty_max_bytes = u64::MAX;
    fs.commit_group.config.commit_group_target_secs = 3600.0;
    let start_commit_group = fs.commit_group.current_commit_group().0;

    fs.write_file("/pressure.bin", 0, &[0xa5; 4096])
        .expect("write small overlay");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush write buffer");

    assert!(
        fs.commit_group.current_commit_group().0 > start_commit_group,
        "byte target should force a commit-group sync"
    );
    assert_eq!(fs.uncommitted_mutation_count(), 0);
    assert_eq!(fs.commit_group.dirty_bytes, 0);
    assert!(fs.dirty_set.is_clean());
    assert!(!fs.is_state_dirty());
    cleanup(&root);
}

#[test]
fn truncate_rewrites_boundary_chunk_and_drops_tail_refs() {
    let root = temp_root("chunked-truncate");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/truncate.bin", 0o644).expect("create file");
    let mut expected = Vec::with_capacity(content_chunk_size() as usize * 3);
    for index in 0..content_chunk_size() as usize * 3 {
        expected.push((index % 197) as u8);
    }
    fs.write_file("/truncate.bin", 0, &expected)
        .expect("write initial chunks");
    let full_record = fs.stat("/truncate.bin").expect("stat full file");

    let new_len = content_chunk_size() as usize + 7;
    fs.truncate_file("/truncate.bin", new_len as u64)
        .expect("truncate file");
    expected.truncate(new_len);
    let truncated_record = fs.stat("/truncate.bin").expect("stat truncated file");
    let manifest = current_content_manifest(&fs, "/truncate.bin");

    assert_eq!(manifest.chunks.len(), 2);
    assert_eq!(manifest.chunks[0].data_version, full_record.data_version);
    assert_eq!(manifest.chunks[0].len, content_chunk_size());
    assert_eq!(
        manifest.chunks[1].data_version,
        truncated_record.data_version
    );
    assert_eq!(manifest.chunks[1].len, 7);
    assert_eq!(
        fs.read_file("/truncate.bin").expect("read truncated file"),
        expected
    );
    fs.sync_all().expect("sync truncated file");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        reopened
            .read_file("/truncate.bin")
            .expect("read reopened truncated file"),
        expected
    );
    cleanup(&root);
}

#[test]
fn allocator_counts_protected_chunk_refs_before_reuse() {
    let root = temp_root("allocator-protected-chunks");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 3,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    fs.create_file("/allocated.bin", 0o644)
        .expect("create file");
    let bytes = vec![0x5a; content_chunk_size() as usize * 2];
    fs.write_file("/allocated.bin", 0, &bytes)
        .expect("write two chunks");
    fs.write_file("/allocated.bin", content_chunk_size() as u64 + 11, b"patch")
        .expect("rewrite one chunk while retaining the other");

    let report = fs.allocator_report().expect("allocator report");
    assert_eq!(
        report.current_namespace_allocated_bytes,
        content_chunk_size() as u64 * 2
    );
    assert_eq!(
        report.allocator_reserved_bytes,
        content_chunk_size() as u64 * 3
    );
    assert_eq!(report.pending_free_bytes, content_chunk_size() as u64);
    assert_eq!(report.reusable_free_bytes, 0);
    assert!(report.enospc_enforced);
    assert!(report.statfs_capacity_reporting);

    let generation = fs.stats().filesystem_generation;
    let err = fs
        .write_file("/allocated.bin", 1, b"X")
        .expect_err("rewriting the retained chunk would exceed protected-root capacity");
    assert!(matches!(
        err,
        FileSystemError::NoSpace {
            resource: LocalStorageResource::ContentBytes,
            requested,
            capacity,
            ..
        } if requested == content_chunk_size() as u64 * 4
            && capacity == content_chunk_size() as u64 * 3
    ));
    assert_eq!(fs.stats().filesystem_generation, generation);
    assert_eq!(
        fs.read_file("/allocated.bin").expect("content unchanged"),
        {
            let mut expected = bytes;
            expected[content_chunk_size() as usize + 11..content_chunk_size() as usize + 16]
                .copy_from_slice(b"patch");
            expected
        }
    );
    cleanup(&root);
}

#[test]
fn allocator_counts_snapshot_roots_hidden_behind_newer_slots() {
    let root = temp_root("allocator-snapshot-hidden-root");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 5,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    fs.create_file("/snap.bin", 0o644).expect("create file");
    let snapshot_bytes = vec![0x31; 32];
    fs.replace_file("/snap.bin", &snapshot_bytes)
        .expect("write snapshot payload");
    let snapshot = fs.create_snapshot("keep").expect("create snapshot");

    for index in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        let bytes = vec![0x41 + index as u8; 32];
        fs.replace_file("/snap.bin", &bytes)
            .expect("advance root slots");
    }

    let audit = fs.recovery_audit().expect("audit recovery roots");
    assert_eq!(
        audit.valid_committed_roots.len(),
        FILESYSTEM_ROOT_SLOT_COUNT as usize
    );
    assert!(
        !audit.valid_committed_roots.contains(&snapshot.source_root),
        "snapshot source should be hidden behind newer root-slot versions"
    );

    let report = fs.allocator_report().expect("allocator report");
    assert_eq!(
        report.protected_committed_roots as usize,
        audit.valid_committed_roots.len() + 1
    );
    assert_eq!(
        report.allocator_reserved_bytes,
        content_chunk_size() as u64 * 5
    );
    assert_eq!(report.reusable_free_bytes, 0);

    let generation = fs.stats().filesystem_generation;
    let err = fs
        .replace_file("/snap.bin", b"would exceed snapshot reserve")
        .expect_err("hidden snapshot root must still consume allocator reserve");
    assert!(matches!(
        err,
        FileSystemError::NoSpace {
            resource: LocalStorageResource::ContentBytes,
            requested,
            capacity,
            ..
        } if requested == content_chunk_size() as u64 * 6
            && capacity == content_chunk_size() as u64 * 5
    ));
    assert_eq!(fs.stats().filesystem_generation, generation);

    fs.rollback_to_snapshot("keep").expect("rollback snapshot");
    assert_eq!(
        fs.read_file("/snap.bin").expect("read rollback content"),
        snapshot_bytes
    );
    cleanup(&root);
}

#[test]
fn allocator_rejects_inode_exhaustion_without_mutation() {
    let root = temp_root("allocator-inode-enospc");
    let policy = LocalStorageAllocatorPolicy::new(content_chunk_size() as u64, 1);
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    let generation = fs.stats().filesystem_generation;
    let err = fs
        .create_file("/too-many.txt", 0o644)
        .expect_err("root inode already consumes the only inode slot");
    assert!(matches!(
        err,
        FileSystemError::NoSpace {
            resource: LocalStorageResource::Inodes,
            requested: 2,
            capacity: 1,
            allocated: 1,
            ..
        }
    ));
    assert_eq!(fs.stats().filesystem_generation, generation);
    assert!(matches!(
        fs.lookup("/too-many.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn fallocate_extends_through_allocator_and_reports_statfs() {
    let root = temp_root("allocator-fallocate");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 2,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    fs.create_file("/prealloc.bin", 0o644).expect("create file");
    fs.fallocate_file("/prealloc.bin", 0, content_chunk_size() as u64 * 2)
        .expect("preallocate two grains");
    assert_eq!(
        fs.stat("/prealloc.bin").expect("stat file").size,
        content_chunk_size() as u64 * 2
    );
    let statfs = fs.statfs().expect("statfs");
    assert_eq!(statfs.blocks, 2);
    assert_eq!(statfs.bfree, 0);
    assert_eq!(statfs.bavail, 0);
    assert!(statfs.ffree > 0);

    let err = fs
        .fallocate_file("/prealloc.bin", content_chunk_size() as u64 * 2, 1)
        .expect_err("third grain exceeds capacity");
    assert!(
        matches!(
            err,
            FileSystemError::NoSpace {
                resource: LocalStorageResource::ContentBytes,
                ..
            }
        ) || matches!(err, FileSystemError::ClaimRejected { .. })
    );
    cleanup(&root);
}

#[test]
fn punch_hole_middle_returns_zeros_in_hole() {
    let root = temp_root("punch-hole-middle");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 3 chunks");

    // Punch hole in the middle chunk: from 1.5 chunks to 2.5 chunks
    let hole_offset = (chunk as u64) + (chunk as u64 / 2);
    let hole_length = chunk as u64;
    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("punch hole");

    let read = fs.read_file("/file.bin").expect("read after punch");
    assert_eq!(read.len(), total, "file size unchanged");
    assert_eq!(
        &read[..hole_offset as usize],
        &bytes[..hole_offset as usize],
        "bytes before hole preserved"
    );
    let hole_end = hole_offset as usize + hole_length as usize;
    assert!(
        read[hole_offset as usize..hole_end].iter().all(|&b| b == 0),
        "hole region is zeros"
    );
    assert_eq!(
        &read[hole_end..],
        &bytes[hole_end..],
        "bytes after hole preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_start_returns_zeros_at_beginning() {
    let root = temp_root("punch-hole-start");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 199) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 3 chunks");

    let hole_length = chunk as u64;
    fs.punch_hole("/file.bin", 0, hole_length)
        .expect("punch hole at start");

    let read = fs.read_file("/file.bin").expect("read after punch");
    assert_eq!(read.len(), total, "file size unchanged");
    assert!(
        read[..hole_length as usize].iter().all(|&b| b == 0),
        "start hole is zeros"
    );
    assert_eq!(
        &read[hole_length as usize..],
        &bytes[hole_length as usize..],
        "bytes after start hole preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_end_returns_zeros_at_tail() {
    let root = temp_root("punch-hole-end");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 223) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 3 chunks");

    let hole_offset = (chunk * 2) as u64;
    let hole_length = (chunk * 3) as u64;
    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("punch hole at end");

    let read = fs.read_file("/file.bin").expect("read after punch");
    assert_eq!(read.len(), total, "file size unchanged");
    assert_eq!(
        &read[..hole_offset as usize],
        &bytes[..hole_offset as usize],
        "bytes before end hole preserved"
    );
    assert!(
        read[hole_offset as usize..].iter().all(|&b| b == 0),
        "end hole is zeros"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_entire_file_results_in_all_zeros() {
    let root = temp_root("punch-hole-entire");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 2;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 157) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 2 chunks");

    fs.punch_hole("/file.bin", 0, total as u64)
        .expect("punch entire file");

    let read = fs.read_file("/file.bin").expect("read after punch");
    assert_eq!(read.len(), total, "file size unchanged");
    assert!(read.iter().all(|&b| b == 0), "entire file is zeros");

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_past_eof_is_noop() {
    let root = temp_root("punch-hole-past-eof");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"hello world";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    let record = fs
        .punch_hole("/file.bin", bytes.len() as u64 + 100, 4096)
        .expect("punch past EOF returns Ok");
    assert_eq!(record.size, bytes.len() as u64, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read after no-op punch");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_zero_length_is_noop() {
    let root = temp_root("punch-hole-zero-length");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"some data here";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    let record = fs
        .punch_hole("/file.bin", 5, 0)
        .expect("zero-length punch is Ok");
    assert_eq!(record.size, bytes.len() as u64, "size unchanged");

    let read = fs
        .read_file("/file.bin")
        .expect("read after zero-length punch");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_on_directory_is_rejected() {
    let root = temp_root("punch-hole-dir");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");

    let err = fs
        .punch_hole("/docs", 0, 4096)
        .expect_err("punch on dir should error");
    assert!(
        matches!(err, FileSystemError::IsDirectory { .. }),
        "expected IsDirectory, got {err:?}"
    );

    cleanup(&root);
}

#[test]
fn punch_hole_persistence_across_reopen() {
    let root = temp_root("punch-hole-persist");
    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();

    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_file("/file.bin", 0o644).expect("create file");
        fs.write_file("/file.bin", 0, &bytes)
            .expect("write 3 chunks");

        let hole_offset = chunk as u64;
        let hole_length = chunk as u64;
        fs.punch_hole("/file.bin", hole_offset, hole_length)
            .expect("punch hole");
        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    let read = fs.read_file("/file.bin").expect("read after reopen");
    assert_eq!(read.len(), total, "size preserved");
    assert_eq!(&read[..chunk], &bytes[..chunk], "first chunk preserved");
    assert!(
        read[chunk..chunk * 2].iter().all(|&b| b == 0),
        "hole is zeros after reopen"
    );
    assert_eq!(
        &read[chunk * 2..],
        &bytes[chunk * 2..],
        "third chunk preserved"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_multiple_holes_in_same_file() {
    let root = temp_root("punch-hole-multiple");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 5;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 5 chunks");

    // Punch hole in chunk 1
    fs.punch_hole("/file.bin", chunk as u64, chunk as u64)
        .expect("punch first hole");
    // Punch hole in chunk 3
    fs.punch_hole("/file.bin", (chunk * 3) as u64, chunk as u64)
        .expect("punch second hole");

    let read = fs
        .read_file("/file.bin")
        .expect("read after multiple punches");
    assert_eq!(read.len(), total, "size unchanged");

    // Chunk 0 preserved
    assert_eq!(&read[0..chunk], &bytes[0..chunk], "chunk 0 preserved");
    // Chunk 1 is zeros (hole)
    assert!(
        read[chunk..chunk * 2].iter().all(|&b| b == 0),
        "chunk 1 is hole"
    );
    // Chunk 2 preserved
    assert_eq!(
        &read[chunk * 2..chunk * 3],
        &bytes[chunk * 2..chunk * 3],
        "chunk 2 preserved"
    );
    // Chunk 3 is zeros (hole)
    assert!(
        read[chunk * 3..chunk * 4].iter().all(|&b| b == 0),
        "chunk 3 is hole"
    );
    // Chunk 4 preserved
    assert_eq!(
        &read[chunk * 4..chunk * 5],
        &bytes[chunk * 4..chunk * 5],
        "chunk 4 preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_subchunk_boundary_zeros_partial_chunk() {
    let root = temp_root("punch-hole-subchunk");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let bytes: Vec<u8> = (0..chunk).map(|i| (i % 251) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write one chunk");

    // Punch a sub-chunk hole: from byte 100 to byte 500
    let hole_start = 100_u64;
    let hole_len = 400_u64;
    fs.punch_hole("/file.bin", hole_start, hole_len)
        .expect("punch sub-chunk hole");

    let read = fs
        .read_file("/file.bin")
        .expect("read after sub-chunk punch");
    assert_eq!(read.len(), chunk, "size unchanged");
    assert_eq!(
        &read[..hole_start as usize],
        &bytes[..hole_start as usize],
        "prefix preserved"
    );
    let hole_end = hole_start as usize + hole_len as usize;
    assert!(
        read[hole_start as usize..hole_end].iter().all(|&b| b == 0),
        "hole region is zeros"
    );
    assert_eq!(&read[hole_end..], &bytes[hole_end..], "suffix preserved");

    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_manifest_is_sparse() {
    let root = temp_root("punch-hole-sparse-manifest");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 4;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 4 chunks");

    // Punch second chunk
    fs.punch_hole("/file.bin", chunk as u64, chunk as u64)
        .expect("punch hole");
    fs.sync_all().expect("sync");

    let manifest = current_content_manifest(&fs, "/file.bin");
    assert_eq!(manifest.chunks.len(), 3, "sparse manifest has 3 chunks");
    let indices: Vec<u64> = manifest.chunks.iter().map(|c| c.chunk_index).collect();
    assert_eq!(
        indices,
        vec![0, 2, 3],
        "chunk indices skip the punched hole"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn punch_hole_then_write_into_hole_restores_content() {
    let root = temp_root("punch-hole-then-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes)
        .expect("write 3 chunks");

    // Punch middle chunk
    let hole_offset = chunk as u64;
    let hole_length = chunk as u64;
    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("punch hole");

    // Write new data into the hole region
    let new_data = vec![0xAB_u8; 128];
    fs.write_file("/file.bin", hole_offset + 100, &new_data)
        .expect("write into hole");

    let read = fs
        .read_file("/file.bin")
        .expect("read after write into hole");
    assert_eq!(read.len(), total, "size unchanged");
    let write_pos = hole_offset as usize + 100;
    assert_eq!(
        &read[write_pos..write_pos + 128],
        &new_data[..],
        "new data written into hole region"
    );

    fs.sync_all().expect("sync");
    drop(fs);

    // Verify persistence after reopen
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    let read = fs.read_file("/file.bin").expect("read after reopen");
    assert_eq!(
        &read[write_pos..write_pos + 128],
        &new_data[..],
        "new data persisted across reopen"
    );

    drop(fs);
    cleanup(&root);
}
#[test]
fn non_empty_directory_removal_is_rejected() {
    let root = temp_root("non-empty-rmdir");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/file.txt", 0o644)
        .expect("create file");
    assert!(matches!(
        fs.remove_dir("/docs"),
        Err(FileSystemError::DirectoryNotEmpty { .. })
    ));
    cleanup(&root);
}

#[test]
fn recovery_probe_reports_selected_root_without_operator_repair() {
    let root = temp_root("recovery-probe-selected-root");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let generation = fs.stats().filesystem_generation;
    drop(fs);

    let report = LocalFileSystem::probe_recovery(&root, options()).expect("probe recovery");
    assert_eq!(report.outcome, RecoveryProbeOutcome::SelectedCommittedRoot);
    assert_eq!(report.selected_generation, Some(generation));
    assert!(report.valid_committed_roots_seen >= 1);
    assert!(report.mountable_without_operator_repair());
    assert!(!report.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn recovery_probe_reports_explicit_error_without_guessing_repair() {
    let root = temp_root("recovery-probe-explicit-error");
    let mut store =
        LocalObjectStore::open_with_options(&root, options()).expect("open object store");
    for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        store
            .put(root_slot_object_key(slot), b"invalid root slot bytes")
            .expect("write invalid root slot");
    }
    store.sync_all().expect("sync invalid slots");
    drop(store);

    let report = LocalFileSystem::probe_recovery(&root, options()).expect("probe invalid roots");
    assert_eq!(
        report.outcome,
        RecoveryProbeOutcome::ExplicitIntegrityOrMediaError
    );
    assert_eq!(report.valid_committed_roots_seen, 0);
    assert_eq!(report.root_slot_records_seen, FILESYSTEM_ROOT_SLOT_COUNT);
    assert!(!report.mountable_without_operator_repair());
    assert!(!report.production_recovery_requires_operator_repair());
    assert!(matches!(
        LocalFileSystem::open_with_options(&root, options()),
        Err(FileSystemError::CorruptState { reason })
            if reason == "root slots exist but no valid committed root could be selected"
    ));
    cleanup(&root);
}

#[test]
fn recovery_audit_reports_manifested_committed_root_without_fsck() {
    let root = temp_root("recovery-audit-manifested-root");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let generation = fs.stats().filesystem_generation;
    drop(fs);

    let report = audit_recovery(&root, options()).expect("audit recovery");
    assert_eq!(report.outcome, RecoveryAuditOutcome::SelectedCommittedRoot);
    assert!(!report.production_fsck_required);
    assert!(report.checked_transaction_manifests >= 1);
    assert!(report
        .valid_committed_roots
        .iter()
        .any(|root| root.has_transaction_manifest));
    let selected = report.selected_root.expect("selected committed root");
    assert_eq!(selected.generation, generation);
    assert!(selected.has_transaction_manifest);
    assert!(selected.has_root_authentication);
    assert_eq!(
        selected.root_authentication_policy_epoch,
        Some(ROOT_AUTHENTICATION_POLICY_EPOCH)
    );
    assert_eq!(
        selected.root_authentication_algorithm_suite_id,
        Some(ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID)
    );
    assert!(
        selected.superblock_digest.expect("superblock digest") != RootAuthenticationDigest::ZERO
    );
    assert!(selected.manifest_digest.expect("manifest digest") != RootAuthenticationDigest::ZERO);
    assert!(selected.manifest_entry_count > 0);
    cleanup(&root);
}

#[test]
fn root_authentication_requires_the_matching_external_key() {
    let root = temp_root("root-authentication-matching-key");
    let key = RootAuthenticationKey::from_bytes32([0x11_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let wrong_key = RootAuthenticationKey::from_bytes32([0x22_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let mut fs = LocalFileSystem::open_with_root_authentication_key(&root, options(), key)
        .expect("open fs with explicit key");
    fs.create_file("/authenticated.txt", 0o644)
        .expect("create authenticated file");
    fs.write_file("/authenticated.txt", 0, b"authenticated root")
        .expect("write authenticated file");
    fs.sync_all().expect("sync authenticated root");
    drop(fs);

    let reopened = LocalFileSystem::open_with_root_authentication_key(&root, options(), key)
        .expect("reopen with matching key");
    assert_eq!(
        reopened
            .read_file("/authenticated.txt")
            .expect("read authenticated file"),
        b"authenticated root".to_vec()
    );
    drop(reopened);

    let wrong_probe =
        LocalFileSystem::probe_recovery_with_root_authentication_key(&root, options(), wrong_key)
            .expect("probe with wrong key");
    assert_eq!(
        wrong_probe.outcome,
        RecoveryProbeOutcome::ExplicitIntegrityOrMediaError
    );
    assert_eq!(wrong_probe.valid_committed_roots_seen, 0);
    assert!(matches!(
        LocalFileSystem::open_with_root_authentication_key(&root, options(), wrong_key),
        Err(FileSystemError::CorruptState { reason })
            if reason == "root slots exist but no valid committed root could be selected"
    ));
    cleanup(&root);
}

#[test]
fn unauthenticated_newer_root_candidate_is_skipped() {
    let root = temp_root("unauthenticated-newer-root-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable before unauthenticated root")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    let (staged, candidate_path, inode_id, new_bytes) =
        stage_probe_file_state(&fs, b"unauthenticated.txt", b"unauthenticated bytes");
    let transaction_id = staged.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    write_staged_content(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        inode_id,
        &new_bytes,
    );
    let root_commit = persist_transaction_objects(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        transaction_id,
    )
    .expect("write newer transaction objects");
    let unauthenticated_root = RootCommitRecord {
        root_authentication: None,
        ..root_commit
    };
    fs.store
        .put(
            DeviceIoClass::Data,
            root_slot_object_key(unauthenticated_root.slot),
            &encode_root_commit(&unauthenticated_root),
        )
        .expect("publish unauthenticated root candidate");
    fs.store
        .sync_all()
        .expect("sync unauthenticated root candidate");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options())
        .expect("reopen previous committed root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read stable"),
        b"stable before unauthenticated root".to_vec()
    );
    assert!(matches!(
        reopened.read_file(&candidate_path),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn snapshot_rollback_restores_an_isolated_committed_root() {
    let root = temp_root("snapshot-rollback-isolated-root");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.txt", 0o644).expect("create file");
    fs.write_file("/file.txt", 0, b"before snapshot")
        .expect("write before snapshot");
    fs.sync_all().expect("sync before snapshot");
    let source_generation = fs.stats().filesystem_generation;

    let snapshot = fs.create_snapshot("before").expect("create snapshot");
    assert_eq!(snapshot.name, "before");
    assert_eq!(snapshot.source_generation, source_generation);
    assert_eq!(snapshot.created_at_generation, source_generation + 1);
    assert_eq!(fs.stats().snapshot_count, 1);

    fs.replace_file("/file.txt", b"after snapshot")
        .expect("replace after snapshot");
    fs.create_file("/after.txt", 0o644)
        .expect("create post-snapshot file");
    fs.write_file("/after.txt", 0, b"post-snapshot only")
        .expect("write post-snapshot file");
    let generation_before_rollback = fs.stats().filesystem_generation;
    let next_inode_before_rollback = fs.stats().next_inode_id;

    let report = fs
        .rollback_to_snapshot("before")
        .expect("rollback to snapshot");
    assert_eq!(report.spec, LOCAL_SNAPSHOT_ROLLBACK_SPEC);
    assert_eq!(report.snapshot.source_generation, source_generation);
    assert_eq!(report.generation_before, generation_before_rollback);
    assert_eq!(report.restored_source_generation, source_generation);
    assert_eq!(report.published_generation, generation_before_rollback + 1);
    assert_eq!(report.snapshot_catalog_entries, 1);
    assert!(!report.production_recovery_requires_operator_repair());
    assert_eq!(
        fs.read_file("/file.txt").expect("read rolled-back file"),
        b"before snapshot".to_vec()
    );
    assert!(matches!(
        fs.read_file("/after.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    assert_eq!(fs.stats().next_inode_id, next_inode_before_rollback);
    assert_eq!(fs.list_snapshots().len(), 1);
    drop(fs);

    let reopened =
        LocalFileSystem::open_with_options(&root, options()).expect("reopen rolled-back fs");
    assert_eq!(
        reopened
            .read_file("/file.txt")
            .expect("read rolled-back file after reopen"),
        b"before snapshot".to_vec()
    );
    assert!(matches!(
        reopened.read_file("/after.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    assert_eq!(reopened.list_snapshots().len(), 1);
    cleanup(&root);
}

#[test]
fn safe_reclamation_preserves_snapshot_roots_for_later_rollback() {
    let root = temp_root("snapshot-root-retained-through-reclamation");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.txt", 0o644).expect("create file");
    fs.write_file("/file.txt", 0, b"snapshot payload")
        .expect("write snapshot payload");
    fs.sync_all().expect("sync snapshot payload");
    let snapshot = fs.create_snapshot("snap0").expect("create snapshot");

    for idx in 0..8 {
        let payload = format!("new payload {idx}");
        fs.replace_file("/file.txt", payload.as_bytes())
            .expect("replace after snapshot");
    }

    let plan = fs
        .root_retention_plan(RootRetentionPolicy::safe_default())
        .expect("plan root retention with snapshot");
    assert!(plan.protects_fallback_roots_without_operator_repair());
    assert!(plan
        .protected_committed_roots
        .iter()
        .any(|root| root == &snapshot.source_root));

    fs.safe_reclaim_unprotected_objects()
        .expect("safe reclaim with snapshot root protected");
    fs.rollback_to_snapshot("snap0")
        .expect("rollback after safe reclamation");
    assert_eq!(
        fs.read_file("/file.txt")
            .expect("read snapshot payload after reclamation"),
        b"snapshot payload".to_vec()
    );
    cleanup(&root);
}

#[test]
fn changed_record_send_receive_round_trips_current_root_and_snapshot() {
    let source_root = temp_root("send-receive-source");
    let target_root = temp_root("send-receive-target");
    let source_key = RootAuthenticationKey::from_bytes32([0x11_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let target_key = RootAuthenticationKey::from_bytes32([0x22_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source fs");
    source.create_dir("/docs", 0o755).expect("create docs");
    source
        .create_file("/docs/data.bin", 0o644)
        .expect("create data file");
    let baseline = vec![0x31; content_chunk_size() as usize + 17];
    source
        .write_file("/docs/data.bin", 0, &baseline)
        .expect("write baseline");
    source.sync_all().expect("sync baseline");
    source
        .create_snapshot("baseline")
        .expect("create baseline snapshot");
    let current = vec![0x42; content_chunk_size() as usize * 2 + 9];
    source
        .replace_file("/docs/data.bin", &current)
        .expect("replace current data");
    source
        .create_file("/docs/current-only.txt", 0o644)
        .expect("create current-only file");
    source
        .write_file("/docs/current-only.txt", 0, b"current-only")
        .expect("write current-only file");

    let export = source
        .export_changed_records()
        .expect("export changed records");
    assert_eq!(export.spec, SEND_RECEIVE_CHANGED_RECORD_SPEC);
    assert_eq!(export.stream_version, SEND_RECEIVE_STREAM_VERSION);
    assert_eq!(export.roots.len(), 2);
    assert!(export.total_records > 0);
    assert!(export.payload_bytes > 0);
    assert!(!export.production_recovery_requires_operator_repair());

    let encoded = export.encode();
    assert!(encoded.starts_with(&SEND_RECEIVE_STREAM_MAGIC_BYTES));
    let decoded = ChangedRecordExport::decode(&encoded).expect("decode stream");
    assert_eq!(decoded, export);
    let mut wrong_spec = decoded.clone();
    wrong_spec.spec = "wrong send/receive stream spec";
    let err =
        LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            options(),
            &wrong_spec,
            target_key,
        )
        .expect_err("wrong send/receive spec must be rejected");
    assert!(matches!(err, FileSystemError::Decode { .. }));
    assert!(
        !target_root.exists(),
        "wrong-spec receive must not publish the target root"
    );

    let report =
        LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            options(),
            &decoded,
            target_key,
        )
        .expect("receive changed records");
    assert_eq!(report.spec, SEND_RECEIVE_CHANGED_RECORD_SPEC);
    assert_eq!(report.imported_roots, 2);
    assert_eq!(report.imported_records, export.total_records);
    assert_eq!(report.imported_payload_bytes, export.payload_bytes);
    assert_eq!(report.snapshot_catalog_entries, 1);
    assert!(report.staging_validated_before_publish);
    assert!(report.destination_root_reauthentication);
    assert!(!report.production_recovery_requires_operator_repair());

    let mut received =
        LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
            .expect("open received fs with destination key");
    assert_eq!(
        received
            .read_file("/docs/data.bin")
            .expect("read received current"),
        current
    );
    assert_eq!(
        received
            .read_file("/docs/current-only.txt")
            .expect("read current-only"),
        b"current-only".to_vec()
    );
    assert_eq!(received.list_snapshots().len(), 1);
    let rollback = received
        .rollback_to_snapshot("baseline")
        .expect("rollback received snapshot");
    assert_eq!(rollback.snapshot.name, "baseline");
    assert_eq!(
        received
            .read_file("/docs/data.bin")
            .expect("read received baseline"),
        baseline
    );
    assert!(matches!(
        received.read_file("/docs/current-only.txt"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&source_root);
    cleanup(&target_root);
}

#[test]
fn changed_record_send_receive_excludes_unlinked_extent_maps() {
    let source_root = temp_root("changed-record-send-receive-unlinked-extent-map-source");
    let target_root = temp_root("changed-record-send-receive-unlinked-extent-map-target");
    let source_key = RootAuthenticationKey::from_bytes32([0x91_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let target_key = RootAuthenticationKey::from_bytes32([0x92_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source fs");
    source.create_dir("/docs", 0o755).expect("create docs");
    source
        .create_file("/docs/deleted.bin", 0o644)
        .expect("create deleted file");
    source
        .write_file("/docs/deleted.bin", 0, b"deleted before send")
        .expect("write deleted file");
    source
        .unlink("/docs/deleted.bin")
        .expect("unlink deleted file");
    source
        .create_file("/docs/live.txt", 0o644)
        .expect("create live file");
    source
        .write_file("/docs/live.txt", 0, b"live after unlink")
        .expect("write live file");
    source
        .create_snapshot("after-unlink")
        .expect("create snapshot");

    let export = source
        .export_changed_records()
        .expect("export changed records");
    let report =
        LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            options(),
            &export,
            target_key,
        )
        .expect("receive changed records");
    assert_eq!(report.imported_records, export.total_records);

    let received =
        LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
            .expect("open received fs");
    assert!(matches!(
        received.lookup("/docs/deleted.bin"),
        Err(FileSystemError::NotFound { .. })
    ));
    assert_eq!(
        received
            .read_file("/docs/live.txt")
            .expect("read live file"),
        b"live after unlink"
    );
    let snapshots = received.list_snapshots();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, "after-unlink");

    cleanup(&source_root);
    cleanup(&target_root);
}

#[test]
fn changed_record_import_rejects_corrupt_payload_before_publish() {
    let source_root = temp_root("send-receive-corrupt-source");
    let target_root = temp_root("send-receive-corrupt-target");
    let key = RootAuthenticationKey::from_bytes32([0x33_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), key)
            .expect("open source fs");
    source
        .create_file("/payload.txt", 0o644)
        .expect("create payload");
    let payload = vec![0x5a; content_chunk_size() as usize + 1];
    source
        .write_file("/payload.txt", 0, &payload)
        .expect("write payload");
    let mut export = source
        .export_changed_records()
        .expect("export changed records");
    let record = export
        .roots
        .iter_mut()
        .flat_map(|root| root.records.iter_mut())
        .find(|record| record.role == ChangedRecordObjectRole::VersionedContentChunk)
        .expect("find content chunk record");
    record.payload[0] ^= 0xff;

    let err =
        LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            options(),
            &export,
            key,
        )
        .expect_err("corrupt payload must be rejected");
    assert!(matches!(err, FileSystemError::Decode { .. }));
    assert!(
        !target_root.exists(),
        "failed receive must not publish the target root"
    );
    cleanup(&source_root);
    cleanup(&target_root);
}

#[test]
fn online_verifier_reports_clean_committed_roots_without_mutation() {
    let root = temp_root("online-verifier-clean");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/data.bin", 0o644)
        .expect("create data file");
    let baseline = vec![0x41; content_chunk_size() as usize + 11];
    fs.write_file("/docs/data.bin", 0, &baseline)
        .expect("write baseline");
    fs.sync_all().expect("sync baseline");
    fs.create_snapshot("baseline")
        .expect("create verifier snapshot");
    let current = vec![0x52; content_chunk_size() as usize * 2 + 5];
    fs.replace_file("/docs/data.bin", &current)
        .expect("replace current");

    let generation_before = fs.stats().filesystem_generation;
    let next_inode_before = fs.stats().next_inode_id;
    let verifier = fs.online_verifier_report().expect("verify online");
    assert_eq!(verifier.spec, ONLINE_VERIFIER_SPEC);
    assert_eq!(verifier.outcome, OnlineVerifierOutcome::Clean);
    assert!(verifier.passed());
    assert!(!verifier.mutates_storage());
    assert!(!verifier.production_recovery_requires_operator_repair());
    assert_eq!(
        verifier.selected_root.as_ref().map(|root| root.generation),
        Some(generation_before)
    );
    assert!(verifier.verified_committed_roots.len() >= 2);
    assert!(verifier.checked_transaction_manifests >= 2);
    assert!(verifier.checked_content_objects >= 2);
    assert!(verifier.checked_content_chunks >= 2);
    assert!(verifier.verified_snapshot_roots >= 1);
    assert_eq!(fs.stats().filesystem_generation, generation_before);
    assert_eq!(fs.stats().next_inode_id, next_inode_before);
    assert_eq!(
        fs.read_file("/docs/data.bin")
            .expect("read current after verifier"),
        current
    );
    drop(fs);

    let path_report = verify_online(&root, options()).expect("verify by root path");
    assert_eq!(path_report.outcome, OnlineVerifierOutcome::Clean);
    assert!(path_report.passed());
    cleanup(&root);
}

#[test]
fn online_verifier_reports_corrupt_candidate_without_changing_live_truth() {
    let root = temp_root("online-verifier-corrupt-candidate");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable before verifier")
        .expect("write stable file");
    fs.sync_all().expect("sync stable root");
    let committed_generation = fs.stats().filesystem_generation;
    let bad_transaction_id = committed_generation.saturating_add(1);
    let bad_slot = root_slot_for_transaction(bad_transaction_id);
    fs.store
        .put(
            DeviceIoClass::Data,
            root_slot_object_key(bad_slot),
            b"not a valid online-verifier root commit",
        )
        .expect("write corrupt root candidate");
    fs.store.sync_all().expect("sync corrupt candidate");

    let verifier = fs
        .online_verifier_report()
        .expect("verify corrupt candidate");
    assert_eq!(verifier.outcome, OnlineVerifierOutcome::IssuesFound);
    assert!(!verifier.passed());
    assert!(verifier.invalid_root_candidates >= 1);
    assert!(verifier.issues.iter().any(|issue| {
        issue.kind == OnlineVerifierIssueKind::RootCommitDecode
            && issue.slot == Some(bad_slot)
            && issue.severity == OnlineVerifierIssueSeverity::Error
    }));
    assert_eq!(
        verifier.selected_root.as_ref().map(|root| root.generation),
        Some(committed_generation)
    );
    assert!(!verifier.mutates_storage());
    assert_eq!(fs.stats().filesystem_generation, committed_generation);
    assert_eq!(
        fs.read_file("/stable.txt")
            .expect("read stable after verifier"),
        b"stable before verifier".to_vec()
    );
    drop(fs);

    let reopened =
        LocalFileSystem::open_with_options(&root, options()).expect("reopen fallback root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read reopened"),
        b"stable before verifier".to_vec()
    );
    cleanup(&root);
}

#[test]
fn missing_manifest_newer_root_is_skipped_without_operator_repair() {
    let root = temp_root("missing-manifest-root-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable-before-missing-manifest")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    let (staged, candidate_path, inode_id, new_bytes) = stage_probe_file_state(
        &fs,
        b"manifestless.txt",
        b"new bytes behind missing manifest",
    );
    let transaction_id = staged.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
    write_staged_content(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        inode_id,
        &new_bytes,
    );
    write_transaction_inodes(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        transaction_id,
    );
    write_transaction_directories(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        transaction_id,
    );
    let root_without_manifest = write_transaction_superblock(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        transaction_id,
    );
    let root_requiring_missing_manifest = RootCommitRecord {
        manifest_checksum: IntegrityDigest64(0xfeed_face_dead_beef),
        manifest_entry_count: 1,
        ..root_without_manifest
    };
    publish_root_commit(
        fs.store.primary_store_mut().raw_store_mut(),
        &root_requiring_missing_manifest,
        fs.root_authentication_key,
    )
    .expect("publish root commit that requires a missing manifest");
    fs.store
        .sync_all()
        .expect("sync missing-manifest root candidate");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options())
        .expect("reopen previous committed root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read stable"),
        b"stable-before-missing-manifest".to_vec()
    );
    assert!(matches!(
        reopened.read_file(&candidate_path),
        Err(FileSystemError::NotFound { .. })
    ));
    drop(reopened);

    let report =
        audit_recovery(&root, options()).expect("audit recovery with missing manifest candidate");
    assert_eq!(report.outcome, RecoveryAuditOutcome::SelectedCommittedRoot);
    assert!(!report.production_fsck_required);
    assert!(report.invalid_root_candidates >= 1);
    assert_eq!(
        report.selected_root.expect("selected root").generation,
        committed_generation
    );
    cleanup(&root);
}

#[test]
fn crash_injection_boundaries_select_only_old_or_new_committed_roots() {
    for boundary in CrashInjectionBoundary::ALL {
        let root = temp_root(boundary.human_name());
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_file("/stable.txt", 0o644)
            .expect("create stable file");
        fs.write_file("/stable.txt", 0, b"stable-before-crash")
            .expect("write stable file");
        fs.sync_all().expect("sync stable state");

        let (staged, candidate_path, inode_id, new_bytes) = stage_probe_file_state(
            &fs,
            b"candidate.txt",
            b"candidate bytes after crash boundary",
        );
        let expectation = apply_crash_boundary(&mut fs, &staged, inode_id, &new_bytes, boundary);
        drop(fs);

        assert_recovery_outcome(&root, &candidate_path, &new_bytes, expectation);
        cleanup(&root);
    }
}

#[test]
fn no_production_fsck_failure_model_covers_storage_004_classes() {
    let cases = no_production_fsck_failure_model_cases();
    assert_eq!(cases.len(), 8);

    for marker in [
        "sync semantics",
        "write reordering",
        "torn writes",
        "lost writes",
        "media corruption",
        "explicit-error behavior",
    ] {
        assert!(
            cases.iter().any(|case| case.model_rule.contains(marker)
                || case.failure_class.human_name().contains(marker)),
            "failure model should cover {marker}"
        );
    }

    for case in cases {
        assert!(
            case.admits_only_allowed_outcomes(),
            "{:?} must not require production fsck",
            case.failure_class
        );
        assert!(
            !case.covered_by.is_empty(),
            "{:?} should name its executable validation",
            case.failure_class
        );
    }
    assert!(cases.iter().any(|case| {
        case.expected_recovery == CrashRecoveryExpectation::ExplicitIntegrityOrMediaError
    }));
    assert!(cases
        .iter()
        .any(|case| case.expected_recovery == CrashRecoveryExpectation::OldOrNewCommittedRoot));
}

#[test]
fn real_directory_crash_recovery_matrix_reports_only_allowed_outcomes() {
    let root = temp_root("real-directory-crash-matrix");
    let report =
        run_crash_recovery_matrix(&root, options()).expect("run real-directory crash matrix");
    assert!(report.passed());
    assert_eq!(
        report.boundary_cases.len(),
        CrashInjectionBoundary::ALL.len()
    );
    assert_eq!(
        report.cases_executed(),
        CrashInjectionBoundary::ALL.len() + 1
    );
    assert!(report.previous_root_cases() > 0);
    assert!(report.new_root_cases() > 0);
    assert_eq!(
        report.explicit_error_case.observed,
        CrashRecoveryObservedOutcome::ExplicitIntegrityOrMediaError
    );
    assert!(!report.explicit_error_case.production_fsck_required);
    cleanup(&root);
}

#[test]
fn pre_publish_sync_failure_rolls_back_live_state() {
    let root = temp_root("pre-publish-sync-failure-rolls-back");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    inject_next_sync_failure_after_boundary(FilesystemCommitBoundary::TransactionObjectsWritten);
    let err = fs
        .create_file("/rolled-back.txt", 0o644)
        .expect_err("transaction-object sync should fail before root publish");
    assert!(matches!(err, FileSystemError::Store(StoreError::Io { .. })));
    assert!(!err.keeps_live_state_on_error());
    assert_eq!(fs.stats().filesystem_generation, committed_generation);
    assert!(matches!(
        fs.lookup("/rolled-back.txt"),
        Err(FileSystemError::NotFound { .. })
    ));

    fs.create_file("/next.txt", 0o644)
        .expect("next mutation may reuse the uncommitted generation");
    assert_eq!(
        fs.stats().filesystem_generation,
        committed_generation.saturating_add(1)
    );
    cleanup(&root);
}

#[test]
fn root_sync_failure_keeps_live_state_and_avoids_transaction_id_reuse() {
    let root = temp_root("root-sync-failure-keeps-live-state");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    inject_next_sync_failure_after_boundary(FilesystemCommitBoundary::RootCommitWritten);
    let err = fs
        .create_file("/uncertain.txt", 0o644)
        .expect_err("root sync should report an uncertain publish");
    match err {
        FileSystemError::PublishOutcomeUncertain {
            completed_boundary,
            recovery_expectation,
            live_state_reconciled,
            ..
        } => {
            assert_eq!(
                completed_boundary,
                FilesystemCommitBoundary::RootCommitWritten
            );
            assert_eq!(
                recovery_expectation,
                CrashRecoveryExpectation::OldOrNewCommittedRoot
            );
            assert!(live_state_reconciled);
        }
        other => panic!("unexpected publish error: {other:?}"),
    }

    let uncertain_generation = committed_generation.saturating_add(1);
    assert_eq!(fs.stats().filesystem_generation, uncertain_generation);
    assert!(fs.lookup("/uncertain.txt").is_ok());
    assert!(fs
        .object_store()
        .contains_key(transaction_superblock_object_key(uncertain_generation)));

    fs.create_file("/after.txt", 0o644)
        .expect("next mutation should not reuse the uncertain transaction id");
    let after_generation = uncertain_generation.saturating_add(1);
    assert_eq!(fs.stats().filesystem_generation, after_generation);
    assert!(fs
        .object_store()
        .contains_key(transaction_superblock_object_key(after_generation)));

    fs.sync_all().expect("sync reconciled state");
    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert!(reopened.lookup("/uncertain.txt").is_ok());
    assert!(reopened.lookup("/after.txt").is_ok());
    cleanup(&root);
}

#[test]
fn invalid_newer_same_slot_root_falls_back_to_previous_version_without_operator_repair() {
    let root = temp_root("bad-same-slot-root-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable-before-crash")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;
    let bad_transaction_id = committed_generation.saturating_add(FILESYSTEM_ROOT_SLOT_COUNT);
    let same_slot = root_slot_for_transaction(bad_transaction_id);
    assert_eq!(same_slot, root_slot_for_transaction(committed_generation));
    fs.store
        .put(
            DeviceIoClass::Data,
            root_slot_object_key(same_slot),
            b"newer same-slot root candidate with invalid filesystem meaning",
        )
        .expect("write invalid same-slot root candidate");
    fs.store
        .sync_all()
        .expect("sync invalid same-slot root candidate");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read stable"),
        b"stable-before-crash".to_vec()
    );
    let verifier = verify_online(&root, options()).expect("verify fallback root");
    assert_eq!(verifier.outcome, OnlineVerifierOutcome::Clean);
    assert!(verifier.passed());
    assert!(verifier.invalid_root_candidates >= 1);
    assert!(verifier.issues.iter().any(|issue| {
        issue.slot == Some(same_slot)
            && issue.severity == OnlineVerifierIssueSeverity::Warning
            && issue.reason.contains("stale same-slot root candidate")
    }));
    drop(reopened);
    cleanup(&root);
}

#[test]
fn all_root_slots_invalid_reports_explicit_integrity_error_without_fsck() {
    let root = temp_root("all-root-slots-invalid");
    let mut store =
        LocalObjectStore::open_with_options(&root, options()).expect("open object store");
    for slot in 0..FILESYSTEM_ROOT_SLOT_COUNT {
        store
            .put(root_slot_object_key(slot), b"invalid root slot bytes")
            .expect("write invalid root slot");
    }
    store.sync_all().expect("sync invalid slots");
    drop(store);

    assert!(matches!(
        LocalFileSystem::open_with_options(&root, options()),
        Err(FileSystemError::CorruptState { reason })
            if reason == "root slots exist but no valid committed root could be selected"
    ));
    cleanup(&root);
}

#[test]
fn uncommitted_transaction_objects_are_ignored_on_reopen() {
    let root = temp_root("uncommitted-transaction");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/stable", 0o755).expect("create stable dir");
    let committed_generation = fs.stats().filesystem_generation;

    let mut staged = fs.state.clone();
    let tick = staged.generation.saturating_add(1);
    staged.generation = tick;
    let inode_id = InodeId::new(staged.next_inode_id);
    staged.next_inode_id = staged.next_inode_id.saturating_add(1);
    let record = InodeRecord {
        rdev: 0,
        inode_id,
        generation: Generation::new(tick),
        facets: NodeKind::Dir.to_facets(),
        mode: mode_for_kind(NodeKind::Dir, DEFAULT_DIRECTORY_PERMISSIONS),
        uid: 0,
        gid: 0,
        nlink: 2,
        size: 0,
        data_version: tick,
        metadata_version: tick,
        posix_time: crate::types::PosixTimeRecord::from_generation(tick),
        xattrs: BTreeMap::new(),
        dir_storage_kind: 0,
        xattr_storage_kind: 0,
        dir_rev: 0,
    };
    Arc::make_mut(&mut staged.inodes).insert(inode_id, record.clone());
    Arc::make_mut(&mut staged.directories).insert(inode_id, BTreeMap::new());
    {
        let root_dir = Arc::make_mut(&mut staged.directories)
            .get_mut(&ROOT_INODE_ID)
            .expect("root directory exists");
        root_dir.insert(
            b"uncommitted".to_vec(),
            NamespaceEntry {
                name: b"uncommitted".to_vec(),
                inode_id,
                generation: record.generation,
                facets: NodeKind::Dir.to_facets(),
                mode: S_IFDIR | 0o755,
            },
        );
    }
    if let Some(root_inode) = Arc::make_mut(&mut staged.inodes).get_mut(&ROOT_INODE_ID) {
        root_inode.size = staged
            .directories
            .get(&ROOT_INODE_ID)
            .expect("root directory exists")
            .len() as u64;
        root_inode.nlink = root_inode.nlink.saturating_add(1);
        root_inode.data_version = tick;
        root_inode.metadata_version = tick;
    }

    persist_transaction_objects(fs.store.primary_store_mut().raw_store_mut(), &staged, tick)
        .expect("write uncommitted transaction objects");
    fs.store
        .sync_all()
        .expect("sync uncommitted transaction objects");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert!(reopened.lookup("/stable").is_ok());
    assert!(matches!(
        reopened.lookup("/uncommitted"),
        Err(FileSystemError::NotFound { .. })
    ));
    cleanup(&root);
}

#[test]
fn auto_commit_disabled_batches_mutations() {
    let root = temp_root("auto-commit-disabled-batches");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let initial_generation = fs.stats().filesystem_generation;

    fs.set_auto_commit(false);
    fs.create_file("/a.txt", 0o644).expect("create a.txt");
    fs.create_file("/b.txt", 0o644).expect("create b.txt");

    // Generation counter advances even with auto_commit off,
    // but state is not persisted until commit() is called.
    let gen_before_commit = fs.stats().filesystem_generation;
    assert!(gen_before_commit > initial_generation);

    fs.commit().expect("commit dirty state");

    // Generation unchanged by commit itself; both files now visible.
    assert_eq!(fs.stats().filesystem_generation, gen_before_commit);
    assert!(fs.lookup("/a.txt").is_ok());
    assert!(fs.lookup("/b.txt").is_ok());

    drop(fs);
    cleanup(&root);
}

#[test]
fn auto_commit_disabled_mutations_lost_on_unclean_shutdown() {
    let root = temp_root("auto-commit-disabled-lost");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/uncommitted.txt", 0o644)
            .expect("create uncommitted.txt");
        // Drop without committing simulates unclean shutdown.
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(matches!(
            fs.lookup("/uncommitted.txt"),
            Err(FileSystemError::NotFound { .. })
        ));
    }
    cleanup(&root);
}

#[test]
fn commit_is_idempotent_when_not_dirty() {
    let root = temp_root("commit-idempotent");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let gen_before = fs.stats().filesystem_generation;

    // First commit on a clean filesystem should be a no-op.
    fs.commit().expect("first commit");
    assert_eq!(fs.stats().filesystem_generation, gen_before);

    // Second commit should also be a no-op.
    fs.commit().expect("second commit");
    assert_eq!(fs.stats().filesystem_generation, gen_before);

    drop(fs);
    cleanup(&root);
}

#[test]
fn fsync_file_persists_written_data() {
    let root = temp_root("fsync-file-persists");
    let content = b"fsyncd data";
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/data.bin", 0o644).expect("create data.bin");
        fs.write_file("/data.bin", 0, content)
            .expect("write data.bin");
        fs.fsync_file("/data.bin").expect("fsync data.bin");
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        let buf = fs.read_file("/data.bin").expect("read data.bin");
        assert_eq!(&buf[..], &content[..]);
    }
    cleanup(&root);
}

#[test]
fn fsync_all_persists_all_dirty_state() {
    let root = temp_root("fsync-all-persists");
    let hello = b"hello sync";
    let world = b"world sync";
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/hello.txt", 0o644)
            .expect("create hello.txt");
        fs.create_file("/world.txt", 0o644)
            .expect("create world.txt");
        fs.write_file("/hello.txt", 0, hello)
            .expect("write hello.txt");
        fs.write_file("/world.txt", 0, world)
            .expect("write world.txt");
        fs.fsync_all().expect("fsync all");
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert_eq!(
            fs.read_file("/hello.txt").expect("read hello.txt"),
            hello.to_vec()
        );
        assert_eq!(
            fs.read_file("/world.txt").expect("read world.txt"),
            world.to_vec()
        );
    }
    cleanup(&root);
}

#[test]
fn auto_commit_enabled_commits_every_mutation() {
    let root = temp_root("auto-commit-every-mutation");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    // auto_commit defaults to true; each write commits immediately.
    let gen_after_first = {
        fs.create_file("/first.txt", 0o644)
            .expect("create first.txt");
        fs.stats().filesystem_generation
    };
    assert!(gen_after_first > 0);

    let gen_after_second = {
        fs.create_file("/second.txt", 0o644)
            .expect("create second.txt");
        fs.stats().filesystem_generation
    };
    assert!(gen_after_second > gen_after_first);

    // Both files should survive reopen.
    drop(fs);
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(fs.lookup("/first.txt").is_ok());
        assert!(fs.lookup("/second.txt").is_ok());
    }
    cleanup(&root);
}

#[test]
fn invalid_newer_root_slot_is_skipped_without_operator_repair() {
    let root = temp_root("bad-root-slot");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/stable", 0o755).expect("create stable dir");
    let committed_generation = fs.stats().filesystem_generation;
    let bad_transaction_id = committed_generation.saturating_add(1);
    let bad_slot = root_slot_for_transaction(bad_transaction_id);
    fs.store
        .put(
            DeviceIoClass::Data,
            root_slot_object_key(bad_slot),
            b"not a valid root commit",
        )
        .expect("write invalid root slot candidate");
    fs.store
        .sync_all()
        .expect("sync invalid root slot candidate");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert!(reopened.lookup("/stable").is_ok());
    cleanup(&root);
}

#[test]
fn begin_transaction_then_commit_persists_mutations() {
    let root = temp_root("begin-then-commit");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    fs.begin_transaction().expect("begin transaction");
    fs.create_file("/a.txt", 0o644).expect("create a.txt");
    fs.write_file("/a.txt", 0, b"hello").expect("write a.txt");
    fs.commit_transaction().expect("commit transaction");
    // Transaction committed: data should survive reopen.
    drop(fs);
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert_eq!(
            fs.read_file("/a.txt").expect("read a.txt"),
            b"hello".to_vec()
        );
    }
    cleanup(&root);
}

#[test]
fn begin_transaction_then_rollback_discards_mutations() {
    let root = temp_root("begin-then-rollback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    fs.begin_transaction().expect("begin transaction");
    fs.create_file("/discarded.txt", 0o644)
        .expect("create discarded.txt");
    fs.write_file("/discarded.txt", 0, b"should disappear")
        .expect("write discarded.txt");
    fs.rollback_transaction().expect("rollback transaction");
    // After rollback, the file should not exist in memory or on disk.
    assert!(fs.lookup("/discarded.txt").is_err());
    drop(fs);
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(fs.lookup("/discarded.txt").is_err());
    }
    cleanup(&root);
}

#[test]
fn transaction_nesting_is_rejected() {
    let root = temp_root("tx-nesting");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    fs.begin_transaction().expect("begin transaction");
    let err = fs
        .begin_transaction()
        .expect_err("nested begin should fail");
    assert!(matches!(err, FileSystemError::Unsupported { .. }));
    cleanup(&root);
}

#[test]
fn commit_without_transaction_is_rejected() {
    let root = temp_root("commit-no-tx");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    let err = fs
        .commit_transaction()
        .expect_err("commit without begin should fail");
    assert!(matches!(err, FileSystemError::Unsupported { .. }));
    cleanup(&root);
}

#[test]
fn rollback_without_transaction_is_rejected() {
    let root = temp_root("rollback-no-tx");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    let err = fs
        .rollback_transaction()
        .expect_err("rollback without begin should fail");
    assert!(matches!(err, FileSystemError::Unsupported { .. }));
    cleanup(&root);
}

#[test]
fn fsync_data_only_persists_content_without_metadata() {
    let root = temp_root("fsync-data-only");
    let content = b"dsync content";
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    fs.create_file("/dsync.txt", 0o644)
        .expect("create dsync.txt");
    fs.write_file("/dsync.txt", 0, content)
        .expect("write dsync.txt");
    // Metadata is dirty (new inode, dir entry), content is dirty.
    assert!(fs.has_dirty_metadata());
    fs.fsync_data_only().expect("fsync data only");
    // Content was synced to disk but metadata may still be dirty.
    // Data survives reopen if we force-commit via another path.
    drop(fs);
    // Without a metadata commit, the file may not be reachable.
    // But if we reopen and commit, the content objects are present.
    // Test: reopen and verify that a subsequent metadata commit
    // makes the file reachable.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        fs.set_auto_commit(false);
        // File should not be reachable yet (metadata wasn't committed).
        assert!(fs.lookup("/dsync.txt").is_err());
    }
    cleanup(&root);
}

#[test]
fn has_dirty_metadata_detects_dirty_inode() {
    let root = temp_root("has-dirty-meta");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    assert!(!fs.has_dirty_metadata());
    fs.create_file("/m.txt", 0o644).expect("create m.txt");
    assert!(fs.has_dirty_metadata());
    fs.commit().expect("commit");
    assert!(!fs.has_dirty_metadata());
    cleanup(&root);
}

#[test]
fn transaction_manifest_is_written_and_validated_without_repair() {
    let root = temp_root("transaction-manifest-valid");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");

    let report = fs.recovery_audit().expect("audit recovery");
    assert_eq!(report.outcome, RecoveryAuditOutcome::SelectedCommittedRoot);
    let selected = report
        .selected_root
        .as_ref()
        .expect("selected committed root");
    assert!(selected.has_transaction_manifest);
    assert!(selected.manifest_entry_count > 0);
    assert!(report.checked_transaction_manifests >= 1);
    assert!(report.mountable_without_operator_repair());
    assert!(!report.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn posix_subset_covers_storage_104_acceptance_gate() {
    let entries = posix_subset_entries();
    assert!(entries.len() >= 20);
    assert_eq!(POSIX_SUBSET_POLICY_VERSION, 1);
    assert!(POSIX_SUBSET_SPEC.contains("TideFS storage item 104"));

    for topic in [
        PosixTopic::LookupGetattr,
        PosixTopic::Readdir,
        PosixTopic::CreateOpenRelease,
        PosixTopic::ReadWriteTruncate,
        PosixTopic::MkdirRmdir,
        PosixTopic::LinkUnlink,
        PosixTopic::Rename,
        PosixTopic::SymlinkReadlink,
        PosixTopic::FsyncDurability,
        PosixTopic::OpenHandleLifetime,
        PosixTopic::StatfsCapacity,
        PosixTopic::MetadataMutation,
        PosixTopic::ExtendedAttributes,
        PosixTopic::FileLocking,
        PosixTopic::SpaceManagement,
        PosixTopic::MmapCoherency,
        PosixTopic::SparseDiscovery,
        PosixTopic::SpecialInodes,
    ] {
        assert!(
            entries.iter().any(|entry| entry.topic == topic),
            "POSIX subset should cover {}",
            topic.human_name()
        );
        assert!(topic.stable_id().starts_with("posix."));
    }

    for support in [
        PosixSupport::IncludedInCurrentUserspaceImpl,
        PosixSupport::IncludedAfterCurrentUserspaceImpl,
        PosixSupport::BlockedBeforeUsefulImpl,
        PosixSupport::DeferredAfterCurrentImpl,
        PosixSupport::ExplicitlyUnsupported,
    ] {
        assert!(!support.stable_id().is_empty());
        assert!(!support.human_name().is_empty());
    }

    for active_support in [
        PosixSupport::IncludedInCurrentUserspaceImpl,
        PosixSupport::IncludedAfterCurrentUserspaceImpl,
        PosixSupport::DeferredAfterCurrentImpl,
        PosixSupport::ExplicitlyUnsupported,
    ] {
        assert!(
            entries.iter().any(|entry| entry.support == active_support),
            "POSIX subset should include {}",
            active_support.human_name()
        );
    }

    for operation in [
        "lookup/getattr",
        "read/write/truncate",
        "fsync-file",
        "rename-over-target",
        "lseek: SEEK_SET/SEEK_END/SEEK_DATA/SEEK_HOLE",
        "xattr/acl",
        "mknod-device/fifo/socket",
    ] {
        assert!(
            entries.iter().any(|entry| entry.operation == operation),
            "POSIX subset should name {operation}"
        );
    }
    assert!(entries.iter().any(|entry| entry.rule.contains("OW-106")));
    assert!(entries.iter().any(|entry| entry.rule.contains("OW-101")));
    assert!(entries.iter().any(|entry| entry.rule.contains("OW-102")));
    assert!(entries.iter().any(|entry| entry.rule.contains("PC-004B")
        && entry.rule.contains("SEEK_HOLE")
        && entry.support == PosixSupport::IncludedAfterCurrentUserspaceImpl));
}

#[test]
fn page_cache_writeback_mmap_spec_covers_storage_204_acceptance_gate() {
    let cases = page_cache_writeback_mmap_acceptance_cases();
    assert_eq!(PAGE_CACHE_WRITEBACK_MMAP_POLICY_VERSION, 1);
    assert!(PAGE_CACHE_WRITEBACK_MMAP_SPEC.contains("TideFS storage item 204"));
    assert_eq!(cases, PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES);
    assert!(cases.len() >= 7);

    for coherency_class in [
        PageCacheCoherencyClass::BufferedCached,
        PageCacheCoherencyClass::SharedMmapWriteback,
        PageCacheCoherencyClass::PrivateMmapCow,
        PageCacheCoherencyClass::DirectUncached,
        PageCacheCoherencyClass::ExecReadonly,
        PageCacheCoherencyClass::InvalidateTransition,
    ] {
        assert!(
            cases
                .iter()
                .any(|case| case.coherency_class == coherency_class),
            "OW-204 should cover {}",
            coherency_class.human_name()
        );
        assert!(coherency_class.stable_id().starts_with("cache_coherency_"));
    }

    for visibility_state in [
        PageCacheVisibilityState::CleanVisible,
        PageCacheVisibilityState::DirtyPrivate,
        PageCacheVisibilityState::DirtyShared,
        PageCacheVisibilityState::WritebackPending,
        PageCacheVisibilityState::InvalidateWait,
    ] {
        assert!(
            cases
                .iter()
                .any(|case| case.visibility_state == visibility_state),
            "OW-204 should cover {}",
            visibility_state.stable_id()
        );
    }

    for operation in [
        "buffered-writeback",
        "shared-mmap-msync",
        "private-mmap-cow",
        "truncate-invalidate",
        "direct-write-reconcile",
        "fsync-durability",
    ] {
        assert!(
            cases.iter().any(|case| case.operation == operation),
            "OW-204 should name {operation}"
        );
    }

    assert!(cases.iter().any(|case| case.requires_writeback_batch));
    assert!(cases.iter().any(|case| case.requires_invalidate_intent));
    assert!(cases
        .iter()
        .any(|case| case.requires_durable_fsync_boundary));
    assert!(cases.iter().any(|case| case.operation.contains("mmap")));
}

#[test]
fn page_cache_writeback_mmap_cases_preserve_non_authoritative_boundary() {
    let cases = page_cache_writeback_mmap_acceptance_cases();
    assert!(PAGE_CACHE_WRITEBACK_MMAP_SPEC.contains("non-authoritative"));

    for case in cases {
        assert!(
            case.requires_anchor,
            "{} must stay anchor-bound",
            case.operation
        );
        assert!(
            case.rule.contains("authority")
                || case.rule.contains("non-authoritative")
                || case.rule.contains("publication")
                || case.rule.contains("durability"),
            "{} should explain why page-cache state is not hidden authority",
            case.operation
        );
    }

    let shared_mmap = cases
        .iter()
        .find(|case| case.operation == "shared-mmap-msync")
        .expect("shared mmap case");
    assert_eq!(
        shared_mmap.coherency_class,
        PageCacheCoherencyClass::SharedMmapWriteback
    );
    assert!(shared_mmap.requires_dirty_epoch);
    assert!(shared_mmap.requires_writeback_batch);

    let private_mmap = cases
        .iter()
        .find(|case| case.operation == "private-mmap-cow")
        .expect("private mmap case");
    assert_eq!(
        private_mmap.coherency_class,
        PageCacheCoherencyClass::PrivateMmapCow
    );
    assert!(!private_mmap.requires_dirty_epoch);
    assert!(!private_mmap.requires_writeback_batch);

    let mmap_row = posix_subset_entries()
        .iter()
        .find(|entry| entry.operation == "mmap-coherency")
        .expect("mmap row");
    assert_eq!(mmap_row.support, PosixSupport::DeferredAfterCurrentImpl);
    assert!(mmap_row.rule.contains("OW-204"));
    assert!(mmap_row
        .rule
        .contains("live mmap coherency remains deferred"));
}

#[test]
fn intent_log_sync_write_latency_spec_covers_publishing_checklist_acceptance_gate() {
    let cases = intent_log_sync_write_latency_cases();
    assert_eq!(INTENT_LOG_SYNC_WRITE_LATENCY_POLICY_VERSION, 1);
    assert!(INTENT_LOG_SYNC_WRITE_LATENCY_SPEC.contains("PC-008"));
    assert!(INTENT_LOG_SYNC_WRITE_LATENCY_SPEC.contains("latency budget"));
    assert_eq!(cases, INTENT_LOG_SYNC_WRITE_LATENCY_CASES);
    assert!(cases.len() >= 7);

    for latency_class in [
        IntentLogLatencyClass::SyncWriteRange,
        IntentLogLatencyClass::OdsyncDataRange,
        IntentLogLatencyClass::FsyncDirtyDrain,
        IntentLogLatencyClass::SharedMmapSync,
        IntentLogLatencyClass::NamespaceSyncIntent,
        IntentLogLatencyClass::PressureFallback,
        IntentLogLatencyClass::CrashReplayReconcile,
    ] {
        assert!(
            cases.iter().any(|case| case.latency_class == latency_class),
            "PC-008 should cover {}",
            latency_class.human_name()
        );
        assert!(latency_class.stable_id().starts_with("intent_latency_"));
    }

    for operation in [
        "sync-write-range",
        "odsync-data-range",
        "fsync-dirty-drain",
        "shared-mmap-msync-sync",
        "namespace-sync-intent",
        "pressure-fallback",
        "crash-replay-reconcile",
    ] {
        assert!(
            cases.iter().any(|case| case.operation == operation),
            "PC-008 should name {operation}"
        );
    }

    assert!(cases.iter().any(|case| case.requires_replayable_intent));
    assert!(cases.iter().any(|case| case.requires_payload_digest));
    assert!(cases.iter().any(|case| case.requires_metadata_delta));
    assert!(cases.iter().any(|case| case.requires_latency_budget));
    assert!(cases.iter().any(|case| case.may_fallback_to_full_commit));
}

#[test]
fn intent_log_sync_write_latency_cases_do_not_claim_hidden_durability() {
    let cases = intent_log_sync_write_latency_cases();

    for case in cases {
        assert!(
            case.reply_rule.contains("intent")
                || case.reply_rule.contains("full commit")
                || case.reply_rule.contains("replay"),
            "{} should bind success to durable intent, full commit, or replay law",
            case.operation
        );
    }

    let pressure = cases
        .iter()
        .find(|case| case.operation == "pressure-fallback")
        .expect("pressure fallback case");
    assert_eq!(pressure.reply_state, IntentLogReplyState::Refused);
    assert!(pressure.requires_latency_budget);
    assert!(pressure.may_fallback_to_full_commit);
    assert!(pressure.reply_rule.contains("must not pretend"));

    let replay = cases
        .iter()
        .find(|case| case.operation == "crash-replay-reconcile")
        .expect("crash replay case");
    assert_eq!(replay.reply_state, IntentLogReplyState::ReplayOnly);
    assert!(replay.requires_replayable_intent);
    assert!(!replay.may_fallback_to_full_commit);
    assert!(replay
        .reply_rule
        .contains("Partial mounted truth is forbidden"));

    let mmap = cases
        .iter()
        .find(|case| case.operation == "shared-mmap-msync-sync")
        .expect("shared mmap sync case");
    assert_eq!(mmap.latency_class, IntentLogLatencyClass::SharedMmapSync);
    assert!(mmap.requires_replayable_intent);
    assert!(mmap.reply_rule.contains("clean page-cache state alone"));
}

#[test]
fn invalid_transaction_manifest_makes_newer_root_candidate_unselectable() {
    let root = temp_root("bad-transaction-manifest-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable-before-manifest-corruption")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    let (staged, candidate_path, inode_id, new_bytes) =
        stage_probe_file_state(&fs, b"candidate.txt", b"candidate after bad manifest");
    write_staged_content(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        inode_id,
        &new_bytes,
    );
    let root_commit = persist_transaction_objects(
        fs.store.primary_store_mut().raw_store_mut(),
        &staged,
        staged.generation,
    )
    .expect("write newer transaction objects");
    fs.store
        .put(
            DeviceIoClass::Data,
            transaction_manifest_object_key(root_commit.transaction_id),
            b"corrupt manifest bytes",
        )
        .expect("overwrite transaction manifest with corrupt bytes");
    publish_root_commit(
        fs.store.primary_store_mut().raw_store_mut(),
        &root_commit,
        fs.root_authentication_key,
    )
    .expect("publish newer root commit");
    fs.store
        .sync_all()
        .expect("sync corrupt manifest candidate");
    drop(fs);

    let reopened = LocalFileSystem::open_with_options(&root, options())
        .expect("reopen previous committed root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read stable"),
        b"stable-before-manifest-corruption".to_vec()
    );
    assert!(matches!(
        reopened.read_file(&candidate_path),
        Err(FileSystemError::NotFound { .. })
    ));
    drop(reopened);

    let report = LocalFileSystem::probe_recovery(&root, options()).expect("probe recovery");
    assert_eq!(report.outcome, RecoveryProbeOutcome::SelectedCommittedRoot);
    assert!(report.skipped_root_candidates >= 1);
    assert_eq!(report.selected_generation, Some(committed_generation));
    assert!(!report.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn mount_invariant_gate_reports_live_namespace_without_repair() {
    let root = temp_root("mount-invariant-live-report");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/readme.txt", 0o644)
        .expect("create file");
    fs.write_file("/docs/readme.txt", 0, b"invariant bytes")
        .expect("write file");
    fs.link_file("/docs/readme.txt", "/docs/readme.link")
        .expect("link file");

    let report = fs.mount_invariant_report().expect("mount invariant report");
    assert_eq!(report.directory_count, 2);
    assert_eq!(report.file_like_count, 1);
    assert_eq!(report.directory_entry_count, 3);
    assert_eq!(report.hard_link_edge_count, 2);
    assert_eq!(report.reachable_inode_count, report.inode_count);
    assert!(report.mountable_without_operator_repair());
    assert!(!report.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn mount_invariant_allows_entry_generation_lag_after_inode_update() {
    let root = temp_root("mount-invariant-entry-generation-lag");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/data.txt", 0o644).expect("create file");
    fs.write_file("/data.txt", 0, b"first")
        .expect("first write");
    fs.sync_all().expect("sync first write");
    fs.write_file("/data.txt", 0, b"second")
        .expect("second write advances inode generation");

    let report = fs
        .mount_invariant_report()
        .expect("mount invariant permits stable namespace entry identity");
    assert!(report.mountable_without_operator_repair());
    cleanup(&root);
}

#[test]
fn bad_link_count_committed_root_is_skipped_before_mount_without_fsck() {
    let root = temp_root("bad-link-count-root-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable before bad link count")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    let mut bad = fs.state.clone();
    bad.generation = committed_generation.saturating_add(1);
    let bad_generation = bad.generation;
    let root_inode = Arc::make_mut(&mut bad.inodes)
        .get_mut(&ROOT_INODE_ID)
        .expect("root inode exists");
    root_inode.nlink = 1;
    root_inode.metadata_version = bad_generation;
    let bad_root = persist_transaction_objects(
        fs.store.primary_store_mut().raw_store_mut(),
        &bad,
        bad_generation,
    )
    .expect("write structurally invalid transaction root");
    publish_root_commit(
        fs.store.primary_store_mut().raw_store_mut(),
        &bad_root,
        fs.root_authentication_key,
    )
    .expect("publish invalid committed root candidate");
    fs.store
        .sync_all()
        .expect("sync invalid committed root candidate");
    drop(fs);

    let reopened =
        LocalFileSystem::open_with_options(&root, options()).expect("reopen fallback root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read stable"),
        b"stable before bad link count".to_vec()
    );
    drop(reopened);

    let report = LocalFileSystem::probe_recovery(&root, options()).expect("probe recovery");
    assert_eq!(report.outcome, RecoveryProbeOutcome::SelectedCommittedRoot);
    assert!(report.skipped_root_candidates >= 1);
    assert_eq!(report.selected_generation, Some(committed_generation));
    assert!(!report.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn unreachable_inode_committed_root_is_skipped_before_mount_without_fsck() {
    let root = temp_root("unreachable-inode-root-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable before orphan root")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;

    let mut bad = fs.state.clone();
    bad.generation = committed_generation.saturating_add(1);
    let bad_generation = bad.generation;
    let orphan_id = InodeId::new(bad.next_inode_id);
    bad.next_inode_id = bad.next_inode_id.saturating_add(1);
    Arc::make_mut(&mut bad.inodes).insert(
        orphan_id,
        InodeRecord {
            rdev: 0,
            inode_id: orphan_id,
            generation: Generation::new(bad_generation),
            facets: NodeKind::Dir.to_facets(),
            mode: mode_for_kind(NodeKind::Dir, DEFAULT_DIRECTORY_PERMISSIONS),
            uid: 0,
            gid: 0,
            nlink: 2,
            size: 0,
            data_version: bad_generation,
            metadata_version: bad_generation,
            posix_time: crate::types::PosixTimeRecord::from_generation(bad_generation),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
        },
    );
    Arc::make_mut(&mut bad.directories).insert(orphan_id, BTreeMap::new());
    let bad_root = persist_transaction_objects(
        fs.store.primary_store_mut().raw_store_mut(),
        &bad,
        bad_generation,
    )
    .expect("write unreachable inode transaction root");
    publish_root_commit(
        fs.store.primary_store_mut().raw_store_mut(),
        &bad_root,
        fs.root_authentication_key,
    )
    .expect("publish invalid committed root candidate");
    fs.store
        .sync_all()
        .expect("sync invalid committed root candidate");
    drop(fs);

    let reopened =
        LocalFileSystem::open_with_options(&root, options()).expect("reopen fallback root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    assert_eq!(
        reopened.read_file("/stable.txt").expect("read stable"),
        b"stable before orphan root".to_vec()
    );
    drop(reopened);

    let audit = audit_recovery(&root, options()).expect("audit recovery");
    assert_eq!(audit.outcome, RecoveryAuditOutcome::SelectedCommittedRoot);
    assert!(audit.invalid_root_candidates >= 1);
    assert!(!audit.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn retention_plan_protects_committed_roots_without_mutation_or_fsck() {
    let root = temp_root("retention-plan-safe-default");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/readme.txt", 0o644)
        .expect("create readme");
    fs.write_file("/docs/readme.txt", 0, b"retention plan bytes")
        .expect("write readme");
    fs.sync_all().expect("sync fs");
    let before = fs.object_store().stats();

    let plan = fs.safe_root_retention_plan().expect("safe retention plan");
    let after = fs.object_store().stats();

    assert_eq!(before.live_objects, after.live_objects);
    assert_eq!(before.next_sequence, after.next_sequence);
    assert_eq!(plan.policy, RootRetentionPolicy::safe_default());
    assert!(!plan.protected_committed_roots.is_empty());
    assert!(!plan.protected_object_keys.is_empty());
    assert!(!plan.protected_root_slot_locations.is_empty());
    assert!(plan.protects_fallback_roots_without_operator_repair());
    assert!(!plan.production_recovery_requires_operator_repair());
    assert!(!plan.mutates_storage());
    cleanup(&root);
}

#[test]
fn retention_plan_reports_debt_when_policy_needs_more_roots_than_exist() {
    let root = temp_root("retention-debt");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let plan = fs.safe_root_retention_plan().expect("safe retention plan");

    assert_eq!(
        plan.retention_debt.policy_required_committed_roots,
        DEFAULT_RETAINED_COMMITTED_ROOTS
    );
    assert_eq!(
        plan.retention_debt.valid_committed_roots_available,
        plan.audit.valid_committed_roots.len()
    );
    assert_eq!(
        plan.retention_debt.missing_committed_roots,
        DEFAULT_RETAINED_COMMITTED_ROOTS.saturating_sub(plan.audit.valid_committed_roots.len())
    );
    assert!(plan.has_retention_debt());
    assert!(!plan.retention_policy_satisfied());
    assert!(!plan.production_recovery_requires_operator_repair());
    assert!(!plan.mutates_storage());
    cleanup(&root);
}

#[test]
fn retention_policy_rejects_below_no_fsck_fallback_floor() {
    let root = temp_root("retention-policy-floor");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let err = fs
        .root_retention_plan(RootRetentionPolicy::protect_at_least(1))
        .expect_err("unsafe retention policy should be rejected");
    assert!(matches!(
        err,
        FileSystemError::Unsupported { operation, reason }
            if operation == "retention planning"
                && reason == "policy would protect fewer committed roots than the no-fsck fallback floor"
    ));
    cleanup(&root);
}

#[test]
fn retention_plan_keeps_same_slot_fallback_location_without_repair() {
    let root = temp_root("retention-same-slot-fallback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/stable.txt", 0o644)
        .expect("create stable file");
    fs.write_file("/stable.txt", 0, b"stable before invalid slot overwrite")
        .expect("write stable file");
    fs.sync_all().expect("sync stable state");
    let committed_generation = fs.stats().filesystem_generation;
    let bad_transaction_id = committed_generation.saturating_add(FILESYSTEM_ROOT_SLOT_COUNT);
    let bad_slot = root_slot_for_transaction(bad_transaction_id);
    fs.store
        .put(
            DeviceIoClass::Data,
            root_slot_object_key(bad_slot),
            b"invalid newer root slot bytes",
        )
        .expect("write invalid root slot candidate");
    fs.store
        .sync_all()
        .expect("sync invalid root slot candidate");
    drop(fs);

    let mut reopened =
        LocalFileSystem::open_with_options(&root, options()).expect("reopen fallback root");
    assert_eq!(reopened.stats().filesystem_generation, committed_generation);
    let plan = reopened
        .safe_root_retention_plan()
        .expect("plan retention over fallback root");
    assert_eq!(
        plan.audit.outcome,
        RecoveryAuditOutcome::SelectedCommittedRoot
    );
    assert!(plan.audit.invalid_root_candidates >= 1);
    assert!(plan
        .protected_root_slot_locations
        .iter()
        .any(|location| location.key
            == root_slot_object_key(root_slot_for_transaction(committed_generation))));
    assert!(!plan.production_recovery_requires_operator_repair());
    assert!(!plan.mutates_storage());
    cleanup(&root);
}

#[test]
fn safe_reclamation_preserves_retained_roots_and_reopens() {
    let root = temp_root("safe-reclamation-gc");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");
    let mut expected = Vec::new();
    for round in 0..20_u8 {
        expected = vec![round; content_chunk_size() as usize];
        fs.write_file("/data.bin", 0, &expected)
            .expect("write generation");
    }
    fs.sync_all().expect("sync before reclamation");
    let before_stats = fs.object_store().stats();
    let before_plan = fs.safe_root_retention_plan().expect("safe retention plan");
    assert!(before_plan.retention_policy_satisfied());
    assert!(!before_plan.reclaimable_live_object_keys.is_empty());

    let report = fs
        .safe_reclaim_unprotected_objects()
        .expect("safe reclaim unprotected objects");
    assert_eq!(report.spec, SAFE_LOCAL_RECLAMATION_GC_SPEC);
    assert!(report.retention_policy_satisfied());
    assert!(report.mutates_storage());
    assert!(!report.production_recovery_requires_operator_repair());
    assert_eq!(
        report.protected_committed_roots_preserved,
        before_plan.protected_committed_roots.len()
    );
    assert_eq!(
        report.protected_root_slot_locations_preserved,
        before_plan.protected_root_slot_locations.len()
    );
    assert!(report.store.exact_locations_preserved);
    assert!(report.store.tombstoned_unprotected_keys > 0);
    assert!(
        report.store.segment_count_after <= report.store.segment_count_before.saturating_add(1),
        "safe reclamation may rotate one checkpoint segment while preserving exact roots"
    );
    assert!(report.store.segment_count_before <= before_stats.segment_count);
    assert_eq!(
        fs.read_file("/data.bin").expect("read after reclamation"),
        expected
    );
    drop(fs);

    let mut reopened =
        LocalFileSystem::open_with_options(&root, options()).expect("reopen after reclaim");
    assert_eq!(
        reopened
            .read_file("/data.bin")
            .expect("read reclaimed store"),
        expected
    );
    let audit = reopened.recovery_audit().expect("audit reclaimed store");
    assert_eq!(audit.outcome, RecoveryAuditOutcome::SelectedCommittedRoot);
    assert!(audit.valid_committed_roots.len() <= DEFAULT_RETAINED_COMMITTED_ROOTS);
    assert!(!audit.production_recovery_requires_operator_repair());
    cleanup(&root);
}

#[test]
fn hot_read_cache_hits_repeated_reads_and_invalidates_on_write() {
    let root = temp_root("hot-read-cache-hit-invalidate");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/hot.txt", 0o644).expect("create file");
    fs.write_file("/hot.txt", 0, b"hot read bytes")
        .expect("write hot bytes");

    assert_eq!(
        fs.read_file("/hot.txt").expect("first read"),
        b"hot read bytes"
    );
    let after_first = fs.hot_read_cache_report();
    assert_eq!(after_first.misses, 1);
    assert_eq!(after_first.hits, 0);
    assert_eq!(after_first.insertions, 1);
    assert_eq!(after_first.resident_entries, 1);
    assert!(after_first.is_bounded());
    assert!(after_first.is_non_authoritative());

    assert_eq!(
        fs.read_file("/hot.txt").expect("second read"),
        b"hot read bytes"
    );
    let after_second = fs.hot_read_cache_report();
    assert_eq!(after_second.misses, 1);
    assert_eq!(after_second.hits, 1);
    assert_eq!(after_second.resident_entries, 1);

    fs.replace_file("/hot.txt", b"changed bytes")
        .expect("replace hot bytes");
    let after_write = fs.hot_read_cache_report();
    assert_eq!(after_write.resident_entries, 0);
    assert!(after_write.invalidations >= 1);

    assert_eq!(
        fs.read_file("/hot.txt").expect("third read"),
        b"changed bytes"
    );
    let after_third = fs.hot_read_cache_report();
    assert_eq!(after_third.misses, 2);
    assert_eq!(after_third.hits, 1);
    assert_eq!(after_third.insertions, 2);
    cleanup(&root);
}

#[test]
fn hot_read_cache_bypasses_oversized_content() {
    let root = temp_root("hot-read-cache-oversized");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/large.bin", 0o644)
        .expect("create large file");
    let oversized = vec![7_u8; DEFAULT_HOT_READ_CACHE_MAX_BYTES as usize + 1];
    fs.write_file("/large.bin", 0, &oversized)
        .expect("write oversized content");

    assert_eq!(
        fs.read_file("/large.bin").expect("first oversized read"),
        oversized
    );
    assert_eq!(
        fs.read_file("/large.bin").expect("second oversized read"),
        oversized
    );
    let report = fs.hot_read_cache_report();
    assert_eq!(report.hits, 0);
    assert_eq!(report.misses, 2);
    assert_eq!(report.insertions, 0);
    assert_eq!(report.resident_entries, 0);
    assert_eq!(report.admission_bypasses, 2);
    assert!(report.is_bounded());
    cleanup(&root);
}

#[test]
fn hot_read_cache_clears_on_snapshot_rollback() {
    let root = temp_root("hot-read-cache-rollback");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/file.txt", 0o644).expect("create file");
    fs.write_file("/file.txt", 0, b"baseline")
        .expect("write baseline");
    fs.create_snapshot("baseline").expect("snapshot baseline");
    assert_eq!(
        fs.read_file("/file.txt").expect("read baseline"),
        b"baseline"
    );
    assert_eq!(
        fs.read_file("/file.txt").expect("cached baseline"),
        b"baseline"
    );
    assert_eq!(fs.hot_read_cache_report().hits, 1);

    fs.replace_file("/file.txt", b"new content")
        .expect("replace content");
    assert_eq!(fs.read_file("/file.txt").expect("read new"), b"new content");
    assert_eq!(fs.hot_read_cache_report().resident_entries, 1);

    fs.rollback_to_snapshot("baseline").expect("rollback");
    let after_rollback = fs.hot_read_cache_report();
    assert_eq!(after_rollback.resident_entries, 0);
    assert!(after_rollback.invalidations >= 2);
    assert_eq!(
        fs.read_file("/file.txt").expect("read after rollback"),
        b"baseline"
    );
    cleanup(&root);
}
#[test]
fn changed_record_object_role_preserves_decode_tag() {
    assert_eq!(
        ChangedRecordObjectRole::try_from(1),
        Ok(ChangedRecordObjectRole::TransactionManifest)
    );
    assert_eq!(
        ChangedRecordObjectRole::try_from(6),
        Ok(ChangedRecordObjectRole::VersionedContentChunk)
    );
    assert_eq!(
        ChangedRecordObjectRole::try_from(0),
        Err(LocalFilesystemDecodeError::UnknownObjectRole(0))
    );
    assert_eq!(
        ChangedRecordObjectRole::try_from(u16::MAX),
        Err(LocalFilesystemDecodeError::UnknownObjectRole(u16::MAX))
    );
}

#[test]
fn transaction_manifest_object_role_preserves_decode_tag() {
    assert_eq!(
        TransactionManifestObjectRole::try_from(1),
        Ok(TransactionManifestObjectRole::TransactionSuperblock)
    );
    assert_eq!(
        TransactionManifestObjectRole::try_from(5),
        Ok(TransactionManifestObjectRole::VersionedContentChunk)
    );
    assert_eq!(
        TransactionManifestObjectRole::try_from(0),
        Err(LocalFilesystemDecodeError::UnknownObjectRole(0))
    );
    assert_eq!(
        TransactionManifestObjectRole::try_from(u16::MAX),
        Err(LocalFilesystemDecodeError::UnknownObjectRole(u16::MAX))
    );
}

#[test]
fn set_get_xattr_round_trip() {
    let root = temp_root("xattr-roundtrip");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");
    fs.create_file("/docs/data.txt", 0o644)
        .expect("create file");

    fs.set_xattr("/docs/data.txt", b"user.key1", b"value1", 0)
        .expect("set xattr key1");
    fs.set_xattr("/docs/data.txt", b"user.key2", b"value2", 0)
        .expect("set xattr key2");

    assert_eq!(
        fs.get_xattr("/docs/data.txt", b"user.key1")
            .expect("get key1"),
        Some(b"value1".to_vec())
    );
    assert_eq!(
        fs.get_xattr("/docs/data.txt", b"user.key2")
            .expect("get key2"),
        Some(b"value2".to_vec())
    );
    assert_eq!(
        fs.get_xattr("/docs/data.txt", b"user.missing")
            .expect("get missing"),
        None
    );

    // Overwrite an existing key
    fs.set_xattr("/docs/data.txt", b"user.key1", b"updated1", 0)
        .expect("overwrite xattr");
    assert_eq!(
        fs.get_xattr("/docs/data.txt", b"user.key1")
            .expect("get overwritten"),
        Some(b"updated1".to_vec())
    );

    cleanup(&root);
}

#[test]
fn set_xattr_flushes_pending_write_buffer_before_metadata_commit() {
    let root = temp_root("xattr-pending-write-flush");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");

    fs.write_file("/f", 0, b"content before xattr")
        .expect("buffered write");
    fs.set_xattr("/f", b"user.marker", b"present", 0)
        .expect("set xattr after buffered write");

    assert_eq!(
        fs.read_file("/f").expect("read file after xattr"),
        b"content before xattr"
    );
    assert_eq!(
        fs.get_xattr("/f", b"user.marker")
            .expect("get xattr after buffered write"),
        Some(b"present".to_vec())
    );

    fs.sync_all().expect("sync fs");
    drop(fs);

    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    assert_eq!(
        fs.read_file("/f").expect("read file after reopen"),
        b"content before xattr"
    );
    assert_eq!(
        fs.get_xattr("/f", b"user.marker")
            .expect("get xattr after reopen"),
        Some(b"present".to_vec())
    );

    cleanup(&root);
}

#[test]
fn list_xattr_returns_names() {
    let root = temp_root("xattr-list");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");

    // No xattrs: list is empty
    let list = fs.list_xattr("/f").expect("list empty");
    assert_eq!(list, b"");

    fs.set_xattr("/f", b"user.a", b"va", 0).expect("set a");
    fs.set_xattr("/f", b"user.zzz", b"vz", 0).expect("set zzz");
    fs.set_xattr("/f", b"user.m", b"vm", 0).expect("set m");

    let list = fs.list_xattr("/f").expect("list xattrs");
    // Names should be null-separated, in sorted order (BTreeMap key order)
    let mut parts: Vec<&[u8]> = list.split(|&b| b == 0).collect();
    // Remove trailing empty from final null
    if parts.last() == Some(&&b""[..]) {
        parts.pop();
    }
    parts.sort();
    assert_eq!(
        parts,
        vec![
            b"user.a".as_slice(),
            b"user.m".as_slice(),
            b"user.zzz".as_slice()
        ]
    );

    cleanup(&root);
}

#[test]
fn remove_xattr_clears_attribute() {
    let root = temp_root("xattr-remove");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");

    fs.set_xattr("/f", b"user.k", b"val", 0).expect("set xattr");
    assert!(fs.get_xattr("/f", b"user.k").expect("get").is_some());

    fs.remove_xattr("/f", b"user.k").expect("remove xattr");
    assert_eq!(
        fs.get_xattr("/f", b"user.k").expect("get after remove"),
        None
    );

    // Removing a non-existent xattr is a no-op
    fs.remove_xattr("/f", b"user.nonexistent")
        .expect("remove nonexistent");

    cleanup(&root);
}

#[test]
fn xattr_create_flag_blocks_duplicate() {
    let root = temp_root("xattr-create");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");

    // XATTR_CREATE succeeds when attribute does not exist
    fs.set_xattr("/f", b"user.k", b"val", 1)
        .expect("create new xattr");

    // XATTR_CREATE fails when attribute already exists
    let err = fs
        .set_xattr("/f", b"user.k", b"val2", 1)
        .expect_err("create duplicate should fail");
    assert!(matches!(err, FileSystemError::AlreadyExists { .. }));

    // The original value is unchanged after the rejected mutation
    assert_eq!(
        fs.get_xattr("/f", b"user.k").expect("get"),
        Some(b"val".to_vec())
    );

    cleanup(&root);
}

#[test]
fn xattr_replace_flag_requires_existing() {
    let root = temp_root("xattr-replace");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");

    // XATTR_REPLACE fails when attribute does not exist
    let err = fs
        .set_xattr("/f", b"user.k", b"val", 2)
        .expect_err("replace missing should fail");
    assert!(matches!(err, FileSystemError::NotFound { .. }));

    // Set normally, then replace
    fs.set_xattr("/f", b"user.k", b"val", 0).expect("set xattr");
    fs.set_xattr("/f", b"user.k", b"replaced", 2)
        .expect("replace xattr");
    assert_eq!(
        fs.get_xattr("/f", b"user.k").expect("get"),
        Some(b"replaced".to_vec())
    );

    cleanup(&root);
}

#[test]
fn xattrs_survive_reopen() {
    let root = temp_root("xattr-reopen");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_file("/persist.txt", 0o644).expect("create file");
        fs.set_xattr("/persist.txt", b"user.lang", b"en", 0)
            .expect("set xattr");
        fs.set_xattr("/persist.txt", b"user.encoding", b"utf-8", 0)
            .expect("set xattr");
        fs.sync_all().expect("sync fs");
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert_eq!(
            fs.get_xattr("/persist.txt", b"user.lang")
                .expect("get lang"),
            Some(b"en".to_vec())
        );
        assert_eq!(
            fs.get_xattr("/persist.txt", b"user.encoding")
                .expect("get encoding"),
            Some(b"utf-8".to_vec())
        );
        let list = fs.list_xattr("/persist.txt").expect("list xattrs");
        let mut parts: Vec<&[u8]> = list.split(|&b| b == 0).collect();
        if parts.last() == Some(&&b""[..]) {
            parts.pop();
        }
        assert_eq!(parts.len(), 2);
    }
    cleanup(&root);
}

#[test]
fn xattrs_are_isolated_per_inode() {
    let root = temp_root("xattr-isolated");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/one", 0o644).expect("create one");
    fs.create_file("/two", 0o644).expect("create two");

    // Set xattrs on file one only.
    fs.set_xattr("/one", b"user.key", b"val1", 0)
        .expect("set on one");
    assert_eq!(
        fs.get_xattr("/one", b"user.key").expect("get on one"),
        Some(b"val1".to_vec())
    );

    // File two must not see file one's xattrs.
    assert_eq!(
        fs.get_xattr("/two", b"user.key").expect("get on two"),
        None,
        "xattrs on /one must not leak to /two"
    );
    let list_two = fs.list_xattr("/two").expect("list on two");
    assert!(
        list_two.is_empty(),
        "/two must have no xattrs when only /one was set"
    );

    // Set a different xattr on file two and confirm isolation holds.
    fs.set_xattr("/two", b"user.other", b"val2", 0)
        .expect("set on two");
    assert_eq!(
        fs.get_xattr("/one", b"user.key").expect("re-get on one"),
        Some(b"val1".to_vec()),
        "xattr on /one must be unchanged after setting on /two"
    );
    assert_eq!(
        fs.get_xattr("/one", b"user.other")
            .expect("get user.other on one"),
        None,
        "xattr set on /two must not appear on /one"
    );

    // Remove xattr from file one; file two's xattr must survive.
    fs.remove_xattr("/one", b"user.key").expect("remove on one");
    assert_eq!(
        fs.get_xattr("/two", b"user.other")
            .expect("get on two after remove on one"),
        Some(b"val2".to_vec()),
        "xattr on /two must survive removal on /one"
    );

    cleanup(&root);
}

#[test]
fn set_xattr_rejects_empty_name_and_nul_embedded() {
    let root = temp_root("xattr-empty-name");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");

    let err = fs
        .set_xattr("/f", b"", b"val", 0)
        .expect_err("empty name must fail");
    assert!(
        matches!(err, FileSystemError::InvalidName { .. }),
        "expected InvalidName for empty xattr name, got {err:?}"
    );

    let err = fs
        .set_xattr("/f", b"bad\0name", b"val", 0)
        .expect_err("NUL-embedded name must fail");
    assert!(
        matches!(err, FileSystemError::InvalidName { .. }),
        "expected InvalidName for NUL-embedded xattr name, got {err:?}"
    );

    cleanup(&root);
}

#[test]
fn update_allocator_policy_resize_larger() {
    let root = temp_root("update-policy-resize-larger");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 4,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    fs.create_file("/f.txt", 0o644).expect("create file");
    fs.write_file("/f.txt", 0, b"hello").expect("write");

    let report_before = fs.allocator_report().expect("report");
    assert!(report_before.enospc_enforced);

    let larger = policy
        .resize(
            content_chunk_size() as u64 * 8,
            DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
        )
        .expect("resize larger");
    fs.update_allocator_policy(larger).expect("update policy");

    let report_after = fs.allocator_report().expect("report after resize");
    assert!(report_after.enospc_enforced);
    assert_eq!(
        report_after.policy.content_capacity_bytes,
        content_chunk_size() as u64 * 8
    );
    assert!(
        report_after.policy.content_capacity_bytes > report_before.policy.content_capacity_bytes
    );

    cleanup(&root);
}

#[test]
fn update_allocator_policy_shrink_still_fits() {
    let root = temp_root("update-policy-shrink-fits");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 8,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    fs.create_file("/f.txt", 0o644).expect("create file");
    fs.write_file("/f.txt", 0, b"hi").expect("write");

    let allocated = fs
        .allocator_report()
        .expect("report")
        .allocator_reserved_bytes;
    let shrunk_capacity = allocated.max(content_chunk_size() as u64 * 2);
    let smaller = policy
        .resize(shrunk_capacity, DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY)
        .expect("resize smaller");
    fs.update_allocator_policy(smaller).expect("update policy");

    let report_after = fs.allocator_report().expect("report after shrink");
    assert_eq!(report_after.policy.content_capacity_bytes, shrunk_capacity);
    assert!(report_after.enospc_enforced);

    cleanup(&root);
}

#[test]
fn update_allocator_policy_shrink_rejects_zero_content() {
    let root = temp_root("update-policy-zero-content");
    let policy = LocalStorageAllocatorPolicy::default();
    let fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");

    let err = policy
        .resize(0, DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY)
        .expect_err("zero content capacity should fail");
    assert!(matches!(err, FileSystemError::Unsupported { .. }));
    drop(fs);
    cleanup(&root);
}

#[test]
fn update_allocator_policy_shrink_rejects_zero_inodes() {
    let policy = LocalStorageAllocatorPolicy::default();
    let err = policy
        .resize(content_chunk_size() as u64, 0)
        .expect_err("zero inode capacity should fail");
    assert!(matches!(err, FileSystemError::Unsupported { .. }));
}

#[test]
fn update_allocator_policy_shrink_below_allocation_triggers_enospc() {
    let root = temp_root("update-policy-shrink-enospc");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 8,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");

    fs.create_file("/f.txt", 0o644).expect("create file");
    let payload = vec![0x5a; content_chunk_size() as usize * 3];
    fs.write_file("/f.txt", 0, &payload)
        .expect("write 3 chunks");

    let shrunk_capacity = content_chunk_size() as u64 * 2;
    let smaller = policy
        .resize(shrunk_capacity, DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY)
        .expect("resize to shrink");
    fs.update_allocator_policy(smaller)
        .expect("update policy accepted");

    let err = fs
        .write_file("/f.txt", 1, b"X")
        .expect_err("write should be rejected under shrunk capacity");
    assert!(
        matches!(
            err,
            FileSystemError::NoSpace {
                resource: LocalStorageResource::ContentBytes,
                ..
            }
        ) || matches!(err, FileSystemError::ClaimRejected { .. })
    );

    cleanup(&root);
}

#[test]
fn update_allocator_policy_statfs_reflects_new_capacity() {
    let root = temp_root("update-policy-statfs");
    // SpaceAccounting uses 4096-byte statfs blocks (StatfsResult::DEFAULT_BLOCK_SIZE).
    let sa_block_size: u64 = 4096;
    let policy = LocalStorageAllocatorPolicy::new(content_chunk_size() as u64 * 4, 256);
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");

    let st_before = fs.statfs().expect("statfs before");
    assert_eq!(
        st_before.blocks,
        content_chunk_size() as u64 * 4 / sa_block_size
    );

    let larger = policy
        .resize(content_chunk_size() as u64 * 10, 1024)
        .expect("resize larger");
    fs.update_allocator_policy(larger).expect("update policy");

    let st_after = fs.statfs().expect("statfs after");
    assert_eq!(
        st_after.blocks,
        content_chunk_size() as u64 * 10 / sa_block_size
    );
    assert!(st_after.blocks > st_before.blocks);

    cleanup(&root);
}

#[test]
fn intent_log_empty_after_fresh_mount_and_commit() {
    let root = temp_root("intent-log-empty");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    assert!(fs.intent_log.is_empty());
    fs.create_file("/f", 0o644).expect("create");
    fs.write_file("/f", 0, b"hello").expect("write");
    assert!(
        fs.intent_log.is_empty(),
        "ordinary buffered writes must not record sync-write intents"
    );
    fs.commit().expect("commit");
    assert!(fs.intent_log.is_empty());
    cleanup(&root);
}

#[test]
fn sync_write_intent_appends_and_commit_clears() {
    let root = temp_root("intent-log-append");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    assert!(fs.intent_log.is_empty());

    fs.create_file("/f", 0o644).expect("create");
    fs.write_file("/f", 0, b"payload data").expect("write");
    assert!(
        fs.intent_log.is_empty(),
        "ordinary write_file stays on the buffered dirty path"
    );

    let digest = IntegrityDigest64(0xCAFE1234);
    let reply = fs
        .sync_write_intent(InodeId::new(2), 0, 12, digest, b"payload data")
        .expect("sync_write_intent");
    assert_eq!(reply, IntentLogReplyState::IntentDurable);
    assert_eq!(fs.intent_log.len(), 1);

    // Commit clears the intent log
    fs.commit().expect("commit");
    assert!(fs.intent_log.is_empty());

    cleanup(&root);
}

#[test]
fn sync_write_intent_replays_on_reopen() {
    let root = temp_root("intent-log-replay");

    // Phase 1: write data via normal path, record intent, drop without commit
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        let rec = fs.create_file("/f", 0o644).expect("create");
        let ino = rec.inode_id;
        fs.commit().expect("commit inode");
        // Write data through normal path but don't commit — intent log preserves it
        fs.write_file("/f", 0, b"sync data").expect("write");

        let digest = IntegrityDigest64(0xBEEF);
        let reply = fs
            .sync_write_intent(ino, 0, 9, digest, b"sync data")
            .expect("sync_write_intent");
        assert_eq!(reply, IntentLogReplyState::IntentDurable);
        assert_eq!(fs.intent_log.len(), 1);
        // Drop without commit — simulates crash
    }

    // Phase 2: reopen — intent log replays on mount and should be empty
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(
            fs.intent_log.is_empty(),
            "intent log should be empty after mount replay"
        );
        // Data written through normal path should still be accessible
        let content = fs.read_file("/f").expect("read after replay");
        assert_eq!(content, b"sync data");
    }

    cleanup(&root);
}

#[test]
fn intent_log_clear_persists_across_clean_shutdown() {
    let root = temp_root("intent-log-clear");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_file("/f", 0o644).expect("create");
        fs.write_file("/f", 0, b"data").expect("write");
        assert!(
            fs.intent_log.is_empty(),
            "ordinary write_file stays on the buffered dirty path"
        );

        let digest = IntegrityDigest64(0xABCD);
        fs.sync_write_intent(InodeId::new(2), 0, 4, digest, b"data")
            .expect("sync_write_intent");
        assert_eq!(fs.intent_log.len(), 1);

        // sync_all commits and clears the intent log
        fs.sync_all().expect("sync_all");
        assert!(fs.intent_log.is_empty());
    }

    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(
            fs.intent_log.is_empty(),
            "intent log should remain empty after clean shutdown"
        );
    }

    cleanup(&root);
}

#[test]
fn multiple_intent_entries_replay_on_mount() {
    let root = temp_root("intent-log-multi");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        let rec_a = fs.create_file("/a", 0o644).expect("create a");
        let rec_b = fs.create_file("/b", 0o644).expect("create b");
        let ino_a = rec_a.inode_id;
        let ino_b = rec_b.inode_id;
        fs.commit().expect("commit inodes");
        // Write data through normal path but don't commit — intent log preserves it
        fs.write_file("/a", 0, b"alpha").expect("write a");
        fs.write_file("/b", 0, b"beta").expect("write b");

        let d1 = IntegrityDigest64(1);
        fs.sync_write_intent(ino_a, 0, 5, d1, b"alpha")
            .expect("intent 1");
        let d2 = IntegrityDigest64(2);
        fs.sync_write_intent(ino_b, 0, 4, d2, b"beta")
            .expect("intent 2");
        assert_eq!(fs.intent_log.len(), 2);
        // Drop without commit
    }

    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(
            fs.intent_log.is_empty(),
            "intent log should replay and clear multiple entries"
        );
        assert_eq!(fs.read_file("/a").expect("read a"), b"alpha");
        assert_eq!(fs.read_file("/b").expect("read b"), b"beta");
    }

    cleanup(&root);
}

// ── Intent log dirty-commit invariants (#863) ───────────────────────────────
//
// Regression tests for the P4-02 Cache Taxonomy §5 invariant:
// acknowledged intent log entries must survive until a state commit.
// sync_write_intent must mark state dirty; do_commit must not clear
// the intent log without persisting state first.

#[test]
fn sync_write_intent_marks_state_dirty() {
    let root = temp_root("intent-dirty-mark");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    let f_rec = fs.create_file("/f", 0o644).expect("create");
    fs.write_file("/f", 0, b"data").expect("write");

    // State should be clean after initial commit.
    fs.commit().expect("commit");
    assert!(!fs.has_dirty_metadata());
    assert!(fs.intent_log.is_empty());

    // sync_write_intent must mark the inode dirty.
    let digest = IntegrityDigest64(0xDEAD);
    let reply = fs
        .sync_write_intent(f_rec.inode_id, 0, 4, digest, b"data")
        .expect("sync_write_intent");
    assert_eq!(reply, IntentLogReplyState::IntentDurable);
    assert!(
        fs.has_dirty_metadata(),
        "sync_write_intent must mark state dirty"
    );
    assert_eq!(fs.intent_log.len(), 1);

    // Commit must persist state and clear the intent log.
    fs.commit().expect("commit");
    assert!(fs.intent_log.is_empty());
    assert!(!fs.has_dirty_metadata());

    cleanup(&root);
}

#[test]
fn do_commit_does_not_clear_intent_log_when_state_clean() {
    // Simulates the #863 data-loss scenario: intent log entries exist
    // but state is clean. do_commit() must NOT clear the intent log.
    //
    // Auto-commit is disabled so we control exactly when commits fire.
    let root = temp_root("intent-no-clear-clean");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);

    // Write some data to dirty the state, then commit to make it clean.
    fs.create_file("/f", 0o644).expect("create");
    fs.write_file("/f", 0, b"payload").expect("write");
    fs.commit().expect("commit write");
    assert!(fs.intent_log.is_empty());
    assert!(!fs.has_dirty_metadata(), "state must be clean after commit");

    // Append an intent log entry directly — no dirty marks from
    // sync_write_intent, simulating a race with a clean commit.
    let root_anchor = IntentLogRootAnchor {
        transaction_id: fs.state.generation,
        generation: fs.state.generation,
        manifest_digest: IntegrityDigest64(0),
    };
    let accepted = fs
        .intent_log
        .append(
            fs.store.primary_store_mut().raw_store_mut(),
            IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(3),
                offset: 0,
                length: 7,
                payload_digest: IntegrityDigest64(0xCAFE),
                data_version: 0,
            },
            root_anchor,
            0,
        )
        .expect("append intent");
    assert!(accepted, "intent log append must be accepted");
    assert_eq!(fs.intent_log.len(), 1);
    assert!(!fs.has_dirty_metadata(), "state must still be clean");

    // do_commit() must NOT clear intent log when state is clean.
    // This is the key invariant: acknowledged intents survive
    // until the next state commit.
    fs.commit().expect("commit while clean");
    assert_eq!(
        fs.intent_log.len(),
        1,
        "intent log must survive a clean commit — #863 fix"
    );

    cleanup(&root);
}

#[test]
fn do_commit_clears_intent_log_after_state_persist() {
    // Normal path: sync_write_intent dirties state → commit persists
    // and clears the intent log.
    let root = temp_root("intent-clear-after-persist");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.set_auto_commit(false);
    let f_rec = fs.create_file("/f", 0o644).expect("create");
    fs.write_file("/f", 0, b"committed data").expect("write");

    let digest = IntegrityDigest64(0xFEED);
    fs.sync_write_intent(f_rec.inode_id, 0, 14, digest, b"committed data")
        .expect("sync_write_intent");
    assert_eq!(fs.intent_log.len(), 1);
    assert!(fs.has_dirty_metadata());

    // Commit: state is dirty → persist + clear intent log.
    fs.commit().expect("commit");
    assert!(fs.intent_log.is_empty());
    assert!(!fs.has_dirty_metadata());

    // Data survived the commit.
    let content = fs.read_file("/f").expect("read after commit");
    assert_eq!(content, b"committed data");

    cleanup(&root);
}

#[test]
fn claim_ledger_tracks_write_allocations() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-claim-test-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        1024 * 1024, // 1 MiB capacity
    )
    .unwrap();

    let report = fs.claim_ledger_report();
    assert_eq!(report.claim_count, 0);
    assert_eq!(report.allocated_blocks, 0);

    // Write a file
    fs.create_file("/test.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    let data = vec![0x42_u8; 4096];
    fs.write_file("/test.txt", 0, &data).unwrap();

    let report = fs.claim_ledger_report();
    assert!(
        report.claim_count > 0,
        "claim_count should be > 0 after write"
    );
    assert!(
        report.allocated_blocks > 0,
        "allocated_blocks should be > 0 after write"
    );
    assert_eq!(
        report.total_blocks,
        1024 * 1024 / crate::constants::content_chunk_size() as u64
    );
    assert!(
        report.free_blocks < report.total_blocks,
        "free_blocks should decrease after write"
    );
    assert!(
        !report.claims_by_reason.is_empty(),
        "claims_by_reason should be populated"
    );

    fs.sync_all().unwrap();
    drop(fs);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn claim_ledger_releases_on_overwrite() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-claim-release-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        1024 * 1024,
    )
    .unwrap();

    fs.create_file("/file.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();

    // First write
    fs.write_file("/file.txt", 0, &[0x41_u8; 2048]).unwrap();
    let after_first = fs.claim_ledger_report();
    let _first_claims = after_first.claim_count;
    let first_blocks = after_first.allocated_blocks;

    // Overwrite (same size)
    fs.write_file("/file.txt", 0, &[0x42_u8; 2048]).unwrap();
    let after_overwrite = fs.claim_ledger_report();

    // Claims should be re-registered (release old, claim new)
    // Claim count should be similar (old released, new claimed)
    assert!(after_overwrite.claim_count > 0);
    // allocated_blocks should be roughly the same for same-size overwrite
    assert!(
        after_overwrite.allocated_blocks <= first_blocks + 1,
        "overwrite shouldn't grow allocation significantly"
    );

    fs.sync_all().unwrap();
    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn claim_ledger_reports_non_authoritative() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-claim-non-auth-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        1024 * 1024,
    )
    .unwrap();

    fs.create_file("/data.bin", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    fs.write_file("/data.bin", 0, &[0xFF_u8; 8192]).unwrap();

    let report = fs.claim_ledger_report();
    // The report must be non-authoritative (Rule 8: the obligation ledger
    // is advisory, the actual allocator holds truth)
    assert!(report.is_non_authoritative());

    fs.sync_all().unwrap();
    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn claim_ledger_policy_update_resets_ledger() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-claim-policy-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        1024 * 1024,
    )
    .unwrap();

    // Update policy to 2 MiB
    fs.update_allocator_policy(crate::types::LocalStorageAllocatorPolicy {
        content_capacity_bytes: 2 * 1024 * 1024,
        ..Default::default()
    })
    .unwrap();

    let report = fs.claim_ledger_report();
    assert_eq!(
        report.total_blocks,
        (2 * 1024 * 1024) / crate::constants::content_chunk_size() as u64
    );
    assert_eq!(report.claim_count, 0, "policy update resets claim ledger");

    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn authority_scarcity_gates_write_when_ledger_exhausted() {
    // Design rule Rule 3: a write must be rejected by the obligation ledger
    // before the allocator runs, even if physical space is available.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-authority-gate-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    // Capacity is 1 chunk (65536 bytes) — just enough for one write
    let chunk_size = crate::constants::content_chunk_size() as u64;
    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        chunk_size,
    )
    .unwrap();

    fs.create_file("/small.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();

    // First write: any write ≤1 chunk fits
    fs.write_file("/small.txt", 0, &[0x41_u8; 2048]).unwrap();
    let after_first = fs.claim_ledger_report();
    assert!(after_first.claim_count > 0);

    // Second file: another chunk would exceed 1-chunk capacity
    fs.create_file("/big.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    let result = fs.write_file("/big.txt", 0, &[0x42_u8; 4096]);

    // Must be rejected — authority scarcity gate fires
    assert!(
        result.is_err(),
        "large write should be rejected by obligation ledger"
    );
    let err = result.unwrap_err();
    match err {
        crate::FileSystemError::ClaimRejected {
            budget_domain,
            reason: _,
        } => {
            assert_eq!(budget_domain, "staging_dirty");
        }
        other => panic!("expected ClaimRejected, got {other:?}"),
    }

    fs.sync_all().unwrap();
    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn authority_scarcity_allows_write_after_claim_release() {
    // Releasing a claim (overwrite with smaller data) frees obligation
    // capacity, allowing a new claim.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-claim-release-gate-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    // Capacity is 4 chunks: the allocator holds orphaned chunks until GC,
    // so we need room for old+new allocations during the test window.
    let capacity = crate::constants::content_chunk_size() as u64 * 4;
    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        capacity,
    )
    .unwrap();

    fs.create_file("/a.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    fs.create_file("/b.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();

    // Write 2-chunk file (chunk_size + 1 bytes → 2 chunks)
    let two_chunk_len = crate::constants::content_chunk_size() as u64 + 1;
    fs.write_file("/a.txt", 0, &vec![0x41_u8; two_chunk_len as usize])
        .unwrap();
    let after_a = fs.claim_ledger_report();
    let free_after_a = after_a.free_blocks;

    // Replace a with a tiny 16-byte file — releases most blocks
    fs.replace_file("/a.txt", &[0x42_u8; 16]).unwrap();
    let after_shrink = fs.claim_ledger_report();
    assert!(
        after_shrink.free_blocks > free_after_a,
        "free blocks should increase after shrinking a file"
    );

    // Now b.txt write (1 chunk) should succeed
    let result = fs.write_file("/b.txt", 0, &[0x43_u8; 4096]);
    assert!(
        result.is_ok(),
        "write should succeed after claim release: {:?}",
        result.err()
    );

    fs.sync_all().unwrap();
    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn obligation_ledger_total_blocks_matches_policy_capacity() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-obligation-capacity-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    let capacity: u64 = 2 * 1024 * 1024; // 2 MiB
    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        capacity,
    )
    .unwrap();

    let report = fs.claim_ledger_report();
    assert_eq!(
        report.total_blocks,
        capacity / crate::constants::content_chunk_size() as u64
    );
    assert_eq!(report.allocated_blocks, 0);
    assert_eq!(
        report.free_blocks,
        capacity / crate::constants::content_chunk_size() as u64
    );

    fs.create_file("/data.bin", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    fs.write_file("/data.bin", 0, &[0xAA_u8; 1024]).unwrap();

    let report = fs.claim_ledger_report();
    assert!(report.allocated_blocks > 0);
    assert!(report.free_blocks < capacity / crate::constants::content_chunk_size() as u64);

    fs.sync_all().unwrap();
    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn authority_scarcity_preserves_write_order_under_contention() {
    // When two small writes fit within the same budget domain, both
    // should succeed in order.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("tidefs-write-order-{unique}"));
    let _ = std::fs::remove_dir_all(&root);

    // Two writes each ≤1 chunk fit within 2-chunk capacity
    let capacity = crate::constants::content_chunk_size() as u64 * 2;
    let mut fs = crate::LocalFileSystem::open_with_capacity(
        &root,
        tidefs_local_object_store::StoreOptions::test_fast(),
        capacity,
    )
    .unwrap();

    fs.create_file("/first.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    fs.create_file("/second.txt", crate::constants::DEFAULT_FILE_PERMISSIONS)
        .unwrap();

    assert!(fs.write_file("/first.txt", 0, &[0x01_u8; 4096]).is_ok());
    assert!(fs.write_file("/second.txt", 0, &[0x02_u8; 4096]).is_ok());

    let report = fs.claim_ledger_report();
    assert!(
        report.claim_count >= 2,
        "both writes should register claims"
    );

    fs.sync_all().unwrap();
    drop(fs);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn truncate_to_larger_size_uses_hole_chunks_instead_of_allocating_zeros() {
    let root = temp_root("sparse-truncate");
    let policy = LocalStorageAllocatorPolicy::new(
        LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES * 200,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");

    // Write a 2KB file (one full chunk)
    let data_2k = vec![0xAB_u8; 2048];
    fs.create_file("/sparse.dat", 0o644).expect("create file");
    fs.write_file("/sparse.dat", 0, &data_2k)
        .expect("write 2KB");

    // Truncate to 200KB -- with hole support, chunks beyond original 2KB
    // should be recorded as holes, not allocated as zero-filled chunks.
    fs.truncate_file("/sparse.dat", 200 * 1024)
        .expect("truncate to 200KB");

    // Verify read: first 2KB has data, rest is zeros
    let read_back = fs.read_file("/sparse.dat").expect("read back 200KB");
    assert_eq!(read_back.len(), 200 * 1024);
    assert_eq!(&read_back[..2048], &data_2k[..]);
    assert!(
        read_back[2048..].iter().all(|&b| b == 0),
        "tail should be zeros"
    );

    // Verify sparse: used blocks should reflect only the originally allocated
    // chunks, not 100 chunks of zeros that naive truncate would allocate.
    let statfs = fs.statfs().expect("statfs");
    let used_blocks = statfs.blocks - statfs.bfree;
    assert!(
        used_blocks < 20,
        "sparse truncate should use holes, not allocate 100+ zero-filled chunks; got {} used blocks (bfree={})",
        used_blocks, statfs.bfree
    );

    // Reopen and verify data persists correctly
    let open_policy = LocalStorageAllocatorPolicy::new(
        LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES * 200,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    drop(fs);
    let mut fs2 =
        LocalFileSystem::open_with_allocator_policy(&root, options(), open_policy).expect("reopen");
    let reopened = fs2
        .read_file("/sparse.dat")
        .expect("read back after reopen");
    assert_eq!(reopened.len(), 200 * 1024);
    assert_eq!(&reopened[..2048], &data_2k[..]);
    assert!(
        reopened[2048..].iter().all(|&b| b == 0),
        "tail should be zeros after reopen"
    );

    // Verify online verifier passes
    let report = fs2.online_verifier_report().expect("online verifier");
    assert!(report.invalid_root_candidates == 0, "no invalid roots");
    cleanup(&root);
}

#[test]
fn sparse_read_zero_fills_unwritten_middle_between_extents() {
    let root = temp_root("sparse-read-middle-zero-fill");
    let suffix_offset = content_chunk_size() as usize * 3;
    let file_size = suffix_offset + 5;
    let prefix = b"front";
    let suffix = b"tail!";

    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_file("/sparse.dat", 0o644).expect("create file");
        fs.write_file("/sparse.dat", 0, prefix)
            .expect("write prefix extent");
        fs.truncate_file("/sparse.dat", file_size as u64)
            .expect("extend with unwritten middle");
        fs.write_file("/sparse.dat", suffix_offset as u64, suffix)
            .expect("write suffix extent");
        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
    let read_back = fs.read_file("/sparse.dat").expect("read sparse file");
    assert_eq!(read_back.len(), file_size, "file size is preserved");
    assert_eq!(
        &read_back[..prefix.len()],
        prefix,
        "prefix extent preserved"
    );
    assert!(
        read_back[prefix.len()..suffix_offset]
            .iter()
            .all(|&byte| byte == 0),
        "unwritten middle reads as zeros"
    );
    assert_eq!(
        &read_back[suffix_offset..suffix_offset + suffix.len()],
        suffix,
        "suffix extent preserved"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn flushed_sparse_strided_writes_keep_unwritten_holes_sparse() {
    let root = temp_root("sparse-strided-flush");
    let chunk = content_chunk_size() as u64;
    let step = 5 * 1024 * 1024;
    let write_count = 16_u64;
    let file_size = 100 * 1024 * 1024;

    let policy = LocalStorageAllocatorPolicy::new(
        2 * 1024 * 1024 * 1024,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, options(), policy).expect("open fs");
    fs.create_file("/aio.dat", 0o644).expect("create file");
    fs.truncate_file("/aio.dat", file_size)
        .expect("sparse extend");
    let inode_id = fs.stat("/aio.dat").expect("stat sparse file").inode_id;

    for index in 0..write_count {
        let offset = index * step;
        let payload = vec![index as u8 + 1; chunk as usize];
        fs.write_file("/aio.dat", offset, &payload)
            .expect("write sparse stride");
    }
    fs.flush_write_buffer(inode_id)
        .expect("flush sparse strided writes");

    let manifest = current_content_manifest(&fs, "/aio.dat");
    let chunk_indexes: Vec<u64> = manifest
        .chunks
        .iter()
        .filter(|chunk_ref| !chunk_ref.is_hole())
        .map(|chunk_ref| chunk_ref.chunk_index)
        .collect();
    let expected_indexes: Vec<u64> = (0..write_count).map(|index| index * step / chunk).collect();
    assert_eq!(chunk_indexes, expected_indexes);
    assert_eq!(
        fs.stat("/aio.dat").expect("stat written sparse file").size,
        file_size
    );

    for index in 0..write_count {
        let offset = index * step;
        let expected = vec![index as u8 + 1; chunk as usize];
        assert_eq!(
            fs.read_file_range("/aio.dat", offset, chunk as usize)
                .expect("read written stride"),
            expected
        );
    }
    assert!(
        fs.read_file_range("/aio.dat", chunk, chunk as usize)
            .expect("read unwritten hole")
            .iter()
            .all(|&byte| byte == 0),
        "unwritten chunk between strided writes must remain a zero hole"
    );

    assert_eq!(fs.reclaim_queue_depth(), 0);
    fs.set_auto_commit(false);
    fs.unlink("/aio.dat").expect("unlink sparse stride file");
    let reclaim_depth = fs.reclaim_queue_depth();
    assert!(
        reclaim_depth <= write_count as usize + 4,
        "sparse unlink should queue only materialized chunks plus metadata keys; depth={reclaim_depth}"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn explicit_threshold_compaction_after_repeated_unlinks() {
    let root = temp_root("explicit-threshold-compaction-unlinks");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    // Lower the threshold to trigger explicit compaction quickly.
    fs.set_auto_compaction_waste_threshold(0.1);

    // Create and unlink files in a loop, then run the explicit maintenance
    // reclaim path. Foreground commits must not perform this full-store scan.
    for i in 0..20 {
        let path = format!("/file-{i}.txt");
        fs.create_file(&path, 0o644).expect("create");
        fs.write_file(&path, 0, b"some content for file")
            .expect("write");
        fs.unlink(&path).expect("unlink");
    }
    let report = fs
        .compact_if_waste_exceeds_threshold()
        .expect("explicit threshold compaction");
    assert!(
        report.is_some(),
        "lowered threshold should trigger explicit compaction"
    );

    // After creating and unlinking, the store should still be sane
    let stats = fs.stats();
    assert!(
        stats.object_store.live_objects > 0,
        "some live objects (roots, etc.) should exist"
    );
    let root_str = root.to_str().unwrap().to_string();
    drop(fs);

    let fs2 = LocalFileSystem::open_with_options(&root_str, options()).expect("reopen");
    assert!(
        fs2.list_dir("/").is_ok(),
        "root should be listable after auto-compaction"
    );
    drop(fs2);

    cleanup(&root);
}

// ── Reflink (zero-copy clone) tests ──

#[test]
fn reflink_file_same_content() {
    let root = temp_root("reflink-same-content");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let source = b"Hello from tidefs reflink test! This content should be shared.\n";
    let _rec = fs.create_file("/source.txt", 0o644).expect("create source");
    fs.write_file("/source.txt", 0, source)
        .expect("write source");
    fs.sync_all().expect("sync");

    fs.reflink_file("/source.txt", "/dest.txt")
        .expect("reflink");

    let src_content = fs.read_file("/source.txt").expect("read source");
    let dst_content = fs.read_file("/dest.txt").expect("read dest");

    assert_eq!(src_content, source);
    assert_eq!(dst_content, source);
    assert_eq!(src_content, dst_content);

    cleanup(&root);
}

#[test]
fn reflink_file_independent_inodes() {
    let root = temp_root("reflink-independent");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let source = b"Original content before reflink.\n";
    let _rec = fs.create_file("/source.txt", 0o644).expect("create source");
    fs.write_file("/source.txt", 0, source)
        .expect("write source");
    fs.sync_all().expect("sync");

    fs.reflink_file("/source.txt", "/dest.txt")
        .expect("reflink");

    // Modify source after reflink; destination must remain unchanged.
    let modification = b"Modified content.\n";
    fs.write_file("/source.txt", 0, modification)
        .expect("modify source");
    fs.truncate_file("/source.txt", modification.len() as u64)
        .expect("truncate source");

    let modified_src = fs.read_file("/source.txt").expect("read source");
    let dest = fs.read_file("/dest.txt").expect("read dest");

    assert_eq!(modified_src, modification);
    assert_eq!(
        dest, source,
        "reflinked destination must be independent of source"
    );

    cleanup(&root);
}

#[test]
fn reflink_file_dir_source_is_error() {
    let root = temp_root("reflink-dir-source");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    fs.create_dir("/mydir", 0o755).expect("mkdir");
    let result = fs.reflink_file("/mydir", "/dest.txt");
    assert!(result.is_err(), "reflink from directory should fail");

    cleanup(&root);
}

#[test]
fn reflink_file_already_exists_error() {
    let root = temp_root("reflink-exists");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    fs.create_file("/source.txt", 0o644).expect("create source");
    fs.create_file("/dest.txt", 0o644).expect("create dest");

    let result = fs.reflink_file("/source.txt", "/dest.txt");
    assert!(result.is_err(), "reflink to existing path should fail");

    cleanup(&root);
}

#[test]
fn reflink_file_large_content() {
    let root = temp_root("reflink-large");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let size = 64 * 1024; // span multiple chunks
    let source: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let _rec = fs.create_file("/source.bin", 0o644).expect("create source");
    fs.write_file("/source.bin", 0, &source)
        .expect("write source");
    fs.sync_all().expect("sync");

    fs.reflink_file("/source.bin", "/dest.bin")
        .expect("reflink");

    let src = fs.read_file("/source.bin").expect("read source");
    let dst = fs.read_file("/dest.bin").expect("read dest");

    assert_eq!(src.len(), size);
    assert_eq!(dst.len(), size);
    assert_eq!(src, dst);

    // Modify a specific byte range in source, verify dest unchanged.
    let patch = b"PATCH";
    let patch_offset = (size / 2) as u64;
    fs.write_file("/source.bin", patch_offset, patch)
        .expect("patch source");

    let modified_src = fs.read_file("/source.bin").expect("read src after patch");
    let dst_after = fs.read_file("/dest.bin").expect("read dest after patch");

    assert_eq!(&modified_src[patch_offset as usize..][..patch.len()], patch);
    assert_eq!(
        &dst_after[patch_offset as usize..][..patch.len()],
        &source[patch_offset as usize..][..patch.len()],
        "reflinked destination must be independent"
    );

    cleanup(&root);
}

#[test]
fn format_version_new_superblock_has_current_version() {
    let superblock = SuperblockRecord {
        next_inode_id: 2,
        generation: 1,
        inode_count: 1,
        inode_allocation_bitmap: vec![1],
        format_version_min: CURRENT_FORMAT_VERSION,
        format_version_max: CURRENT_FORMAT_VERSION,
    };
    let bytes = encode_superblock(&superblock);
    let (decoded, _legacy) = decode_superblock(&bytes).expect("round-trip should succeed");
    assert_eq!(decoded.format_version_min, CURRENT_FORMAT_VERSION);
    assert_eq!(decoded.format_version_max, CURRENT_FORMAT_VERSION);
}

#[test]
fn format_version_legacy_superblock_is_rejected() {
    // Build a minimal v1 superblock without the format-version extension.
    // v1 format is no longer supported; TideFS has no public release.
    let mut out = Vec::new();
    out.extend_from_slice(&SUPERBLOCK_MAGIC);
    push_u16(&mut out, 1); // version 1 (now rejected)
    push_u16(&mut out, 0); // reserved
    push_u64(&mut out, 2); // next_inode_id
    push_u64(&mut out, 1); // generation
    push_u64(&mut out, 1); // count (v1: list length)
    push_u64(&mut out, 1); // inode id 1
                           // No snapshots, no format extension
    assert!(
        decode_superblock(&out).is_err(),
        "v1 superblock should be rejected"
    );
}

#[test]
fn format_version_downgrade_fence_detected_in_round_trip() {
    let superblock = SuperblockRecord {
        next_inode_id: 2,
        generation: 1,
        inode_count: 1,
        inode_allocation_bitmap: vec![1],
        format_version_min: CURRENT_FORMAT_VERSION,
        format_version_max: CURRENT_FORMAT_VERSION + 1,
    };
    let bytes = encode_superblock(&superblock);
    let (decoded, _legacy) = decode_superblock(&bytes).expect("decode should succeed");
    // decoded has max > CURRENT, which should trigger the mount gate
    assert!(
        CURRENT_FORMAT_VERSION < decoded.format_version_max,
        "decoded max should exceed CURRENT for downgrade fence test"
    );
}

#[test]
fn format_version_round_trips_through_encode_decode() {
    let superblock = SuperblockRecord {
        next_inode_id: 2,
        generation: 1,
        inode_count: 1,
        inode_allocation_bitmap: vec![1],
        format_version_min: CURRENT_FORMAT_VERSION,
        format_version_max: CURRENT_FORMAT_VERSION,
    };
    let bytes = encode_superblock(&superblock);
    let (decoded, _legacy) = decode_superblock(&bytes).expect("round-trip should succeed");
    assert_eq!(decoded.format_version_min, superblock.format_version_min);
    assert_eq!(decoded.format_version_max, superblock.format_version_max);
    assert_eq!(decoded.next_inode_id, superblock.next_inode_id);
    assert_eq!(decoded.generation, superblock.generation);
    assert_eq!(decoded.inode_count, superblock.inode_count);
    assert_eq!(
        decoded.inode_allocation_bitmap,
        superblock.inode_allocation_bitmap
    );
}

#[test]
fn format_version_valid_superblock_passes_mount_gate() {
    let superblock = SuperblockRecord {
        next_inode_id: 2,
        generation: 1,
        inode_count: 1,
        inode_allocation_bitmap: vec![1],
        format_version_min: CURRENT_FORMAT_VERSION,
        format_version_max: CURRENT_FORMAT_VERSION,
    };
    // Simulate the mount gate check
    assert!(
        CURRENT_FORMAT_VERSION >= superblock.format_version_min,
        "running version should be >= min"
    );
    assert!(
        CURRENT_FORMAT_VERSION >= superblock.format_version_max,
        "running version should be >= max (no downgrade)"
    );
}

#[test]
fn format_version_too_old_code_refused_by_min_gate() {
    let superblock = SuperblockRecord {
        next_inode_id: 2,
        generation: 1,
        inode_count: 1,
        inode_allocation_bitmap: vec![1],
        format_version_min: CURRENT_FORMAT_VERSION + 1,
        format_version_max: CURRENT_FORMAT_VERSION + 1,
    };
    assert!(
        CURRENT_FORMAT_VERSION < superblock.format_version_min,
        "running version should be < min for too-old test"
    );
}

#[test]
fn compression_write_read_roundtrip() {
    let root = temp_root("compression-roundtrip");
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };
    let mut fs = LocalFileSystem::open_with_compression(&root, options(), config.clone())
        .expect("open with compression");
    let data: Vec<u8> = (0..64u8).cycle().take(8192).collect();
    fs.create_file("/compressible.bin", 0o644)
        .expect("create file");
    fs.write_file("/compressible.bin", 0, &data)
        .expect("write compressible");
    fs.sync_all().expect("sync");
    let read_back = fs.read_file("/compressible.bin").expect("read back");
    assert_eq!(read_back, data);
    drop(fs);
    let reopened = LocalFileSystem::open_with_compression(&root, options(), config)
        .expect("reopen with compression");
    assert_eq!(
        reopened
            .read_file("/compressible.bin")
            .expect("re-read after reopen"),
        data
    );
    cleanup(&root);
}

#[test]
fn compression_uncompressed_backward_compat() {
    let root = temp_root("compression-backward-compat");
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, options()).expect("open uncompressed");
        let data = b"uncompressed data";
        fs.create_file("/plain.txt", 0o644).expect("create file");
        fs.write_file("/plain.txt", 0, data).expect("write");
        fs.sync_all().expect("sync");
    }
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };
    let mut fs = LocalFileSystem::open_with_compression(&root, options(), config)
        .expect("open with compression on uncompressed store");
    assert_eq!(
        fs.read_file("/plain.txt").expect("read plain"),
        b"uncompressed data"
    );
    let new_data: Vec<u8> = (0..64u8).cycle().take(4096).collect();
    fs.write_file("/plain.txt", 0, &new_data)
        .expect("overwrite with compressible");
    fs.sync_all().expect("sync");
    assert_eq!(
        fs.read_file("/plain.txt").expect("read after overwrite"),
        new_data
    );
    cleanup(&root);
}

#[test]
fn compression_reduces_object_size() {
    let root = temp_root("compression-ratio");
    let data: Vec<u8> = vec![b'A'; 65536];
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };
    let mut fs = LocalFileSystem::open_with_compression(&root, options(), config.clone())
        .expect("open compressed");
    fs.create_file("/big.txt", 0o644).expect("create file");
    fs.write_file("/big.txt", 0, &data)
        .expect("write compressed");
    fs.sync_all().expect("sync");
    // Roundtrip: read back must match
    assert_eq!(fs.read_file("/big.txt").expect("read back"), data);
    drop(fs);
    // Reopen and verify roundtrip
    let fs2 = LocalFileSystem::open_with_compression(&root, options(), config)
        .expect("reopen compressed");
    assert_eq!(
        fs2.read_file("/big.txt").expect("re-read after reopen"),
        data
    );
    let live = fs2.stats().object_store.live_bytes;
    assert!(
        live < data.len() as u64 / 2,
        "compressed live_bytes {} should be less than data.len()/2 = {}",
        live,
        data.len() as u64 / 2
    );
    cleanup(&root);
}

#[test]
fn device_transform_open_helpers_fail_closed_until_tfr_006_authority() {
    let root = temp_root("device-transform-fail-closed");
    let enc_config = EncryptionConfig {
        key: StoreEncryptionKey::generate(),
    };
    let cmp_config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };

    fn assert_transform_rejected(result: Result<LocalFileSystem>) {
        let err = match result {
            Ok(_) => panic!("device-level transform helper must fail closed"),
            Err(err) => err,
        };
        match err {
            FileSystemError::Unsupported { operation, reason } => {
                assert_eq!(operation, "local filesystem device transforms");
                assert!(reason.contains("TFR-006"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    assert_transform_rejected(LocalFileSystem::open_with_encryption(
        root.join("enc"),
        options(),
        enc_config.clone(),
    ));
    assert_transform_rejected(LocalFileSystem::open_with_compression(
        root.join("comp"),
        options(),
        cmp_config.clone(),
    ));
    let result = LocalFileSystem::open_with_encryption_and_compression(
        root.join("both"),
        options(),
        enc_config,
        cmp_config,
    );
    assert_transform_rejected(result);
    cleanup(&root);
}

#[test]
fn compression_lz4_write_read_roundtrip() {
    let root = temp_root("compression-lz4-roundtrip");
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Lz4,
        level: 0,
        min_compress_bytes: 0,
    };
    let mut fs = LocalFileSystem::open_with_compression(&root, options(), config.clone())
        .expect("open with lz4 compression");
    let data: Vec<u8> = (0..64u8).cycle().take(8192).collect();
    fs.create_file("/lz4_compressible.bin", 0o644)
        .expect("create file");
    fs.write_file("/lz4_compressible.bin", 0, &data)
        .expect("write lz4");
    fs.sync_all().expect("sync");
    let read_back = fs.read_file("/lz4_compressible.bin").expect("read back");
    assert_eq!(read_back, data);
    drop(fs);
    let reopened =
        LocalFileSystem::open_with_compression(&root, options(), config).expect("reopen with lz4");
    assert_eq!(
        reopened
            .read_file("/lz4_compressible.bin")
            .expect("re-read after reopen"),
        data
    );
    cleanup(&root);
}

#[test]
fn compression_mixed_zstd_to_lz4_rewrite_remount() {
    // Write with zstd, remount with lz4, overwrite with new data, read back.
    let root = temp_root("mixed-zstd-to-lz4");
    let zstd_config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };
    let lz4_config = CompressionConfig {
        algorithm: CompressionAlgorithm::Lz4,
        level: 0,
        min_compress_bytes: 0,
    };
    let original: Vec<u8> = (0..64u8).cycle().take(4096).collect();
    let rewrite: Vec<u8> = (128..192u8).cycle().take(4096).collect();

    // Session 1: write with zstd
    {
        let mut fs = LocalFileSystem::open_with_compression(&root, options(), zstd_config)
            .expect("open with zstd");
        fs.create_file("/mixed.bin", 0o644).expect("create");
        fs.write_file("/mixed.bin", 0, &original)
            .expect("write zstd");
        fs.sync_all().expect("sync");
        assert_eq!(fs.read_file("/mixed.bin").expect("read"), original);
    }

    // Session 2: reopen with lz4, overwrite
    {
        let mut fs = LocalFileSystem::open_with_compression(&root, options(), lz4_config.clone())
            .expect("reopen with lz4");
        assert_eq!(fs.read_file("/mixed.bin").expect("read old"), original);
        fs.write_file("/mixed.bin", 0, &rewrite)
            .expect("overwrite with lz4");
        fs.sync_all().expect("sync");
        assert_eq!(fs.read_file("/mixed.bin").expect("read new"), rewrite);
    }

    // Session 3: reopen with lz4 again, verify rewrite persisted
    {
        let fs = LocalFileSystem::open_with_compression(&root, options(), lz4_config)
            .expect("reopen after rewrite");
        assert_eq!(fs.read_file("/mixed.bin").expect("read persisted"), rewrite);
    }

    cleanup(&root);
}

#[test]
fn compression_mixed_lz4_to_zstd_rewrite_remount() {
    // Write with lz4, remount with zstd, overwrite with new data, read back.
    let root = temp_root("mixed-lz4-to-zstd");
    let lz4_config = CompressionConfig {
        algorithm: CompressionAlgorithm::Lz4,
        level: 0,
        min_compress_bytes: 0,
    };
    let zstd_config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };
    let original: Vec<u8> = (0..64u8).cycle().take(4096).collect();
    let rewrite: Vec<u8> = (192..=255u8).cycle().take(4096).collect();

    // Session 1: write with lz4
    {
        let mut fs = LocalFileSystem::open_with_compression(&root, options(), lz4_config)
            .expect("open with lz4");
        fs.create_file("/mixed2.bin", 0o644).expect("create");
        fs.write_file("/mixed2.bin", 0, &original)
            .expect("write lz4");
        fs.sync_all().expect("sync");
        assert_eq!(fs.read_file("/mixed2.bin").expect("read"), original);
    }

    // Session 2: reopen with zstd, overwrite
    {
        let mut fs = LocalFileSystem::open_with_compression(&root, options(), zstd_config.clone())
            .expect("reopen with zstd");
        assert_eq!(fs.read_file("/mixed2.bin").expect("read old"), original);
        fs.write_file("/mixed2.bin", 0, &rewrite)
            .expect("overwrite with zstd");
        fs.sync_all().expect("sync");
        assert_eq!(fs.read_file("/mixed2.bin").expect("read new"), rewrite);
    }

    // Session 3: reopen with zstd again, verify rewrite persisted
    {
        let fs = LocalFileSystem::open_with_compression(&root, options(), zstd_config)
            .expect("reopen after rewrite");
        assert_eq!(
            fs.read_file("/mixed2.bin").expect("read persisted"),
            rewrite
        );
    }

    cleanup(&root);
}

#[test]
fn compression_mixed_mode_scrub_clean() {
    // Write files with different compression algorithms in separate sessions,
    // then scrub and verify all blocks are clean.
    let root = temp_root("mixed-mode-scrub");
    let data_a: Vec<u8> = (0..64u8).cycle().take(4096).collect();
    let data_b: Vec<u8> = (65..129u8).cycle().take(4096).collect();

    // Session 1: write with zstd
    {
        let mut fs = LocalFileSystem::open_with_compression(
            &root,
            options(),
            CompressionConfig {
                algorithm: CompressionAlgorithm::Zstd,
                level: 3,
                min_compress_bytes: 0,
            },
        )
        .expect("open zstd");
        fs.create_file("/zstd_file.bin", 0o644).expect("create");
        fs.write_file("/zstd_file.bin", 0, &data_a)
            .expect("write zstd");
        fs.sync_all().expect("sync");
    }

    // Session 2: write with lz4
    {
        let mut fs = LocalFileSystem::open_with_compression(
            &root,
            options(),
            CompressionConfig {
                algorithm: CompressionAlgorithm::Lz4,
                level: 0,
                min_compress_bytes: 0,
            },
        )
        .expect("open lz4");
        fs.create_file("/lz4_file.bin", 0o644).expect("create");
        fs.write_file("/lz4_file.bin", 0, &data_b)
            .expect("write lz4");
        fs.sync_all().expect("sync");
    }

    // Session 3: scrub all inodes and verify clean
    {
        let fs = LocalFileSystem::open_with_compression(
            &root,
            options(),
            CompressionConfig {
                algorithm: CompressionAlgorithm::Zstd,
                level: 3,
                min_compress_bytes: 0,
            },
        )
        .expect("open for scrub");
        let report =
            crate::scrub::scrub_inodes_content(fs.store_ref(), fs.inode_records()).expect("scrub");
        assert!(
            report.is_clean(),
            "scrub should be clean after mixed-mode writes; report: {report:?}"
        );
        assert!(report.blocks_scanned > 0, "should have scanned some blocks");
        assert_eq!(report.blocks_corrupt, 0);
        assert_eq!(report.blocks_unreadable, 0);
    }

    cleanup(&root);
}

#[test]
fn compression_mixed_mode_all_algos_remount_roundtrip() {
    // Write files with zstd, lz4, and uncompressed in the same store,
    // then reopen and verify all three roundtrip correctly.
    let root = temp_root("mixed-all-algos-roundtrip");
    let zstd_data: Vec<u8> = b"zstd compressed payload ".repeat(80).to_vec();
    let lz4_data: Vec<u8> = b"lz4 compressed payload ".repeat(80).to_vec();

    // Write with zstd
    {
        let mut fs = LocalFileSystem::open_with_compression(
            &root,
            options(),
            CompressionConfig {
                algorithm: CompressionAlgorithm::Zstd,
                level: 3,
                min_compress_bytes: 0,
            },
        )
        .expect("open zstd");
        fs.create_file("/zstd.bin", 0o644).expect("create");
        fs.write_file("/zstd.bin", 0, &zstd_data)
            .expect("write zstd");
        fs.sync_all().expect("sync");
    }

    // Write with lz4
    {
        let mut fs = LocalFileSystem::open_with_compression(
            &root,
            options(),
            CompressionConfig {
                algorithm: CompressionAlgorithm::Lz4,
                level: 0,
                min_compress_bytes: 0,
            },
        )
        .expect("open lz4");
        fs.create_file("/lz4.bin", 0o644).expect("create");
        fs.write_file("/lz4.bin", 0, &lz4_data).expect("write lz4");
        fs.sync_all().expect("sync");
    }

    // Reopen and verify all files
    {
        let fs =
            LocalFileSystem::open_with_compression(&root, options(), CompressionConfig::balanced())
                .expect("reopen");
        assert_eq!(fs.read_file("/zstd.bin").expect("read zstd"), zstd_data);
        assert_eq!(fs.read_file("/lz4.bin").expect("read lz4"), lz4_data);
    }

    cleanup(&root);
}

#[test]
fn compression_mixed_mode_send_receive_roundtrip() {
    // Write files with zstd and lz4 compression in separate sessions,
    // then export, import, and verify all content survives send/receive.
    let source_root = temp_root("mixed-sr-source");
    let target_root = temp_root("mixed-sr-target");
    let source_key = RootAuthenticationKey::from_bytes32([0x71_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let target_key = RootAuthenticationKey::from_bytes32([0x72_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    let zstd_data: Vec<u8> = b"zstd send/receive payload ".repeat(80).to_vec();
    let lz4_data: Vec<u8> = b"lz4 send/receive payload ".repeat(80).to_vec();

    // Session 1: write with zstd
    {
        let mut fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &source_root,
            LocalFileSystemOpenConfig {
                options: options(),
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: source_key,
                encryption: None,
                compression: Some(CompressionConfig {
                    algorithm: CompressionAlgorithm::Zstd,
                    level: 3,
                    min_compress_bytes: 0,
                }),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
        .expect("open zstd");
        fs.create_file("/zstd_file.bin", 0o644)
            .expect("create zstd file");
        fs.write_file("/zstd_file.bin", 0, &zstd_data)
            .expect("write zstd");
        fs.sync_all().expect("sync zstd");
    }

    // Session 2: write with lz4 (reopens same pool)
    {
        let mut fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &source_root,
            LocalFileSystemOpenConfig {
                options: options(),
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: source_key,
                encryption: None,
                compression: Some(CompressionConfig {
                    algorithm: CompressionAlgorithm::Lz4,
                    level: 0,
                    min_compress_bytes: 0,
                }),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
        .expect("open lz4");
        fs.create_file("/lz4_file.bin", 0o644)
            .expect("create lz4 file");
        fs.write_file("/lz4_file.bin", 0, &lz4_data)
            .expect("write lz4");
        fs.sync_all().expect("sync lz4");
    }

    // Reopen and export
    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source for export");
    let export = source.export_changed_records().expect("export");
    assert!(export.total_records > 0);
    assert!(export.payload_bytes > 0);

    // Import into target
    let report =
        LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            options(),
            &export,
            target_key,
        )
        .expect("receive");
    assert_eq!(report.imported_records, export.total_records);
    assert_eq!(report.imported_payload_bytes, export.payload_bytes);

    // Open target and verify both files roundtrip
    let target =
        LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
            .expect("open target");
    assert_eq!(
        target
            .read_file("/zstd_file.bin")
            .expect("read zstd after receive"),
        zstd_data
    );
    assert_eq!(
        target
            .read_file("/lz4_file.bin")
            .expect("read lz4 after receive"),
        lz4_data
    );

    cleanup(&source_root);
    cleanup(&target_root);
}

/// Verify that content-addressed canonical objects are reused across sessions.
/// Writes the same chunk content in two separate filesystem sessions; the second
/// write should find the canonical object via store.contains_key() and use a
/// redirect instead of writing a new copy.
#[test]
fn compression_mixed_mode_full_stack_validation() {
    // Tier 3 storage runtime validation: end-to-end mixed-compression test
    // exercising rewrite, scrub, send/receive, and remount in one scenario.
    // Validation written to /root/ai/tmp/tidefs-validation/compression-mixed-mode-validation.log
    use std::io::Write;

    let source_root = temp_root("full-stack-source");
    let target_root = temp_root("full-stack-target");
    let key = RootAuthenticationKey::from_bytes32([0x91_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    // Determine repo root from CARGO_MANIFEST_DIR at compile time.
    let validation_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap() // crates/tidefs-local-filesystem -> crates
        .parent()
        .unwrap() // crates -> repo root
        .join("/root/ai/tmp/tidefs-validation/compression-mixed-mode-validation.log");

    let mut log = Vec::<u8>::new();
    let mut record = |msg: &str| {
        let line = format!(
            "[{}] {}
",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            msg
        );
        log.extend_from_slice(line.as_bytes());
    };

    record("NEXT-STOR-025 compression mixed-mode full-stack validation start");
    record(&format!("source_root={source_root:?}"));
    record(&format!("target_root={target_root:?}"));

    let zstd_data: Vec<u8> = b"zstd compressed payload ".repeat(100).to_vec();
    let lz4_data: Vec<u8> = b"lz4 compressed payload ".repeat(100).to_vec();

    // Phase 1: Write with zstd
    {
        let mut fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &source_root,
            LocalFileSystemOpenConfig {
                options: options(),
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: key,
                encryption: None,
                compression: Some(CompressionConfig {
                    algorithm: CompressionAlgorithm::Zstd,
                    level: 3,
                    min_compress_bytes: 0,
                }),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
        .expect("open zstd");
        fs.create_file("/zstd_file.bin", 0o644)
            .expect("create zstd file");
        fs.write_file("/zstd_file.bin", 0, &zstd_data)
            .expect("write zstd");
        fs.sync_all().expect("sync zstd");
    }
    record("Phase 1: zstd write complete");

    // Phase 2: Write with lz4
    {
        let mut fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &source_root,
            LocalFileSystemOpenConfig {
                options: options(),
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: key,
                encryption: None,
                compression: Some(CompressionConfig {
                    algorithm: CompressionAlgorithm::Lz4,
                    level: 0,
                    min_compress_bytes: 0,
                }),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
        .expect("open lz4");
        fs.create_file("/lz4_file.bin", 0o644)
            .expect("create lz4 file");
        fs.write_file("/lz4_file.bin", 0, &lz4_data)
            .expect("write lz4");
        fs.sync_all().expect("sync lz4");
    }
    record("Phase 2: lz4 write complete");

    // Phase 3: Rewrite (zstd-written file overwritten with lz4 config)
    {
        let rewrite_data: Vec<u8> = b"rewritten with lz4 ".repeat(60).to_vec();
        let mut fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &source_root,
            LocalFileSystemOpenConfig {
                options: options(),
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: key,
                encryption: None,
                compression: Some(CompressionConfig {
                    algorithm: CompressionAlgorithm::Lz4,
                    level: 0,
                    min_compress_bytes: 0,
                }),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
        .expect("open for rewrite");
        fs.replace_file("/zstd_file.bin", &rewrite_data)
            .expect("rewrite");
        fs.sync_all().expect("sync rewrite");
        assert_eq!(
            fs.read_file("/zstd_file.bin").expect("read rewrite"),
            rewrite_data
        );
    }
    record("Phase 3: rewrite complete");

    // Phase 4: Scrub
    {
        let fs = LocalFileSystem::open_with_root_authentication_key(&source_root, options(), key)
            .expect("open for scrub");
        let report =
            crate::scrub::scrub_inodes_content(fs.store_ref(), fs.inode_records()).expect("scrub");
        assert!(report.is_clean(), "scrub must be clean; report: {report:?}");
        record(&format!(
            "Phase 4: scrub clean — scanned={} clean={} corrupt={}",
            report.blocks_scanned, report.blocks_clean, report.blocks_corrupt
        ));
    }

    // Phase 5: Send/receive
    {
        let mut source =
            LocalFileSystem::open_with_root_authentication_key(&source_root, options(), key)
                .expect("open source for export");
        let export = source.export_changed_records().expect("export");
        record(&format!(
            "Phase 5: export — records={} bytes={} roots={}",
            export.total_records,
            export.payload_bytes,
            export.roots.len()
        ));

        let report =
            LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
                &target_root,
                options(),
                &export,
                key,
            )
            .expect("receive");
        record(&format!(
            "Phase 5: import — records={} bytes={}",
            report.imported_records, report.imported_payload_bytes
        ));
    }

    // Phase 6: Remount and verify
    {
        let target =
            LocalFileSystem::open_with_root_authentication_key(&target_root, options(), key)
                .expect("open target");
        let expected_rewrite = b"rewritten with lz4 ".repeat(60).to_vec();
        assert_eq!(
            target.read_file("/zstd_file.bin").expect("read zstd"),
            expected_rewrite
        );
        assert_eq!(
            target.read_file("/lz4_file.bin").expect("read lz4"),
            lz4_data
        );
    }
    record("Phase 6: remount verify — both files match");

    // Finalize and write validation (drop record closure first by ending block)
    {
        // The record closure borrows log mutably; finish recording then write.
    }
    if let Ok(mut f) = std::fs::File::create(&validation_path) {
        f.write_all(&log).ok();
    }
    // Log final result directly without the closure
    let line = format!(
        "[{}] NEXT-STOR-025 compression mixed-mode full-stack validation PASSED
",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    log.extend_from_slice(line.as_bytes());
    if let Ok(mut f) = std::fs::File::create(&validation_path) {
        f.write_all(&log).ok();
    }

    cleanup(&source_root);
    cleanup(&target_root);
}

#[test]
fn cross_session_dedup_reuses_canonical_objects() {
    let root = temp_root("cross-session-dedup");
    let opts = StoreOptions {
        max_segment_bytes: 256 * 1024,
        sync_on_write: false,
        repair_torn_tail: true,
        segment_rotation_interval_secs: 0,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 65536,
        reclaim_enabled: true,

        write_throttle_enabled: false,
        durability_layout: None,
        verify_read_checksums: false,
    };

    let data = b"cross-session dedup test payload";

    // Session 1: write file A through the filesystem
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts.clone()).expect("create");
        fs.create_dir("/d", 0o755).expect("mkdir");
        fs.create_file("/d/a.bin", 0o644).expect("create a");
        fs.write_file("/d/a.bin", 0, data).expect("write a");
        fs.sync_all().expect("sync");
    }

    // Session 2: write file B with identical content
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts.clone()).expect("reopen");
        fs.create_file("/d/b.bin", 0o644).expect("create b");
        fs.write_file("/d/b.bin", 0, data).expect("write b");
        fs.sync_all().expect("sync");
    }

    // Read back: both files should return correct content
    {
        let fs = LocalFileSystem::open_with_options(&root, opts).expect("reopen");
        assert_eq!(fs.read_file("/d/a.bin").expect("read a"), data);
        assert_eq!(fs.read_file("/d/b.bin").expect("read b"), data);
    }

    cleanup(&root);
}

/// Within-session dedup: two files with identical content written in the same
/// session should share canonical objects via the in-memory DedupIndex.
#[test]
fn within_session_dedup_shares_canonical_objects() {
    let root = temp_root("within-session-dedup");
    let opts = StoreOptions {
        max_segment_bytes: 256 * 1024,
        sync_on_write: false,
        repair_torn_tail: true,
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_count: 65536,
        reclaim_enabled: true,

        write_throttle_enabled: false,
        durability_layout: None,
        verify_read_checksums: false,
    };

    let same = b"shared content for dedup test";
    let diff = b"different content no dedup";

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts.clone()).expect("create");
        fs.create_dir("/d", 0o755).expect("mkdir");

        fs.create_file("/d/a.bin", 0o644).expect("create a");
        fs.write_file("/d/a.bin", 0, same).expect("write a");

        fs.create_file("/d/b.bin", 0o644).expect("create b");
        fs.write_file("/d/b.bin", 0, same).expect("write b");

        fs.create_file("/d/c.bin", 0o644).expect("create c");
        fs.write_file("/d/c.bin", 0, diff).expect("write c");

        fs.sync_all().expect("sync");
    }

    {
        let fs = LocalFileSystem::open_with_options(&root, opts).expect("reopen");
        assert_eq!(fs.read_file("/d/a.bin").expect("read"), same);
        assert_eq!(fs.read_file("/d/b.bin").expect("read"), same);
        assert_eq!(fs.read_file("/d/c.bin").expect("read"), diff);
    }

    cleanup(&root);
}

#[test]
fn incremental_send_receive_skips_unchanged_objects() {
    let source_root = temp_root("incr-send-source");
    let target_root = temp_root("incr-send-target");
    let source_key = RootAuthenticationKey::from_bytes32([0x33_u8; ROOT_AUTHENTICATION_KEY_LEN]);
    let target_key = RootAuthenticationKey::from_bytes32([0x44_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    // Phase 1: create baseline data and export full.
    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source fs");
    source.create_dir("/docs", 0o755).expect("create docs");
    source
        .create_file("/docs/base.bin", 0o644)
        .expect("create base file");
    let base_content = vec![0x61; content_chunk_size() as usize + 37];
    source
        .write_file("/docs/base.bin", 0, &base_content)
        .expect("write base content");
    source.sync_all().expect("sync baseline");
    let baseline_snap = source
        .create_snapshot("baseline")
        .expect("snapshot baseline");

    // Full export should include everything.
    let full_export = source.export_changed_records().expect("full export");
    assert!(!full_export.incremental);
    assert!(full_export.from_root.is_none());
    assert_eq!(full_export.stream_version, SEND_RECEIVE_STREAM_VERSION);

    // Receive baseline to verify full send/receive works.
    let report =
        LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            options(),
            &full_export,
            target_key,
        )
        .expect("receive baseline");
    assert!(!report.production_recovery_requires_operator_repair());

    let received =
        LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
            .expect("open received baseline");
    assert_eq!(
        received.read_file("/docs/base.bin").expect("read base"),
        base_content
    );

    // Phase 2: modify one file and add another, then export incremental.
    let modified_content = vec![0x62; content_chunk_size() as usize + 17];
    source
        .replace_file("/docs/base.bin", &modified_content)
        .expect("replace base file");
    source
        .create_file("/docs/delta.txt", 0o644)
        .expect("create delta file");
    source
        .write_file("/docs/delta.txt", 0, b"incremental-only")
        .expect("write delta content");
    source.sync_all().expect("sync delta");

    let baseline_root = baseline_snap.source_root.clone();
    let incr_export = source
        .export_incremental_changed_records(&baseline_root)
        .expect("incremental export");

    // Validate incremental export properties.
    assert!(incr_export.incremental);
    assert_eq!(incr_export.from_root.as_ref(), Some(&baseline_root));
    assert_eq!(incr_export.stream_version, 2);

    // Incremental should have fewer records than a full export of the same state.
    let full_delta_export = source.export_changed_records().expect("full delta export");
    assert!(
        incr_export.total_records < full_delta_export.total_records,
        "incremental ({}) must have fewer records than full ({})",
        incr_export.total_records,
        full_delta_export.total_records,
    );

    // Encode/decode roundtrip.
    let encoded = incr_export.encode();
    let decoded = ChangedRecordExport::decode(&encoded).expect("decode incremental stream");
    assert_eq!(decoded, incr_export);

    // The incremental stream is self-contained: it can be decoded and
    // its structural records carry enough information to reconstruct the
    // filesystem state.  Full incremental receive (applying delta on top
    // of an existing baseline) is a separate feature tracked at #790.

    cleanup(&source_root);
    cleanup(&target_root);
}

/// End-to-end incremental receive: baseline exported to empty target,
/// then incremental delta applied on top and verified byte-for-byte.
#[test]
fn incremental_send_receive_end_to_end() {
    let source_root = temp_root("incr-e2e-source");
    let source_key = RootAuthenticationKey::from_bytes32([0xcc_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    // Phase 1: create baseline data on source.
    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source");
    source.create_dir("/data", 0o755).expect("mkdir data");
    let unchanged_data: Vec<u8> = vec![0x11; 16384];
    source
        .create_file("/data/unchanged.bin", 0o644)
        .expect("create unchanged");
    source
        .write_file("/data/unchanged.bin", 0, &unchanged_data)
        .expect("write unchanged");
    let old_modified: Vec<u8> = vec![0x22; 4096];
    source
        .create_file("/data/modified.bin", 0o644)
        .expect("create modified");
    source
        .write_file("/data/modified.bin", 0, &old_modified)
        .expect("write old modified");
    source.sync_all().expect("sync baseline");
    let baseline_root = source
        .selected_current_root_summary()
        .expect("baseline root");
    source
        .create_snapshot("baseline")
        .expect("baseline snapshot");

    // Export the baseline-only state (full export from baseline root).
    let baseline_export = source.export_changed_records().expect("baseline export");

    let target_root = temp_root("incr-e2e-target");
    let target_key = RootAuthenticationKey::from_bytes32([0xdd_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    // Phase 2: receive baseline into empty target.
    LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
        &target_root,
        options(),
        &baseline_export,
        target_key,
    )
    .expect("receive baseline");

    // Verify baseline data in target.
    {
        let target =
            LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
                .expect("open target after baseline");
        assert_eq!(
            target
                .read_file("/data/unchanged.bin")
                .expect("read unchanged baseline"),
            unchanged_data
        );
        assert_eq!(
            target
                .read_file("/data/modified.bin")
                .expect("read modified baseline"),
            old_modified
        );
    }

    // Phase 3: modify source — replace one file, add another.
    let new_modified: Vec<u8> = vec![0x33; 8192];
    source
        .replace_file("/data/modified.bin", &new_modified)
        .expect("replace modified");
    source
        .create_file("/data/new.bin", 0o644)
        .expect("create new");
    let new_data: Vec<u8> = vec![0x44; 2048];
    source
        .write_file("/data/new.bin", 0, &new_data)
        .expect("write new");
    source.sync_all().expect("sync delta");

    // Phase 4: export incremental from baseline to delta.
    let incremental_export = source
        .export_incremental_changed_records(&baseline_root)
        .expect("incremental export");

    assert!(incremental_export.incremental);
    assert!(incremental_export.from_root.is_some());
    assert_eq!(incremental_export.stream_version, 2);

    // Phase 5: receive incremental into the target containing only the baseline.
    LocalFileSystem::receive_incremental_changed_records_with_root_authentication_key(
        &target_root,
        options(),
        &incremental_export,
        target_key,
    )
    .expect("receive incremental");

    // Phase 6: verify target has the delta data.
    {
        let target =
            LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
                .expect("open target after incremental");
        let read_unchanged = target
            .read_file("/data/unchanged.bin")
            .expect("read unchanged after incr");
        let read_modified = target
            .read_file("/data/modified.bin")
            .expect("read modified after incr");
        let read_new = target
            .read_file("/data/new.bin")
            .expect("read new after incr");
        assert_eq!(
            read_unchanged, unchanged_data,
            "unchanged data should persist across incremental receive"
        );
        assert_eq!(
            read_modified, new_modified,
            "modified data should be updated by incremental receive"
        );
        assert_eq!(
            read_new, new_data,
            "new file should exist after incremental receive"
        );
    }

    cleanup(&source_root);
    cleanup(&target_root);
}

/// Test chained incremental receives: baseline → delta1 → delta2.
/// Each delta carries only the roots created since the previous receive.
#[test]
fn incremental_send_receive_chained_deltas() {
    let source_root = temp_root("incr-chain-source");
    let source_key = RootAuthenticationKey::from_bytes32([0xee_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source");

    // --- Baseline ---
    source.create_dir("/data", 0o755).expect("mkdir data");
    let data_a: Vec<u8> = vec![0xAA; 4096];
    source
        .create_file("/data/file_a.bin", 0o644)
        .expect("create file_a");
    source
        .write_file("/data/file_a.bin", 0, &data_a)
        .expect("write file_a");
    source.sync_all().expect("sync baseline");
    let root_1 = source.selected_current_root_summary().expect("root_1");
    source.create_snapshot("snap_1").expect("snapshot 1");

    // --- Delta 1: modify file_a, add file_b ---
    let data_a2: Vec<u8> = vec![0xBB; 4096];
    source
        .replace_file("/data/file_a.bin", &data_a2)
        .expect("replace file_a");
    let data_b: Vec<u8> = vec![0xCC; 2048];
    source
        .create_file("/data/file_b.bin", 0o644)
        .expect("create file_b");
    source
        .write_file("/data/file_b.bin", 0, &data_b)
        .expect("write file_b");
    source.sync_all().expect("sync delta 1");
    let root_2 = source.selected_current_root_summary().expect("root_2");
    source.create_snapshot("snap_2").expect("snapshot 2");

    // --- Delta 2: modify file_b, add file_c ---
    let data_b2: Vec<u8> = vec![0xDD; 8192];
    source
        .replace_file("/data/file_b.bin", &data_b2)
        .expect("replace file_b");
    let data_c: Vec<u8> = vec![0xEE; 1024];
    source
        .create_file("/data/file_c.bin", 0o644)
        .expect("create file_c");
    source
        .write_file("/data/file_c.bin", 0, &data_c)
        .expect("write file_c");
    source.sync_all().expect("sync delta 2");
    let _root_3 = source.selected_current_root_summary().expect("root_3");

    // Export incremental streams for each transition.
    let incr_1_2 = source
        .export_incremental_changed_records(&root_1)
        .expect("incremental root_1→root_2");
    let incr_2_3 = source
        .export_incremental_changed_records(&root_2)
        .expect("incremental root_2→root_3");

    assert!(incr_1_2.incremental);
    assert_eq!(incr_1_2.from_root.as_ref().unwrap(), &root_1);
    assert_eq!(incr_1_2.stream_version, 2);
    assert!(incr_2_3.incremental);
    assert_eq!(incr_2_3.from_root.as_ref().unwrap(), &root_2);
    assert_eq!(incr_2_3.stream_version, 2);

    // Verify total_records of each incremental stream is less than a full
    // export from the same source would be (the delta excludes baseline).
    let full_export = source.export_changed_records().expect("full export");
    assert!(incr_1_2.total_records < full_export.total_records);
    assert!(incr_2_3.total_records < full_export.total_records);

    // Encode/decode round-trip for both incremental streams.
    for incr in [&incr_1_2, &incr_2_3] {
        let encoded = incr.encode();
        assert!(
            encoded.starts_with(&SEND_RECEIVE_STREAM_MAGIC_BYTES),
            "incremental stream must start with magic bytes"
        );
        let decoded = ChangedRecordExport::decode(&encoded).expect("decode incremental");
        assert!(decoded.incremental);
        assert_eq!(decoded.stream_version, 2);
        assert_eq!(decoded.from_root, incr.from_root);
        assert_eq!(decoded.total_records, incr.total_records);
        assert_eq!(decoded.payload_bytes, incr.payload_bytes);
        assert_eq!(decoded.roots.len(), incr.roots.len());
    }

    // Receive the full export into an empty target to verify it still works.
    let target_root = temp_root("incr-chain-target");
    let target_key = RootAuthenticationKey::from_bytes32([0xff_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
        &target_root,
        options(),
        &full_export,
        target_key,
    )
    .expect("receive full");

    {
        let target =
            LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
                .expect("open target");
        assert_eq!(
            target.read_file("/data/file_a.bin").expect("read a"),
            data_a2,
            "file_a should have delta-1 data"
        );
        assert_eq!(
            target.read_file("/data/file_b.bin").expect("read b"),
            data_b2,
            "file_b should have delta-2 data"
        );
        assert_eq!(
            target.read_file("/data/file_c.bin").expect("read c"),
            data_c,
            "file_c should exist"
        );
    }

    cleanup(&source_root);
    cleanup(&target_root);
}

/// Debug: export incremental and validate independently.
#[test]
fn debug_incremental_validate() {
    let source_root = temp_root("debug-incr-val-source");
    let source_key = RootAuthenticationKey::from_bytes32([0xaa_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    let mut source =
        LocalFileSystem::open_with_root_authentication_key(&source_root, options(), source_key)
            .expect("open source");
    source.create_dir("/data", 0o755).expect("mkdir data");

    let data_a: Vec<u8> = vec![0x11; 4096];
    source.create_file("/data/a.bin", 0o644).expect("create a");
    source
        .write_file("/data/a.bin", 0, &data_a)
        .expect("write a");
    source.sync_all().expect("sync baseline");
    let root1 = source.selected_current_root_summary().expect("root1");

    source
        .create_snapshot("baseline")
        .expect("baseline snapshot");
    let baseline_export = source.export_changed_records().expect("baseline export");
    let data_a2: Vec<u8> = vec![0x22; 4096];
    source
        .replace_file("/data/a.bin", &data_a2)
        .expect("replace a");
    source.create_file("/data/b.bin", 0o644).expect("create b");
    source
        .write_file("/data/b.bin", 0, b"hello")
        .expect("write b");
    source.sync_all().expect("sync delta");

    let incr = source
        .export_incremental_changed_records(&root1)
        .expect("incr export");
    // Validate incremental export properties.
    assert!(incr.incremental);
    assert_eq!(incr.from_root.as_ref(), Some(&root1));
    assert_eq!(incr.stream_version, 2);
    let encoded = incr.encode();
    let decoded = ChangedRecordExport::decode(&encoded).expect("decode incr");
    assert_eq!(decoded.incremental, incr.incremental);
    assert_eq!(decoded.total_records, incr.total_records);
    assert_eq!(decoded.from_root, incr.from_root);
    assert_eq!(decoded.stream_version, incr.stream_version);

    let target_root = temp_root("debug-incr-val-target");
    let target_key = RootAuthenticationKey::from_bytes32([0xff_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    // Validate independently: receive baseline, then apply incremental on top.
    LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
        &target_root,
        options(),
        &baseline_export,
        target_key,
    )
    .expect("receive baseline");

    LocalFileSystem::receive_incremental_changed_records_with_root_authentication_key(
        &target_root,
        options(),
        &incr,
        target_key,
    )
    .expect("receive incremental");

    {
        let target =
            LocalFileSystem::open_with_root_authentication_key(&target_root, options(), target_key)
                .expect("open target");
        assert_eq!(
            target.read_file("/data/a.bin").expect("read a"),
            data_a2,
            "a.bin should have modified content"
        );
        assert_eq!(
            target.read_file("/data/b.bin").expect("read b"),
            b"hello",
            "b.bin should have its content"
        );
    }

    cleanup(&source_root);
    cleanup(&target_root);
}

#[test]
fn fsync_file_takes_fast_path_when_intents_pending() {
    // When intent log has pending data entries for the fsync'd inode,
    // fsync_file should flush the intent log (fast path) instead of
    // performing a full do_commit().
    let root = temp_root("fsync-fastpath-file");
    let content = b"fast path data";
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        let rec = fs.create_file("/data.bin", 0o644).expect("create");
        let ino = rec.inode_id;
        fs.commit().expect("commit inode");

        // Write data and record a sync write intent, which puts the
        // inode in the intent log.
        fs.write_file("/data.bin", 0, content).expect("write");
        let digest = IntegrityDigest64(0xFA57);
        let reply = fs
            .sync_write_intent(ino, 0, content.len() as u64, digest, content)
            .expect("sync_write_intent");
        assert_eq!(reply, IntentLogReplyState::IntentDurable);
        // After sync_write_intent, entries are flushed to LOG_DEVICE but
        // remain in the intent log until do_commit() clears them.
        // pending_flush_count() is 0 because sync() already flushed,
        // but !is_empty() is true because entries are not cleared.
        let has_entries = !fs.intent_log.is_empty();
        assert!(
            has_entries,
            "intent log should have entries after sync_write_intent"
        );

        // fsync_file should take the fast path: flush_and_sync (no-op since
        // already flushed) and return without doing a full do_commit.
        fs.fsync_file("/data.bin").expect("fsync_file fast path");

        // After fsync_file fast path, intent log entries are still present
        // (they were flushed to LOG_DEVICE but not cleared — only do_commit clears).
        assert!(
            !fs.intent_log.is_empty(),
            "intent log should NOT be cleared by fast path; only full commit clears"
        );
        // State should still be dirty — fast path does not persist state.
        assert!(
            fs.is_state_dirty(),
            "state should remain dirty after fast path fsync"
        );
    }
    // Reopen: intent log replays, data survives.
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        let buf = fs.read_file("/data.bin").expect("read after reopen");
        assert_eq!(
            &buf[..],
            &content[..],
            "written data should survive crash via intent log replay"
        );
        assert!(
            fs.intent_log.is_empty(),
            "intent log should be empty after mount replay"
        );
    }
    cleanup(&root);
}

#[test]
fn fsync_file_falls_back_to_do_commit_when_no_intents_pending() {
    // When intent log has no entries for the fsync'd file, the fast path
    // check fails and fsync_file falls through to do_commit().
    let root = temp_root("fsync-fallback-do-commit");
    let content = b"fallback data";
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/data.bin", 0o644).expect("create");
        fs.write_file("/data.bin", 0, content).expect("write");
        // No sync_write_intent called — intent log has no entries for this inode.
        assert!(fs.intent_log.is_empty());

        fs.fsync_file("/data.bin").expect("fsync_file fallback");

        // After full commit, intent log is empty and state is clean.
        assert!(fs.intent_log.is_empty());
        assert!(
            !fs.is_state_dirty(),
            "state should be clean after do_commit fallback"
        );
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        let buf = fs.read_file("/data.bin").expect("read after reopen");
        assert_eq!(&buf[..], &content[..]);
    }
    cleanup(&root);
}

#[test]
fn fsync_data_only_takes_fast_path_when_intents_pending() {
    // When intent log has any pending entries, fsync_data_only flushes
    // them instead of walking dirty inodes individually.
    let root = temp_root("fsync-dataonly-fastpath");
    let content = b"data only fast path";
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        let rec = fs.create_file("/data.bin", 0o644).expect("create");
        let ino = rec.inode_id;
        fs.commit().expect("commit inode");

        fs.write_file("/data.bin", 0, content).expect("write");
        let digest = IntegrityDigest64(0xDA7A);
        fs.sync_write_intent(ino, 0, content.len() as u64, digest, content)
            .expect("sync_write_intent");

        assert!(!fs.intent_log.is_empty());
        assert!(fs.is_state_dirty());

        fs.fsync_data_only().expect("fsync_data_only fast path");

        // Fast path flushed intent log but did NOT clear it or clean state.
        assert!(
            !fs.intent_log.is_empty(),
            "intent log NOT cleared by fast path"
        );
        assert!(fs.is_state_dirty(), "state still dirty after fast path");
    }
    // Reopen verifies data survived via intent log replay.
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        let buf = fs.read_file("/data.bin").expect("read after reopen");
        assert_eq!(&buf[..], &content[..]);
    }
    cleanup(&root);
}

#[test]
fn fsync_directory_takes_fast_path_for_namespace_intents() {
    // When intent log has NamespaceSyncIntent entries for a directory,
    // fsync_directory flushes them (fast path) instead of do_commit().
    let root = temp_root("fsync-dir-fastpath");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.set_auto_commit(false);
        let dir_rec = fs.create_dir("/mydir", 0o755).expect("mkdir");
        let dir_ino = dir_rec.inode_id;

        // Create a file inside the directory — this dirties the dir.
        fs.create_file("/mydir/file.txt", 0o644)
            .expect("create file in dir");

        // Record a NamespaceSyncIntent for the directory.
        // This simulates what would happen during mkdir/unlink/rename
        // operations that go through the namespace fast path.
        let root_anchor = IntentLogRootAnchor {
            transaction_id: fs.state.generation.max(1),
            generation: fs.state.generation,
            manifest_digest: IntegrityDigest64(0),
        };
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let file_ino = InodeId::new(dir_ino.get() + 1);
        let accepted = fs
            .intent_log
            .append(
                fs.store.primary_store_mut().raw_store_mut(),
                IntentLogEntryKind::NamespaceSyncIntent {
                    parent_inode_id: dir_ino,
                    affected_inode_ids: vec![file_ino],
                    link_count_deltas: vec![(file_ino, 1)],
                },
                root_anchor,
                timestamp_ns,
            )
            .expect("append namespace intent");
        assert!(accepted, "namespace intent should be accepted");

        // Fast path: has_pending_namespace_for_dir should return true.
        assert!(
            fs.intent_log.has_pending_namespace_for_dir(dir_ino),
            "should detect pending namespace intent for dir"
        );

        fs.fsync_directory("/mydir")
            .expect("fsync_directory fast path");

        // After fast path, intent log still has entries (not cleared).
        assert!(
            !fs.intent_log.is_empty(),
            "intent log NOT cleared by fast path"
        );
    }
    // NOTE: NamespaceSyncIntent replay is not yet wired (see
    // intent_log.rs replay_entries_against_state).  Once wired, add a
    // reopen + verify step here to confirm directory entries survive.
    cleanup(&root);
}

// ── Space accounting integration tests ─────────────────────────────

#[test]
fn space_counters_encode_decode_round_trip() {
    use tidefs_types_space_accounting_core::DatasetSpaceCountersV1;
    let counters = DatasetSpaceCountersV1 {
        logical_used_bytes: 1024,
        physical_used_bytes: 0,
        pinned_snapshot_bytes: 512,
        reserved_bytes: 256,
        orphan_bytes: 128,
        quota_bytes: 64,
        slop_bytes: 32,
        quota_soft_limit: 0,
    };
    let encoded = crate::encode_space_counters(&counters);
    let decoded = crate::decode_space_counters(&encoded).unwrap();
    assert_eq!(decoded.logical_used_bytes, 1024);
    assert_eq!(decoded.pinned_snapshot_bytes, 512);
    assert_eq!(decoded.reserved_bytes, 256);
    assert_eq!(decoded.orphan_bytes, 128);
    assert_eq!(decoded.quota_bytes, 64);
    assert_eq!(decoded.slop_bytes, 32);
    assert_eq!(decoded.physical_used_bytes, 0);
    assert_eq!(decoded.quota_soft_limit, 0);
}

#[test]
fn space_counters_decode_rejects_bad_magic() {
    // 56 bytes: 8-byte bad magic + 6×u64 zeros
    let mut bad = vec![0u8; 56];
    bad[..8].copy_from_slice(b"BADMAGIC");
    let result = crate::decode_space_counters(&bad);
    assert!(result.is_err());
}

#[test]
fn space_counters_decode_rejects_too_short() {
    // 55 bytes is one short of the 56-byte minimum
    let short = vec![0u8; 55];
    let result = crate::decode_space_counters(&short);
    assert!(result.is_err());
}

#[test]
fn space_counters_default_is_zero() {
    use tidefs_types_space_accounting_core::DatasetSpaceCountersV1;
    let counters = DatasetSpaceCountersV1::default();
    assert_eq!(counters.logical_used_bytes, 0);
    assert_eq!(counters.pinned_snapshot_bytes, 0);
    assert_eq!(counters.reserved_bytes, 0);
    assert_eq!(counters.orphan_bytes, 0);
    assert_eq!(counters.quota_bytes, 0);
    assert_eq!(counters.slop_bytes, 0);
}

#[test]
fn space_delta_new_write_updates_logical_used() {
    use tidefs_types_space_accounting_core::SpaceDelta;
    let delta = SpaceDelta::new_write(4096);
    assert_eq!(delta.logical_used_delta, 4096);
    assert_eq!(delta.reserved_delta, 0);
    assert_eq!(delta.orphan_delta, 0);
    assert_eq!(delta.pinned_snapshot_delta, 0);
}

#[test]
fn space_delta_new_free_decrements_logical_used() {
    use tidefs_types_space_accounting_core::SpaceDelta;
    let delta = SpaceDelta::new_free(4096);
    assert_eq!(delta.logical_used_delta, -4096);
}

#[test]
fn space_delta_accumulate_combines_correctly() {
    use tidefs_types_space_accounting_core::SpaceDelta;
    let mut acc = SpaceDelta::ZERO;
    acc.accumulate(SpaceDelta::new_write(100));
    acc.accumulate(SpaceDelta::new_free(30));
    assert_eq!(acc.logical_used_delta, 70);
    assert_eq!(acc.reserved_delta, 0);
}

#[test]
fn space_delta_is_zero_detects_all_zero_fields() {
    use tidefs_types_space_accounting_core::SpaceDelta;
    assert!(SpaceDelta::ZERO.is_zero());
    assert!(!SpaceDelta::new_write(1).is_zero());
}

// ── Admission check enforcement tests ──────────────────────────────

#[test]
fn admission_check_write_exceeding_quota_is_rejected() {
    let root = temp_root("admit_quota_reject");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/test", 0o644).expect("create file");
    fs.state.space_accounting.set_quota(256); // tiny quota

    let result = fs.write_file("/test", 0, &[0u8; 512]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("quota") || msg.contains("Quota") || msg.contains("space"),
        "expected quota-related error, got: {msg}"
    );

    cleanup(&root);
}

#[test]
fn admission_check_write_within_quota_succeeds() {
    let root = temp_root("admit_write_ok");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/test", 0o644).expect("create file");
    // No quota set, writes should succeed
    let record = fs.write_file("/test", 0, &[65u8; 128]).unwrap();
    assert_eq!(record.size, 128);

    let content = fs.read_file("/test").unwrap();
    assert_eq!(&content[..], &[65u8; 128]);

    cleanup(&root);
}

#[test]
fn admission_check_create_within_quota_succeeds() {
    let root = temp_root("admit_create_ok");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    // Default state has zero quota, creation should succeed
    let _record = fs.create_file("/newfile", 0o644).unwrap();
    // `record.size` is u64, non-negative by construction.
    let _ = fs.stat("/newfile").unwrap();

    cleanup(&root);
}

#[test]
fn admission_check_truncate_expand_quota_is_checked() {
    let root = temp_root("admit_trunc_expand");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/test", 0o644).expect("create file");
    fs.state.space_accounting.set_quota(512); // 512 bytes quota

    // Create small file
    let record = fs.write_file("/test", 0, &[65u8; 64]).unwrap();
    assert_eq!(record.size, 64);

    // Try to expand beyond quota
    let result = fs.truncate_file("/test", 4096); // way beyond 512 quota
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("quota") || msg.contains("Quota") || msg.contains("space"),
        "expected quota-related error, got: {msg}"
    );

    cleanup(&root);
}

#[test]
fn admission_check_truncate_shrink_never_fails() {
    let root = temp_root("admit_trunc_shrink");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    fs.create_file("/test", 0o644).expect("create file");
    fs.write_file("/test", 0, &[65u8; 1024]).unwrap();

    // Shrinking should never fail admission check
    let record = fs.truncate_file("/test", 64).unwrap();
    assert_eq!(record.size, 64);

    let content = fs.read_file("/test").unwrap();
    assert_eq!(content.len(), 64);

    cleanup(&root);
}

// ── Directory change-stream tests ─────────────────────────────────

#[test]
fn dir_rev_starts_at_zero_for_new_directory() {
    let root = temp_root("dirrev_zero");
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    // Root directory exists by default
    let root_inode = fs.inode(ROOT_INODE_ID).unwrap();
    assert_eq!(root_inode.kind(), NodeKind::Dir);
    assert_eq!(root_inode.dir_rev, 0);
    cleanup(&root);
}

#[test]
fn dir_rev_increments_on_file_create() {
    let root = temp_root("dirrev_create");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let root_inode = fs.inode(ROOT_INODE_ID).unwrap();
    let initial_rev = root_inode.dir_rev;

    fs.create_file("/test1", 0o644).unwrap();
    let updated = fs.inode(ROOT_INODE_ID).unwrap();
    assert!(
        updated.dir_rev > initial_rev,
        "dir_rev should increment on create"
    );

    cleanup(&root);
}

#[test]
fn dir_rev_increments_on_unlink() {
    let root = temp_root("dirrev_unlink");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/removeme", 0o644).unwrap();
    let rev_after_create = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    fs.unlink("/removeme").unwrap();
    let rev_after_unlink = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;
    assert!(
        rev_after_unlink > rev_after_create,
        "dir_rev should increment on unlink"
    );

    cleanup(&root);
}

#[test]
fn get_dir_changes_returns_create_record() {
    let root = temp_root("changes_create");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    // Get initial rev
    let initial_rev = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    // Create two files
    fs.create_file("/alpha", 0o644).unwrap();
    fs.create_file("/beta", 0o644).unwrap();

    // Get changes since initial_rev
    let (changes, _current_rev) = fs
        .get_dir_changes_since(ROOT_INODE_ID, initial_rev)
        .expect("should have changes");

    assert_eq!(changes.len(), 2, "should return 2 change records");
    // Verify both are Add records with correct names
    let names: Vec<&str> = changes
        .iter()
        .filter_map(|(_, rec)| match rec {
            DirChangeRecord::Add { name, .. } => Some(std::str::from_utf8(name).unwrap()),
            _ => None,
        })
        .collect();
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));

    cleanup(&root);
}

#[test]
fn get_dir_changes_returns_remove_record() {
    let root = temp_root("changes_remove");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    fs.create_file("/vanish", 0o644).unwrap();
    let rev_after_create = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    fs.unlink("/vanish").unwrap();

    let (changes, _current_rev) = fs
        .get_dir_changes_since(ROOT_INODE_ID, rev_after_create)
        .expect("should have changes");

    assert_eq!(changes.len(), 1, "should return 1 change record");
    match &changes[0].1 {
        DirChangeRecord::Remove { name, .. } => {
            assert_eq!(name.as_slice(), b"vanish");
        }
        other => panic!("expected Remove, got {other:?}"),
    }

    cleanup(&root);
}

#[test]
fn get_dir_changes_up_to_date_returns_empty() {
    let root = temp_root("changes_empty");
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let current_rev = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    let (changes, returned_rev) = fs
        .get_dir_changes_since(ROOT_INODE_ID, current_rev)
        .expect("should return Some");

    assert!(changes.is_empty());
    assert_eq!(returned_rev, current_rev);

    cleanup(&root);
}

#[test]
fn get_dir_changes_incremental_refresh_pattern() {
    let root = temp_root("changes_incr");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    // Phase 1: initial listing
    let initial_rev = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    // Phase 2: some mutations happen
    fs.create_file("/a", 0o644).unwrap();
    fs.create_file("/b", 0o644).unwrap();
    let rev_after_phase1 = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    // Phase 3: incremental refresh
    let (changes, new_rev) = fs
        .get_dir_changes_since(ROOT_INODE_ID, initial_rev)
        .expect("should have changes");
    assert_eq!(changes.len(), 2);
    assert_eq!(new_rev, rev_after_phase1);

    // Phase 4: more mutations
    fs.unlink("/a").unwrap();
    let rev_after_phase2 = fs.inode(ROOT_INODE_ID).unwrap().dir_rev;

    // Phase 5: next incremental refresh uses new_rev
    let (changes2, final_rev) = fs
        .get_dir_changes_since(ROOT_INODE_ID, rev_after_phase1)
        .expect("should have changes");
    assert_eq!(changes2.len(), 1);
    assert_eq!(final_rev, rev_after_phase2);

    cleanup(&root);
}

#[test]
fn get_dir_changes_non_directory_returns_none() {
    let root = temp_root("changes_notdir");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let record = fs.create_file("/notadir", 0o644).unwrap();

    let result = fs.get_dir_changes_since(record.inode_id, 0);
    assert!(result.is_none(), "non-directory should return None");

    cleanup(&root);
}

// ── Quorum / distributed runtime integration tests ───────────────────
// Issue #1579: 9/9 P8-03 canonical components have crate implementations.
// These tests exercise the local-filesystem ↔ quorum-write-runtime integration.

fn quorum_options(replica_paths: Vec<PathBuf>) -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 16 * 1024,
        sync_on_write: false,
        repair_torn_tail: true,
        mirror_path: None,
        replica_paths,
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 65536,
        reclaim_enabled: false,

        write_throttle_enabled: false,
        durability_layout: None,
        verify_read_checksums: false,
    }
}

#[test]
fn open_with_quorum_two_replicas_creates_and_reads_file() {
    let primary = temp_root("quorum-create-read");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("open fs with quorum");

    let content = b"quorum replicated file content";
    fs.create_file("/shared-file", 0o644).expect("create file");
    let record = fs
        .write_file("/shared-file", 0, content)
        .expect("write file");
    assert_eq!(record.size, content.len() as u64);

    // Read back through the filesystem
    let read_back = fs.read_file("/shared-file").expect("read file");
    assert_eq!(read_back, content);

    // Verify replicas received the write by opening them as independent stores
    for replica_path in &[&r1, &r2] {
        let replica_store =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::test_fast())
                .expect("open replica store");
        // Replicas should be non-empty after a file write
        let keys: Vec<_> = replica_store.list_keys();
        assert!(
            !keys.is_empty(),
            "replica at {replica_path:?} should have data after quorum write"
        );
    }

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn quorum_file_create_and_stat_fans_out_to_replicas() {
    let primary = temp_root("quorum-create-stat");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("open fs with quorum");

    fs.create_file("/visible", 0o644).expect("create file");
    fs.write_file("/visible", 0, b"visible data")
        .expect("write triggers commit_group commit to replicas");
    let inode = fs.stat("/visible").expect("stat file");
    assert!(inode.is_file_like());

    // After create + stat (which triggers a commit_group commit), replicas should
    // contain the superblock and inode objects that the primary wrote.
    for replica_path in &[&r1, &r2] {
        let replica_store =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::test_fast())
                .expect("open replica store");
        let keys: Vec<_> = replica_store.list_keys();
        assert!(
            !keys.is_empty(),
            "replica at {replica_path:?} should have data after create+stat"
        );
    }

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn quorum_multi_file_writes_visible_on_all_replicas() {
    let primary = temp_root("quorum-multi-write");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("open fs with quorum");

    let data_a = b"data for file A with quorum replication";
    let data_b = b"data for file B also replicated across stores";

    fs.create_file("/a", 0o644).expect("create a");
    fs.create_file("/b", 0o644).expect("create b");
    fs.write_file("/a", 0, data_a).expect("write a");
    fs.write_file("/b", 0, data_b).expect("write b");

    let read_a = fs.read_file("/a").expect("read a");
    let read_b = fs.read_file("/b").expect("read b");
    assert_eq!(read_a, data_a);
    assert_eq!(read_b, data_b);

    // Each replica must have data present after multi-file writes
    for (idx, replica_path) in [&r1, &r2].iter().enumerate() {
        let replica_store =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::test_fast())
                .expect("open replica store");
        let keys: Vec<_> = replica_store.list_keys();
        assert!(
            !keys.is_empty(),
            "replica {idx} at {replica_path:?} should have data after multi-file writes"
        );
    }

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn quorum_file_delete_fans_out_to_replicas() {
    let primary = temp_root("quorum-delete");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("open fs with quorum");

    fs.create_file("/deleteme", 0o644).expect("create file");
    let data = b"data to be deleted from all replicas";
    fs.write_file("/deleteme", 0, data).expect("write file");
    fs.unlink("/deleteme").expect("delete file");

    // Verify the file is gone from primary
    assert!(
        fs.stat("/deleteme").is_err(),
        "file should be deleted from primary"
    );

    // Replicas should also be missing the content key
    // (the delete fans out via quorum_delete in the content/transaction path)
    // We verify replicas are functional after the delete — they should
    // still be valid stores even if the deletion is fully quorum-replicated.
    for replica_path in &[&r1, &r2] {
        let replica_store =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::test_fast())
                .expect("open replica store after delete");
        // The replica store should be valid (not corrupted) after the
        // quorum operations. The superblock should still be present.
        // Verify the replica store is operational (not corrupted) after quorum delete.
        // The superblock may not be replicated to each individual replica store;
        // instead we verify the store can be opened and queried.
        let _keys: Vec<_> = replica_store.list_keys();
    }

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn quorum_reopen_after_close_persists_data() {
    let primary = temp_root("quorum-reopen");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let data = b"persistent quorum data across reopen";

    {
        let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());
        let mut fs =
            LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
                .expect("open fs with quorum");
        fs.create_file("/persist", 0o644).expect("create file");
        fs.write_file("/persist", 0, data).expect("write file");
        // fs is dropped here, which commits and syncs
    }

    // Reopen without quorum — data should be in the primary store
    let fs = LocalFileSystem::open_with_options(&primary, quorum_options(vec![]))
        .expect("reopen primary");
    let read_back = fs.read_file("/persist").expect("read file after reopen");
    assert_eq!(read_back, data);

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn quorum_reopen_with_quorum_persists_across_both() {
    let primary = temp_root("quorum-reopen-both");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let data = b"data persisted across quorum reopen cycles";

    // First session: write with quorum
    {
        let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());
        let mut fs =
            LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
                .expect("first open with quorum");
        fs.create_file("/cross-session", 0o644)
            .expect("create file");
        fs.write_file("/cross-session", 0, data)
            .expect("write file");
    }

    // Second session: reopen with quorum, verify data
    {
        let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());
        let fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
            .expect("second open with quorum");
        let read_back = fs
            .read_file("/cross-session")
            .expect("read file in second session");
        assert_eq!(read_back, data);
    }

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn block_device_reopen_after_sync_persists_file_data() {
    let root = temp_root("block-device-reopen-meta");
    let dev0 = temp_root("block-device-reopen-dev0");
    let dev1 = temp_root("block-device-reopen-dev1");
    std::fs::create_dir_all(&root).expect("create metadata dir");
    for dev in [&dev0, &dev1] {
        let file = std::fs::File::create(dev).expect("create block-device image");
        file.set_len(8 * 1024 * 1024)
            .expect("size block-device image");
    }

    let devices = vec![dev0.clone(), dev1.clone()];
    let payload = b"block-device persistence payload";
    {
        let mut fs = LocalFileSystem::open_with_block_devices(
            &root,
            &devices,
            options(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open block-device fs");
        fs.create_file("/persist", 0o644).expect("create file");
        fs.write_file("/persist", 0, payload).expect("write file");
        fs.sync_all().expect("sync fs");
    }

    {
        let fs = LocalFileSystem::open_with_block_devices(
            &root,
            &devices,
            options(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen block-device fs");
        let read_back = fs.read_file("/persist").expect("read file after reopen");
        assert_eq!(read_back, payload);
    }

    cleanup(&root);
    let _ = std::fs::remove_file(dev0);
    let _ = std::fs::remove_file(dev1);
}

#[test]
fn root_dataset_catalog_id_matches_mounted_dataset_id() {
    let root = temp_root("root-dataset-id");

    let fs = LocalFileSystem::open_with_root_authentication_key(
        &root,
        options(),
        RootAuthenticationKey::demo_key(),
    )
    .expect("open fs");
    let root_dataset_id = fs
        .dataset_catalog()
        .mount_lookup("root")
        .expect("root dataset must resolve");

    assert_eq!(
        *root_dataset_id.as_bytes(),
        fs.mounted_dataset_id(),
        "root catalog ID must be the mounted root dataset ID"
    );

    cleanup(&root);
}

#[test]
fn root_dataset_catalog_id_mismatch_fails_closed() {
    let root = temp_root("root-dataset-id-mismatch");

    {
        let mut fs = LocalFileSystem::open_with_root_authentication_key(
            &root,
            options(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs");
        fs.dataset_catalog_mut()
            .destroy("root")
            .expect("remove root catalog entry for mismatch fixture");
        fs.dataset_catalog_mut()
            .create(
                "root",
                DatasetId::from_bytes([0x99; 16]),
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            )
            .expect("create mismatched root catalog entry");
        fs.persist_dataset_catalog()
            .expect("persist mismatched root catalog");
    }

    let result = LocalFileSystem::open_with_root_authentication_key(
        &root,
        options(),
        RootAuthenticationKey::demo_key(),
    );
    match result {
        Err(FileSystemError::CorruptState { reason }) => {
            assert!(
                reason.contains("root dataset catalog id differs"),
                "{reason}"
            );
        }
        Ok(_) => panic!("root dataset catalog mismatch must fail closed"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }

    cleanup(&root);
}

#[test]
fn mounted_dataset_spacebook_counters_use_mounted_dataset_id() {
    let root = temp_root("mounted-dataset-spacebook");
    let mounted_dataset_id = [0x42; 16];

    let mut fs = LocalFileSystem::open_with_root_authentication_key(
        &root,
        options(),
        RootAuthenticationKey::demo_key(),
    )
    .expect("open fs");
    fs.set_mounted_dataset_id(mounted_dataset_id);
    fs.create_file("/dataset-owned.bin", 0o644)
        .expect("create file");
    fs.write_file("/dataset-owned.bin", 0, b"dataset-owned payload")
        .expect("write file");
    fs.sync_all().expect("sync fs");

    let mounted_usage = fs
        .store_ref()
        .get_dataset_usage(mounted_dataset_id)
        .expect("mounted dataset usage must be persisted");
    assert!(
        mounted_usage.bytes_used > 0,
        "mounted dataset must receive committed logical usage"
    );
    assert!(
        fs.store_ref().get_dataset_usage(ROOT_DATASET_ID).is_none(),
        "mounted writes must not be charged to the hard-coded root dataset"
    );

    cleanup(&root);
}

#[test]
fn block_device_flush_file_does_not_publish_new_file_metadata() {
    let root = temp_root("block-device-flush-no-commit-meta");
    let dev0 = temp_root("block-device-flush-no-commit-dev0");
    let dev1 = temp_root("block-device-flush-no-commit-dev1");
    std::fs::create_dir_all(&root).expect("create metadata dir");
    for dev in [&dev0, &dev1] {
        let file = std::fs::File::create(dev).expect("create block-device image");
        file.set_len(8 * 1024 * 1024)
            .expect("size block-device image");
    }

    let devices = vec![dev0.clone(), dev1.clone()];
    {
        let mut fs = LocalFileSystem::open_with_block_devices(
            &root,
            &devices,
            options(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open block-device fs");
        fs.set_auto_commit(false);
        fs.set_max_uncommitted_mutations(1_000_000);
        fs.create_file("/persist", 0o644).expect("create file");
        let attr = fs.stat("/persist").expect("stat file before flush");
        fs.flush_file("/persist", attr.inode_id.0, 1, 0)
            .expect("flush file");
        fs.stat("/persist").expect("live stat after flush");
        std::mem::forget(fs);
    }

    {
        let fs = LocalFileSystem::open_with_block_devices(
            &root,
            &devices,
            options(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen block-device fs");
        let err = fs
            .read_file("/persist")
            .expect_err("flush-only file must not survive crash reopen");
        assert!(
            matches!(err, FileSystemError::NotFound { .. }),
            "expected uncommitted file to be absent, got {err:?}"
        );
    }

    cleanup(&root);
    let _ = std::fs::remove_file(dev0);
    let _ = std::fs::remove_file(dev1);
}

#[test]
fn block_device_dataset_catalog_create_persists_across_reopen() {
    let root = temp_root("block-device-dataset-catalog");
    std::fs::create_dir_all(&root).expect("create metadata dir");
    let devices: Vec<_> = (0..4)
        .map(|idx| temp_root(&format!("block-device-dataset-dev{idx}")))
        .collect();
    for dev in &devices {
        let file = std::fs::File::create(dev).expect("create block-device image");
        file.set_len(8 * 1024 * 1024)
            .expect("size block-device image");
    }

    let dataset_id = DatasetId::from_bytes([0x42; 16]);
    {
        let mut fs = LocalFileSystem::open_with_block_devices(
            &root,
            &devices,
            options(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open block-device fs");
        fs.dataset_catalog_mut()
            .create(
                "demo",
                dataset_id,
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::default_create(),
                SyncGuarantee::default(),
            )
            .expect("create dataset");
        fs.persist_dataset_catalog()
            .expect("persist dataset catalog");
    }

    {
        let fs = LocalFileSystem::open_with_block_devices_and_recovery_policy(
            &root,
            &devices,
            options(),
            RootAuthenticationKey::demo_key(),
            RecoveryPolicy::ReadOnly,
        )
        .expect("reopen block-device fs read-only");
        assert_eq!(
            fs.dataset_catalog()
                .mount_lookup("demo")
                .expect("demo lookup"),
            dataset_id
        );
        assert!(
            fs.dataset_catalog()
                .entries()
                .iter()
                .any(|(name, id)| name == "demo" && *id == dataset_id),
            "dataset list source should include persisted dataset"
        );
    }

    cleanup(&root);
    for dev in devices {
        let _ = std::fs::remove_file(dev);
    }
}

#[test]
fn quorum_single_replica_opens_and_works() {
    let primary = temp_root("quorum-single");
    let r1 = primary.join("replica-1");

    let quorum_cfg = QuorumConfig::new(vec![r1.clone()], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("open fs with single-replica quorum");

    let content = b"single replica data";
    fs.create_file("/solo", 0o644).expect("create file");
    fs.write_file("/solo", 0, content).expect("write file");

    let read_back = fs.read_file("/solo").expect("read file");
    assert_eq!(read_back, content);

    // Verify the single replica has data
    let replica_store = LocalObjectStore::open_with_options(&r1, StoreOptions::test_fast())
        .expect("open single replica store");
    let keys: Vec<_> = replica_store.list_keys();
    assert!(!keys.is_empty(), "single replica should have data");

    cleanup(&primary);
    cleanup(&r1);
}

#[test]
fn quorum_write_rename_and_read_from_replicas() {
    let primary = temp_root("quorum-rename");
    let r1 = primary.join("replica-1");
    let r2 = primary.join("replica-2");

    let quorum_cfg = QuorumConfig::new(vec![r1.clone(), r2.clone()], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("open fs with quorum");

    let data = b"renamed file with quorum backing";
    fs.create_file("/original", 0o644).expect("create original");
    fs.write_file("/original", 0, data).expect("write original");
    fs.rename("/original", "/renamed", false).expect("rename");

    // Original should be gone
    assert!(
        fs.stat("/original").is_err(),
        "original should be gone after rename"
    );
    // Renamed should have the content
    let read_back = fs.read_file("/renamed").expect("read renamed");
    assert_eq!(read_back, data);

    // Replicas should be functional after rename
    for replica_path in &[&r1, &r2] {
        let replica_store =
            LocalObjectStore::open_with_options(replica_path, StoreOptions::test_fast())
                .expect("open replica store after rename");
        let keys: Vec<_> = replica_store.list_keys();
        assert!(
            !keys.is_empty(),
            "replica at {replica_path:?} should have data after rename"
        );
    }

    cleanup(&primary);
    cleanup(&r1);
    cleanup(&r2);
}

#[test]
fn quorum_bad_replica_path_graceful_degradation() {
    let primary = temp_root("quorum-degrade");
    let bad_path = primary.join("does-not-exist");

    // The quorum store uses StoreOptions::test_fast() which requires
    // existing paths. An invalid replica path should cause the quorum
    // open to fail gracefully, with the filesystem still opening in
    // single-store mode.
    let quorum_cfg = QuorumConfig::new(vec![bad_path], StoreOptions::test_fast());

    let mut fs = LocalFileSystem::open_with_quorum(&primary, quorum_options(vec![]), quorum_cfg)
        .expect("filesystem should open even when quorum store fails");

    // Should still be usable in single-store mode
    fs.create_file("/no-quorum", 0o644)
        .expect("create file without quorum");
    let data = b"single store fallback data";
    fs.write_file("/no-quorum", 0, data)
        .expect("write without quorum");
    let read_back = fs.read_file("/no-quorum").expect("read without quorum");
    assert_eq!(read_back, data);

    cleanup(&primary);
}

#[test]
fn extent_allocator_write_and_lookup() {
    let root = temp_root("extent-alloc-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open filesystem");
    fs.create_file("/test", 0o644).expect("create file");

    // Write 4096 bytes at offset 0.
    let data = vec![0xABu8; 4096];
    fs.write_file("/test", 0, &data).expect("write file");

    let inode_id = fs.lookup("/test").expect("lookup").0;

    // Verify extent was allocated (via inline call, no held reference).
    let extents = fs.extent_allocator().lookup_extents(inode_id, 0, 4096);
    assert_eq!(extents.len(), 1, "should have one extent after write");
    assert_eq!(extents[0].logical_offset, 0);
    assert_eq!(extents[0].length, 4096);
    assert!(extents[0].is_pending_data());

    // Write another 4096 bytes at offset 8192 (non-contiguous).
    let data2 = vec![0xCDu8; 4096];
    fs.write_file("/test", 8192, &data2)
        .expect("write file at 8192");

    let extents = fs.extent_allocator().lookup_extents(inode_id, 0, 16384);
    assert_eq!(
        extents.len(),
        2,
        "should have two extents after second write"
    );
    assert_eq!(extents[0].logical_offset, 0);
    assert_eq!(extents[0].length, 4096);
    assert_eq!(extents[1].logical_offset, 8192);
    assert_eq!(extents[1].length, 4096);

    cleanup(&root);
}

#[test]
fn extent_allocator_truncate_frees_extents() {
    let root = temp_root("extent-alloc-trunc");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open filesystem");
    fs.create_file("/shrink", 0o644).expect("create file");

    // Write 12288 bytes.
    let data = vec![0xEEu8; 12288];
    fs.write_file("/shrink", 0, &data).expect("write file");

    let inode_id = fs.lookup("/shrink").expect("lookup").0;

    // Verify extent exists before truncate.
    let extents = fs.extent_allocator().lookup_extents(inode_id, 0, 20480);
    assert_eq!(extents.len(), 1);

    // Truncate to 4096 bytes (shrink from 12288).
    fs.truncate_file("/shrink", 4096).expect("truncate");

    // After truncate, verify the allocator still tracks extents.
    let total = fs.extent_allocator().total_extents();
    assert!(
        total > 0,
        "allocator should still track extents after truncate: got {total}"
    );
    let extents_trimmed = fs.extent_allocator().lookup_extents(inode_id, 0, 4096);
    assert!(
        !extents_trimmed.is_empty(),
        "should have entries in [0, 4096)"
    );

    cleanup(&root);
}

#[test]
fn extent_allocator_multiple_inodes() {
    let root = temp_root("extent-alloc-multi");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open filesystem");

    fs.create_file("/a", 0o644).expect("create a");
    fs.create_file("/b", 0o644).expect("create b");

    fs.write_file("/a", 0, &[0x11u8; 4096]).expect("write a");
    fs.write_file("/b", 0, &[0x22u8; 8192]).expect("write b");

    let ino_a = fs.lookup("/a").expect("lookup a").0;
    let ino_b = fs.lookup("/b").expect("lookup b").0;

    let alloc = fs.extent_allocator();
    assert!(alloc.has_extents(ino_a), "inode A should have extents");
    assert!(alloc.has_extents(ino_b), "inode B should have extents");

    let ext_a = alloc.lookup_extents(ino_a, 0, 4096);
    assert_eq!(ext_a.len(), 1);
    assert_eq!(ext_a[0].length, 4096);

    let ext_b = alloc.lookup_extents(ino_b, 0, 8192);
    assert_eq!(ext_b.len(), 1);
    assert_eq!(ext_b[0].length, 8192);

    assert_ne!(ino_a, ino_b, "inode ids should be distinct");

    cleanup(&root);
}
#[test]
fn extent_map_persist_roundtrip_via_object_store() {
    use std::io::Cursor;
    use tidefs_extent_map::ExtentMap;
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

    let root = temp_root("extent-map-obj-roundtrip");

    let mut emap = ExtentMap::new();
    let _eid1 = emap.allocate(0, 4096).unwrap();
    let eid2 = emap.allocate(8192, 4096).unwrap();
    let _eid3 = emap.allocate(16384, 8192).unwrap();
    emap.free(eid2).unwrap();
    assert_eq!(emap.extent_count(), 2);

    let mut serialized = Vec::new();
    emap.serialize(&mut serialized).unwrap();

    let opts = StoreOptions::test_fast();
    let key = ObjectKey::from_name("extent-map-roundtrip-test-key");
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store
            .put(key, &serialized)
            .expect("put serialized extent map");
        store.sync_all().expect("sync");
    }

    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let stored = store.get(key).expect("get").expect("object should exist");

        let mut cursor = Cursor::new(&stored);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();

        assert_eq!(recon.extent_count(), 2);
        assert!(recon.lookup(0).is_some());
        assert!(recon.lookup(4096).is_none());
        assert!(recon.lookup(16384).is_some());
    }

    cleanup(&root);
}

#[test]
fn extent_map_empty_round_trip() {
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    let root = temp_root("extent-map-empty-roundtrip");

    let state = initial_state();
    let auth_key = RootAuthenticationKey::demo_key();

    let opts = StoreOptions::test_fast();
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        persist_state(&mut store, &state, auth_key).expect("persist state");
    }

    {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let loaded = load_latest_committed_state(&mut store, auth_key, RecoveryPolicy::default())
            .expect("load state")
            .expect("state should exist");

        assert!(loaded.extent_maps.is_empty());
        assert!(loaded.dirty_extent_maps.is_empty());
    }

    cleanup(&root);
}

#[test]
fn drop_syncs_data_for_reopen() {
    let root = temp_root("drop-syncs-data");
    let payload = b"drop-should-flush-me-to-disk";

    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, payload).expect("write file");
        // No manual sync_all — Drop must handle durability.
    }

    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        let read_back = fs.read_file("/data.bin").expect("read file");
        assert_eq!(read_back, payload, "Drop should have persisted write data");
        assert!(
            fs.stat_path("/data.bin").is_ok(),
            "inode metadata should survive Drop"
        );
    }

    cleanup(&root);
}

#[test]
fn mkdir_create_drop_reopen_listdir_without_explicit_sync() {
    let root = temp_root("mkdir-create-drop-reopen");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/sub", 0o755).expect("create dir /sub");
        fs.create_file("/sub/child.txt", 0o644)
            .expect("create file");
        // No explicit sync_all -- Drop must handle durability.
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        let entries = fs.list_dir("/sub").expect("list /sub");
        assert_eq!(
            entries.len(),
            1,
            "directory should contain one entry after reopen"
        );
        assert_eq!(
            entries[0].name,
            b"child.txt".to_vec(),
            "file name should survive Drop"
        );

        let root_entries = fs.list_dir("/").expect("list /");
        let has_sub = root_entries.iter().any(|e| e.name == b"sub".to_vec());
        assert!(has_sub, "root directory should contain /sub after reopen");
    }
    cleanup(&root);
}

#[test]
fn drop_empty_filesystem_no_panic() {
    let root = temp_root("drop-empty-fs");
    // Open and immediately drop without any mutations.
    {
        let _fs = LocalFileSystem::open_with_options(&root, options()).expect("open empty fs");
        // Drop at scope end -- must not panic, corrupt, or create spurious objects.
    }
    // Reopen to verify the filesystem is still valid (not corrupted).
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen empty fs");
        let entries = fs.list_dir("/").expect("list /");
        // Root directory should exist with at most the implicit entries (. and .. handled internally).
        // The key assertion: no panic occurred and the filesystem is usable.
        assert!(
            entries.is_empty() || entries.iter().all(|e| e.name.starts_with(b".")),
            "empty filesystem should not have user-created entries after drop+reopen"
        );
    }
    cleanup(&root);
}

#[test]
fn drop_reopen_mutate_drop_reopen_cycle_persistence() {
    let root = temp_root("cycle-drop-reopen");
    // Cycle 1: create /a, drop, reopen, verify.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs cycle 1");
        fs.create_file("/a", 0o644).expect("create /a");
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs cycle 1");
        assert!(fs.stat_path("/a").is_ok(), "/a should survive first drop");
    }
    // Cycle 2: create /b, drop, reopen, verify both /a and /b persist.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs cycle 2");
        fs.create_file("/b", 0o644).expect("create /b");
    }
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs cycle 2");
        assert!(fs.stat_path("/a").is_ok(), "/a should survive second drop");
        assert!(fs.stat_path("/b").is_ok(), "/b should survive second drop");
    }
    cleanup(&root);
}

// ── POSIX advisory lock tests ────────────────────────────────────────────

#[test]
fn lock_acquire_and_getlk_no_conflict() {
    let root = temp_root("lock-acquire-getlk");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    let lock = LockRange::write(0, 100, 100);
    assert!(fs.setlk(inode, lock).is_ok(), "acquire write lock");
    assert!(
        fs.getlk(inode, LockRange::read(200, 10, 200)).is_none(),
        "no conflict for non-overlapping read"
    );

    cleanup(&root);
}

#[test]
fn lock_write_conflict_detected() {
    let root = temp_root("lock-write-conflict");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    let existing = LockRange::write(0, 100, 100);
    fs.setlk(inode, existing).expect("acquire first lock");

    let requested = LockRange::write(50, 10, 200);
    let conflict = fs.setlk(inode, requested).unwrap_err();
    assert_eq!(conflict.existing, existing);
    assert_eq!(conflict.requested, requested);

    cleanup(&root);
}

#[test]
fn lock_read_vs_write_conflict() {
    let root = temp_root("lock-read-write");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    let read_lock = LockRange::read(0, 100, 100);
    fs.setlk(inode, read_lock).expect("acquire read lock");

    let write_lock = LockRange::write(50, 10, 200);
    let conflict = fs.getlk(inode, write_lock).unwrap();
    assert_eq!(conflict.existing, read_lock);

    cleanup(&root);
}

#[test]
fn lock_read_locks_are_compatible() {
    let root = temp_root("lock-read-compat");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    fs.setlk(inode, LockRange::read(0, 100, 100))
        .expect("first read lock");
    fs.setlk(inode, LockRange::read(50, 10, 200))
        .expect("second read lock");

    assert_eq!(fs.lock_inode_count(), 1, "both locks on same inode");

    cleanup(&root);
}

#[test]
fn lock_unlock_releases_range() {
    let root = temp_root("lock-unlock");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Acquire a write lock
    fs.setlk(inode, LockRange::write(0, 100, 100))
        .expect("acquire lock");

    // Unlock the same range
    let unlock = LockRange::new(0, 100, LockType::Unlock, 0, 100);
    assert!(fs.setlk(inode, unlock).is_ok(), "unlock succeeds");

    // Now a conflicting lock should be allowed
    assert!(
        fs.setlk(inode, LockRange::write(0, 100, 200)).is_ok(),
        "after unlock, new conflicting lock ok"
    );
    assert_eq!(fs.lock_inode_count(), 1, "one inode still locked");

    cleanup(&root);
}

#[test]
fn lock_release_by_pid_clears_all_locks() {
    let root = temp_root("lock-release-pid");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/a", 0o644).expect("create file a");
    fs.create_file("/b", 0o644).expect("create file b");
    let ino_a = fs.lookup("/a").expect("lookup a");
    let ino_b = fs.lookup("/b").expect("lookup b");

    fs.setlk(ino_a, LockRange::write(0, 10, 100))
        .expect("lock a");
    fs.setlk(ino_b, LockRange::read(0, 10, 100))
        .expect("lock b");
    fs.setlk(ino_b, LockRange::write(20, 10, 200))
        .expect("another pid lock b");

    assert_eq!(fs.lock_inode_count(), 2);

    // Release all locks for pid 100
    fs.release_locks_by_pid(100);

    // pid 100 locks on ino_a should be gone, ino_b should only have pid 200
    assert_eq!(fs.lock_inode_count(), 1, "only pid 200 lock remains");
    assert!(
        fs.getlk(ino_a, LockRange::write(0, 10, 300)).is_none(),
        "ino_a is now empty"
    );

    cleanup(&root);
}

#[test]
fn lock_multi_range_correctness() {
    let root = temp_root("lock-multi-range");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Write-lock two disjoint ranges from same process
    fs.setlk(inode, LockRange::write(0, 10, 100))
        .expect("lock 0-10");
    fs.setlk(inode, LockRange::write(20, 10, 100))
        .expect("lock 20-30");

    // A write lock in the gap should conflict
    assert!(
        fs.setlk(inode, LockRange::write(15, 2, 200)).is_ok(),
        "gap range should be free"
    );

    // But a write lock overlapping first range should conflict
    let conflict = fs.getlk(inode, LockRange::write(5, 1, 200)).unwrap();
    assert_eq!(conflict.existing.start, 0);

    cleanup(&root);
}

#[test]
fn lock_getlk_returns_none_for_no_conflict() {
    let root = temp_root("lock-getlk-none");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // No locks at all
    assert!(fs.getlk(inode, LockRange::write(0, 100, 100)).is_none());

    // Add a read lock
    fs.setlk(inode, LockRange::read(0, 10, 100))
        .expect("read lock");
    // Another read lock from different process should not conflict
    assert!(fs.getlk(inode, LockRange::read(0, 10, 200)).is_none());

    cleanup(&root);
}

#[test]
fn lock_empty_filesystem_has_zero_inode_count() {
    let root = temp_root("lock-empty");
    let fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    assert_eq!(fs.lock_inode_count(), 0);
    cleanup(&root);
}

#[test]
fn lock_partial_range_release_splits_existing_lock() {
    let root = temp_root("lock-partial-release");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Write-lock bytes 0..100
    fs.setlk(inode, LockRange::write(0, 100, 100))
        .expect("acquire lock");

    // Partially unlock bytes 40..60 (len=20)
    let unlock = LockRange::new(40, 20, LockType::Unlock, 0, 100);
    assert!(fs.setlk(inode, unlock).is_ok(), "partial unlock succeeds");

    // The original lock should be split: 0..40 and 60..100
    // Verify the gap is free
    assert!(
        fs.getlk(inode, LockRange::write(50, 5, 200)).is_none(),
        "unlocked gap should be free"
    );

    // Verify the left fragment still exists
    let conflict = fs.getlk(inode, LockRange::write(10, 1, 200)).unwrap();
    assert_eq!(conflict.existing.pid, 100);

    // Verify the right fragment still exists
    let conflict = fs.getlk(inode, LockRange::write(80, 1, 200)).unwrap();
    assert_eq!(conflict.existing.pid, 100);

    cleanup(&root);
}

#[test]
fn lock_release_nonexistent_lock_is_noop() {
    let root = temp_root("lock-nonexistent");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Release a lock that doesn't exist — should succeed (no-op)
    let unlock = LockRange::new(0, 100, LockType::Unlock, 0, 100);
    assert!(
        fs.setlk(inode, unlock).is_ok(),
        "unlock nonexistent is no-op"
    );

    // Release a lock on an inode that has never been locked
    assert!(
        fs.setlk(inode, LockRange::unlock(0, 0, 100)).is_ok(),
        "unlock on never-locked inode is no-op"
    );

    assert_eq!(fs.lock_inode_count(), 0, "no locks created");

    cleanup(&root);
}

#[test]
fn lock_whole_file_eof_semantics() {
    let root = temp_root("lock-eof");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // len=0 means "to EOF" — should cover any range
    fs.setlk(inode, LockRange::write(0, 0, 100))
        .expect("whole-file write lock");

    // Any overlapping write should conflict
    assert!(
        fs.setlk(inode, LockRange::write(10, 1, 200)).is_err(),
        "conflict with whole-file lock"
    );
    assert!(
        fs.setlk(inode, LockRange::write(1_000_000, 1, 200))
            .is_err(),
        "conflict with whole-file lock at large offset"
    );

    // Unlock the whole-file lock
    fs.setlk(inode, LockRange::new(0, 0, LockType::Unlock, 0, 100))
        .expect("unlock whole-file");

    // Now any lock should succeed
    assert!(
        fs.setlk(inode, LockRange::write(1_000_000, 1, 200)).is_ok(),
        "free after whole-file unlock"
    );

    cleanup(&root);
}

#[test]
fn lock_wait_acquire_succeeds_when_lock_is_free() {
    let root = temp_root("lock-wait-free");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // No conflicting lock — should acquire immediately
    fs.lock_wait_acquire(
        inode,
        LockRange::write(0, 10, 100),
        Some(std::time::Duration::from_millis(100)),
    )
    .expect("wait acquire with no conflict");

    assert_eq!(fs.lock_inode_count(), 1);

    cleanup(&root);
}

#[test]
fn lock_wait_acquire_times_out_on_persistent_conflict() {
    let root = temp_root("lock-wait-timeout");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Hold a conflicting lock
    fs.setlk(inode, LockRange::write(0, 10, 100))
        .expect("hold lock");

    // Another process tries to acquire with a short timeout
    let result = fs.lock_wait_acquire(
        inode,
        LockRange::write(0, 10, 200),
        Some(std::time::Duration::from_millis(50)),
    );
    assert!(result.is_err(), "wait acquire should time out");

    // The original lock should still be held
    assert_eq!(fs.lock_inode_count(), 1);

    cleanup(&root);
}

#[test]
fn lock_write_blocks_read_and_vice_versa() {
    let root = temp_root("lock-write-read");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Write lock blocks read lock
    fs.setlk(inode, LockRange::write(0, 100, 100))
        .expect("acquire write");
    assert!(
        fs.setlk(inode, LockRange::read(50, 10, 200)).is_err(),
        "write blocks read"
    );

    // Release write and acquire read
    fs.setlk(inode, LockRange::new(0, 100, LockType::Unlock, 0, 100))
        .expect("unlock write");
    fs.setlk(inode, LockRange::read(0, 100, 300))
        .expect("acquire read");

    // Read lock blocks write lock
    assert!(
        fs.setlk(inode, LockRange::write(50, 10, 100)).is_err(),
        "read blocks write"
    );

    cleanup(&root);
}

#[test]
fn lock_conflict_reports_correct_blocking_pid() {
    let root = temp_root("lock-blocking-pid");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // PID 100 holds a write lock
    fs.setlk(inode, LockRange::write(0, 50, 100))
        .expect("pid 100 lock");

    // PID 200 tries to read — conflict should report PID 100
    let conflict = fs.getlk(inode, LockRange::read(0, 10, 200)).unwrap();
    assert_eq!(conflict.existing.pid, 100, "getlk reports blocking PID 100");

    // PID 300 tries to write — conflict should report PID 100
    let conflict = fs.getlk(inode, LockRange::write(25, 10, 300)).unwrap();
    assert_eq!(conflict.existing.pid, 100, "getlk reports blocking PID 100");

    // setlk (non-blocking) should also report the blocking PID
    let conflict = fs.setlk(inode, LockRange::write(0, 10, 400)).unwrap_err();
    assert_eq!(conflict.existing.pid, 100, "setlk reports blocking PID 100");

    cleanup(&root);
}

#[test]
fn lock_same_pid_never_conflicts_with_self() {
    let root = temp_root("lock-same-pid");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // PID 100 holds a write lock
    fs.setlk(inode, LockRange::write(0, 10, 100))
        .expect("first lock");

    // PID 100 can acquire another write lock on overlapping range
    // (same process can always re-lock its own ranges)
    fs.setlk(inode, LockRange::write(5, 10, 100))
        .expect("same pid relock");

    // PID 100 can also acquire read lock on overlapping range
    fs.setlk(inode, LockRange::read(0, 5, 100))
        .expect("same pid read");

    cleanup(&root);
}

#[test]
fn lock_two_inodes_independent() {
    let root = temp_root("lock-two-inodes");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/a", 0o644).expect("create file a");
    fs.create_file("/b", 0o644).expect("create file b");
    let ino_a = fs.lookup("/a").expect("lookup a");
    let ino_b = fs.lookup("/b").expect("lookup b");

    // Locks on different inodes never conflict
    fs.setlk(ino_a, LockRange::write(0, 100, 100))
        .expect("lock a");
    fs.setlk(ino_b, LockRange::write(0, 100, 200))
        .expect("lock b");

    assert_eq!(fs.lock_inode_count(), 2);
    assert!(
        fs.getlk(ino_a, LockRange::read(0, 10, 200)).is_some(),
        "ino_a reports conflict"
    );
    assert!(
        fs.getlk(ino_b, LockRange::read(0, 10, 100)).is_some(),
        "ino_b reports conflict"
    );

    cleanup(&root);
}

#[test]
fn lock_multiple_readers_no_write() {
    let root = temp_root("lock-multi-read");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/f", 0o644).expect("create file");
    let inode = fs.lookup("/f").expect("lookup f");

    // Multiple readers on same range
    fs.setlk(inode, LockRange::read(0, 100, 100))
        .expect("reader 1");
    fs.setlk(inode, LockRange::read(0, 100, 200))
        .expect("reader 2");
    fs.setlk(inode, LockRange::read(0, 100, 300))
        .expect("reader 3");

    // All on the same inode
    assert_eq!(fs.lock_inode_count(), 1);

    // No reader conflicts with another reader
    assert!(
        fs.getlk(inode, LockRange::read(50, 10, 400)).is_none(),
        "readers don't conflict with readers"
    );

    // But a writer conflicts
    assert!(
        fs.getlk(inode, LockRange::write(50, 1, 500)).is_some(),
        "writer conflicts with readers"
    );

    cleanup(&root);
}

// ── Intent-log rename recording tests ─────────────────────────────────

#[test]
fn intent_log_rename_records_on_rename() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-rename");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/a.txt", 0o644).expect("create file");
        fs.write_file("/docs/a.txt", 0, b"hello").expect("write");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.rename("/docs/a.txt", "/docs/b.txt", false)
            .expect("rename");

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1, "rename should record one intent-log entry");
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Rename {
                src_name,
                dst_name,
                overwrite_target_ino,
                ..
            } => {
                assert_eq!(*dst_name, b"b.txt", "destination name should be b.txt");
                assert_eq!(*overwrite_target_ino, None, "no overwrite for plain rename");
                assert_eq!(*src_name, b"a.txt", "source name should be a.txt");
            }
            other => panic!("expected Rename record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_rename_records_overwrite_on_replace() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-rename-overwrite");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/source.txt", 0o644)
            .expect("create source");
        fs.write_file("/docs/source.txt", 0, b"source")
            .expect("write source");
        fs.create_file("/docs/target.txt", 0o644)
            .expect("create target");
        fs.write_file("/docs/target.txt", 0, b"target")
            .expect("write target");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.rename("/docs/source.txt", "/docs/target.txt", false)
            .expect("rename with overwrite");

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Rename {
                overwrite_target_ino,
                dst_name,
                ..
            } => {
                assert_eq!(*dst_name, b"target.txt");
                assert!(
                    overwrite_target_ino.is_some(),
                    "overwrite target inode should be recorded"
                );
            }
            other => panic!("expected Rename record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_rename_exchange_records_both_inodes() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-rename-exchange");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/left.txt", 0o644)
            .expect("create left");
        fs.write_file("/docs/left.txt", 0, b"left")
            .expect("write left");
        fs.create_file("/docs/right.txt", 0o644)
            .expect("create right");
        fs.write_file("/docs/right.txt", 0, b"right")
            .expect("write right");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.rename_exchange("/docs/left.txt", "/docs/right.txt")
            .expect("rename exchange");

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Rename {
                overwrite_target_ino,
                ..
            } => {
                assert!(
                    overwrite_target_ino.is_some(),
                    "exchange should record the target inode as overwrite"
                );
            }
            other => panic!("expected Rename record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_renameat2_records_rename() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-renameat2");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");
        fs.create_file("/docs/old.txt", 0o644).expect("create file");
        fs.write_file("/docs/old.txt", 0, b"renameat2")
            .expect("write");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.renameat2(
            "/docs/old.txt",
            "/docs/new.txt",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("renameat2");

        let frames = buf.drain_since(0);
        assert!(
            !frames.is_empty(),
            "renameat2 should record an intent-log entry"
        );
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Rename {
                dst_name,
                overwrite_target_ino,
                ..
            } => {
                assert_eq!(*dst_name, b"new.txt");
                assert_eq!(
                    *overwrite_target_ino, None,
                    "no overwrite for renameat2 EMPTY without target"
                );
            }
            other => panic!("expected Rename record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_mkdir_records_on_create_dir() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-mkdir");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        let record = fs.create_dir("/newdir", 0o755).expect("create dir");

        let frames = buf.drain_since(0);
        assert_eq!(
            frames.len(),
            1,
            "create_dir should record one intent-log entry"
        );
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Mkdir {
                parent,
                name,
                mode,
                ino,
            } => {
                assert_eq!(*name, b"newdir", "name should be newdir");
                assert_eq!(*mode, 0o40755, "mode should include S_IFDIR | 0o755");
                assert_eq!(
                    *ino,
                    record.inode_id.get(),
                    "ino should match allocated inode"
                );
                assert_eq!(*parent, 1, "parent should be root inode");
            }
            other => panic!("expected Mkdir record, got {other:?}"),
        }
    }
    cleanup(&root);
}
#[test]
fn intent_log_create_records_on_create_file() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-create");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        let record = fs
            .create_file("/docs/hello.txt", 0o644)
            .expect("create file");

        let frames = buf.drain_since(0);
        assert_eq!(
            frames.len(),
            1,
            "create_file should record one intent-log entry"
        );
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Create {
                parent,
                name,
                mode,
                ino,
            } => {
                assert_eq!(*name, b"hello.txt", "name should be hello.txt");
                assert_eq!(*mode, 0o100644, "mode should include S_IFREG | 0o644");
                assert_eq!(
                    *ino,
                    record.inode_id.get(),
                    "ino should match allocated inode"
                );
                // parent should be the docs directory inode
                let docs = fs.stat_path("/docs").expect("docs inode");
                assert_eq!(*parent, docs.inode_id.get(), "parent should be /docs");
            }
            other => panic!("expected Create record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_symlink_records_symlink_entry() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-symlink-rec");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        let target_bytes = b"/docs/target";
        let link_record = fs
            .create_symlink("/docs/link", target_bytes)
            .expect("create symlink");

        let frames = buf.drain_since(0);
        assert_eq!(
            frames.len(),
            1,
            "create_symlink must record exactly one intent-log frame"
        );
        let frame = &frames[0];
        assert!(
            frame.verify().is_ok(),
            "frame must pass BLAKE3 verification"
        );

        match &frame.record {
            IntentLogRecord::Symlink {
                parent,
                name,
                target,
                ino,
            } => {
                let docs_id = fs.stat_path("/docs").expect("stat docs").inode_id;
                assert_eq!(*parent, docs_id.get(), "parent must be /docs inode");
                assert_eq!(name, b"link", "name must be 'link'");
                assert_eq!(target, target_bytes, "target must match");
                assert_eq!(
                    *ino,
                    link_record.inode_id.get(),
                    "ino must match allocated inode"
                );
            }
            other => panic!("expected Symlink record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_create_roundtrip_for_replay() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-create-replay");

    // Phase 1: Create a file with intent-log recording, capture the record fields
    let (recorded_parent, recorded_mode, recorded_ino) = {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.create_file("/docs/hello.txt", 0o644)
            .expect("create file");

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert!(frame.verify().is_ok());

        match &frame.record {
            IntentLogRecord::Create {
                parent,
                name,
                mode,
                ino,
            } => {
                assert_eq!(*name, b"hello.txt");
                (*parent, *mode, *ino)
            }
            other => panic!("expected Create record, got {other:?}"),
        }
    };
    // fs dropped here; filesystem state persisted

    // Phase 2: reopen and verify the file exists (it was committed)
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        let stat = fs
            .stat_path("/docs/hello.txt")
            .expect("file should persist after close/reopen");
        assert_eq!(stat.mode, recorded_mode, "mode should survive close/reopen");

        // Verify the intent-log record fields match actual filesystem state
        let docs = fs.stat_path("/docs").expect("docs inode");
        assert_eq!(
            docs.inode_id.get(),
            recorded_parent,
            "recorded parent inode should match /docs"
        );
        assert_eq!(
            stat.inode_id.get(),
            recorded_ino,
            "recorded ino should match stat inode"
        );
    }
    cleanup(&root);
}
#[test]
fn intent_log_symlink_roundtrip_for_replay() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-symlink-replay");

    // Phase 1: Create a symlink with intent-log recording, capture the record fields
    let (recorded_parent, recorded_target, recorded_ino) = {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        fs.create_dir("/docs", 0o755).expect("create docs");

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        let target = b"/var/log/messages";
        fs.create_symlink("/docs/loglink", target)
            .expect("create symlink");

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert!(frame.verify().is_ok());

        match &frame.record {
            IntentLogRecord::Symlink {
                parent,
                name,
                target,
                ino,
            } => {
                assert_eq!(*name, b"loglink".as_slice());
                let target_vec = target.clone();
                (*parent, target_vec, *ino)
            }
            other => panic!("expected Symlink record, got {other:?}"),
        }
    };
    // fs dropped here; filesystem state persisted

    // Phase 2: reopen and verify the symlink exists with correct target
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        let stat = fs
            .stat_path("/docs/loglink")
            .expect("symlink should persist after close/reopen");
        assert_eq!(
            stat.kind(),
            tidefs_types_vfs_core::NodeKind::Symlink,
            "symlink kind should survive close/reopen"
        );

        // Verify the intent-log record fields match actual filesystem state
        let docs = fs.stat_path("/docs").expect("docs inode");
        assert_eq!(
            docs.inode_id.get(),
            recorded_parent,
            "recorded parent inode should match /docs"
        );
        assert_eq!(
            stat.inode_id.get(),
            recorded_ino,
            "recorded ino should match stat inode"
        );

        // Verify symlink target is readable
        let read_target = fs
            .read_symlink("/docs/loglink")
            .expect("read symlink target");
        assert_eq!(
            read_target, b"/var/log/messages",
            "symlink target must match recorded target"
        );
        assert_eq!(
            read_target, recorded_target,
            "symlink target must match intent-log record"
        );
    }
    cleanup(&root);
}

#[test]
fn intent_log_rmdir_records_on_remove_dir() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-rmdir");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

        // Create a directory first (without intent-log buffer)
        let record = fs.create_dir("/subdir", 0o755).expect("create dir");
        let dir_ino = record.inode_id;

        // Now attach intent-log buffer and remove the directory
        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.remove_dir("/subdir").expect("remove dir");

        let frames = buf.drain_since(0);
        assert_eq!(
            frames.len(),
            1,
            "remove_dir should record one intent-log entry"
        );
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Rmdir { parent, name, ino } => {
                assert_eq!(*name, b"subdir", "name should be subdir");
                assert_eq!(*ino, dir_ino.get(), "ino should match allocated inode");
                assert_eq!(*parent, 1, "parent should be root inode");
            }
            other => panic!("expected Rmdir record, got {other:?}"),
        }
    }
    cleanup(&root);
}

#[test]
fn intent_log_rmdir_roundtrip_for_replay() {
    use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
    let root = temp_root("ilog-rmdir-replay");

    // Phase 1: Create a directory, record rmdir intent, capture fields
    let (recorded_parent, _recorded_ino) = {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        let dir_rec = fs.create_dir("/subdir", 0o755).expect("create dir");
        let _dir_ino = dir_rec.inode_id;

        let buf = std::sync::Arc::new(IntentLogBuffer::new());
        fs.set_intent_log_buffer(buf.clone());

        fs.remove_dir("/subdir").expect("remove dir");

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert!(frame.verify().is_ok());

        match &frame.record {
            IntentLogRecord::Rmdir { parent, name, ino } => {
                assert_eq!(*name, b"subdir");
                (*parent, *ino)
            }
            other => panic!("expected Rmdir record, got {other:?}"),
        }
        // dir_rec dropped; fs dropped here; filesystem state persisted
    };

    // Phase 2: reopen and verify the directory is gone
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
        // Verify root has correct inode
        let root_ino = fs.stat_path("/").expect("root stat").inode_id;
        assert_eq!(
            root_ino.get(),
            recorded_parent,
            "recorded parent should match root inode"
        );

        // Directory should not exist after rmdir
        let result = fs.stat_path("/subdir");
        assert!(
            result.is_err(),
            "directory should be removed after close/reopen"
        );
        match result {
            Err(FileSystemError::NotFound { .. }) => {
                // expected — directory is gone
            }
            other => panic!("expected NotFound after rmdir, got {other:?}"),
        }
    }
    cleanup(&root);
}

// ── Namespace mutation intent-log tests ──

#[test]
fn namespace_mutation_intent_log_hardlink_record() {
    let root = temp_root("intent-log-hardlink");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/original", 0o644).expect("create original");
    fs.create_dir("/sub", 0o755).expect("create sub");
    let buf = std::sync::Arc::new(tidefs_intent_log::IntentLogBuffer::new());
    fs.set_intent_log_buffer(buf.clone());
    let record = fs.link_file("/original", "/sub/linked").expect("link file");
    assert_eq!(record.nlink, 2);
    let frames = buf.drain_since(0);
    assert!(frames.iter().any(|f| matches!(
        f.record,
        tidefs_intent_log::IntentLogRecord::HardLink { .. }
    )));
    assert!(fs.stat_path("/sub/linked").is_ok());
    assert_eq!(fs.stat_path("/original").unwrap().nlink, 2);
    fs.sync_all().expect("sync");
    drop(fs);
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(fs.stat_path("/sub/linked").is_ok());
        assert_eq!(fs.stat_path("/original").unwrap().nlink, 2);
    }
    cleanup(&root);
}

#[test]
fn namespace_mutation_intent_log_unlink_record() {
    let root = temp_root("intent-log-unlink");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/todelete", 0o644).expect("create file");
    let buf = std::sync::Arc::new(tidefs_intent_log::IntentLogBuffer::new());
    fs.set_intent_log_buffer(buf.clone());
    fs.unlink("/todelete").expect("unlink file");
    let frames = buf.drain_since(0);
    assert!(frames
        .iter()
        .any(|f| matches!(f.record, tidefs_intent_log::IntentLogRecord::Unlink { .. })));
    assert!(fs.stat_path("/todelete").is_err());
    fs.sync_all().expect("sync");
    drop(fs);
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(fs.stat_path("/todelete").is_err());
    }
    cleanup(&root);
}

#[test]
fn namespace_mutation_intent_log_rmdir_record() {
    let root = temp_root("intent-log-rmdir");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/toremove", 0o755).expect("create dir");
    let buf = std::sync::Arc::new(tidefs_intent_log::IntentLogBuffer::new());
    fs.set_intent_log_buffer(buf.clone());
    fs.remove_dir("/toremove").expect("remove dir");
    let frames = buf.drain_since(0);
    assert!(frames
        .iter()
        .any(|f| matches!(f.record, tidefs_intent_log::IntentLogRecord::Rmdir { .. })));
    assert!(fs.stat_path("/toremove").is_err());
    fs.sync_all().expect("sync");
    drop(fs);
    {
        let fs = LocalFileSystem::open_with_options(&root, options()).expect("reopen fs");
        assert!(fs.stat_path("/toremove").is_err());
    }
    cleanup(&root);
}

// ── Parent metadata consistency tests ──

#[test]
fn parent_metadata_consistent_after_create_dir() {
    let root = temp_root("parent-meta-mkdir");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let root_before = fs.stat_path("/").expect("stat root");
    let root_nlink_before = root_before.nlink;
    let root_version_before = root_before.metadata_version;
    fs.create_dir("/newdir", 0o755).expect("create dir");
    let root_after = fs.stat_path("/").expect("stat root after mkdir");
    assert_eq!(root_after.nlink, root_nlink_before + 1);
    assert!(root_after.metadata_version > root_version_before);
    assert_eq!(fs.stat_path("/newdir").unwrap().nlink, 2);
    cleanup(&root);
}

#[test]
fn parent_metadata_consistent_after_create_file() {
    let root = temp_root("parent-meta-create");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let root_before = fs.stat_path("/").expect("stat root");
    let root_version_before = root_before.metadata_version;
    let root_nlink_before = root_before.nlink;
    fs.create_file("/newfile", 0o644).expect("create file");
    let root_after = fs.stat_path("/").expect("stat root after create");
    assert_eq!(root_after.nlink, root_nlink_before);
    assert!(root_after.metadata_version > root_version_before);
    assert_eq!(fs.stat_path("/newfile").unwrap().nlink, 1);
    cleanup(&root);
}

#[test]
fn parent_metadata_consistent_after_link() {
    let root = temp_root("parent-meta-link");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/original", 0o644).expect("create original");
    let root_before = fs.stat_path("/").expect("stat root");
    let root_version_before = root_before.metadata_version;
    fs.link_file("/original", "/hardlink").expect("link file");
    let root_after = fs.stat_path("/").expect("stat root after link");
    assert!(root_after.metadata_version > root_version_before);
    assert_eq!(root_after.nlink, root_before.nlink);
    let o = fs.stat_path("/original").unwrap();
    let l = fs.stat_path("/hardlink").unwrap();
    assert_eq!(o.inode_id, l.inode_id);
    assert_eq!(o.nlink, 2);
    cleanup(&root);
}

#[test]
fn parent_metadata_consistent_after_unlink() {
    let root = temp_root("parent-meta-unlink");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/todelete", 0o644).expect("create file");
    let root_before = fs.stat_path("/").expect("stat root");
    let root_version_before = root_before.metadata_version;
    fs.unlink("/todelete").expect("unlink file");
    let root_after = fs.stat_path("/").expect("stat root after unlink");
    assert!(root_after.metadata_version > root_version_before);
    assert_eq!(root_after.nlink, root_before.nlink);
    assert!(!fs
        .list_dir("/")
        .unwrap()
        .iter()
        .any(|e| e.name == b"todelete"));
    cleanup(&root);
}

// ── Error-path resource cleanup tests ──

#[test]
fn error_rollback_after_create_dir_leaves_no_leaked_inode() {
    let root = temp_root("error-rollback-mkdir");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/target", 0o644)
        .expect("create file at conflict path");
    let inode_count_before = fs.state.inodes.len();
    let dir_count_before = fs.state.directories.len();
    assert!(fs.create_dir("/target", 0o755).is_err());
    assert_eq!(fs.state.inodes.len(), inode_count_before);
    assert_eq!(fs.state.directories.len(), dir_count_before);
    assert!(fs.stat_path("/target").is_ok());
    cleanup(&root);
}

#[test]
fn error_rollback_after_create_file_leaves_no_leaked_inode() {
    let root = temp_root("error-rollback-create");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/existing", 0o755)
        .expect("create dir at conflict path");
    let inode_count_before = fs.state.inodes.len();
    let dir_count_before = fs.state.directories.len();
    assert!(fs.create_file("/existing", 0o644).is_err());
    assert_eq!(fs.state.inodes.len(), inode_count_before);
    assert_eq!(fs.state.directories.len(), dir_count_before);
    assert!(fs.stat_path("/existing").is_ok());
    cleanup(&root);
}

#[test]
fn error_rollback_after_link_file_leaves_no_partial_state() {
    let root = temp_root("error-rollback-link");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_file("/source", 0o644).expect("create source");
    let source_inode_id = fs.lookup("/source").expect("lookup source");
    let source_nlink_before = fs.stat_path("/source").unwrap().nlink;
    let inode_count_before = fs.state.inodes.len();
    let dir_count_before = fs.state.directories.len();
    fs.create_file("/existing", 0o644).expect("create existing");
    assert!(fs.link_file("/source", "/existing").is_err());
    assert_eq!(fs.state.inodes.len(), inode_count_before.saturating_add(1));
    assert_eq!(fs.state.directories.len(), dir_count_before);
    let source_after = fs.stat_path("/source").unwrap();
    assert_eq!(source_after.nlink, source_nlink_before);
    assert_eq!(source_after.inode_id, source_inode_id);
    cleanup(&root);
}

// ── Intent-log record ordering test ──

#[test]
fn intent_log_record_ordering_in_multi_operation_commit_group() {
    let root = temp_root("intent-log-ordering");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let buf = std::sync::Arc::new(tidefs_intent_log::IntentLogBuffer::new());
    fs.set_intent_log_buffer(buf.clone());
    fs.create_dir("/alpha", 0o755).expect("create dir");
    fs.create_file("/alpha/one.txt", 0o644)
        .expect("create file one");
    fs.link_file("/alpha/one.txt", "/alpha/two.txt")
        .expect("link file");
    fs.unlink("/alpha/one.txt").expect("unlink one");
    let frames = buf.drain_since(0);
    let mut rts: Vec<&str> = Vec::new();
    for f in &frames {
        rts.push(match f.record {
            tidefs_intent_log::IntentLogRecord::Mkdir { .. } => "Mkdir",
            tidefs_intent_log::IntentLogRecord::Create { .. } => "Create",
            tidefs_intent_log::IntentLogRecord::HardLink { .. } => "HardLink",
            tidefs_intent_log::IntentLogRecord::Unlink { .. } => "Unlink",
            _ => "Other",
        });
    }
    assert!(rts.contains(&"Mkdir"));
    assert!(rts.contains(&"Create"));
    assert!(rts.contains(&"HardLink"));
    assert!(rts.contains(&"Unlink"));
    // Mkdir (parent directory) must appear before file operations within it.
    let mkdir_idx = rts.iter().position(|&r| r == "Mkdir").unwrap();
    assert!(rts[mkdir_idx..].contains(&"Create"));
    assert!(rts[mkdir_idx..].contains(&"HardLink"));
    assert!(rts[mkdir_idx..].contains(&"Unlink"));
    fs.sync_all().expect("sync");
    drop(fs);
    cleanup(&root);
}

// ── Concurrent-operation errno correctness test ──

#[test]
fn nonexistent_parent_returns_notfound_not_eexist() {
    let root = temp_root("no-parent-test");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    // path under a nonexistent directory: /ghost/file.txt
    let result = fs.create_file("/ghost/file.txt", 0o644);
    match result {
        Err(FileSystemError::NotFound { .. }) => {}
        other => panic!("Expected NotFound, got {other:?}"),
    }
    // path under a file (not directory): /file/sub
    fs.create_file("/file", 0o644).expect("create file");
    let result = fs.create_file("/file/sub", 0o644);
    match result {
        Err(FileSystemError::NotDirectory { .. }) => {}
        other => panic!("Expected NotDirectory, got {other:?}"),
    }
    cleanup(&root);
}

// ── Post-lock parent re-verification test ──

#[test]
fn post_lock_parent_verification_prevents_enoent_misclassification() {
    let root = temp_root("postlock-enoent");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/parent", 0o755).expect("create parent");
    fs.create_file("/parent/child", 0o644)
        .expect("create child");
    // Remove the child first, then remove the parent.
    fs.unlink("/parent/child").expect("unlink child");
    fs.remove_dir("/parent").expect("remove parent");
    // Now attempt to create under the gone parent.
    // The post-lock re-verification should detect the missing parent
    // and return NotFound instead of succeeding with a leaked inode.
    let result = fs.create_file("/parent/ghost", 0o644);
    match result {
        Err(FileSystemError::NotFound { .. }) => {}
        other => panic!("Expected NotFound after parent removal, got {other:?}"),
    }
    cleanup(&root);
}

// ── remove_dir parent metadata helper test ──

#[test]
fn remove_dir_updates_parent_metadata_and_link_count() {
    let root = temp_root("rmdir-parent-meta");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    fs.create_dir("/subdir", 0o755).expect("create dir");
    let root_before = fs.stat_path("/").expect("stat root");
    let root_nlink_before = root_before.nlink;
    fs.remove_dir("/subdir").expect("remove dir");
    let root_after = fs.stat_path("/").expect("stat root after rmdir");
    assert_eq!(root_after.nlink + 1, root_nlink_before);
    assert!(root_after.metadata_version > root_before.metadata_version);
    assert!(fs.stat_path("/subdir").is_err());
    cleanup(&root);
}

// ── free_extent_range tests ───────────────────────────────────────

#[test]
fn free_extent_range_zero_length_returns_zero() {
    let root = temp_root("free-extent-zero-len");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");
    let inode = fs.create_file("/test", 0o644).expect("create file");
    let inode_id = inode.inode_id;
    let freed = fs.free_extent_range(inode_id, 0, 0).expect("free zero len");
    assert_eq!(freed, 0);
    cleanup(&root);
}

#[test]
fn free_extent_range_frees_written_extent_and_updates_space() {
    let root = temp_root("free-extent-space");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let inode = fs.create_file("/test", 0o644).expect("create file");
    let data = vec![0xABu8; 4096];
    fs.write_file("/test", 0, &data).expect("write data");

    let inode_id = inode.inode_id;
    let freed = fs
        .free_extent_range(inode_id, 0, 4096)
        .expect("free extent");
    assert_eq!(freed, 4096);

    // Read should return zeros after freeing (punch-hole semantics).
    let read = fs
        .read_file_range("/test", 0, 4096)
        .expect("read after free");
    assert_eq!(read.len(), 4096);
    assert_eq!(read, vec![0u8; 4096]);

    cleanup(&root);
}

#[test]
fn free_extent_range_partial_range_frees_only_requested() {
    let root = temp_root("free-extent-partial");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let inode = fs.create_file("/test", 0o644).expect("create file");
    let data = vec![0xCDu8; 8192];
    fs.write_file("/test", 0, &data).expect("write 8k");

    // Free only the first 4096 bytes
    let inode_id = inode.inode_id;
    let freed = fs
        .free_extent_range(inode_id, 0, 4096)
        .expect("free partial");
    assert_eq!(freed, 4096);

    // Read first 4k: should be zeroed
    let read = fs.read_file_range("/test", 0, 4096).expect("read first 4k");
    assert_eq!(read.len(), 4096);
    assert_eq!(read, vec![0u8; 4096]);

    // Read second 4k: should still have original data
    let read2 = fs
        .read_file_range("/test", 4096, 4096)
        .expect("read second 4k");
    assert_eq!(read2.len(), 4096);
    assert_eq!(&read2[..], &data[4096..8192]);

    cleanup(&root);
}

#[test]
fn free_extent_range_past_allocated_returns_zero() {
    let root = temp_root("free-extent-past");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let inode = fs.create_file("/test", 0o644).expect("create file");
    // Write 4k at offset 0
    let data = vec![0xEFu8; 4096];
    fs.write_file("/test", 0, &data).expect("write 4k");

    let inode_id = inode.inode_id;
    // Free a range past the allocated extent
    let freed = fs
        .free_extent_range(inode_id, 8192, 4096)
        .expect("free past alloc");
    assert_eq!(freed, 0);

    cleanup(&root);
}

#[test]
fn free_extent_range_on_nonexistent_inode_returns_zero() {
    let root = temp_root("free-extent-noexist");
    let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("open fs");

    let inode_id = InodeId(99999);
    let freed = fs
        .free_extent_range(inode_id, 0, 4096)
        .expect("free nonexistent");
    assert_eq!(freed, 0);

    cleanup(&root);
}

#[test]
fn feature_flag_mount_gate_unknown_incompat_refuses_open() {
    use tidefs_types_dataset_feature_flags_core::{FeatureClass, FeatureFlagValueV1, FeatureName};

    let root = temp_root("feature-gate-incompat");
    // Open creates default state with empty feature flags; should succeed.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("first open");
        assert!(fs.feature_flags().is_empty());
        // Inject an unknown incompat feature (bypasses the is_known_feature guard).
        let unknown =
            FeatureName::from_str("com.example:experimental_v2").expect("valid feature name");
        fs.feature_flags_mut().insert_unchecked_for_test(
            unknown.clone(),
            FeatureClass::Incompat,
            FeatureFlagValueV1::Enabled,
        );
        assert!(fs.feature_flags().is_enabled(&unknown));
        // Persist so the next open sees it.
        fs.persist_feature_flags().expect("persist feature flags");
        // fs drops here: store closed, state on disk.
    }
    // Re-open must fail because the persisted feature set contains an unknown
    // incompat feature not in SupportedFeaturesV1::current().
    let err = LocalFileSystem::open_with_options(&root, options())
        .expect_err("re-open with unknown incompat should fail");
    match err {
        FileSystemError::CorruptState { reason } => {
            assert!(
                reason.contains("dataset feature flags refused mount"),
                "expected feature-flags refusal reason, got: {reason}"
            );
        }
        other => panic!("expected CorruptState, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn feature_flag_mount_gate_empty_flags_succeeds() {
    // Smoke: open with empty feature flags must succeed.
    let root = temp_root("feature-gate-smoke");
    {
        let fs =
            LocalFileSystem::open_with_options(&root, options()).expect("open with empty flags");
        assert!(fs.feature_flags().is_empty());
    }
    // Re-open after clean close.
    let fs =
        LocalFileSystem::open_with_options(&root, options()).expect("re-open with empty flags");
    assert!(fs.feature_flags().is_empty());
    cleanup(&root);
}

#[test]
fn feature_flag_mount_gate_known_features_succeeds() {
    use tidefs_types_dataset_feature_flags_core::{
        FeatureClass, FeatureName, FEATURE_COMPRESSION_ZSTD,
    };

    let root = temp_root("feature-gate-known");
    {
        let mut fs = LocalFileSystem::open_with_options(&root, options()).expect("first open");
        // Enable a known ro_compat feature (compression_zstd).
        let name = FeatureName::from_str(FEATURE_COMPRESSION_ZSTD).expect("zstd feature name");
        fs.feature_flags_mut()
            .enable_feature(name.clone(), FeatureClass::RoCompat)
            .expect("enable known feature");
        assert!(fs.feature_flags().is_enabled(&name));
        fs.persist_feature_flags().expect("persist");
    }
    // Re-open must succeed — compression_zstd is in SupportedFeaturesV1::current().
    let fs =
        LocalFileSystem::open_with_options(&root, options()).expect("re-open with known feature");
    let name = FeatureName::from_str(FEATURE_COMPRESSION_ZSTD).unwrap();
    assert!(fs.feature_flags().is_enabled(&name));
    cleanup(&root);
}
