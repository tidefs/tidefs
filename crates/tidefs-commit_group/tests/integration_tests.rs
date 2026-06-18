// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the TideFS transaction group subsystem.
//!
//! These tests exercise the full commit_group pipeline: dirty tracking →
//! accumulation → commit → sync → recovery.

use tidefs_commit_group::{
    CommitGroupAccumulator, CommitGroupCommit, CommitGroupId, CommitGroupKey, CommitGroupState,
    CommitGroupSync, DirtyMetaFlags, DirtyTracker,
};

// ---------------------------------------------------------------------------
// Dirty tracker integration
// ---------------------------------------------------------------------------

#[test]
fn dirty_tracker_full_lifecycle() {
    let mut dt = DirtyTracker::new();

    dt.mark_dirty(1, 0, 4096);
    dt.mark_dirty(1, 8192, 4096);
    dt.mark_dirty(2, 0, 16384);

    let mut dirty = dt.dirty_inodes();
    dirty.sort();
    assert_eq!(dirty, vec![1, 2]);

    let ranges = dt.dirty_ranges(1);
    assert_eq!(ranges.len(), 2);

    dt.clear_dirty(1);
    assert!(!dt.has_dirty_data(1));
    assert_eq!(dt.dirty_inodes(), vec![2]);
}

// ---------------------------------------------------------------------------
// Accumulator integration
// ---------------------------------------------------------------------------

#[test]
fn accumulator_writes_and_drain() {
    let mut acc = CommitGroupAccumulator::new(CommitGroupId(1));
    acc.queue_write(10, 0, vec![0u8; 4096]);
    acc.queue_write(10, 4096, vec![1u8; 4096]);
    acc.queue_write(20, 0, vec![2u8; 1024]);

    assert!(!acc.is_empty());
    assert_eq!(acc.write_count(), 3);
    assert_eq!(acc.commit_group_id(), CommitGroupId(1));

    let (writes, _, _, _) = acc.drain();
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0].ino, 10);
    assert_eq!(writes[1].ino, 10);
    assert_eq!(writes[2].ino, 20);
}

#[test]
fn accumulator_setattr_coalescing() {
    let mut acc = CommitGroupAccumulator::new(CommitGroupId(2));
    acc.queue_setattr(1, DirtyMetaFlags::SIZE, Some(8192), None, None);
    acc.queue_setattr(1, DirtyMetaFlags::MTIME, None, Some(500), None);
    acc.queue_setattr(1, DirtyMetaFlags::CTIME, None, None, Some(500));

    assert_eq!(acc.setattr_count(), 1);
    let sa = &acc.setattrs()[0];
    assert!(sa
        .attr_mask
        .contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME | DirtyMetaFlags::CTIME));
    assert_eq!(sa.new_size, Some(8192));
    assert_eq!(sa.new_mtime, Some(500));
    assert_eq!(sa.new_ctime, Some(500));
}

#[test]
fn accumulator_state_transitions() {
    let mut acc = CommitGroupAccumulator::new(CommitGroupId(3));
    assert_eq!(acc.state(), CommitGroupState::Open);
    acc.mark_committing();
    assert_eq!(acc.state(), CommitGroupState::Committing);
}

// ---------------------------------------------------------------------------
// Commit: journal round-trip
// ---------------------------------------------------------------------------

#[test]
fn journal_roundtrip_with_keys() {
    let commit_group_id = CommitGroupId(42);
    let keys = vec![
        CommitGroupKey::from_bytes32([0xAA; 32]),
        CommitGroupKey::from_bytes32([0xBB; 32]),
    ];
    let inodes = vec![100, 200];

    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&commit_group_id.0.to_le_bytes());
    payload.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in &keys {
        payload.extend_from_slice(&k.as_bytes32());
    }
    payload.extend_from_slice(&(inodes.len() as u32).to_le_bytes());
    for &ino in &inodes {
        let ino: u64 = ino;
        payload.extend_from_slice(&ino.to_le_bytes());
    }

    let (parsed_commit_group, parsed_keys, parsed_inodes) =
        CommitGroupCommit::parse_journal_payload(&payload).unwrap();

    assert_eq!(parsed_commit_group, commit_group_id);
    assert_eq!(parsed_keys.len(), 2);
    assert_eq!(parsed_inodes, inodes);
    assert_eq!(parsed_keys[0].as_bytes32(), [0xAA; 32]);
    assert_eq!(parsed_keys[1].as_bytes32(), [0xBB; 32]);
}

#[test]
fn journal_roundtrip_empty() {
    let mut payload: Vec<u8> = Vec::new();
    let commit_group_id = CommitGroupId(1);
    payload.extend_from_slice(&commit_group_id.0.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes()); // key_count = 0
    payload.extend_from_slice(&0u32.to_le_bytes()); // inode_count = 0

    let (commit_group, keys, inodes) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
    assert_eq!(commit_group, CommitGroupId(1));
    assert!(keys.is_empty());
    assert!(inodes.is_empty());
}

// ---------------------------------------------------------------------------
// Sync: fsync and syncfs coordination
// ---------------------------------------------------------------------------

#[test]
fn syncfs_notification_chain() {
    use std::thread;
    use tidefs_commit_group::SyncGate;

    let gate = SyncGate::new();
    let sync = CommitGroupSync::new(gate.clone());

    let handle = thread::spawn(move || {
        sync.syncfs().unwrap();
    });

    thread::sleep(std::time::Duration::from_millis(50));

    gate.notify_synced();

    handle.join().unwrap();
}

#[test]
fn fsync_multi_inode_commit_group_boundary() {
    use std::thread;
    use tidefs_commit_group::SyncGate;

    let gate = SyncGate::new();
    gate.register_dirty(1, CommitGroupId(1));
    gate.register_dirty(2, CommitGroupId(2));

    let sync1 = CommitGroupSync::new(gate.clone());
    let sync2 = CommitGroupSync::new(gate.clone());

    let h1 = thread::spawn(move || sync1.fsync(1).unwrap());
    let h2 = thread::spawn(move || sync2.fsync(2).unwrap());

    thread::sleep(std::time::Duration::from_millis(50));

    gate.notify_committed(CommitGroupId(1));
    h1.join().unwrap();

    thread::sleep(std::time::Duration::from_millis(50));
    gate.notify_committed(CommitGroupId(2));
    h2.join().unwrap();
}

// ---------------------------------------------------------------------------
// Recovery: journal scan (parsing-only tests)
// ---------------------------------------------------------------------------

#[test]
fn recovery_parse_valid_and_corrupt() {
    let mut payload: Vec<u8> = Vec::new();
    let commit_group_id = CommitGroupId(7);
    payload.extend_from_slice(&commit_group_id.0.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes()); // key_count = 0
    let inodes = vec![10u64, 20u64];
    payload.extend_from_slice(&(inodes.len() as u32).to_le_bytes());
    for &ino in &inodes {
        let ino: u64 = ino;
        payload.extend_from_slice(&ino.to_le_bytes());
    }
    assert!(CommitGroupCommit::parse_journal_payload(&payload).is_some());

    assert!(CommitGroupCommit::parse_journal_payload(&[0xFF; 5]).is_none());
    assert!(CommitGroupCommit::parse_journal_payload(&[]).is_none());
}

#[test]
fn recovery_result_next_commit_group() {
    let mut payload: Vec<u8> = Vec::new();
    let commit_group_id = CommitGroupId(5);
    payload.extend_from_slice(&commit_group_id.0.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    let (commit_group, _, _) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
    assert_eq!(commit_group.next(), CommitGroupId(6));
}

// ---------------------------------------------------------------------------
// CommitGroupId arithmetic
// ---------------------------------------------------------------------------

#[test]
fn commit_group_id_arithmetic() {
    assert!(!CommitGroupId::NIL.is_valid());
    assert!(CommitGroupId::FIRST.is_valid());
    assert_eq!(CommitGroupId::NIL.next(), CommitGroupId(1));
    assert_eq!(CommitGroupId(5).next(), CommitGroupId(6));
    assert_eq!(CommitGroupId(u64::MAX).next(), CommitGroupId(u64::MAX));
}

// ---------------------------------------------------------------------------
// DirtyMetaFlags bitwise
// ---------------------------------------------------------------------------

#[test]
fn dirty_meta_flags_operations() {
    let mut flags = DirtyMetaFlags::NONE;
    assert!(!flags.is_dirty());
    assert!(flags.is_empty());

    flags.insert(DirtyMetaFlags::SIZE);
    assert!(flags.is_dirty());
    assert!(flags.contains(DirtyMetaFlags::SIZE));
    assert!(!flags.contains(DirtyMetaFlags::MTIME));

    flags.insert(DirtyMetaFlags::MTIME | DirtyMetaFlags::CTIME);
    assert!(flags.contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME | DirtyMetaFlags::CTIME));

    flags.remove(DirtyMetaFlags::SIZE);
    assert!(!flags.contains(DirtyMetaFlags::SIZE));
    assert!(flags.contains(DirtyMetaFlags::MTIME));

    flags.clear();
    assert!(!flags.is_dirty());
}

// ---------------------------------------------------------------------------
// CommitGroupError display
// ---------------------------------------------------------------------------

#[test]
fn commit_group_error_display() {
    let e = tidefs_commit_group::CommitGroupError::EmptyCommitGroup;
    assert_eq!(format!("{e}"), "commit_group accumulator is empty");

    let e = tidefs_commit_group::CommitGroupError::UnlinkWithDirtyWrites { ino: 42 };
    assert!(format!("{e}").contains("42"));
    assert!(format!("{e}").contains("dirty writes"));
}

// ---------------------------------------------------------------------------
// Two-phase pipeline: commit_group() bridge
// ---------------------------------------------------------------------------

#[test]
fn commit_group_requires_prepared_phase() {
    use tidefs_commit_group::{CommitGroup, CommitGroupId, CommitGroupPhase, RootPointer};

    let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
    group.queue_write(1, 0, vec![0x42u8; 64]).unwrap();

    assert_eq!(group.phase(), CommitGroupPhase::Open);
    let result = group.commit();
    assert!(result.is_err());

    group.prepare().unwrap();
    assert_eq!(group.phase(), CommitGroupPhase::Prepared);
    let root = group.commit().unwrap();
    assert_eq!(group.phase(), CommitGroupPhase::Committed);
    assert!(root.is_valid());
}

// ---------------------------------------------------------------------------
// CommitGroupStore adapter for LocalObjectStore (dev-dep only)
// ---------------------------------------------------------------------------

/// Adapter that implements `tidefs_commit_group::CommitGroupStore` for
/// `tidefs_local_object_store::LocalObjectStore`, bridging the wire-compatible
/// key types.
struct LoStoreAdapter<'a>(&'a mut tidefs_local_object_store::LocalObjectStore);

impl tidefs_commit_group::CommitGroupStore for LoStoreAdapter<'_> {
    fn put_named(&mut self, name: &str, payload: &[u8]) -> Result<CommitGroupKey, String> {
        use tidefs_local_object_store::ObjectKey;
        let stored = self
            .0
            .put(ObjectKey::from_name(name), payload)
            .map_err(|e| format!("{e}"))?;
        Ok(CommitGroupKey::from_bytes32(stored.key.as_bytes32()))
    }

    fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        use tidefs_local_object_store::ObjectKey;
        self.0
            .get(ObjectKey::from_name(name))
            .map_err(|e| format!("{e}"))
    }
}

#[test]
fn commit_group_succeeds_with_real_store() {
    use std::collections::BTreeMap;
    use tidefs_commit_group::{
        CommitGroup, CommitGroupCommit, CommitGroupId, CommitGroupPhase, NoopInodeTable,
        NoopNamespace, RootPointer,
    };
    use tidefs_extent_map::btree::BTreeExtentMap;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
    use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps};

    let dir = tempfile::tempdir().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

    let mut group = CommitGroup::new(CommitGroupId::FIRST, RootPointer::NIL);
    group.queue_write(1, 0, vec![0x42u8; 64]).unwrap();
    group.prepare().unwrap();
    assert_eq!(group.phase(), CommitGroupPhase::Prepared);

    let mut extent_maps: BTreeMap<u64, BTreeExtentMap> = BTreeMap::new();
    let mut em = BTreeExtentMap::new();
    let unwritten_entry = ExtentMapEntryV2::new_unwritten(0, 64, 1);
    em.insert_extent(&[unwritten_entry]).unwrap();
    extent_maps.insert(1, em);

    let (committed_root, committed_keys) = CommitGroupCommit::commit_group(
        &mut group,
        &mut LoStoreAdapter(&mut store),
        &mut extent_maps,
        &mut NoopInodeTable,
        &mut NoopNamespace,
    )
    .unwrap();

    assert_eq!(group.phase(), CommitGroupPhase::Committed);
    assert_eq!(committed_root.commit_group_id, CommitGroupId::FIRST);
    assert!(committed_root.is_valid());
    assert_eq!(committed_keys.len(), 1);
}

#[test]
fn commit_group_preserves_prepared_on_io_error() {
    use std::collections::BTreeMap;
    use tidefs_commit_group::{
        CommitGroup, CommitGroupCommit, CommitGroupId, CommitGroupPhase, NoopInodeTable,
        NoopNamespace, RootPointer,
    };
    use tidefs_extent_map::btree::BTreeExtentMap;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    let dir = tempfile::tempdir().unwrap();
    let mut store =
        LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();

    let mut group = CommitGroup::new(CommitGroupId(1), RootPointer::NIL);
    group.queue_write(1, 0, vec![0x42u8; 64]).unwrap();
    group.prepare().unwrap();

    let result = CommitGroupCommit::commit_group(
        &mut group,
        &mut LoStoreAdapter(&mut store),
        &mut BTreeMap::<u64, BTreeExtentMap>::new(),
        &mut NoopInodeTable,
        &mut NoopNamespace,
    );
    assert!(result.is_err());
    assert_eq!(group.phase(), CommitGroupPhase::Prepared);
}
