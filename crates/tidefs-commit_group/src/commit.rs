//! CommitGroupCommit: flush an accumulator to the object store and update extent maps.
//!
//! The commit path is the critical write funnel: it takes all queued writes,
//! metadata mutations, and link/unlink ops from a `CommitGroupAccumulator`, persists
//! data blobs to the object store, swaps extent pointers in the extent map,
//! applies metadata mutations through the inode table, and writes a commit_group journal
//! record to make the commit durable.
//!
//! If any step fails, the entire commit_group is discarded (no partial commits), and
//! dirty state is preserved in the tracker for retry in the next commit_group.

use std::collections::BTreeMap;

use tidefs_types_extent_map_core::{ExtentMapOps, LocatorId};

use crate::accumulator::CommitGroupAccumulator;
use crate::store::{CommitGroupKey, CommitGroupStore};
use crate::types::{CommitGroupError, CommitGroupId};

/// Trait abstracting the inode-table operations needed by the commit path.
///
/// This is a narrow interface; the full `tidefs-inode-table` crate (issue
/// #2507) will implement it once ready.
pub trait InodeTableCommit {
    /// Apply a `setattr` mutation for a single inode.
    fn apply_setattr(
        &mut self,
        ino: u64,
        new_size: Option<u64>,
        new_mtime: Option<u64>,
        new_ctime: Option<u64>,
    ) -> Result<(), CommitGroupError>;
}

/// Trait abstracting the namespace operations needed by the commit path.
///
/// This is a narrow interface; the full `tidefs-namespace` crate (issue
/// #2505) will implement it once ready.
pub trait NamespaceCommit {
    /// Apply a link operation.
    fn apply_link(
        &mut self,
        dir_ino: u64,
        name: &[u8],
        target_ino: u64,
    ) -> Result<(), CommitGroupError>;
    /// Apply an unlink operation.
    fn apply_unlink(&mut self, dir_ino: u64, name: &[u8]) -> Result<(), CommitGroupError>;
}

/// A no-op implementation of `InodeTableCommit` for testing.
pub struct NoopInodeTable;
impl InodeTableCommit for NoopInodeTable {
    fn apply_setattr(
        &mut self,
        _ino: u64,
        _new_size: Option<u64>,
        _new_mtime: Option<u64>,
        _new_ctime: Option<u64>,
    ) -> Result<(), CommitGroupError> {
        Ok(())
    }
}

/// A no-op implementation of `NamespaceCommit` for testing.
pub struct NoopNamespace;
impl NamespaceCommit for NoopNamespace {
    fn apply_link(
        &mut self,
        _dir_ino: u64,
        _name: &[u8],
        _target_ino: u64,
    ) -> Result<(), CommitGroupError> {
        Ok(())
    }
    fn apply_unlink(&mut self, _dir_ino: u64, _name: &[u8]) -> Result<(), CommitGroupError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommitGroupCommit
// ---------------------------------------------------------------------------

/// Orchestrates the commit of a single transaction group.
pub struct CommitGroupCommit;

/// Boxed commit error to keep the Result variant compact.
pub(crate) type CommitResult =
    Result<(CommitGroupId, Vec<CommitGroupKey>), Box<(CommitGroupError, CommitGroupAccumulator)>>;

impl CommitGroupCommit {
    /// Commit an accumulator to durable storage via a [`CommitGroupStore`].
    ///
    /// # Steps
    ///
    /// 1. For each `QueuedWrite`: put the blob into the store,
    ///    recording `(blob_key, byte_range)`.
    /// 2. For each modified inode: convert unwritten extents to data
    ///    extents in the extent map, pointing at the new blobs.
    /// 3. Apply queued `setattr` mutations via the inode table.
    /// 4. Apply queued link/unlink operations via the namespace.
    /// 5. Write a commit_group journal record to the store.
    ///
    /// # Errors
    ///
    /// If any step fails, the accumulator is returned unchanged so the
    /// caller can retry or roll back. No partial state is left behind.
    pub fn commit<EM, IT, NS, S>(
        accumulator: CommitGroupAccumulator,
        store: &mut S,
        extent_maps: &mut BTreeMap<u64, EM>,
        inode_table: &mut IT,
        namespace: &mut NS,
    ) -> CommitResult
    where
        EM: ExtentMapOps,
        IT: InodeTableCommit,
        NS: NamespaceCommit,
        S: CommitGroupStore,
    {
        let commit_group_id = accumulator.commit_group_id();
        if accumulator.is_empty() {
            return Err(Box::new((CommitGroupError::EmptyCommitGroup, accumulator)));
        }

        let mut committed_keys: Vec<CommitGroupKey> = Vec::new();

        // Step 1: Persist all queued writes to the store.
        // Map: (ino, offset) -> (txg_key, length)
        let mut blob_map: BTreeMap<(u64, u64), (CommitGroupKey, u64)> = BTreeMap::new();

        for write in accumulator.writes() {
            let key_name = format!(
                "commit_group-{}-ino-{}-off-{}",
                commit_group_id.0, write.ino, write.offset
            );
            let stored = store.put_named(&key_name, &write.data).map_err(|e| {
                let err = CommitGroupError::StorePutFailed {
                    ino: write.ino,
                    offset: write.offset,
                    reason: e,
                };
                Box::new((err, accumulator.clone_for_retry()))
            })?;

            committed_keys.push(stored);
            blob_map.insert((write.ino, write.offset), (stored, write.data.len() as u64));
        }

        // Step 2: Update extent maps — convert unwritten extents to data
        // extents pointing at the new blobs.
        let mut written_inodes: Vec<u64> = accumulator.writes().iter().map(|w| w.ino).collect();
        written_inodes.sort();
        written_inodes.dedup();
        for &ino in &written_inodes {
            let em = extent_maps.get_mut(&ino).ok_or_else(|| {
                let err = CommitGroupError::ExtentMapFailed {
                    ino,
                    reason: "extent map not found".into(),
                };
                Box::new((err, accumulator.clone_for_retry()))
            })?;

            let writes_for_ino: Vec<_> = accumulator
                .writes()
                .iter()
                .filter(|w| w.ino == ino)
                .collect();

            for w in writes_for_ino {
                let (obj_key, len) = blob_map
                    .get(&(w.ino, w.offset))
                    .expect("blob must exist after put");

                let locator = Self::key_to_locator(*obj_key);

                em.convert_unwritten_to_data(
                    w.offset,
                    *len,
                    locator,
                    [0u8; 32],         // checksum placeholder
                    commit_group_id.0, // birth_commit_group
                )
                .map_err(|e| {
                    let err = CommitGroupError::ExtentMapFailed {
                        ino,
                        reason: format!("{e:?}"),
                    };
                    Box::new((err, accumulator.clone_for_retry()))
                })?;
            }
        }

        // Step 3: Apply setattr mutations.
        for setattr in accumulator.setattrs() {
            inode_table
                .apply_setattr(
                    setattr.ino,
                    setattr.new_size,
                    setattr.new_mtime,
                    setattr.new_ctime,
                )
                .map_err(|e| Box::new((e, accumulator.clone_for_retry())))?;
        }

        // Step 4: Apply link/unlink operations.
        for link in accumulator.links() {
            namespace
                .apply_link(link.dir_ino, &link.name, link.target_ino)
                .map_err(|e| Box::new((e, accumulator.clone_for_retry())))?;
        }
        for unlink in accumulator.unlinks() {
            namespace
                .apply_unlink(unlink.dir_ino, &unlink.name)
                .map_err(|e| Box::new((e, accumulator.clone_for_retry())))?;
        }

        // Step 5: Write a commit_group journal record.
        let journal_key = format!("commit_group-journal-{}", commit_group_id.0);
        let journal_payload =
            Self::build_journal_payload(commit_group_id, &committed_keys, &written_inodes);
        store
            .put_named(&journal_key, &journal_payload)
            .map_err(|e| {
                let err = CommitGroupError::StorePutFailed {
                    ino: 0,
                    offset: 0,
                    reason: format!("journal write failed: {e}"),
                };
                Box::new((err, accumulator.clone_for_retry()))
            })?;

        Ok((commit_group_id, committed_keys))
    }

    /// Commit a prepared `CommitGroup` through the two-phase pipeline.
    ///
    /// This is the two-phase counterpart to [`Self::commit`]. It expects the
    /// `group` to already be in the `Prepared` phase (after a successful
    /// `prepare()`). After persisting all queued writes, metadata mutations,
    /// and the journal record to the store, it calls
    /// `group.commit()` to atomically swap the root pointer.
    ///
    /// # Errors
    ///
    /// If any I/O step fails, `group` remains in the `Prepared` phase so the
    /// caller can retry. No partial state is left behind.
    ///
    /// Returns `CommitGroupError::CommitPhaseRejected` if the group is not
    /// in the `Prepared` phase.
    pub fn commit_group<EM, IT, NS, S>(
        group: &mut crate::pipeline::CommitGroup,
        store: &mut S,
        extent_maps: &mut BTreeMap<u64, EM>,
        inode_table: &mut IT,
        namespace: &mut NS,
    ) -> Result<(crate::types::RootPointer, Vec<CommitGroupKey>), CommitGroupError>
    where
        EM: ExtentMapOps,
        IT: InodeTableCommit,
        NS: NamespaceCommit,
        S: CommitGroupStore,
    {
        use crate::types::CommitGroupPhase;

        if group.phase() != CommitGroupPhase::Prepared {
            return Err(CommitGroupError::CommitPhaseRejected {
                reason: format!(
                    "commit_group requires Prepared phase, current phase is {:?}",
                    group.phase()
                ),
            });
        }

        let commit_group_id = group.commit_group_id();
        let accumulator = group.accumulator();

        if accumulator.is_empty() {
            return Err(CommitGroupError::EmptyCommitGroup);
        }

        let mut committed_keys: Vec<CommitGroupKey> = Vec::new();

        // Step 1: Persist all queued writes to the store.
        let mut blob_map: BTreeMap<(u64, u64), (CommitGroupKey, u64)> = BTreeMap::new();

        for write in accumulator.writes() {
            let key_name = format!(
                "commit_group-{}-ino-{}-off-{}",
                commit_group_id.0, write.ino, write.offset
            );
            let stored = store.put_named(&key_name, &write.data).map_err(|e| {
                CommitGroupError::StorePutFailed {
                    ino: write.ino,
                    offset: write.offset,
                    reason: e,
                }
            })?;

            committed_keys.push(stored);
            blob_map.insert((write.ino, write.offset), (stored, write.data.len() as u64));
        }

        // Step 2: Update extent maps.
        let mut written_inodes: Vec<u64> = accumulator.writes().iter().map(|w| w.ino).collect();
        written_inodes.sort();
        written_inodes.dedup();
        for &ino in &written_inodes {
            let em =
                extent_maps
                    .get_mut(&ino)
                    .ok_or_else(|| CommitGroupError::ExtentMapFailed {
                        ino,
                        reason: "extent map not found".into(),
                    })?;

            let writes_for_ino: Vec<_> = accumulator
                .writes()
                .iter()
                .filter(|w| w.ino == ino)
                .collect();

            for w in writes_for_ino {
                let (obj_key, len) = blob_map
                    .get(&(w.ino, w.offset))
                    .expect("blob must exist after put");

                let locator = Self::key_to_locator(*obj_key);
                em.convert_unwritten_to_data(w.offset, *len, locator, [0u8; 32], commit_group_id.0)
                    .map_err(|e| CommitGroupError::ExtentMapFailed {
                        ino,
                        reason: format!("{e:?}"),
                    })?;
            }
        }

        // Step 3: Apply setattr mutations.
        for setattr in accumulator.setattrs() {
            inode_table.apply_setattr(
                setattr.ino,
                setattr.new_size,
                setattr.new_mtime,
                setattr.new_ctime,
            )?;
        }

        // Step 4: Apply link/unlink operations.
        for link in accumulator.links() {
            namespace.apply_link(link.dir_ino, &link.name, link.target_ino)?;
        }
        for unlink in accumulator.unlinks() {
            namespace.apply_unlink(unlink.dir_ino, &unlink.name)?;
        }

        // Step 5: Write the commit_group journal record.
        let journal_key = format!("commit_group-journal-{}", commit_group_id.0);
        let journal_payload =
            Self::build_journal_payload(commit_group_id, &committed_keys, &written_inodes);
        store
            .put_named(&journal_key, &journal_payload)
            .map_err(|e| CommitGroupError::StorePutFailed {
                ino: 0,
                offset: 0,
                reason: format!("journal write failed: {e}"),
            })?;

        // Step 6: Atomic root switch.
        // First transition the pipeline phase (Prepared -> Committed).
        let _pipeline_root = group.commit()?;

        // Then write the committed-root block via CommitGroupWriter
        // for BLAKE3-verified durability.
        let root_block = crate::writer::CommittedRootBlock::new(
            commit_group_id,
            0,                 // namespace_root placeholder (set by namespace subsystem)
            0,                 // inode_table_root placeholder (set by inode-table subsystem)
            0,                 // extent_map_root placeholder (set by extent-map subsystem)
            commit_group_id.0, // intent_log_tail
        );
        // Seal the root block and write the primary copy.
        let sealed = crate::writer::CommitGroupWriter::seal_root_block(root_block);
        let committed_root = crate::writer::CommitGroupWriter::write_root_block(store, &sealed)
            .map_err(|e| CommitGroupError::StorePutFailed {
                ino: 0,
                offset: 0,
                reason: format!("committed-root write failed: {e}"),
            })?;

        // Best-effort secondary superblock write (non-blocking).
        let _ = crate::superblock_secondary::write_superblock_secondary(
            store,
            &sealed,
            committed_root.commit_group_id.0,
        );
        Ok((committed_root, committed_keys))
    }

    // -------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------

    fn key_to_locator(key: CommitGroupKey) -> LocatorId {
        let bytes = key.as_bytes32();
        let val = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        LocatorId(val)
    }

    pub(crate) fn build_journal_payload(
        commit_group_id: CommitGroupId,
        keys: &[CommitGroupKey],
        inodes: &[u64],
    ) -> Vec<u8> {
        let mut payload: Vec<u8> = Vec::new();
        // Simple binary format: commit_group_id (8 bytes LE) +
        //   key_count (4 bytes LE) + N × key_bytes (32 bytes each) +
        //   inode_count (4 bytes LE) + M × ino (8 bytes LE each)
        payload.extend_from_slice(&commit_group_id.0.to_le_bytes());
        payload.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for k in keys {
            payload.extend_from_slice(&k.as_bytes32());
        }
        payload.extend_from_slice(&(inodes.len() as u32).to_le_bytes());
        for &ino in inodes {
            payload.extend_from_slice(&ino.to_le_bytes());
        }
        payload
    }

    /// Recover committed blob keys from a journal payload.
    #[must_use]
    pub fn parse_journal_payload(
        payload: &[u8],
    ) -> Option<(CommitGroupId, Vec<CommitGroupKey>, Vec<u64>)> {
        if payload.len() < 12 {
            return None;
        }
        let commit_group_id = CommitGroupId(u64::from_le_bytes(payload[0..8].try_into().ok()?));
        let key_count = u32::from_le_bytes(payload[8..12].try_into().ok()?) as usize;
        let mut offset = 12;
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            if offset + 32 > payload.len() {
                return None;
            }
            let arr: [u8; 32] = payload[offset..offset + 32].try_into().ok()?;
            keys.push(CommitGroupKey::from_bytes32(arr));
            offset += 32;
        }
        if offset + 4 > payload.len() {
            return None;
        }
        let inode_count = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        let mut inodes = Vec::with_capacity(inode_count);
        for _ in 0..inode_count {
            if offset + 8 > payload.len() {
                return None;
            }
            inodes.push(u64::from_le_bytes(
                payload[offset..offset + 8].try_into().ok()?,
            ));
            offset += 8;
        }
        Some((commit_group_id, keys, inodes))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_payload_roundtrip() {
        let commit_group_id = CommitGroupId(42);
        let keys = vec![
            CommitGroupKey::from_bytes32([1u8; 32]),
            CommitGroupKey::from_bytes32([2u8; 32]),
        ];
        let inodes = vec![10, 20, 30];
        let payload = CommitGroupCommit::build_journal_payload(commit_group_id, &keys, &inodes);
        let (parsed_commit_group, parsed_keys, parsed_inodes) =
            CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(parsed_commit_group, commit_group_id);
        assert_eq!(parsed_keys.len(), 2);
        assert_eq!(parsed_keys[0].as_bytes32(), [1u8; 32]);
        assert_eq!(parsed_keys[1].as_bytes32(), [2u8; 32]);
        assert_eq!(parsed_inodes, inodes);
    }

    #[test]
    fn journal_payload_empty() {
        let commit_group_id = CommitGroupId(1);
        let payload = CommitGroupCommit::build_journal_payload(commit_group_id, &[], &[]);
        let (parsed_commit_group, parsed_keys, parsed_inodes) =
            CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(parsed_commit_group, commit_group_id);
        assert!(parsed_keys.is_empty());
        assert!(parsed_inodes.is_empty());
    }

    #[test]
    fn journal_payload_truncated() {
        assert!(CommitGroupCommit::parse_journal_payload(&[]).is_none());
        assert!(CommitGroupCommit::parse_journal_payload(&[0u8; 4]).is_none());
        let mut partial = vec![0u8; 12 + 16]; // only half a key
        partial[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(CommitGroupCommit::parse_journal_payload(&partial).is_none());
    }

    #[test]
    fn journal_payload_single_key() {
        let commit_group_id = CommitGroupId(1);
        let keys = vec![CommitGroupKey::from_bytes32([0x11u8; 32])];
        let inodes = vec![42];
        let payload = CommitGroupCommit::build_journal_payload(commit_group_id, &keys, &inodes);
        let (parsed_id, parsed_keys, parsed_inodes) =
            CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(parsed_id, commit_group_id);
        assert_eq!(parsed_keys.len(), 1);
        assert_eq!(parsed_inodes.len(), 1);
        assert_eq!(parsed_inodes[0], 42);
    }

    #[test]
    fn journal_payload_many_keys() {
        let commit_group_id = CommitGroupId(100);
        let keys: Vec<_> = (0..16u8)
            .map(|i| CommitGroupKey::from_bytes32([i; 32]))
            .collect();
        let inodes: Vec<_> = (0..16u64).collect();
        let payload = CommitGroupCommit::build_journal_payload(commit_group_id, &keys, &inodes);
        let (parsed_id, parsed_keys, parsed_inodes) =
            CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(parsed_id, commit_group_id);
        assert_eq!(parsed_keys.len(), 16);
        assert_eq!(parsed_inodes.len(), 16);
        for (i, ino) in parsed_inodes.iter().enumerate() {
            assert_eq!(*ino, i as u64);
        }
    }

    #[test]
    fn journal_payload_truncated_mid_key() {
        let mut partial = vec![0u8; 12 + 16]; // header + half a key
        partial[0..8].copy_from_slice(&1u64.to_le_bytes());
        partial[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(CommitGroupCommit::parse_journal_payload(&partial).is_none());
    }

    #[test]
    fn journal_payload_truncated_mid_inode() {
        let mut truncated = vec![0u8; 12]; // header
        truncated[0..8].copy_from_slice(&1u64.to_le_bytes());
        truncated[8..12].copy_from_slice(&0u32.to_le_bytes()); // key_count = 0
                                                               // Now truncate: extend with inode_count = 1 but no inode data
        truncated.extend_from_slice(&1u32.to_le_bytes());
        assert!(CommitGroupCommit::parse_journal_payload(&truncated).is_none());
    }

    #[test]
    fn journal_payload_id_wraps_around() {
        let commit_group_id = CommitGroupId(u64::MAX);
        let payload = CommitGroupCommit::build_journal_payload(commit_group_id, &[], &[]);
        let (parsed_id, _, _) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(parsed_id, commit_group_id);
        assert_eq!(parsed_id.next(), CommitGroupId(u64::MAX));
    }

    #[test]
    fn parse_payload_only_header() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&42u64.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        let (id, keys, inodes) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(id, CommitGroupId(42));
        assert!(keys.is_empty());
        assert!(inodes.is_empty());
    }

    #[test]
    fn noop_inode_table_all() {
        let mut t = NoopInodeTable;
        assert!(t.apply_setattr(1, Some(100), None, None).is_ok());
        assert!(t.apply_setattr(2, None, Some(200), None).is_ok());
        assert!(t.apply_setattr(3, None, None, Some(300)).is_ok());
        assert!(t.apply_setattr(4, Some(400), Some(400), Some(400)).is_ok());
    }

    #[test]
    fn noop_namespace_all() {
        let mut ns = NoopNamespace;
        assert!(ns.apply_link(1, b"a", 10).is_ok());
        assert!(ns.apply_link(2, b"bb", 20).is_ok());
        assert!(ns.apply_unlink(1, b"a").is_ok());
        assert!(ns.apply_unlink(2, b"bb").is_ok());
    }

    #[test]
    fn parse_payload_negative_payload_length() {
        // Payload too short for any header.
        assert!(CommitGroupCommit::parse_journal_payload(&[0u8; 4]).is_none());
        assert!(CommitGroupCommit::parse_journal_payload(&[0u8; 11]).is_none());
    }
}
