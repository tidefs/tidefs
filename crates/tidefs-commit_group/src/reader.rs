//! Committed-root block reader with BLAKE3 integrity verification.
//!
//! # Overview
//!
//! [`CommitGroupReader`] is the crash-recovery read counterpart to
//! [`CommitGroupWriter`][super::writer::CommitGroupWriter]. It reads a
//! previously written committed-root block from stable storage via the
//! [`CommitGroupStore`] trait, verifies the VRBT magic, version field,
//! and BLAKE3-256 integrity hash, and returns the decoded block
//! containing the five root handles needed to bootstrap the filesystem
//! after a crash.
//!
//! # On-disk format
//!
//! The committed-root block layout is defined in
//! [`CommittedRootBlock`][super::writer::CommittedRootBlock]:
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       4     Magic ("VRBT")
//! 4       4     Version (u32 LE) = 1
//! 8       8     Commit group ID (u64 LE)
//! 16      8     Namespace root handle (u64 LE)
//! 24      8     Inode-table root handle (u64 LE)
//! 32      8     Extent-map root handle (u64 LE)
//! 40      8     Intent-log tail pointer (u64 LE)
//! 48      8     Reserved (zero)
//! 56      32    BLAKE3-256 hash (covers bytes 0..56)
//! ```
//!
//! Total: 88 bytes.
//!
//! # Recovery integration
//!
//! During crash recovery, the committed-root block is read using the
//! highest committed commit-group ID discovered during journal scanning
//! ([`CommitGroupRecovery`][super::recovery::CommitGroupRecovery]).
//! The BLAKE3-256 hash in the block header protects against silent
//! data corruption. A hash mismatch causes the read to fail, preventing
//! recovery from replaying a corrupted root.

use crate::store::CommitGroupStore;
use crate::types::CommitGroupId;
use crate::writer::{CommitGroupWriter, CommittedRootBlock};

/// Reader for committed-root blocks on stable storage.
///
/// Provides the read side of the committed-root lifecycle: locate a
/// root by commit-group ID and verify its integrity before handing
/// the five root handles to the recovery loop.
pub struct CommitGroupReader;

impl CommitGroupReader {
    /// Read the committed-root block for `commit_group_id` from `store`
    /// and verify its BLAKE3-256 integrity.
    ///
    /// Delegates to [`CommitGroupWriter::read_root_block`] for the
    /// actual I/O and verification. The semantic separation into a
    /// dedicated reader provides a clear mount-time recovery read path
    /// distinct from the write-side seal/persist operations.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(block))` if a valid, BLAKE3-verified block exists.
    /// - `Ok(None)` if no block has been written for this commit-group.
    /// - `Err(msg)` if I/O fails or BLAKE3 verification detects tampering.
    pub fn read_root_block<S: CommitGroupStore>(
        store: &S,
        commit_group_id: CommitGroupId,
    ) -> Result<Option<CommittedRootBlock>, String> {
        CommitGroupWriter::read_root_block(store, commit_group_id)
    }

    /// Return the deterministic store key name for a root block.
    #[must_use]
    pub fn root_block_key_name(commit_group_id: CommitGroupId) -> String {
        CommitGroupWriter::root_block_key_name(commit_group_id)
    }

    /// Check whether a committed-root block exists for `commit_group_id`.
    ///
    /// Fast existence check without full BLAKE3 verification.
    /// Call [`read_root_block`][Self::read_root_block] for a verified read.
    pub fn root_block_exists<S: CommitGroupStore>(
        store: &S,
        commit_group_id: CommitGroupId,
    ) -> Result<bool, String> {
        CommitGroupWriter::root_block_exists(store, commit_group_id)
    }

    /// Read and verify the committed-root block, returning an error if
    /// none exists.
    ///
    /// Convenience for callers that expect a root block to always exist
    /// (e.g. post-recovery mount after a dirty shutdown with committed
    /// data).
    pub fn require_root_block<S: CommitGroupStore>(
        store: &S,
        commit_group_id: CommitGroupId,
    ) -> Result<CommittedRootBlock, String> {
        Self::read_root_block(store, commit_group_id)?
            .ok_or_else(|| format!("no committed root for {commit_group_id}"))
    }

    /// Read the committed-root block with secondary superblock fallback.
    ///
    /// Attempts the primary copy first (via
    /// [`read_root_block`][Self::read_root_block]). If the primary is
    /// corrupt or missing, reads and verifies the BLAKE3-sealed secondary
    /// copy (see
    /// [`read_superblock_with_fallback`][super::superblock_secondary::read_superblock_with_fallback]).
    ///
    /// The `last_known_sequence` parameter protects against rollback: if
    /// the secondary copy's sequence number is less than this value, the
    /// fallback is rejected.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(block))` if a valid block was recovered from either copy.
    /// - `Ok(None)` if neither copy exists.
    /// - `Err(msg)` if the primary was corrupt and the secondary fallback
    ///   also failed.
    pub fn read_root_block_with_fallback<S: CommitGroupStore>(
        store: &S,
        commit_group_id: CommitGroupId,
        last_known_sequence: u64,
    ) -> Result<Option<CommittedRootBlock>, String> {
        crate::superblock_secondary::read_superblock_with_fallback(
            store,
            commit_group_id,
            last_known_sequence,
        )
        .map_err(|e| format!("superblock read failed: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockStore {
        data: HashMap<String, Vec<u8>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }
    }

    impl CommitGroupStore for MockStore {
        fn put_named(
            &mut self,
            name: &str,
            payload: &[u8],
        ) -> Result<crate::store::CommitGroupKey, String> {
            self.data.insert(name.to_string(), payload.to_vec());
            Ok(crate::store::CommitGroupKey::from_bytes32([0u8; 32]))
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.data.get(name).cloned())
        }
    }

    #[test]
    fn read_root_block_returns_none_for_fresh_store() {
        let store = MockStore::new();
        let result = CommitGroupReader::read_root_block(&store, CommitGroupId(1)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_root_block_roundtrip() {
        let mut store = MockStore::new();
        let original = CommittedRootBlock::new(
            CommitGroupId(1),
            100, // namespace_root
            200, // inode_table_root
            300, // extent_map_root
            400, // intent_log_tail
        );
        let sealed = CommitGroupWriter::seal_root_block(original);
        CommitGroupWriter::write_root_block(&mut store, &sealed).unwrap();

        let read = CommitGroupReader::read_root_block(&store, CommitGroupId(1))
            .unwrap()
            .expect("block should exist");
        assert_eq!(read.commit_group_id, CommitGroupId(1));
        assert_eq!(read.namespace_root, 100);
        assert_eq!(read.inode_table_root, 200);
        assert_eq!(read.extent_map_root, 300);
        assert_eq!(read.intent_log_tail, 400);
    }

    #[test]
    fn read_root_block_detects_tampering() {
        let mut store = MockStore::new();
        let original = CommittedRootBlock::new(CommitGroupId(1), 100, 200, 300, 400);
        let sealed = CommitGroupWriter::seal_root_block(original);
        let mut bytes = sealed.to_bytes();
        // Tamper with a byte in the header region (not the hash)
        bytes[19] ^= 0xFF;
        store.put_named("committed-root-1", &bytes).unwrap();

        let result = CommitGroupReader::read_root_block(&store, CommitGroupId(1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BLAKE3 verification failed"));
    }

    #[test]
    fn read_root_block_rejects_wrong_magic() {
        let mut store = MockStore::new();
        let original = CommittedRootBlock::new(CommitGroupId(1), 100, 200, 300, 400);
        let sealed = CommitGroupWriter::seal_root_block(original);
        let mut bytes = sealed.to_bytes();
        bytes[0] = b'X'; // corrupt magic
        store.put_named("committed-root-1", &bytes).unwrap();

        let result = CommitGroupReader::read_root_block(&store, CommitGroupId(1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("corrupt root block"));
    }

    #[test]
    fn root_block_key_name_is_deterministic() {
        let key = CommitGroupReader::root_block_key_name(CommitGroupId(42));
        assert_eq!(key, "committed-root-42");
    }

    #[test]
    fn root_block_exists_detects_presence() {
        let mut store = MockStore::new();
        assert!(!CommitGroupReader::root_block_exists(&store, CommitGroupId(1)).unwrap());

        let block = CommittedRootBlock::new(CommitGroupId(1), 0, 0, 0, 0);
        let sealed = CommitGroupWriter::seal_root_block(block);
        CommitGroupWriter::write_root_block(&mut store, &sealed).unwrap();

        assert!(CommitGroupReader::root_block_exists(&store, CommitGroupId(1)).unwrap());
    }

    #[test]
    fn require_root_block_errors_when_missing() {
        let store = MockStore::new();
        let result = CommitGroupReader::require_root_block(&store, CommitGroupId(99));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no committed root"));
    }

    #[test]
    fn require_root_block_returns_block_when_present() {
        let mut store = MockStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(7), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);
        CommitGroupWriter::write_root_block(&mut store, &sealed).unwrap();

        let read = CommitGroupReader::require_root_block(&store, CommitGroupId(7)).unwrap();
        assert_eq!(read.namespace_root, 10);
        assert_eq!(read.extent_map_root, 30);
    }

    #[test]
    fn multiple_commit_groups_read_independently() {
        let mut store = MockStore::new();
        for i in 1..=3 {
            let block =
                CommittedRootBlock::new(CommitGroupId(i), i * 100, i * 200, i * 300, i * 400);
            let sealed = CommitGroupWriter::seal_root_block(block);
            CommitGroupWriter::write_root_block(&mut store, &sealed).unwrap();
        }

        let read2 = CommitGroupReader::read_root_block(&store, CommitGroupId(2))
            .unwrap()
            .expect("block 2 should exist");
        assert_eq!(read2.namespace_root, 200);

        assert!(CommitGroupReader::read_root_block(&store, CommitGroupId(4))
            .unwrap()
            .is_none());
    }
}
