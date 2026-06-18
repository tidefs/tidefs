// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! CommitGroupWriter: BLAKE3-verified committed-root atomic write path.
//!
//! # Overview
//!
//! `CommitGroupWriter` turns a sealed transaction group into a durable committed
//! root on stable storage. It serializes the namespace root, inode table root,
//! extent-map root, and intent-log tail pointer into a `CommittedRootBlock`,
//! computes a BLAKE3-256 checksum over the block header, writes the block via
//! the `CommitGroupStore`, and returns a `RootPointer` that atomically identifies
//! the new committed root.
//!
//! # Root-block layout
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       4     Magic ("VRBT")
//! 4       4     Version (u32 LE)
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
//! # Atomicity
//!
//! The write is atomic from the caller's perspective: the root block is written
//! as a named blob via `CommitGroupStore::put_named`, and the returned key
//! becomes the `RootPointer::root_handle`. The superblock's root-pointer swap is
//! performed by the caller after this write succeeds. Readers see either the old
//! root pointer (pointing to the previous committed-root block) or the new one,
//! never a partial state.
//!
//! # Verification
//!
//! `CommitGroupWriter::verify_root_block()` recomputes the BLAKE3 hash over the
//! block header and compares it to the stored hash. Mismatch detection prevents
//! recovery from replaying a corrupted root block.

#[cfg(feature = "std")]
use crate::store::CommitGroupStore;
use crate::types::CommitGroupId;
#[cfg(feature = "std")]
use crate::types::RootPointer;

/// Magic bytes identifying a committed-root block on disk.
const ROOT_BLOCK_MAGIC: &[u8; 4] = b"VRBT";

/// Current root-block format version.
const ROOT_BLOCK_VERSION: u32 = 1;

/// Total size of a committed-root block on disk (88 bytes).
const ROOT_BLOCK_SIZE: usize = 88;

/// Byte offsets for the BLAKE3 hash (covers bytes 0..HEADER_SIZE).
const HEADER_SIZE: usize = 56;
const HASH_OFFSET: usize = 56;

// ---------------------------------------------------------------------------
// CommittedRootBlock — the on-disk representation of a committed root
// ---------------------------------------------------------------------------

/// A serializable committed-root block that identifies the filesystem state
/// at a specific transaction group boundary.
///
/// The block carries opaque handles to the four system roots (namespace,
/// inode table, extent map, intent-log tail) plus a BLAKE3-256 integrity
/// hash that covers the block header (everything except the hash itself).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRootBlock {
    /// The transaction group at which this root was committed.
    pub commit_group_id: CommitGroupId,
    /// Opaque handle to the namespace root (e.g. directory-entry tree root).
    pub namespace_root: u64,
    /// Opaque handle to the inode-table root.
    pub inode_table_root: u64,
    /// Opaque handle to the extent-map root.
    pub extent_map_root: u64,
    /// Opaque pointer to the intent-log tail (for recovery replay).
    pub intent_log_tail: u64,
    /// BLAKE3-256 hash covering the block header bytes.
    pub block_hash: [u8; 32],
}

impl CommittedRootBlock {
    /// Number of bytes in the VRBT committed-root block wire format.
    pub const WIRE_SIZE: usize = ROOT_BLOCK_SIZE;

    /// Create a new root block for the given commit group.
    ///
    /// The BLAKE3 hash is not computed yet; call [`CommitGroupWriter::seal_root_block`]
    /// to finalize.
    #[must_use]
    pub fn new(
        commit_group_id: CommitGroupId,
        namespace_root: u64,
        inode_table_root: u64,
        extent_map_root: u64,
        intent_log_tail: u64,
    ) -> Self {
        Self {
            commit_group_id,
            namespace_root,
            inode_table_root,
            extent_map_root,
            intent_log_tail,
            block_hash: [0u8; 32],
        }
    }

    /// Serialize the root block to its on-disk representation.
    ///
    /// The returned buffer is `ROOT_BLOCK_SIZE` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ROOT_BLOCK_SIZE] {
        let mut buf = [0u8; ROOT_BLOCK_SIZE];
        buf[0..4].copy_from_slice(ROOT_BLOCK_MAGIC);
        buf[4..8].copy_from_slice(&ROOT_BLOCK_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.commit_group_id.0.to_le_bytes());
        buf[16..24].copy_from_slice(&self.namespace_root.to_le_bytes());
        buf[24..32].copy_from_slice(&self.inode_table_root.to_le_bytes());
        buf[32..40].copy_from_slice(&self.extent_map_root.to_le_bytes());
        buf[40..48].copy_from_slice(&self.intent_log_tail.to_le_bytes());
        // Offset 48..56 is reserved (zero).
        buf[HASH_OFFSET..ROOT_BLOCK_SIZE].copy_from_slice(&self.block_hash);
        buf
    }

    /// Deserialize a root block from its on-disk representation.
    ///
    /// Returns `None` if the buffer is too short or the magic is wrong.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ROOT_BLOCK_SIZE {
            return None;
        }
        if &bytes[0..4] != ROOT_BLOCK_MAGIC {
            return None;
        }
        let _version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let commit_group_id = CommitGroupId(u64::from_le_bytes(bytes[8..16].try_into().unwrap()));
        let namespace_root = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let inode_table_root = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let extent_map_root = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let intent_log_tail = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        // Offset 48..56 is reserved.
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bytes[HASH_OFFSET..ROOT_BLOCK_SIZE]);

        Some(Self {
            commit_group_id,
            namespace_root,
            inode_table_root,
            extent_map_root,
            intent_log_tail,
            block_hash,
        })
    }

    /// The BLAKE3 hash of the block header (bytes 0..HEADER_SIZE).
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let header = self.header_bytes();
        blake3::hash(&header).into()
    }

    /// Return the header bytes (everything except the hash) for hashing.
    fn header_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(ROOT_BLOCK_MAGIC);
        header[4..8].copy_from_slice(&ROOT_BLOCK_VERSION.to_le_bytes());
        header[8..16].copy_from_slice(&self.commit_group_id.0.to_le_bytes());
        header[16..24].copy_from_slice(&self.namespace_root.to_le_bytes());
        header[24..32].copy_from_slice(&self.inode_table_root.to_le_bytes());
        header[32..40].copy_from_slice(&self.extent_map_root.to_le_bytes());
        header[40..48].copy_from_slice(&self.intent_log_tail.to_le_bytes());
        // Offset 48..56 is reserved (zero).
        header
    }
}

// ---------------------------------------------------------------------------
// CommitGroupWriter — the committed-root write-side orchestrator
// ---------------------------------------------------------------------------

/// Writes a sealed transaction group's committed-root block to stable storage.
///
/// The writer serializes the root block, computes its BLAKE3-256 hash, writes
/// it via the `CommitGroupStore`, and returns a `RootPointer` that points to
/// the newly durable root. The caller is responsible for the superblock
/// root-pointer swap.
pub struct CommitGroupWriter;

impl CommitGroupWriter {
    /// Compute the BLAKE3 hash and seal a root block by embedding the hash.
    ///
    /// After sealing, the block is ready to be written.
    #[must_use]
    pub fn seal_root_block(mut block: CommittedRootBlock) -> CommittedRootBlock {
        let hash = block.compute_hash();
        block.block_hash = hash;
        block
    }

    /// Verify that a root block's stored hash matches a recomputation.
    ///
    /// Returns `true` if the block has not been tampered with.
    #[must_use]
    pub fn verify_root_block(block: &CommittedRootBlock) -> bool {
        let recomputed = block.compute_hash();
        recomputed == block.block_hash
    }

    /// Write a sealed root block to the store and return its root pointer.
    ///
    /// The block is stored under a deterministic key name derived from the
    /// commit group id. The returned `RootPointer`'s `root_handle` is the
    /// commit group id (matching the existing convention) so the recovery
    /// loop can locate the root block by commit-group id.
    ///
    /// # Errors
    ///
    /// Returns a string error on I/O failure from the underlying store.
    #[cfg(feature = "std")]
    pub fn write_root_block<S: CommitGroupStore>(
        store: &mut S,
        block: &CommittedRootBlock,
    ) -> Result<RootPointer, String> {
        let key_name = Self::root_block_key_name(block.commit_group_id);
        let serialized = block.to_bytes();
        let _stored_key = store.put_named(&key_name, &serialized)?;

        Ok(RootPointer::new(
            block.commit_group_id,
            block.commit_group_id.0,
        ))
    }

    /// Read a previously written root block from the store.
    ///
    /// Returns `None` if no root block exists for the given commit group id.
    ///
    /// # Errors
    ///
    /// Returns a string error on I/O failure, or if the stored block fails
    /// BLAKE3 verification.
    #[cfg(feature = "std")]
    pub fn read_root_block<S: CommitGroupStore>(
        store: &S,
        commit_group_id: CommitGroupId,
    ) -> Result<Option<CommittedRootBlock>, String> {
        let key_name = Self::root_block_key_name(commit_group_id);
        let raw = store.get_named(&key_name)?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let block = CommittedRootBlock::from_bytes(&bytes)
                    .ok_or_else(|| format!("corrupt root block for {commit_group_id}"))?;
                if !Self::verify_root_block(&block) {
                    return Err(format!(
                        "BLAKE3 verification failed for root block {commit_group_id}"
                    ));
                }
                Ok(Some(block))
            }
        }
    }

    /// Full write path: seal the block, write it, return the root pointer.
    ///
    /// This is the convenience entry point for callers that have a fully
    /// populated but unsealed `CommittedRootBlock`.
    #[cfg(feature = "std")]
    pub fn seal_and_write<S: CommitGroupStore>(
        store: &mut S,
        block: CommittedRootBlock,
    ) -> Result<RootPointer, String> {
        let sealed = Self::seal_root_block(block);
        Self::write_root_block(store, &sealed)
    }

    /// Check if a committed root block exists for the given commit group.
    #[cfg(feature = "std")]
    pub fn root_block_exists<S: CommitGroupStore>(
        store: &S,
        commit_group_id: CommitGroupId,
    ) -> Result<bool, String> {
        let key_name = Self::root_block_key_name(commit_group_id);
        Ok(store.get_named(&key_name)?.is_some())
    }

    /// Return the deterministic store key name for a root block.
    #[must_use]
    #[cfg(feature = "std")]
    pub fn root_block_key_name(commit_group_id: CommitGroupId) -> String {
        format!("committed-root-{}", commit_group_id.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ------------------------------------------------------------------
    // CommittedRootBlock: round-trip
    // ------------------------------------------------------------------

    #[test]
    fn root_block_roundtrip() {
        let block = CommittedRootBlock::new(
            CommitGroupId(1),
            100, // namespace_root
            200, // inode_table_root
            300, // extent_map_root
            400, // intent_log_tail
        );
        let sealed = CommitGroupWriter::seal_root_block(block);
        let bytes = sealed.to_bytes();
        let parsed = CommittedRootBlock::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.commit_group_id, sealed.commit_group_id);
        assert_eq!(parsed.namespace_root, sealed.namespace_root);
        assert_eq!(parsed.inode_table_root, sealed.inode_table_root);
        assert_eq!(parsed.extent_map_root, sealed.extent_map_root);
        assert_eq!(parsed.intent_log_tail, sealed.intent_log_tail);
        assert_eq!(parsed.block_hash, sealed.block_hash);
    }

    #[test]
    fn root_block_hash_covers_all_fields() {
        let a = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed_a = CommitGroupWriter::seal_root_block(a);

        // Different commit_group_id -> different hash.
        let b = CommittedRootBlock::new(CommitGroupId(2), 10, 20, 30, 40);
        let sealed_b = CommitGroupWriter::seal_root_block(b);
        assert_ne!(sealed_a.block_hash, sealed_b.block_hash);

        // Different namespace_root -> different hash.
        let c = CommittedRootBlock::new(CommitGroupId(1), 99, 20, 30, 40);
        let sealed_c = CommitGroupWriter::seal_root_block(c);
        assert_ne!(sealed_a.block_hash, sealed_c.block_hash);

        // Different inode_table_root -> different hash.
        let d = CommittedRootBlock::new(CommitGroupId(1), 10, 99, 30, 40);
        let sealed_d = CommitGroupWriter::seal_root_block(d);
        assert_ne!(sealed_a.block_hash, sealed_d.block_hash);

        // Different extent_map_root -> different hash.
        let e = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 99, 40);
        let sealed_e = CommitGroupWriter::seal_root_block(e);
        assert_ne!(sealed_a.block_hash, sealed_e.block_hash);

        // Different intent_log_tail -> different hash.
        let f = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 99);
        let sealed_f = CommitGroupWriter::seal_root_block(f);
        assert_ne!(sealed_a.block_hash, sealed_f.block_hash);
    }

    #[test]
    fn root_block_verify_detects_tampering() {
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);
        assert!(CommitGroupWriter::verify_root_block(&sealed));

        // Tamper with a field.
        let mut tampered = sealed.clone();
        tampered.namespace_root = 666;
        assert!(!CommitGroupWriter::verify_root_block(&tampered));
    }

    #[test]
    fn root_block_reject_wrong_magic() {
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);
        let mut bytes = sealed.to_bytes();
        bytes[0] = 0;
        assert!(CommittedRootBlock::from_bytes(&bytes).is_none());
    }

    #[test]
    fn root_block_reject_short_buffer() {
        assert!(CommittedRootBlock::from_bytes(&[0u8; 32]).is_none());
        assert!(CommittedRootBlock::from_bytes(&[0u8; 87]).is_none());
    }

    #[test]
    fn empty_root_handles_are_valid() {
        // All-zero handles (identity root) should work.
        let block = CommittedRootBlock::new(CommitGroupId(1), 0, 0, 0, 0);
        let sealed = CommitGroupWriter::seal_root_block(block);
        assert!(CommitGroupWriter::verify_root_block(&sealed));
        assert_ne!(sealed.block_hash, [0u8; 32]);
    }

    #[test]
    fn high_valued_handles() {
        let block = CommittedRootBlock::new(
            CommitGroupId(u64::MAX),
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        );
        let sealed = CommitGroupWriter::seal_root_block(block);
        let bytes = sealed.to_bytes();
        let parsed = CommittedRootBlock::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.commit_group_id, CommitGroupId(u64::MAX));
        assert!(CommitGroupWriter::verify_root_block(&parsed));
    }

    // ------------------------------------------------------------------
    // CommitGroupWriter: store integration
    // ------------------------------------------------------------------

    struct TestStore {
        data: HashMap<String, Vec<u8>>,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }
    }

    impl CommitGroupStore for TestStore {
        fn put_named(
            &mut self,
            name: &str,
            payload: &[u8],
        ) -> Result<crate::store::CommitGroupKey, String> {
            let key = crate::store::CommitGroupKey::from_bytes32({
                let mut arr = [0u8; 32];
                let hash = blake3::hash(name.as_bytes());
                arr[..32].copy_from_slice(hash.as_bytes());
                arr
            });
            self.data.insert(name.to_string(), payload.to_vec());
            Ok(key)
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.data.get(name).cloned())
        }
    }

    #[test]
    fn write_and_read_root_block_roundtrip() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(42), 100, 200, 300, 400);

        let root = CommitGroupWriter::seal_and_write(&mut store, block.clone()).unwrap();
        assert_eq!(root.commit_group_id, CommitGroupId(42));
        assert_eq!(root.root_handle, 42);

        let read_back = CommitGroupWriter::read_root_block(&store, CommitGroupId(42))
            .unwrap()
            .unwrap();
        assert_eq!(read_back.namespace_root, 100);
        assert_eq!(read_back.inode_table_root, 200);
        assert_eq!(read_back.extent_map_root, 300);
        assert_eq!(read_back.intent_log_tail, 400);
        assert!(CommitGroupWriter::verify_root_block(&read_back));
    }

    #[test]
    fn read_nonexistent_root_block_returns_none() {
        let store = TestStore::new();
        let result = CommitGroupWriter::read_root_block(&store, CommitGroupId(1)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn write_and_read_multiple_txgs() {
        let mut store = TestStore::new();

        // Write txg 1
        let block1 = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let _root1 = CommitGroupWriter::seal_and_write(&mut store, block1).unwrap();

        // Write txg 2
        let block2 = CommittedRootBlock::new(CommitGroupId(2), 50, 60, 70, 80);
        let _root2 = CommitGroupWriter::seal_and_write(&mut store, block2).unwrap();

        // Read both back
        let r1 = CommitGroupWriter::read_root_block(&store, CommitGroupId(1))
            .unwrap()
            .unwrap();
        let r2 = CommitGroupWriter::read_root_block(&store, CommitGroupId(2))
            .unwrap()
            .unwrap();

        assert_eq!(r1.namespace_root, 10);
        assert_eq!(r2.namespace_root, 50);

        // Verify both pass integrity checks
        assert!(CommitGroupWriter::verify_root_block(&r1));
        assert!(CommitGroupWriter::verify_root_block(&r2));
    }

    #[test]
    fn sequential_txg_chain_preserves_previous_root() {
        let mut store = TestStore::new();

        for txg in 1..=5u64 {
            let block =
                CommittedRootBlock::new(CommitGroupId(txg), txg * 10, txg * 20, txg * 30, txg * 40);
            CommitGroupWriter::seal_and_write(&mut store, block).unwrap();
        }

        // All five roots must be readable and valid.
        for txg in 1..=5u64 {
            let block = CommitGroupWriter::read_root_block(&store, CommitGroupId(txg))
                .unwrap()
                .unwrap();
            assert!(CommitGroupWriter::verify_root_block(&block));
            assert_eq!(block.namespace_root, txg * 10);
        }
    }

    #[test]
    fn tampered_store_data_is_rejected() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        CommitGroupWriter::seal_and_write(&mut store, block).unwrap();

        // Corrupt the stored data.
        let key_name = CommitGroupWriter::root_block_key_name(CommitGroupId(1));
        if let Some(data) = store.data.get_mut(&key_name) {
            data[16] ^= 0xFF; // flip a bit in namespace_root (offset 16)
        }

        let result = CommitGroupWriter::read_root_block(&store, CommitGroupId(1));
        assert!(result.is_err());
    }

    #[test]
    fn root_block_exists_detects_presence() {
        let mut store = TestStore::new();
        assert!(!CommitGroupWriter::root_block_exists(&store, CommitGroupId(1)).unwrap());

        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        CommitGroupWriter::seal_and_write(&mut store, block).unwrap();

        assert!(CommitGroupWriter::root_block_exists(&store, CommitGroupId(1)).unwrap());
        assert!(!CommitGroupWriter::root_block_exists(&store, CommitGroupId(2)).unwrap());
    }

    #[test]
    fn root_block_key_name_is_deterministic() {
        assert_eq!(
            CommitGroupWriter::root_block_key_name(CommitGroupId(5)),
            "committed-root-5"
        );
        assert_eq!(
            CommitGroupWriter::root_block_key_name(CommitGroupId(0)),
            "committed-root-0"
        );
        assert_eq!(
            CommitGroupWriter::root_block_key_name(CommitGroupId(u64::MAX)),
            "committed-root-18446744073709551615"
        );
    }

    #[test]
    fn root_block_size_is_constant() {
        let block = CommittedRootBlock::new(CommitGroupId(1), 0, 0, 0, 0);
        let sealed = CommitGroupWriter::seal_root_block(block);
        assert_eq!(sealed.to_bytes().len(), ROOT_BLOCK_SIZE);
    }

    // ------------------------------------------------------------------
    // BLAKE3 hash determinism
    // ------------------------------------------------------------------

    #[test]
    fn hash_deterministic_for_same_input() {
        let a = CommittedRootBlock::new(CommitGroupId(7), 1, 2, 3, 4);
        let sealed_a = CommitGroupWriter::seal_root_block(a);
        let b = CommittedRootBlock::new(CommitGroupId(7), 1, 2, 3, 4);
        let sealed_b = CommitGroupWriter::seal_root_block(b);
        assert_eq!(sealed_a.block_hash, sealed_b.block_hash);
    }

    #[test]
    fn reserved_field_is_zero_on_wire() {
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);
        let bytes = sealed.to_bytes();
        // bytes 48..56 should be all zero (reserved)
        for &b in &bytes[48..56] {
            assert_eq!(b, 0);
        }
    }
}
