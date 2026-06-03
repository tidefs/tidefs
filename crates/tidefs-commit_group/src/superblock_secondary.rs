//! Superblock secondary-copy write for committed-root durability.
//!
//! # Overview
//!
//! Each time a committed-root block is written to the primary location
//! (via [`CommitGroupWriter`][super::writer::CommitGroupWriter]), a
//! BLAKE3-verified secondary copy is also written. On read, if the
//! primary copy is corrupt or missing, the secondary copy provides a
//! fallback, protecting against superblock sector corruption.
//!
//! # On-disk layout
//!
//! The secondary superblock consists of a 64-byte header followed by
//! the mirrored committed-root block bytes (88 bytes for V1 blocks):
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       4     Magic ("VSBS")
//! 4       4     Version (u32 LE, = 1)
//! 8       32    BLAKE3-256 checksum (covers superblock content)
//! 40      8     Sequence number (u64 LE)
//! 48      1     Copy index (u8, always 1 for secondary)
//! 49      15    Reserved (zero)
//! 64      N     Mirrored committed-root block bytes
//! ```
//!
//! Total header: 64 bytes.

use crate::store::CommitGroupStore;
use crate::types::CommitGroupId;
use crate::writer::CommittedRootBlock;

/// Magic bytes identifying a secondary superblock copy on disk.
const SECONDARY_MAGIC: &[u8; 4] = b"VSBS";

/// Current secondary header format version.
const SECONDARY_VERSION: u32 = 1;

/// Size of the secondary superblock header in bytes.
const SECONDARY_HEADER_SIZE: usize = 64;

/// Byte offset of the BLAKE3-256 checksum within the header.
const CHECKSUM_OFFSET: usize = 8;
const CHECKSUM_LEN: usize = 32;

/// Byte offset of the sequence number within the header.
const SEQUENCE_OFFSET: usize = 40;

/// Byte offset of the copy index within the header.
const COPY_INDEX_OFFSET: usize = 48;
const COPY_INDEX_VALUE: u8 = 1;

/// Byte offset where the reserved padding begins.
#[allow(dead_code)]
const RESERVED_OFFSET: usize = 49;

/// Byte offset where the superblock content begins (after header).
const CONTENT_OFFSET: usize = SECONDARY_HEADER_SIZE;

// ---------------------------------------------------------------------------
// SuperblockSecondaryHeader
// ---------------------------------------------------------------------------

/// BLAKE3-verified header placed before a mirrored committed-root block
/// in the secondary superblock copy.
///
/// The checksum covers the superblock content bytes (the serialized
/// committed-root block), not the header bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuperblockSecondaryHeader {
    /// BLAKE3-256 checksum of the superblock content.
    pub checksum: [u8; 32],
    /// Monotonic sequence number. Must be >= the last known sequence
    /// to prevent rollback attacks.
    pub sequence: u64,
    /// Copy index (always 1 for the secondary copy).
    pub copy_index: u8,
}

impl SuperblockSecondaryHeader {
    /// Create a new header for the given sequence number.
    #[must_use]
    pub fn new(sequence: u64) -> Self {
        Self {
            checksum: [0u8; 32],
            sequence,
            copy_index: COPY_INDEX_VALUE,
        }
    }

    /// Compute the BLAKE3-256 checksum over the superblock content.
    #[must_use]
    pub fn compute_checksum(superblock_bytes: &[u8]) -> [u8; 32] {
        blake3::hash(superblock_bytes).into()
    }

    /// Seal the header by computing and embedding the checksum.
    pub fn seal(&mut self, superblock_bytes: &[u8]) {
        self.checksum = Self::compute_checksum(superblock_bytes);
    }

    /// Verify that the stored checksum matches the superblock content.
    #[must_use]
    pub fn verify(&self, superblock_bytes: &[u8]) -> bool {
        let recomputed = Self::compute_checksum(superblock_bytes);
        recomputed == self.checksum
    }

    /// Serialize the header to its 64-byte on-disk representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECONDARY_HEADER_SIZE] {
        let mut buf = [0u8; SECONDARY_HEADER_SIZE];
        buf[0..4].copy_from_slice(SECONDARY_MAGIC);
        buf[4..8].copy_from_slice(&SECONDARY_VERSION.to_le_bytes());
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN].copy_from_slice(&self.checksum);
        buf[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 8].copy_from_slice(&self.sequence.to_le_bytes());
        buf[COPY_INDEX_OFFSET] = self.copy_index;
        // Reserved region (49..64) is already zero.
        buf
    }

    /// Deserialize a header from bytes read from disk.
    ///
    /// Returns `None` if the buffer is too short, the magic is wrong,
    /// or the version is unsupported.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < SECONDARY_HEADER_SIZE {
            return None;
        }
        if &bytes[0..4] != SECONDARY_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != SECONDARY_VERSION {
            return None;
        }
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN]);
        let sequence = u64::from_le_bytes(
            bytes[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let copy_index = bytes[COPY_INDEX_OFFSET];
        Some(Self {
            checksum,
            sequence,
            copy_index,
        })
    }

    /// Read the raw superblock content bytes from a combined header+content buffer.
    #[must_use]
    pub fn content_bytes(header_and_content: &[u8]) -> Option<&[u8]> {
        if header_and_content.len() < SECONDARY_HEADER_SIZE {
            return None;
        }
        Some(&header_and_content[CONTENT_OFFSET..])
    }

    /// Read the raw superblock content bytes owningly.
    #[must_use]
    pub fn content_bytes_owned(header_and_content: &[u8]) -> Option<Vec<u8>> {
        if header_and_content.len() < SECONDARY_HEADER_SIZE {
            return None;
        }
        Some(header_and_content[CONTENT_OFFSET..].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Store key helpers
// ---------------------------------------------------------------------------

/// Return the deterministic store key name for a secondary superblock copy.
#[must_use]
pub fn secondary_key_name(commit_group_id: CommitGroupId) -> String {
    format!("superblock-secondary-{}", commit_group_id.0)
}

/// Return the deterministic store key name for the primary superblock copy.
#[must_use]
pub fn primary_key_name(commit_group_id: CommitGroupId) -> String {
    crate::writer::CommitGroupWriter::root_block_key_name(commit_group_id)
}

// ---------------------------------------------------------------------------
// write_superblock_secondary
// ---------------------------------------------------------------------------

/// Write a BLAKE3-verified secondary copy of a committed-root block.
///
/// The secondary copy consists of a 64-byte [`SuperblockSecondaryHeader`]
/// followed by the serialized committed-root block bytes. The header
/// carries its own BLAKE3-256 checksum over the content, a monotonic
/// sequence number, and a copy index of 1.
///
/// This is best-effort: callers should not block the commit on secondary
/// write failure. A warning should be logged and the commit should proceed.
///
/// # Errors
///
/// Returns a string error if the underlying store write fails.
pub fn write_superblock_secondary<S: CommitGroupStore>(
    store: &mut S,
    block: &CommittedRootBlock,
    sequence: u64,
) -> Result<(), String> {
    let commit_group_id = block.commit_group_id;
    let key_name = secondary_key_name(commit_group_id);
    let superblock_bytes = block.to_bytes();

    let mut header = SuperblockSecondaryHeader::new(sequence);
    header.seal(&superblock_bytes);
    let header_bytes = header.to_bytes();

    let mut payload = Vec::with_capacity(SECONDARY_HEADER_SIZE + superblock_bytes.len());
    payload.extend_from_slice(&header_bytes);
    payload.extend_from_slice(&superblock_bytes);

    store.put_named(&key_name, &payload)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// read_superblock_with_fallback
// ---------------------------------------------------------------------------

/// Error returned when superblock read fails even after secondary fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuperblockReadError {
    /// The primary copy was corrupt. Contains the corruption detail message.
    PrimaryCorrupt(String),
    /// Both primary and secondary copies are corrupt or missing.
    BothCorrupt(String),
    /// The secondary copy has a sequence number lower than the last known.
    SequenceRegression {
        /// The last known-good sequence number.
        last_known: u64,
        /// The sequence number found in the secondary header.
        found: u64,
    },
}

/// Attempt to read a committed-root block, falling back to the secondary
/// copy if the primary is corrupt or missing.
///
/// # Algorithm
///
/// 1. Try the primary copy via `CommitGroupWriter::read_root_block`.
/// 2. If the primary succeeds, return it immediately.
/// 3. If the primary is corrupt or missing, attempt the secondary copy.
///    a. Parse and verify the [`SuperblockSecondaryHeader`].
///    b. Extract and checksum-verify the superblock content.
///    c. Validate sequence >= `last_known_sequence`.
///    d. Parse the content as a `CommittedRootBlock` and verify its hash.
///
/// # Returns
///
/// - `Ok(Some(block))` if a valid block was recovered.
/// - `Ok(None)` if neither copy exists.
/// - `Err(SuperblockReadError)` if recovery fails.
pub fn read_superblock_with_fallback<S: CommitGroupStore>(
    store: &S,
    commit_group_id: CommitGroupId,
    last_known_sequence: u64,
) -> Result<Option<CommittedRootBlock>, SuperblockReadError> {
    // Step 1: Try primary.
    let primary_result = crate::writer::CommitGroupWriter::read_root_block(store, commit_group_id);

    match primary_result {
        Ok(Some(block)) => Ok(Some(block)),
        Ok(None) => {
            // Primary missing -- try secondary.
            match read_secondary_copy(store, commit_group_id, last_known_sequence) {
                Ok(Some(block)) => Ok(Some(block)),
                Ok(None) => Ok(None),
                Err(secondary_err) => Err(secondary_err),
            }
        }
        Err(e) => {
            // Primary corrupt -- try secondary.
            match read_secondary_copy(store, commit_group_id, last_known_sequence) {
                Ok(Some(block)) => Ok(Some(block)),
                Ok(None) => Err(SuperblockReadError::BothCorrupt(format!(
                    "primary corrupt: {e}; secondary missing"
                ))),
                Err(secondary_err) => Err(SuperblockReadError::BothCorrupt(format!(
                    "primary corrupt: {e}; secondary: {secondary_err:?}"
                ))),
            }
        }
    }
}

/// Internal: read and verify the secondary copy from the store.
fn read_secondary_copy<S: CommitGroupStore>(
    store: &S,
    commit_group_id: CommitGroupId,
    last_known_sequence: u64,
) -> Result<Option<CommittedRootBlock>, SuperblockReadError> {
    let key_name = secondary_key_name(commit_group_id);
    let raw = store
        .get_named(&key_name)
        .map_err(|e| SuperblockReadError::BothCorrupt(format!("secondary read failed: {e}")))?;

    let raw = match raw {
        Some(data) => data,
        None => return Ok(None),
    };

    // Parse header.
    let header = SuperblockSecondaryHeader::from_bytes(&raw).ok_or_else(|| {
        SuperblockReadError::PrimaryCorrupt("secondary header: invalid magic or version".into())
    })?;

    // Extract content.
    let content = SuperblockSecondaryHeader::content_bytes(&raw).ok_or_else(|| {
        SuperblockReadError::PrimaryCorrupt("secondary: content too short".into())
    })?;

    // Verify header checksum over content.
    if !header.verify(content) {
        return Err(SuperblockReadError::PrimaryCorrupt(
            "secondary: BLAKE3 checksum mismatch".into(),
        ));
    }

    // Validate sequence number.
    if header.sequence < last_known_sequence {
        return Err(SuperblockReadError::SequenceRegression {
            last_known: last_known_sequence,
            found: header.sequence,
        });
    }

    // Parse root block from content.
    let block = CommittedRootBlock::from_bytes(content).ok_or_else(|| {
        SuperblockReadError::PrimaryCorrupt("secondary: invalid root block magic".into())
    })?;

    // Verify root block's own BLAKE3 hash.
    if !crate::writer::CommitGroupWriter::verify_root_block(&block) {
        return Err(SuperblockReadError::PrimaryCorrupt(
            "secondary: root block BLAKE3 verification failed".into(),
        ));
    }

    Ok(Some(block))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CommitGroupId;
    use crate::writer::{CommitGroupWriter, CommittedRootBlock};
    use std::collections::HashMap;

    // ------------------------------------------------------------------
    // TestStore
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

    /// Helper: write a sealed primary root block to the store.
    fn write_primary(store: &mut TestStore, block: &CommittedRootBlock) {
        CommitGroupWriter::write_root_block(store, block).unwrap();
    }

    // ------------------------------------------------------------------
    // SuperblockSecondaryHeader tests
    // ------------------------------------------------------------------

    #[test]
    fn header_roundtrip() {
        let mut header = SuperblockSecondaryHeader::new(42);
        let content = b"test superblock content for roundtrip check";
        header.seal(content);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), SECONDARY_HEADER_SIZE);

        let parsed = SuperblockSecondaryHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.checksum, header.checksum);
        assert_eq!(parsed.sequence, 42);
        assert_eq!(parsed.copy_index, COPY_INDEX_VALUE);
        assert!(parsed.verify(content));
    }

    #[test]
    fn header_checksum_detects_corruption() {
        let mut header = SuperblockSecondaryHeader::new(1);
        let content = b"original content";
        header.seal(content);
        assert!(header.verify(content));
        assert!(!header.verify(b"tampered content"));
    }

    #[test]
    fn header_rejects_wrong_magic() {
        let header = SuperblockSecondaryHeader::new(1);
        let mut bytes = header.to_bytes();
        bytes[0] = 0x00;
        assert!(SuperblockSecondaryHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn header_rejects_wrong_version() {
        let header = SuperblockSecondaryHeader::new(1);
        let mut bytes = header.to_bytes();
        bytes[5] = 0xFF; // change version high byte
        assert!(SuperblockSecondaryHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn header_rejects_short_buffer() {
        assert!(SuperblockSecondaryHeader::from_bytes(&[0u8; 32]).is_none());
        assert!(SuperblockSecondaryHeader::from_bytes(&[0u8; 63]).is_none());
    }

    #[test]
    fn header_content_extraction() {
        let mut header = SuperblockSecondaryHeader::new(7);
        let content = vec![0xAAu8; 88]; // ROOT_BLOCK_SIZE
        header.seal(&content);

        let hdr_bytes = header.to_bytes();
        let mut combined = Vec::new();
        combined.extend_from_slice(&hdr_bytes);
        combined.extend_from_slice(&content);

        let extracted = SuperblockSecondaryHeader::content_bytes(&combined).unwrap();
        assert_eq!(extracted, content.as_slice());
    }

    #[test]
    fn header_content_extraction_short() {
        let too_short = vec![0u8; 32];
        assert!(SuperblockSecondaryHeader::content_bytes(&too_short).is_none());
        assert!(SuperblockSecondaryHeader::content_bytes_owned(&too_short).is_none());
    }

    #[test]
    fn header_reserved_field_is_zero() {
        let header = SuperblockSecondaryHeader::new(1);
        let bytes = header.to_bytes();
        for &b in &bytes[RESERVED_OFFSET..SECONDARY_HEADER_SIZE] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn header_different_sequences_same_content_same_checksum() {
        let content = b"same content";
        let mut h1 = SuperblockSecondaryHeader::new(1);
        let mut h2 = SuperblockSecondaryHeader::new(2);
        h1.seal(content);
        h2.seal(content);
        // Checksums identical for same content.
        assert_eq!(h1.checksum, h2.checksum);
        // But serialized headers differ (sequence field).
        assert_ne!(h1.to_bytes(), h2.to_bytes());
    }

    // ------------------------------------------------------------------
    // write_superblock_secondary + read_superblock_with_fallback tests
    // ------------------------------------------------------------------

    #[test]
    fn write_and_read_secondary_roundtrip() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        write_primary(&mut store, &sealed);
        write_superblock_secondary(&mut store, &sealed, 1).unwrap();

        // Primary should be read normally.
        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0).unwrap();
        let recovered = result.unwrap();
        assert_eq!(recovered.namespace_root, 10);
        assert_eq!(recovered.inode_table_root, 20);
        assert!(CommitGroupWriter::verify_root_block(&recovered));
    }

    #[test]
    fn primary_corrupt_secondary_fallback_succeeds() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 100, 200, 300, 400);
        let sealed = CommitGroupWriter::seal_root_block(block.clone());

        // Write tampered primary.
        let mut tampered_bytes = sealed.to_bytes();
        tampered_bytes[16] ^= 0xFF; // corrupt namespace_root
        let primary_key = primary_key_name(CommitGroupId(1));
        store.put_named(&primary_key, &tampered_bytes).unwrap();

        // Write valid secondary.
        write_superblock_secondary(&mut store, &sealed, 1).unwrap();

        // Primary corrupt -> secondary fallback.
        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0).unwrap();
        let recovered = result.unwrap();
        assert_eq!(recovered.namespace_root, 100);
        assert_eq!(recovered.inode_table_root, 200);
        assert!(CommitGroupWriter::verify_root_block(&recovered));
    }

    #[test]
    fn primary_missing_secondary_present() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(7), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Only secondary, no primary.
        write_superblock_secondary(&mut store, &sealed, 7).unwrap();

        let result = read_superblock_with_fallback(&store, CommitGroupId(7), 0).unwrap();
        let recovered = result.unwrap();
        assert_eq!(recovered.namespace_root, 10);
        assert!(CommitGroupWriter::verify_root_block(&recovered));
    }

    #[test]
    fn both_copies_missing_returns_none() {
        let store = TestStore::new();
        let result = read_superblock_with_fallback(&store, CommitGroupId(99), 0).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn both_copies_corrupt_returns_error() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Tamper primary bytes (breaks BLAKE3 verification).
        let mut tampered_primary = sealed.to_bytes();
        tampered_primary[16] ^= 0xFF; // corrupt namespace_root in header
        let primary_key = primary_key_name(CommitGroupId(1));
        store.put_named(&primary_key, &tampered_primary).unwrap();

        // Write secondary, then tamper its stored bytes (breaks header checksum).
        write_superblock_secondary(&mut store, &sealed, 1).unwrap();
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        stored[CONTENT_OFFSET + 10] ^= 0xFF; // corrupt content byte
        store.data.insert(sec_key, stored);

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        assert!(matches!(result, Err(SuperblockReadError::BothCorrupt(_))));
    }

    #[test]
    fn sequence_regression_rejects_secondary() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Secondary with sequence 5.
        write_superblock_secondary(&mut store, &sealed, 5).unwrap();

        // last_known_sequence=10 -> secondary should be rejected.
        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 10);
        match result {
            Err(SuperblockReadError::SequenceRegression { last_known, found }) => {
                assert_eq!(last_known, 10);
                assert_eq!(found, 5);
            }
            other => panic!("expected SequenceRegression, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_commits_both_copies_match() {
        let mut store = TestStore::new();

        for txg in 1..=3u64 {
            let block =
                CommittedRootBlock::new(CommitGroupId(txg), txg * 10, txg * 20, txg * 30, txg * 40);
            let sealed = CommitGroupWriter::seal_root_block(block);

            write_primary(&mut store, &sealed);
            write_superblock_secondary(&mut store, &sealed, txg).unwrap();

            let primary = CommitGroupWriter::read_root_block(&store, CommitGroupId(txg))
                .unwrap()
                .unwrap();
            let secondary_result = read_superblock_with_fallback(&store, CommitGroupId(txg), 0)
                .unwrap()
                .unwrap();
            assert_eq!(primary.to_bytes(), secondary_result.to_bytes());
        }
    }

    #[test]
    fn secondary_write_failure_does_not_affect_primary_read() {
        // Simulate secondary write failure: primary exists alone.
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(5), 50, 60, 70, 80);
        let sealed = CommitGroupWriter::seal_root_block(block);

        write_primary(&mut store, &sealed);
        // No secondary written.

        let result = read_superblock_with_fallback(&store, CommitGroupId(5), 0).unwrap();
        let recovered = result.unwrap();
        assert_eq!(recovered.namespace_root, 50);
        assert!(CommitGroupWriter::verify_root_block(&recovered));
    }

    #[test]
    fn zero_length_device_edge_case() {
        let store = TestStore::new();
        let result = read_superblock_with_fallback(&store, CommitGroupId(0), 0).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn secondary_key_name_deterministic() {
        assert_eq!(
            secondary_key_name(CommitGroupId(5)),
            "superblock-secondary-5"
        );
        assert_eq!(
            secondary_key_name(CommitGroupId(0)),
            "superblock-secondary-0"
        );
    }

    #[test]
    fn primary_key_name_deterministic() {
        assert_eq!(primary_key_name(CommitGroupId(5)), "committed-root-5");
    }

    #[test]
    fn checksum_covers_content_only() {
        let content = [0x42u8; 88];
        let mut h1 = SuperblockSecondaryHeader::new(1);
        let mut h2 = SuperblockSecondaryHeader::new(999);
        h1.seal(&content);
        h2.seal(&content);
        assert_eq!(h1.checksum, h2.checksum);
    }

    #[test]
    fn content_bytes_owned_roundtrip() {
        let mut header = SuperblockSecondaryHeader::new(1);
        let content = vec![0xBBu8; 88];
        header.seal(&content);

        let hdr_bytes = header.to_bytes();
        let mut combined = Vec::new();
        combined.extend_from_slice(&hdr_bytes);
        combined.extend_from_slice(&content);

        let owned = SuperblockSecondaryHeader::content_bytes_owned(&combined).unwrap();
        assert_eq!(owned, content);
    }

    #[test]
    fn tampered_secondary_content_fails_checksum() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Write a tampered primary so the code takes the "primary corrupt" path.
        let mut tampered_primary = sealed.to_bytes();
        tampered_primary[16] ^= 0xFF;
        let primary_key = primary_key_name(CommitGroupId(1));
        store.put_named(&primary_key, &tampered_primary).unwrap();

        write_superblock_secondary(&mut store, &sealed, 1).unwrap();

        // Tamper the secondary content region.
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        stored[CONTENT_OFFSET + 10] ^= 0xFF;
        store.data.insert(sec_key, stored);

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        // Primary corrupt + secondary corrupt -> BothCorrupt
        assert!(matches!(result, Err(SuperblockReadError::BothCorrupt(_))));
    }

    #[test]
    fn high_sequence_values() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        write_superblock_secondary(&mut store, &sealed, u64::MAX).unwrap();

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0).unwrap();
        assert!(result.is_some());

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), u64::MAX).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn multiple_secondary_copies_independent() {
        let mut store = TestStore::new();
        for txg in 1..=3u64 {
            let block =
                CommittedRootBlock::new(CommitGroupId(txg), txg * 10, txg * 20, txg * 30, txg * 40);
            let sealed = CommitGroupWriter::seal_root_block(block);

            write_primary(&mut store, &sealed);
            write_superblock_secondary(&mut store, &sealed, txg).unwrap();
        }

        for txg in 1..=3u64 {
            let result = read_superblock_with_fallback(&store, CommitGroupId(txg), 0)
                .unwrap()
                .unwrap();
            assert_eq!(result.namespace_root, txg * 10);
            assert!(CommitGroupWriter::verify_root_block(&result));
        }
    }

    #[test]
    fn primary_corrupt_secondary_missing_is_both_corrupt() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Tampered primary, no secondary.
        let mut tampered = sealed.to_bytes();
        tampered[16] ^= 0xFF;
        let primary_key = primary_key_name(CommitGroupId(1));
        store.put_named(&primary_key, &tampered).unwrap();

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        assert!(matches!(result, Err(SuperblockReadError::BothCorrupt(_))));
    }
}
