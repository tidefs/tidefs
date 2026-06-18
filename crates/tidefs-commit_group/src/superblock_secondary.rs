//! Superblock secondary-copy write for committed-root durability.
//!
//! # Overview
//!
//! Each time a committed-root block is written to the primary location
//! (via [`CommitGroupWriter`][super::writer::CommitGroupWriter]), a
//! BLAKE3-verified secondary copy is also written. On read, any present
//! secondary copy is validated alongside the primary before a committed
//! root is accepted. If the primary copy is corrupt or missing, a valid
//! secondary copy provides a fallback.
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
    /// The primary committed-root block is corrupt (BLAKE3 mismatch or malformed).
    PrimaryCorrupt(String),
    /// Both primary and secondary copies are corrupt or missing.
    BothCorrupt(String),
    /// Secondary superblock magic does not match expected "VSBS".
    SecondaryMagicInvalid,
    /// Secondary superblock version is not supported.
    SecondaryVersionUnsupported(u32),
    /// Secondary superblock copy index is invalid (expected 1).
    SecondaryCopyIndexInvalid(u8),
    /// Secondary superblock BLAKE3 checksum does not match content.
    SecondaryChecksumMismatch,
    /// Secondary superblock content region is truncated or too short.
    SecondaryContentTruncated,
    /// Secondary payload could not be decoded as a valid committed-root block.
    SecondaryPayloadCorrupt(String),
    /// Secondary sequence number is older than the last-known recovery floor.
    SequenceRollback {
        /// The last known-good sequence number.
        last_known: u64,
        /// The sequence number found in the secondary header.
        found: u64,
    },
    /// Primary and secondary copies are both valid but carry different committed-root blocks.
    AmbiguousRoot {
        /// The commit-group id from the primary root block.
        primary_id: crate::types::CommitGroupId,
        /// The commit-group id from the secondary root block.
        secondary_id: crate::types::CommitGroupId,
    },
}

impl std::fmt::Display for SuperblockReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrimaryCorrupt(msg) => write!(f, "primary superblock corrupt: {msg}"),
            Self::BothCorrupt(msg) => write!(f, "both superblock copies corrupt: {msg}"),
            Self::SecondaryMagicInvalid => write!(f, "secondary superblock: invalid magic"),
            Self::SecondaryVersionUnsupported(v) => {
                write!(f, "secondary superblock: unsupported version {v}")
            }
            Self::SecondaryCopyIndexInvalid(idx) => {
                write!(f, "secondary superblock: invalid copy index {idx}")
            }
            Self::SecondaryChecksumMismatch => {
                write!(f, "secondary superblock: BLAKE3 checksum mismatch")
            }
            Self::SecondaryContentTruncated => {
                write!(f, "secondary superblock: content truncated")
            }
            Self::SecondaryPayloadCorrupt(msg) => {
                write!(f, "secondary superblock: payload corrupt: {msg}")
            }
            Self::SequenceRollback { last_known, found } => {
                write!(
                    f,
                    "secondary superblock: sequence rollback detected (last_known={last_known}, found={found})"
                )
            }
            Self::AmbiguousRoot {
                primary_id,
                secondary_id,
            } => {
                write!(
                    f,
                    "superblock divergence: primary root={primary_id}, secondary root={secondary_id}"
                )
            }
        }
    }
}

impl std::error::Error for SuperblockReadError {}

/// Recover a committed-root block, comparing primary and secondary copies
/// for coherence before accepting a root.
///
/// # Algorithm
///
/// 1. Read the primary copy via `CommitGroupWriter::read_root_block`.
/// 2. Read and fully validate the secondary copy (magic, version, copy index,
///    checksum, sequence floor, payload integrity).
/// 3. Compare the two copies:
///    a. If the primary is valid and the secondary is absent, accept the
///       primary.
///    b. If the primary is valid and the secondary is also valid, compare
///       the committed-root payloads. Matching payloads accept the primary;
///       divergent payloads produce an [`AmbiguousRoot`][SuperblockReadError::AmbiguousRoot] error.
///    c. If the primary is valid but an existing secondary copy is malformed,
///       corrupt, or rolled back, fail closed with the secondary validation
///       error.
///    d. If the primary is corrupt or missing and the secondary is valid
///       (checksum OK, sequence >= floor), accept the secondary.
///    e. If both copies are missing, return `Ok(None)`.
///    f. If the primary is corrupt and the secondary is missing or corrupt,
///       return a [`BothCorrupt`][SuperblockReadError::BothCorrupt] error.
///
/// Secondary validation failures are returned as distinct error variants
/// ([`SecondaryMagicInvalid`][SuperblockReadError::SecondaryMagicInvalid],
/// [`SecondaryVersionUnsupported`][SuperblockReadError::SecondaryVersionUnsupported],
/// [`SecondaryCopyIndexInvalid`][SuperblockReadError::SecondaryCopyIndexInvalid],
/// [`SecondaryChecksumMismatch`][SuperblockReadError::SecondaryChecksumMismatch],
/// [`SecondaryContentTruncated`][SuperblockReadError::SecondaryContentTruncated],
/// [`SecondaryPayloadCorrupt`][SuperblockReadError::SecondaryPayloadCorrupt],
/// [`SequenceRollback`][SuperblockReadError::SequenceRollback]).
///
/// # Returns
///
/// - `Ok(Some(block))` if a valid block was recovered.
/// - `Ok(None)` if neither copy exists.
/// - `Err(SuperblockReadError)` if recovery fails.
///
/// # Ambiguity safety
///
/// When both primary and secondary copies are individually valid but contain
/// different committed-root blocks, the function fails with
/// [`AmbiguousRoot`][SuperblockReadError::AmbiguousRoot] rather than silently
/// picking one. This protects against torn writes that leave both copies
/// intact but divergent.
pub fn read_superblock_with_fallback<S: CommitGroupStore>(
    store: &S,
    commit_group_id: CommitGroupId,
    last_known_sequence: u64,
) -> Result<Option<CommittedRootBlock>, SuperblockReadError> {
    recover_committed_root(store, commit_group_id, last_known_sequence)
}

/// Parse and validate a secondary superblock header with granular errors.
///
/// Checks magic, version, and copy index independently, returning a distinct
/// [`SuperblockReadError`] variant for each failure mode.
fn parse_secondary_header(raw: &[u8]) -> Result<SuperblockSecondaryHeader, SuperblockReadError> {
    if raw.len() < SECONDARY_HEADER_SIZE {
        return Err(SuperblockReadError::SecondaryContentTruncated);
    }

    // Validate magic.
    if &raw[0..4] != SECONDARY_MAGIC {
        return Err(SuperblockReadError::SecondaryMagicInvalid);
    }

    // Validate version.
    let version = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    if version != SECONDARY_VERSION {
        return Err(SuperblockReadError::SecondaryVersionUnsupported(version));
    }

    // Validate copy index.
    let copy_index = raw[COPY_INDEX_OFFSET];
    if copy_index != COPY_INDEX_VALUE {
        return Err(SuperblockReadError::SecondaryCopyIndexInvalid(copy_index));
    }

    let checksum = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN]);
        arr
    };

    let sequence = u64::from_le_bytes(
        raw[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );

    Ok(SuperblockSecondaryHeader {
        checksum,
        sequence,
        copy_index,
    })
}

/// Full secondary copy validation: parse header, extract content,
/// verify checksum, validate sequence floor, and decode the
/// committed-root block payload.
fn read_secondary_copy_validated<S: CommitGroupStore>(
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

    // Parse and validate header (magic, version, copy index).
    let header = parse_secondary_header(&raw)?;

    // Extract content region.
    let content = SuperblockSecondaryHeader::content_bytes(&raw)
        .ok_or(SuperblockReadError::SecondaryContentTruncated)?;

    // Verify header checksum over content.
    if !header.verify(content) {
        return Err(SuperblockReadError::SecondaryChecksumMismatch);
    }

    // Validate sequence number against recovery floor.
    if header.sequence < last_known_sequence {
        return Err(SuperblockReadError::SequenceRollback {
            last_known: last_known_sequence,
            found: header.sequence,
        });
    }

    // Decode content as a CommittedRootBlock.
    let block = CommittedRootBlock::from_bytes(content).ok_or_else(|| {
        SuperblockReadError::SecondaryPayloadCorrupt("invalid root block magic or version".into())
    })?;

    // Verify root block's own BLAKE3 integrity.
    if !crate::writer::CommitGroupWriter::verify_root_block(&block) {
        return Err(SuperblockReadError::SecondaryPayloadCorrupt(
            "root block BLAKE3 verification failed".into(),
        ));
    }

    Ok(Some(block))
}

/// Compare two committed-root blocks for equality.
///
/// Two blocks are equivalent when their serialized byte representations
/// match.  We compare the full on-wire form so that any field-level
/// divergence (including reserved-zero regions) is treated as a
/// mismatch.
fn root_blocks_equivalent(a: &CommittedRootBlock, b: &CommittedRootBlock) -> bool {
    a.to_bytes() == b.to_bytes()
}

/// Recover the committed-root block for `commit_group_id` by reading
/// both the primary and secondary copies and cross-validating them.
///
/// This is the authoritative recovery entry-point.  See
/// [`read_superblock_with_fallback`] for the public-facing alias.
fn recover_committed_root<S: CommitGroupStore>(
    store: &S,
    commit_group_id: CommitGroupId,
    last_known_sequence: u64,
) -> Result<Option<CommittedRootBlock>, SuperblockReadError> {
    // Read primary copy.
    let primary_result = crate::writer::CommitGroupWriter::read_root_block(store, commit_group_id);

    // Read and fully validate secondary copy (if present).
    let secondary_result =
        read_secondary_copy_validated(store, commit_group_id, last_known_sequence);

    match (primary_result, secondary_result) {
        // --- Primary valid ---------------------------------------------------
        (Ok(Some(primary)), Ok(Some(secondary))) => {
            // Both copies are individually valid.  They must agree.
            if root_blocks_equivalent(&primary, &secondary) {
                Ok(Some(primary))
            } else {
                Err(SuperblockReadError::AmbiguousRoot {
                    primary_id: primary.commit_group_id,
                    secondary_id: secondary.commit_group_id,
                })
            }
        }
        (Ok(Some(primary)), Ok(None)) => {
            // Primary valid; secondary absent is acceptable.
            Ok(Some(primary))
        }
        (Ok(Some(_)), Err(secondary_err)) => {
            // A present secondary copy is recovery evidence. If it is malformed,
            // corrupt, or rolled back, fail closed instead of silently selecting
            // the primary.
            Err(secondary_err)
        }

        // --- Primary missing or corrupt --------------------------------------
        (Ok(None), Ok(Some(secondary))) => {
            // Primary missing, secondary valid.
            Ok(Some(secondary))
        }
        (Err(primary_err), Ok(Some(secondary))) => {
            // Primary corrupt, secondary valid.
            let _ = primary_err; // secondary is the recovery path
            Ok(Some(secondary))
        }

        // --- Neither copy is usable ------------------------------------------
        (Ok(None), Ok(None)) => Ok(None),
        // When primary is missing and secondary has a specific failure,
        // propagate the secondary error directly so callers can match on it.
        (Ok(None), Err(secondary_err)) => Err(secondary_err),
        (Err(primary_err), Ok(None)) => Err(SuperblockReadError::BothCorrupt(format!(
            "primary corrupt: {primary_err}; secondary missing"
        ))),
        (Err(primary_err), Err(secondary_err)) => Err(SuperblockReadError::BothCorrupt(format!(
            "primary corrupt: {primary_err}; secondary: {secondary_err}"
        ))),
    }
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
    fn sequence_rollback_rejects_secondary() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Secondary with sequence 5.
        write_superblock_secondary(&mut store, &sealed, 5).unwrap();

        // last_known_sequence=10 -> secondary should be rejected.
        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 10);
        match result {
            Err(SuperblockReadError::SequenceRollback { last_known, found }) => {
                assert_eq!(last_known, 10);
                assert_eq!(found, 5);
            }
            other => panic!("expected SequenceRollback, got {other:?}"),
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
    // ------------------------------------------------------------------
    // Ambiguous root (primary/secondary disagreement) tests
    // ------------------------------------------------------------------

    #[test]
    fn ambiguous_root_when_both_valid_but_disagree() {
        let mut store = TestStore::new();
        // Primary carries one root.
        let block_primary = CommittedRootBlock::new(CommitGroupId(1), 100, 200, 300, 400);
        let sealed_primary = CommitGroupWriter::seal_root_block(block_primary);
        write_primary(&mut store, &sealed_primary);

        // Secondary carries a different root (different namespace_root).
        let block_secondary = CommittedRootBlock::new(CommitGroupId(1), 999, 200, 300, 400);
        let sealed_secondary = CommitGroupWriter::seal_root_block(block_secondary);
        write_superblock_secondary(&mut store, &sealed_secondary, 1).unwrap();

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        match result {
            Err(SuperblockReadError::AmbiguousRoot {
                primary_id,
                secondary_id,
            }) => {
                assert_eq!(primary_id, CommitGroupId(1));
                assert_eq!(secondary_id, CommitGroupId(1));
            }
            other => panic!("expected AmbiguousRoot, got {other:?}"),
        }
    }

    #[test]
    fn no_ambiguity_when_both_copies_agree() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 42, 43, 44, 45);
        let sealed = CommitGroupWriter::seal_root_block(block);
        write_primary(&mut store, &sealed);
        write_superblock_secondary(&mut store, &sealed, 1).unwrap();

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0)
            .unwrap()
            .unwrap();
        assert_eq!(result.namespace_root, 42);
        assert_eq!(result.inode_table_root, 43);
    }

    // ------------------------------------------------------------------
    // Secondary-specific error variant tests
    // ------------------------------------------------------------------

    #[test]
    fn secondary_magic_invalid_error() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        // Tamper primary so we take the secondary-check path.
        let mut tampered = sealed.to_bytes();
        tampered[16] ^= 0xFF;
        let primary_key = primary_key_name(CommitGroupId(1));
        store.put_named(&primary_key, &tampered).unwrap();

        // Write secondary, then corrupt its magic.
        write_superblock_secondary(&mut store, &sealed, 1).unwrap();
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        stored[0] = 0x00; // break magic
        store.data.insert(sec_key, stored);

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        assert!(matches!(result, Err(SuperblockReadError::BothCorrupt(_))));
        // The secondary error itself is SecondaryMagicInvalid, but it gets wrapped
        // as BothCorrupt when primary is also corrupt.  To test the variant
        // directly we call the inner validator.
    }

    #[test]
    fn secondary_magic_invalid_direct() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        write_superblock_secondary(&mut store, &sealed, 1).unwrap();
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        stored[0] = 0x00; // break magic
        store.data.insert(sec_key, stored);

        // Direct call to the inner validator.
        let result = read_secondary_copy_validated(&store, CommitGroupId(1), 0);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryMagicInvalid)
        ));
    }

    #[test]
    fn secondary_version_unsupported_direct() {
        let header = SuperblockSecondaryHeader::new(1);
        let mut bytes = header.to_bytes();
        // Set version to 99 (unsupported).
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());

        let result = parse_secondary_header(&bytes);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryVersionUnsupported(99))
        ));
    }

    #[test]
    fn secondary_copy_index_invalid_direct() {
        let header = SuperblockSecondaryHeader::new(1);
        let mut bytes = header.to_bytes();
        bytes[COPY_INDEX_OFFSET] = 99; // invalid copy index

        let result = parse_secondary_header(&bytes);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryCopyIndexInvalid(99))
        ));
    }

    #[test]
    fn secondary_checksum_mismatch_direct() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        write_superblock_secondary(&mut store, &sealed, 1).unwrap();
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        // Flip a byte in the content region (after header) to break checksum.
        stored[CONTENT_OFFSET + 5] ^= 0xFF;
        store.data.insert(sec_key, stored);

        let result = read_secondary_copy_validated(&store, CommitGroupId(1), 0);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryChecksumMismatch)
        ));
    }

    #[test]
    fn secondary_content_truncated_direct() {
        let result = parse_secondary_header(&[0u8; 32]);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryContentTruncated)
        ));
    }

    #[test]
    fn secondary_payload_corrupt_direct() {
        // Build a secondary manually: valid header + valid checksum, but
        // content whose VRBT magic is wrong (so payload parsing fails after
        // checksum passes).
        let valid_content = [0xABu8; 88]; // wrong magic, not a real VRBT block
        let mut header = SuperblockSecondaryHeader::new(1);
        header.seal(&valid_content);

        let hdr_bytes = header.to_bytes();
        let mut combined = Vec::new();
        combined.extend_from_slice(&hdr_bytes);
        combined.extend_from_slice(&valid_content);

        let mut store = TestStore::new();
        let sec_key = secondary_key_name(CommitGroupId(1));
        store.data.insert(sec_key, combined);

        let result = read_secondary_copy_validated(&store, CommitGroupId(1), 0);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryPayloadCorrupt(_))
        ));
    }

    // ------------------------------------------------------------------
    // Primary-valid / secondary-invalid: fail closed
    // ------------------------------------------------------------------

    #[test]
    fn primary_valid_secondary_bad_magic_fails_closed() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block.clone());
        write_primary(&mut store, &sealed);

        // Write secondary with bad magic.
        write_superblock_secondary(&mut store, &sealed, 1).unwrap();
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        stored[0] = 0x00; // break magic
        store.data.insert(sec_key, stored);

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryMagicInvalid)
        ));
    }

    #[test]
    fn primary_valid_secondary_checksum_mismatch_fails_closed() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block.clone());
        write_primary(&mut store, &sealed);

        write_superblock_secondary(&mut store, &sealed, 1).unwrap();
        let sec_key = secondary_key_name(CommitGroupId(1));
        let mut stored = store.data.get(&sec_key).unwrap().clone();
        stored[CONTENT_OFFSET + 3] ^= 0xFF; // break checksum
        store.data.insert(sec_key, stored);

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0);
        assert!(matches!(
            result,
            Err(SuperblockReadError::SecondaryChecksumMismatch)
        ));
    }

    #[test]
    fn primary_valid_secondary_rollback_fails_closed() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);
        write_primary(&mut store, &sealed);

        write_superblock_secondary(&mut store, &sealed, 5).unwrap();

        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 10);
        match result {
            Err(SuperblockReadError::SequenceRollback { last_known, found }) => {
                assert_eq!(last_known, 10);
                assert_eq!(found, 5);
            }
            other => panic!("expected SequenceRollback, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Sequence rollback (distinct testable error)
    // ------------------------------------------------------------------

    #[test]
    fn sequence_rollback_distinct_error() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);

        write_superblock_secondary(&mut store, &sealed, 5).unwrap();

        // last_known_sequence=10 -> secondary should be rejected with SequenceRollback.
        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 10);
        match result {
            Err(SuperblockReadError::SequenceRollback { last_known, found }) => {
                assert_eq!(last_known, 10);
                assert_eq!(found, 5);
            }
            other => panic!("expected SequenceRollback, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Primary-only (no secondary at all) -> still works
    // ------------------------------------------------------------------

    #[test]
    fn primary_only_no_secondary_returns_primary() {
        let mut store = TestStore::new();
        let block = CommittedRootBlock::new(CommitGroupId(1), 10, 20, 30, 40);
        let sealed = CommitGroupWriter::seal_root_block(block);
        write_primary(&mut store, &sealed);

        // No secondary written at all.
        let result = read_superblock_with_fallback(&store, CommitGroupId(1), 0)
            .unwrap()
            .unwrap();
        assert_eq!(result.namespace_root, 10);
        assert!(CommitGroupWriter::verify_root_block(&result));
    }

    // ------------------------------------------------------------------
    // Display / Error trait
    // ------------------------------------------------------------------

    #[test]
    fn superblock_read_error_display() {
        let e = SuperblockReadError::SecondaryMagicInvalid;
        let msg = format!("{e}");
        assert!(msg.contains("invalid magic"));

        let e = SuperblockReadError::SecondaryVersionUnsupported(99);
        let msg = format!("{e}");
        assert!(msg.contains("99"));

        let e = SuperblockReadError::SecondaryCopyIndexInvalid(7);
        let msg = format!("{e}");
        assert!(msg.contains("7"));

        let e = SuperblockReadError::SequenceRollback {
            last_known: 10,
            found: 3,
        };
        let msg = format!("{e}");
        assert!(msg.contains("10"));
        assert!(msg.contains("3"));

        let e = SuperblockReadError::AmbiguousRoot {
            primary_id: CommitGroupId(1),
            secondary_id: CommitGroupId(2),
        };
        let msg = format!("{e}");
        // CommitGroupId Display format is "commit_group-N".
        assert!(msg.contains("primary root=commit_group-1"));
        assert!(msg.contains("secondary root=commit_group-2"));
    }
}
