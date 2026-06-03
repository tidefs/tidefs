//! Committed-root recovery: locate and BLAKE3-verify the latest committed
//! transaction group root during pool import.
//!
//! This module scans the commit-record region on each device, identifies
//! the latest committed transaction group, verifies the BLAKE3 hash
//! chain across all committed epochs, and returns an authenticated
//! [`CommittedRoot`] as the starting filesystem state.
//!
//! # On-disk format
//!
//! The commit-record region begins at offset [`COMMIT_RECORD_REGION_OFFSET`]
//! (8 KiB, immediately after the pool label area) and contains:
//!
//! ```text
//! Header:
//!   magic:        [u8; 4]  = b"VBCR"  (0x56, 0x42, 0x43, 0x52)
//!   version:      u8       = 0x01
//!   record_count: u32 LE
//!   header_csum:  [u8; 32]  BLAKE3-256 over header bytes (excluding csum)
//!
//! Per-record (repeated record_count times):
//!   epoch_number:          u64 LE
//!   commit_group_id:       u64 LE
//!   commit_hash:           [u8; 32]
//!   prior_hash_present:    u8  (0 or 1)
//!   prior_epoch_hash:      [u8; 32]  (present only if prior_hash_present == 1)
//!   dirty_object_count:    u64 LE
//!   dirty_ids_count:       u64 LE
//!   dirty_object_ids:      u64 LE × dirty_ids_count
//! ```
//!
//! This region is written once at commit_group commit time and only appended
//! to (records monotonically increase). Pool import reads the last
//! valid record and verifies the BLAKE3 chain backward to epoch 1.

use std::io::{Read, Seek, SeekFrom};

use tidefs_commit_group::{seal_commit_hash, CommitGroupId, CommitRecord, RootPointer};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying the commit-record region.
pub const COMMIT_RECORD_MAGIC: [u8; 4] = [0x56, 0x42, 0x43, 0x52]; // "VBCR"

/// Current binary format version.
pub const COMMIT_RECORD_VERSION: u8 = 0x01;

/// Offset in bytes from the start of the device where the commit-record
/// region begins (8 KiB, after the 4 KiB label area plus a gap).
pub const COMMIT_RECORD_REGION_OFFSET: u64 = 8192;

/// Maximum size of the commit-record region (256 KiB).
pub const COMMIT_RECORD_REGION_MAX: u64 = 256 * 1024;

/// BLAKE3-256 digest size.
const DIGEST_SIZE: usize = 32;

/// Header size: magic(4) + version(1) + record_count(4) + header_csum(32).
const HEADER_SIZE: usize = 4 + 1 + 4 + 32;

// ---------------------------------------------------------------------------
// CommittedRoot
// ---------------------------------------------------------------------------

/// An authenticated committed filesystem root recovered during pool import.
///
/// The root pointer identifies the latest committed transaction group.
/// The commitment_hash is the BLAKE3 hash of that epoch's commit record,
/// which chains back to epoch 1 through [`CommitRecord::prior_epoch_hash`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRoot {
    /// The root pointer (commit group id + object-store handle).
    pub root: RootPointer,
    /// BLAKE3 commitment hash of the latest committed epoch.
    pub commitment_hash: [u8; 32],
    /// Epoch number of the latest committed epoch.
    pub epoch_number: u64,
    /// Number of dirty object IDs in the latest epoch.
    pub dirty_object_count: u64,
}

impl CommittedRoot {
    #[allow(dead_code)]
    /// Create a new authenticated committed root.
    #[allow(dead_code)]
    pub fn new(
        root: RootPointer,
        commitment_hash: [u8; 32],
        epoch_number: u64,
        dirty_object_count: u64,
    ) -> Self {
        Self {
            root,
            commitment_hash,
            epoch_number,
            dirty_object_count,
        }
    }

    /// Returns `true` if this represents a valid committed root.
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        self.root.is_valid()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during committed-root recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommittedRootError {
    /// The commit-record region header is truncated or missing.
    TruncatedHeader {
        /// Bytes found (usually 0).
        found: usize,
    },
    /// Magic bytes do not match.
    BadMagic {
        /// The magic bytes that were found.
        found: [u8; 4],
    },
    /// Unknown commit-record format version.
    UnknownVersion {
        /// The version byte found.
        version: u8,
    },
    /// Header BLAKE3 checksum does not match.
    HeaderChecksumMismatch,
    /// The commit-record region contains no records.
    #[allow(dead_code)]
    NoRecords,
    /// A record in the chain is truncated.
    TruncatedRecord {
        /// Zero-based record index.
        record_index: usize,
    },
    /// A record's prior_epoch_hash references a non-existent hash.
    ChainBroken {
        /// Epoch number where the break was detected.
        epoch_number: u64,
    },
    /// BLAKE3 verification of a commit record failed (corruption).
    RecordVerificationFailed {
        /// Epoch number of the corrupted record.
        epoch_number: u64,
    },
    /// A record's commit_group_id is not monotonically increasing.
    #[allow(dead_code)]
    NonMonotonicCommitGroupId {
        /// Expected minimum id.
        expected: u64,
        /// Actual id found.
        found: u64,
    },
    /// I/O error while reading the commit-record region.
    Io {
        /// Human-readable description.
        msg: String,
    },
    /// The recovered committed root is stale (epoch_number below the
    /// minimum acceptable epoch).  This is the split-brain prevention
    /// gate: a partitioned writer's root is rejected when it rejoins a
    /// cluster whose quorum has advanced past it.
    StaleRoot {
        /// Epoch number of the recovered committed root.
        recovered_epoch: u64,
        /// Minimum acceptable epoch for import.
        min_epoch: u64,
    },
}

impl std::fmt::Display for CommittedRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { found } => {
                write!(
                    f,
                    "commit-record region header truncated: expected {HEADER_SIZE} bytes, found {found}"
                )
            }
            Self::BadMagic { found } => {
                write!(
                    f,
                    "bad commit-record magic: expected {COMMIT_RECORD_MAGIC:02x?}, got {found:02x?}"
                )
            }
            Self::UnknownVersion { version } => {
                write!(f, "unknown commit-record version {version}")
            }
            Self::HeaderChecksumMismatch => {
                write!(f, "commit-record header BLAKE3 checksum mismatch")
            }
            Self::NoRecords => {
                write!(f, "commit-record region contains no records")
            }
            Self::TruncatedRecord { record_index } => {
                write!(f, "commit record {record_index} is truncated")
            }
            Self::ChainBroken { epoch_number } => {
                write!(f, "commit hash chain broken at epoch {epoch_number}")
            }
            Self::RecordVerificationFailed { epoch_number } => {
                write!(
                    f,
                    "BLAKE3 verification failed for commit record at epoch {epoch_number}"
                )
            }
            Self::NonMonotonicCommitGroupId { expected, found } => {
                write!(
                    f,
                    "non-monotonic commit group id: expected >= {expected}, found {found}"
                )
            }
            Self::Io { msg } => {
                write!(f, "I/O error reading commit-record region: {msg}")
            }
            Self::StaleRoot {
                recovered_epoch,
                min_epoch,
            } => {
                write!(
                    f,
                    "stale committed root: recovered epoch {recovered_epoch} is below min epoch {min_epoch}"
                )
            }
        }
    }
}

impl std::error::Error for CommittedRootError {}

// ---------------------------------------------------------------------------
// Internal: on-disk record representation (deserialized)
// ---------------------------------------------------------------------------

/// A parsed commit record from the on-disk region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCommitRecord {
    pub epoch_number: u64,
    pub commit_group_id: u64,
    pub commit_hash: [u8; 32],
    pub prior_epoch_hash: Option<[u8; 32]>,
    pub dirty_object_ids: Vec<u64>,
}

impl ParsedCommitRecord {
    #[allow(dead_code)]
    /// Convert to a `CommitRecord` from tidefs-commit_group.
    #[allow(dead_code)]
    fn to_commit_record(&self) -> CommitRecord {
        CommitRecord {
            epoch_number: self.epoch_number,
            commit_group_id: CommitGroupId(self.commit_group_id),
            commit_hash: self.commit_hash,
            prior_epoch_hash: self.prior_epoch_hash,
            dirty_object_count: self.dirty_object_ids.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding / decoding
// ---------------------------------------------------------------------------

/// Encode the header into `buf`.
#[allow(dead_code)]
fn encode_header_into(record_count: u32, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&COMMIT_RECORD_MAGIC);
    buf.push(COMMIT_RECORD_VERSION);
    buf.extend_from_slice(&record_count.to_le_bytes());
    // Reserve space for header_csum, filled after hashing.
    let csum_pos = buf.len();
    buf.extend_from_slice(&[0u8; DIGEST_SIZE]);
    // Compute header hash over everything before the csum slot.
    let header_bytes = &buf[..HEADER_SIZE - DIGEST_SIZE];
    let csum = blake3::hash(header_bytes);
    buf[csum_pos..csum_pos + DIGEST_SIZE].copy_from_slice(csum.as_bytes());
}

/// Decode header from the first `HEADER_SIZE` bytes of `data`.
///
/// Returns `(record_count, header_bytes)` on success.
fn decode_header(data: &[u8]) -> Result<(u32, &[u8]), CommittedRootError> {
    if data.len() < HEADER_SIZE {
        return Err(CommittedRootError::TruncatedHeader { found: data.len() });
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap();
    if magic != COMMIT_RECORD_MAGIC {
        return Err(CommittedRootError::BadMagic { found: magic });
    }

    let version = data[4];
    if version != COMMIT_RECORD_VERSION {
        return Err(CommittedRootError::UnknownVersion { version });
    }

    let record_count = u32::from_le_bytes(data[5..9].try_into().unwrap());

    // Verify header checksum.
    let expected_csum: [u8; DIGEST_SIZE] = data[9..41].try_into().unwrap();
    let computed = blake3::hash(&data[..9]); // hash over magic + version + record_count
    if computed.as_bytes() != &expected_csum {
        return Err(CommittedRootError::HeaderChecksumMismatch);
    }

    Ok((record_count, &data[HEADER_SIZE..]))
}

/// Encode a single commit record into `buf`.
#[allow(dead_code)]
fn encode_record_into(record: &ParsedCommitRecord, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&record.epoch_number.to_le_bytes());
    buf.extend_from_slice(&record.commit_group_id.to_le_bytes());
    buf.extend_from_slice(&record.commit_hash);
    match &record.prior_epoch_hash {
        Some(h) => {
            buf.push(1u8);
            buf.extend_from_slice(h);
        }
        None => {
            buf.push(0u8);
            buf.extend_from_slice(&[0u8; DIGEST_SIZE]);
        }
    }
    let dirty_count = record.dirty_object_ids.len() as u64;
    buf.extend_from_slice(&dirty_count.to_le_bytes());
    buf.extend_from_slice(&dirty_count.to_le_bytes()); // dirty_ids_count
    for id in &record.dirty_object_ids {
        buf.extend_from_slice(&id.to_le_bytes());
    }
}

/// Decode a single commit record from `data`, returning the record and
/// number of bytes consumed.
fn decode_record(
    data: &[u8],
    record_index: usize,
) -> Result<(ParsedCommitRecord, usize), CommittedRootError> {
    // Minimum size: epoch_number(8) + commit_group_id(8) + commit_hash(32)
    // + prior_hash_present(1) + prior_epoch_hash(32) + dirty_object_count(8)
    // + dirty_ids_count(8) = 97 bytes.
    const MIN_RECORD_SIZE: usize = 8 + 8 + 32 + 1 + 32 + 8 + 8;

    if data.len() < MIN_RECORD_SIZE {
        return Err(CommittedRootError::TruncatedRecord { record_index });
    }

    let epoch_number = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let commit_group_id = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let commit_hash: [u8; 32] = data[16..48].try_into().unwrap();
    let prior_hash_present = data[48];
    let prior_epoch_hash_bytes: [u8; 32] = data[49..81].try_into().unwrap();
    let prior_epoch_hash = if prior_hash_present == 1 {
        Some(prior_epoch_hash_bytes)
    } else if prior_hash_present == 0 {
        None
    } else {
        return Err(CommittedRootError::TruncatedRecord { record_index });
    };

    let _dirty_object_count = u64::from_le_bytes(data[81..89].try_into().unwrap());
    let dirty_ids_count = u64::from_le_bytes(data[89..97].try_into().unwrap());

    let ids_start = 97;
    let ids_end = ids_start + (dirty_ids_count as usize) * 8;
    if data.len() < ids_end {
        return Err(CommittedRootError::TruncatedRecord { record_index });
    }

    let mut dirty_object_ids = Vec::with_capacity(dirty_ids_count as usize);
    for i in 0..dirty_ids_count as usize {
        let off = ids_start + i * 8;
        let id = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        dirty_object_ids.push(id);
    }

    // Verify the BLAKE3 hash of this record matches the stored commit_hash.
    let recomputed = seal_commit_hash(
        epoch_number,
        CommitGroupId(commit_group_id),
        prior_epoch_hash,
        &dirty_object_ids,
    );
    if recomputed != commit_hash {
        return Err(CommittedRootError::RecordVerificationFailed { epoch_number });
    }

    Ok((
        ParsedCommitRecord {
            epoch_number,
            commit_group_id,
            commit_hash,
            prior_epoch_hash,
            dirty_object_ids,
        },
        ids_end,
    ))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encode a list of commit records into a region suitable for writing
/// to a device at [`COMMIT_RECORD_REGION_OFFSET`].
///
/// This is a helper used by tests and by the commit_group commit path to persist
/// the commit-record chain.
#[allow(dead_code)]
pub fn encode_commit_record_region(records: &[ParsedCommitRecord]) -> Vec<u8> {
    let mut buf = Vec::new();
    let count = records.len() as u32;
    encode_header_into(count, &mut buf);
    for record in records {
        encode_record_into(record, &mut buf);
    }
    buf
}

/// Build a test `ParsedCommitRecord` from a `CommitRecord` and dirty IDs.
#[cfg(test)]
#[allow(dead_code)]
pub fn parsed_record_from_commit_record(
    record: &CommitRecord,
    dirty_object_ids: &[u64],
) -> ParsedCommitRecord {
    ParsedCommitRecord {
        epoch_number: record.epoch_number,
        commit_group_id: record.commit_group_id.0,
        commit_hash: record.commit_hash,
        prior_epoch_hash: record.prior_epoch_hash,
        dirty_object_ids: dirty_object_ids.to_vec(),
    }
}

/// Recover the committed root from a raw device file handle.
///
/// This function reads the commit-record region from the given file,
/// parses all records, verifies the BLAKE3 hash chain from epoch 1
/// forward, and returns the latest authenticated committed root.
///
/// Returns `Ok(None)` if the commit-record region is absent (empty/missing),
/// which is valid for a freshly-created pool with no committed epochs.
///
/// # Errors
///
/// Returns [`CommittedRootError`] if the region is present but corrupted.
pub fn recover_committed_root_from_file(
    file: &mut (impl Read + Seek),
    min_epoch: Option<u64>,
) -> Result<Option<CommittedRoot>, CommittedRootError> {
    let region_buf = read_commit_record_region(file)?;
    recover_committed_root_from_bytes(&region_buf, min_epoch)
}

/// Read the commit-record region from a device file into a byte buffer.
///
/// Returns an empty buffer if the file is shorter than the commit-record
/// offset or the region is zero-filled (fresh pool).
fn read_commit_record_region(file: &mut (impl Read + Seek)) -> Result<Vec<u8>, CommittedRootError> {
    let mut region_buf = vec![0u8; COMMIT_RECORD_REGION_MAX as usize];
    file.seek(SeekFrom::Start(COMMIT_RECORD_REGION_OFFSET))
        .map_err(|e| CommittedRootError::Io {
            msg: format!("seek: {e}"),
        })?;
    let n = file
        .read(&mut region_buf)
        .map_err(|e| CommittedRootError::Io {
            msg: format!("read: {e}"),
        })?;
    region_buf.truncate(n);
    Ok(region_buf)
}

/// Parse and verify committed-root records from a byte slice.
///
/// This is the core recovery logic shared between device-file recovery
/// ([`recover_committed_root_from_file`]) and in-memory tests.
/// The bytes are expected to contain the commit-record region starting
/// at position 0.
pub(crate) fn recover_committed_root_from_bytes(
    region_buf: &[u8],
    min_epoch: Option<u64>,
) -> Result<Option<CommittedRoot>, CommittedRootError> {
    let n = region_buf.len();
    if n == 0 {
        return Ok(None);
    }
    // If the region starts with zeros, treat as absent (fresh pool).
    if n >= 4 && region_buf[0..4] == [0u8; 4] {
        return Ok(None);
    }

    let (record_count, record_data) = decode_header(region_buf)?;

    if record_count == 0 {
        return Ok(None);
    }

    // Parse all records, verifying each one's BLAKE3 hash as we go.
    let mut records: Vec<ParsedCommitRecord> = Vec::with_capacity(record_count as usize);
    let mut cursor = 0;

    for i in 0..record_count as usize {
        if cursor >= record_data.len() {
            return Err(CommittedRootError::TruncatedRecord { record_index: i });
        }
        let (record, consumed) = decode_record(&record_data[cursor..], i)?;
        cursor += consumed;
        records.push(record);
    }

    // Verify chain integrity: each record (except epoch 1) must reference
    // the prior record's commit_hash.
    // Extra trailing data after all declared records is accepted.
    for i in 0..records.len() {
        let record = &records[i];
        if i == 0 {
            if record.prior_epoch_hash.is_some() {
                return Err(CommittedRootError::ChainBroken {
                    epoch_number: record.epoch_number,
                });
            }
        } else {
            let expected_prior = records[i - 1].commit_hash;
            match record.prior_epoch_hash {
                Some(h) if h == expected_prior => {}
                _ => {
                    return Err(CommittedRootError::ChainBroken {
                        epoch_number: record.epoch_number,
                    });
                }
            }
        }
    }

    let latest = records.last().unwrap();
    let root = RootPointer::new(CommitGroupId(latest.commit_group_id), 0);

    let recovered_epoch = latest.epoch_number;
    let committed_root = CommittedRoot {
        root,
        commitment_hash: latest.commit_hash,
        epoch_number: recovered_epoch,
        dirty_object_count: latest.dirty_object_ids.len() as u64,
    };

    // Split-brain prevention: reject stale roots from partitioned writers.
    if let Some(min) = min_epoch {
        if recovered_epoch < min {
            return Err(CommittedRootError::StaleRoot {
                recovered_epoch,
                min_epoch: min,
            });
        }
    }

    Ok(Some(committed_root))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_commit_group::CommitGroupId;

    /// Build a single test commit record with known values.
    fn make_test_record(
        epoch: u64,
        cg_id: u64,
        prior_hash: Option<[u8; 32]>,
        dirty_ids: &[u64],
    ) -> ParsedCommitRecord {
        let commit_hash = seal_commit_hash(epoch, CommitGroupId(cg_id), prior_hash, dirty_ids);
        ParsedCommitRecord {
            epoch_number: epoch,
            commit_group_id: cg_id,
            commit_hash,
            prior_epoch_hash: prior_hash,
            dirty_object_ids: dirty_ids.to_vec(),
        }
    }

    #[test]
    fn encode_decode_single_record_roundtrip() {
        let record = make_test_record(1, 1, None, &[10, 20, 30]);
        let encoded = encode_commit_record_region(&[record.clone()]);
        let result = recover_committed_root_from_bytes(&encoded, None).unwrap();
        assert!(result.is_some());
        let root = result.unwrap();
        assert_eq!(root.epoch_number, 1);
        assert_eq!(root.root.commit_group_id.0, 1);
        assert_eq!(root.dirty_object_count, 3);
        assert_eq!(root.commitment_hash, record.commit_hash);
    }

    #[test]
    fn recover_from_valid_chain_of_three_epochs() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        let r3 = make_test_record(3, 3, Some(r2.commit_hash), &[30]);
        let r3_hash = r3.commit_hash;
        let encoded = encode_commit_record_region(&[r1, r2, r3]);
        let result = recover_committed_root_from_bytes(&encoded, None).unwrap();
        assert!(result.is_some());
        let root = result.unwrap();
        assert_eq!(root.epoch_number, 3);
        assert_eq!(root.root.commit_group_id.0, 3);
        assert_eq!(root.commitment_hash, r3_hash);
    }

    #[test]
    fn empty_region_returns_none() {
        let result = recover_committed_root_from_bytes(&[], None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn truncated_header_returns_error() {
        let result = recover_committed_root_from_bytes(&[0x56, 0x42], None); // Only "VB", not full header
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::TruncatedHeader { .. } => {}
            e => panic!("expected TruncatedHeader, got {e}"),
        }
    }

    #[test]
    fn bad_magic_returns_error() {
        let bad_magic = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let result = recover_committed_root_from_bytes(&bad_magic, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::BadMagic { .. } => {}
            e => panic!("expected BadMagic, got {e}"),
        }
    }

    #[test]
    fn tampered_commit_hash_is_detected() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let mut encoded = encode_commit_record_region(&[r1.clone()]);
        // Tamper with the commit_hash field (bytes 16..48 of the record,
        // which is at HEADER_SIZE + 16).
        encoded[HEADER_SIZE + 16] ^= 0xFF;
        let result = recover_committed_root_from_bytes(&encoded, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::RecordVerificationFailed { .. } => {}
            e => panic!("expected RecordVerificationFailed, got {e}"),
        }
    }

    #[test]
    fn broken_hash_chain_is_detected() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        // Create r3 with prior_hash pointing to a wrong hash
        let wrong_prior = [0xFFu8; 32];
        let r3 = make_test_record(3, 3, Some(wrong_prior), &[30]);
        let _r3_hash = r3.commit_hash;
        let encoded = encode_commit_record_region(&[r1, r2, r3]);
        let result = recover_committed_root_from_bytes(&encoded, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::ChainBroken { .. } => {}
            e => panic!("expected ChainBroken, got {e}"),
        }
    }

    #[test]
    fn zero_records_in_header_returns_none() {
        // Valid header with record_count = 0
        let mut buf = Vec::new();
        buf.extend_from_slice(&COMMIT_RECORD_MAGIC);
        buf.push(COMMIT_RECORD_VERSION);
        buf.extend_from_slice(&0u32.to_le_bytes());
        let csum = blake3::hash(&buf);
        buf.extend_from_slice(csum.as_bytes());
        let result = recover_committed_root_from_bytes(&buf, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn header_checksum_mismatch_detected() {
        // Valid magic + version + count, but wrong checksum.
        let mut buf = Vec::new();
        buf.extend_from_slice(&COMMIT_RECORD_MAGIC);
        buf.push(COMMIT_RECORD_VERSION);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&[0xFFu8; 32]); // Wrong checksum
        let result = recover_committed_root_from_bytes(&buf, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::HeaderChecksumMismatch => {}
            e => panic!("expected HeaderChecksumMismatch, got {e}"),
        }
    }

    #[test]
    fn truncated_record_mid_chain_is_detected() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        let mut encoded = encode_commit_record_region(&[r1, r2]);
        // Truncate: cut off the last few bytes of r2
        encoded.truncate(encoded.len() - 10);
        // Update header record_count to still say 2
        // record_count is at bytes 5..9
        encoded[5..9].copy_from_slice(&2u32.to_le_bytes());
        let result = recover_committed_root_from_bytes(&encoded, None);
        assert!(result.is_err());
    }

    #[test]
    fn non_monotonic_ids_are_allowed_since_seal_commit_hash_hashes_everything() {
        // The seal_commit_hash function hashes the dirty IDs in order, so
        // even if IDs are not monotonic in value, the hash is valid.
        let r1 = make_test_record(1, 1, None, &[500, 10, 999]);
        let encoded = encode_commit_record_region(&[r1.clone()]);
        let result = recover_committed_root_from_bytes(&encoded, None).unwrap();
        assert!(result.is_some());
        let root = result.unwrap();
        assert_eq!(root.dirty_object_count, 3);
        assert_eq!(root.commitment_hash, r1.commit_hash);
    }

    #[test]
    fn epoch_one_must_not_have_prior_hash() {
        // Create a record with epoch=1 but with a prior_hash set — invalid.
        let wrong_prior = Some([0xAAu8; 32]);
        let r1 = make_test_record(1, 1, wrong_prior, &[10]);
        let encoded = encode_commit_record_region(&[r1]);
        let result = recover_committed_root_from_bytes(&encoded, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::ChainBroken { .. } => {}
            e => panic!("expected ChainBroken, got {e}"),
        }
    }

    #[test]
    fn large_number_of_records() {
        let mut records = Vec::new();
        let mut prior: Option<[u8; 32]> = None;
        for i in 1..=50u64 {
            let r = make_test_record(i, i, prior, &[i * 10]);
            prior = Some(r.commit_hash);
            records.push(r);
        }
        let encoded = encode_commit_record_region(&records);
        let result = recover_committed_root_from_bytes(&encoded, None).unwrap();
        assert!(result.is_some());
        let root = result.unwrap();
        assert_eq!(root.epoch_number, 50);
        assert_eq!(root.root.commit_group_id.0, 50);
    }

    #[test]
    fn committed_root_valid_and_invalid() {
        let valid = CommittedRoot::new(RootPointer::new(CommitGroupId(1), 0), [0u8; 32], 1, 0);
        assert!(valid.is_valid());

        let invalid = CommittedRoot::new(RootPointer::NIL, [0u8; 32], 0, 0);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn unknown_version_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&COMMIT_RECORD_MAGIC);
        buf.push(0xFF); // Bad version
        buf.extend_from_slice(&0u32.to_le_bytes());
        let csum = blake3::hash(&buf);
        buf.extend_from_slice(csum.as_bytes());
        let result = recover_committed_root_from_bytes(&buf, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::UnknownVersion { version: 0xFF } => {}
            e => panic!("expected UnknownVersion, got {e}"),
        }
    }

    #[test]
    fn commit_record_conversion_to_commitgroup_record() {
        let parsed = make_test_record(5, 5, Some([0x01u8; 32]), &[1, 2, 3]);
        let record = parsed.to_commit_record();
        assert_eq!(record.epoch_number, 5);
        assert_eq!(record.commit_group_id, CommitGroupId(5));
        assert_eq!(record.commit_hash, parsed.commit_hash);
        assert_eq!(record.prior_epoch_hash, Some([0x01u8; 32]));
        assert_eq!(record.dirty_object_count, 3);
    }

    #[test]
    fn stale_root_rejected_when_epoch_below_min_epoch() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        let encoded = encode_commit_record_region(&[r1, r2]);

        // min_epoch=3 > recovered=2 → stale
        let result = recover_committed_root_from_bytes(&encoded, Some(3));
        assert!(result.is_err());
        match result.unwrap_err() {
            CommittedRootError::StaleRoot {
                recovered_epoch,
                min_epoch,
            } => {
                assert_eq!(recovered_epoch, 2);
                assert_eq!(min_epoch, 3);
            }
            e => panic!("expected StaleRoot, got {e}"),
        }
    }

    #[test]
    fn stale_root_passes_when_epoch_at_min_epoch() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        let encoded = encode_commit_record_region(&[r1, r2]);

        // min_epoch=2 == recovered=2 → accepted
        let result = recover_committed_root_from_bytes(&encoded, Some(2)).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().epoch_number, 2);
    }

    #[test]
    fn stale_root_passes_when_epoch_above_min_epoch() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        let encoded = encode_commit_record_region(&[r1, r2]);

        // min_epoch=1 < recovered=2 → accepted
        let result = recover_committed_root_from_bytes(&encoded, Some(1)).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().epoch_number, 2);
    }

    #[test]
    fn stale_root_passes_when_no_min_epoch_set() {
        let r1 = make_test_record(1, 1, None, &[10]);
        let r2 = make_test_record(2, 2, Some(r1.commit_hash), &[20]);
        let encoded = encode_commit_record_region(&[r1, r2]);

        // No min_epoch → always accepted
        let result = recover_committed_root_from_bytes(&encoded, None).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().epoch_number, 2);
    }

    #[test]
    fn stale_root_error_display() {
        let err = CommittedRootError::StaleRoot {
            recovered_epoch: 5,
            min_epoch: 10,
        };
        let s = format!("{err}");
        assert!(s.contains("stale committed root"));
        assert!(s.contains("5"));
        assert!(s.contains("10"));
    }
}
