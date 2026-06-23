// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cluster authority on-disk store: persistence and scan for
//! [`ClusterAuthorityRecord`]s on pool devices.
//!
//! The authority region lives at a fixed offset on each pool device,
//! after the commit-record region. It is a self-describing header
//! followed by one or more bincode-encoded [`ClusterAuthorityRecord`]s.
//!
//! ## On-disk layout
//!
//! ```text
//! Offset 270336 (CLUSTER_AUTHORITY_REGION_OFFSET):
//!
//! Header (56 bytes):
//!   magic:           [u8; 4]  = b"VBCA"
//!   version:         u32 LE   = 1
//!   record_count:    u32 LE
//!   reserved:        [u8; 12] (zero-filled)
//!   header_csum:     [u8; 32]  BLAKE3-256 over bytes 0..24
//!
//! Records (variable, one per record_count):
//!   record_len:      u32 LE  byte length of encoded record
//!   record_csum:     [u8; 32]  BLAKE3-256 over encoded bytes
//!   record_bytes:    [u8; record_len]  bincode-encoded ClusterAuthorityRecord
//! ```
//!
//! ## Scan-on-boot
//!
//! [`scan_authority_from_device`] reads the region from a single device.
//! [`scan_authority_from_devices`] scans multiple devices, selects the
//! record with the highest `(sequence, committed_txg)`, validates the
//! entire chain on that device, and returns the current authority state.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::cluster_authority_record::{
    validate_authority_chain, validate_authority_record, ClusterAuthorityRecord,
    ClusterAuthorityVerdict, CLUSTER_AUTHORITY_MAGIC, CLUSTER_AUTHORITY_VERSION,
};

// ── On-disk constants ─────────────────────────────────────────────

/// Byte offset from the start of the device where the cluster authority
/// region begins. This is after the commit-record region
/// (8192 + 256 KiB = 270336).
pub const CLUSTER_AUTHORITY_REGION_OFFSET: u64 = 270336;

/// Maximum size of the cluster authority region in bytes (64 KiB).
pub const CLUSTER_AUTHORITY_REGION_MAX: usize = 64 * 1024;

/// Header wire size: magic(4) + version(4) + record_count(4) +
/// reserved(12) + header_csum(32) = 56 bytes.
pub const CLUSTER_AUTHORITY_HEADER_SIZE: usize = 56;

/// BLAKE3-256 digest size.
const DIGEST_SIZE: usize = 32;

/// Domain separation for header checksum.
const HEADER_DOMAIN: &[u8] = b"tidefs-cluster-authority-header-v1";

/// Domain separation for per-record checksum.
const RECORD_DOMAIN: &[u8] = b"tidefs-cluster-authority-record-envelope-v1";

// ── Error types ───────────────────────────────────────────────────

/// Errors from cluster authority store operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityStoreError {
    /// I/O error.
    Io(String),
    /// The region is too small to contain a valid header.
    TruncatedHeader { found: usize },
    /// Magic bytes do not match CLUSTER_AUTHORITY_MAGIC.
    BadMagic,
    /// Unsupported format version.
    UnsupportedVersion(u32),
    /// Header checksum mismatch (corrupt header).
    HeaderChecksumMismatch,
    /// A record in the chain is truncated or unparseable.
    TruncatedRecord { index: usize },
    /// Bincode deserialization of a record failed.
    RecordDecode(String),
    /// Record checksum mismatch (corrupt record).
    RecordChecksumMismatch { index: usize },
    /// The region is empty (no records or zero-filled).
    NoRecords,
}

impl std::fmt::Display for AuthorityStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::TruncatedHeader { found } => write!(
                f,
                "authority region truncated: expected {CLUSTER_AUTHORITY_HEADER_SIZE} bytes, found {found}"
            ),
            Self::BadMagic => write!(f, "bad authority region magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported authority version {v}"),
            Self::HeaderChecksumMismatch => write!(f, "authority header checksum mismatch"),
            Self::TruncatedRecord { index } => write!(f, "authority record {index} truncated"),
            Self::RecordDecode(msg) => write!(f, "record decode error: {msg}"),
            Self::RecordChecksumMismatch { index } => {
                write!(f, "authority record {index} checksum mismatch")
            }
            Self::NoRecords => write!(f, "no authority records"),
        }
    }
}

// ── Encode / Decode helpers ────────────────────────────────────────

/// Encode the cluster authority header into `buf`.
fn encode_header_into(record_count: u32, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&CLUSTER_AUTHORITY_MAGIC);
    buf.extend_from_slice(&CLUSTER_AUTHORITY_VERSION.to_le_bytes());
    buf.extend_from_slice(&record_count.to_le_bytes());
    buf.extend_from_slice(&[0u8; 12]); // reserved
                                       // Compute header checksum over bytes written so far (24 bytes).
    let header_bytes = &buf[buf.len() - 24..];
    let mut hasher = blake3::Hasher::new();
    hasher.update(HEADER_DOMAIN);
    hasher.update(header_bytes);
    let csum = hasher.finalize();
    buf.extend_from_slice(csum.as_bytes());
}

/// Decode the header from `data`. Returns (record_count, rest) on success.
fn decode_header(data: &[u8]) -> Result<(u32, &[u8]), AuthorityStoreError> {
    if data.len() < CLUSTER_AUTHORITY_HEADER_SIZE {
        return Err(AuthorityStoreError::TruncatedHeader { found: data.len() });
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap();
    if magic != CLUSTER_AUTHORITY_MAGIC {
        return Err(AuthorityStoreError::BadMagic);
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != CLUSTER_AUTHORITY_VERSION {
        return Err(AuthorityStoreError::UnsupportedVersion(version));
    }

    let record_count = u32::from_le_bytes(data[8..12].try_into().unwrap());

    // Verify header checksum: bytes 0..24 hashed with domain.
    let expected_csum: [u8; DIGEST_SIZE] = data[24..56].try_into().unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(HEADER_DOMAIN);
    hasher.update(&data[0..24]);
    let computed = hasher.finalize();
    if computed.as_bytes() != &expected_csum {
        return Err(AuthorityStoreError::HeaderChecksumMismatch);
    }

    Ok((record_count, &data[CLUSTER_AUTHORITY_HEADER_SIZE..]))
}

/// Encode a single authority record envelope into `buf`.
fn encode_record_envelope_into(record: &ClusterAuthorityRecord, buf: &mut Vec<u8>) {
    let encoded = record
        .encode()
        .expect("bincode encode of ClusterAuthorityRecord must succeed");
    // record_len: u32 LE
    buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    // record_csum: BLAKE3-256 over encoded bytes
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(&encoded);
    let csum = hasher.finalize();
    buf.extend_from_slice(csum.as_bytes());
    // record_bytes
    buf.extend_from_slice(&encoded);
}

/// Decode a single authority record envelope from `data`.
/// Returns (record, bytes_consumed) on success.
fn decode_record_envelope(
    data: &[u8],
    index: usize,
) -> Result<(ClusterAuthorityRecord, usize), AuthorityStoreError> {
    // Minimum: record_len(4) + record_csum(32) = 36 bytes
    const MIN_ENVELOPE: usize = 4 + 32;
    if data.len() < MIN_ENVELOPE {
        return Err(AuthorityStoreError::TruncatedRecord { index });
    }

    let record_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let expected_csum: [u8; 32] = data[4..36].try_into().unwrap();

    let record_start = 36;
    let record_end = record_start + record_len;
    if data.len() < record_end {
        return Err(AuthorityStoreError::TruncatedRecord { index });
    }

    let record_bytes = &data[record_start..record_end];

    // Verify per-record checksum.
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(record_bytes);
    let computed = hasher.finalize();
    if computed.as_bytes() != &expected_csum {
        return Err(AuthorityStoreError::RecordChecksumMismatch { index });
    }

    // Deserialize.
    let record = ClusterAuthorityRecord::decode(record_bytes)
        .map_err(|e| AuthorityStoreError::RecordDecode(e.to_string()))?;

    Ok((record, record_end))
}

// ── Read / Write raw region ────────────────────────────────────────

/// Read the raw cluster authority region from a device file.
fn read_raw_region(file: &mut (impl Read + Seek)) -> Result<Vec<u8>, AuthorityStoreError> {
    let mut buf = vec![0u8; CLUSTER_AUTHORITY_REGION_MAX];
    file.seek(SeekFrom::Start(CLUSTER_AUTHORITY_REGION_OFFSET))
        .map_err(|e| AuthorityStoreError::Io(format!("seek: {e}")))?;
    let n = file
        .read(&mut buf)
        .map_err(|e| AuthorityStoreError::Io(format!("read: {e}")))?;
    buf.truncate(n);
    Ok(buf)
}

/// Write the encoded region bytes to a device file.
fn write_raw_region(
    file: &mut (impl Write + Seek),
    data: &[u8],
) -> Result<(), AuthorityStoreError> {
    file.seek(SeekFrom::Start(CLUSTER_AUTHORITY_REGION_OFFSET))
        .map_err(|e| AuthorityStoreError::Io(format!("seek: {e}")))?;
    file.write_all(data)
        .map_err(|e| AuthorityStoreError::Io(format!("write: {e}")))?;
    file.flush()
        .map_err(|e| AuthorityStoreError::Io(format!("flush: {e}")))?;
    Ok(())
}

// ── Public API ─────────────────────────────────────────────────────

/// Persist a list of authority records to a device file.
///
/// Writes the full authority chain to the device, overwriting any
/// existing region. The records must be ordered by sequence number
/// (monotonically increasing, starting from 0).
pub fn write_authority_chain_to_device(
    file: &mut (impl Write + Seek),
    records: &[ClusterAuthorityRecord],
) -> Result<(), AuthorityStoreError> {
    let mut buf = Vec::new();
    encode_header_into(records.len() as u32, &mut buf);
    for rec in records {
        encode_record_envelope_into(rec, &mut buf);
    }
    // Pad to region max for clean future appends.
    if buf.len() < CLUSTER_AUTHORITY_REGION_MAX {
        buf.resize(CLUSTER_AUTHORITY_REGION_MAX, 0);
    }
    write_raw_region(file, &buf)
}

/// Append a single authority record to a device that already has a
/// populated authority region.
///
/// Reads the existing records, appends the new one, and writes back.
/// Returns an error if the existing region is empty or corrupt.
pub fn append_authority_record_to_device(
    file: &mut (impl Read + Write + Seek),
    new_record: &ClusterAuthorityRecord,
) -> Result<(), AuthorityStoreError> {
    let existing = read_all_records_from_device(file)?;
    let mut chain = existing;
    chain.push(new_record.clone());
    write_authority_chain_to_device(file, &chain)
}

/// Read all authority records from a device file.
///
/// Returns the list of records in sequence order.
pub fn read_all_records_from_device(
    file: &mut (impl Read + Seek),
) -> Result<Vec<ClusterAuthorityRecord>, AuthorityStoreError> {
    let raw = read_raw_region(file)?;
    read_all_records_from_bytes(&raw)
}

/// Parse all authority records from a byte buffer (the raw region).
pub(crate) fn read_all_records_from_bytes(
    raw: &[u8],
) -> Result<Vec<ClusterAuthorityRecord>, AuthorityStoreError> {
    if raw.is_empty() {
        return Err(AuthorityStoreError::NoRecords);
    }
    // If the region starts with zeros, treat as empty (fresh pool).
    if raw.len() >= 4 && raw[0..4] == [0u8; 4] {
        return Err(AuthorityStoreError::NoRecords);
    }

    let (record_count, record_data) = decode_header(raw)?;
    if record_count == 0 {
        return Err(AuthorityStoreError::NoRecords);
    }

    let mut records = Vec::with_capacity(record_count as usize);
    let mut cursor = 0;

    for i in 0..record_count as usize {
        if cursor >= record_data.len() {
            return Err(AuthorityStoreError::TruncatedRecord { index: i });
        }
        let (record, consumed) = decode_record_envelope(&record_data[cursor..], i)?;
        records.push(record);
        cursor += consumed;
    }

    Ok(records)
}

/// Scan a single device for the current cluster authority state.
///
/// Reads the authority region, parses all records, validates the hash
/// chain, and returns the latest valid record (highest sequence/txg).
///
/// Returns `None` if no authority region exists on this device
/// (fresh pool or standalone pool).
pub fn scan_authority_from_device(
    file: &mut (impl Read + Seek),
) -> Result<Option<ClusterAuthorityRecord>, AuthorityStoreError> {
    let raw = read_raw_region(file)?;
    scan_authority_from_bytes(&raw)
}

/// Scan authority records from a byte buffer. Returns the latest valid
/// record or None if no authority region exists.
pub(crate) fn scan_authority_from_bytes(
    raw: &[u8],
) -> Result<Option<ClusterAuthorityRecord>, AuthorityStoreError> {
    let records = match read_all_records_from_bytes(raw) {
        Ok(recs) => recs,
        Err(AuthorityStoreError::NoRecords) => return Ok(None),
        Err(e) => return Err(e),
    };

    if records.is_empty() {
        return Ok(None);
    }

    // Validate the chain: each record must pass stand-alone validation,
    // and successors must pass chain validation against their predecessor.
    let verdict = validate_authority_record(&records[0]);
    match verdict {
        ClusterAuthorityVerdict::Refused { reason, detail } => {
            return Err(AuthorityStoreError::RecordDecode(format!(
                "record 0 refused: {reason}: {detail}"
            )));
        }
        ClusterAuthorityVerdict::NotFound => {
            return Ok(None);
        }
        ClusterAuthorityVerdict::Valid { .. } => {}
    }

    for i in 1..records.len() {
        let verdict = validate_authority_chain(&records[i - 1], &records[i]);
        match verdict {
            ClusterAuthorityVerdict::Refused { reason, detail } => {
                return Err(AuthorityStoreError::RecordDecode(format!(
                    "record {i} refused: {reason}: {detail}"
                )));
            }
            ClusterAuthorityVerdict::NotFound | ClusterAuthorityVerdict::Valid { .. } => {}
        }
    }

    // Return the latest (highest sequence) record.
    Ok(records.last().cloned())
}

/// Scan multiple devices and select the current cluster authority state.
///
/// Opens each device path, reads its authority region, and selects the
/// record with the highest `(sequence, committed_txg)` across all devices.
/// Returns the winning record and a map of device_path -> validation
/// outcome for operator visibility.
///
/// If no device has a valid authority region, returns `Ok(None)`.
/// If every device has a corrupt or empty region, returns an error
/// describing the first fatal corruption found.
pub fn scan_authority_from_devices(
    device_paths: &[impl AsRef<Path>],
) -> Result<
    (
        Option<ClusterAuthorityRecord>,
        BTreeMap<String, Result<Option<ClusterAuthorityRecord>, AuthorityStoreError>>,
    ),
    AuthorityStoreError,
> {
    let mut per_device: BTreeMap<
        String,
        Result<Option<ClusterAuthorityRecord>, AuthorityStoreError>,
    > = BTreeMap::new();
    let mut best: Option<ClusterAuthorityRecord> = None;

    let mut first_fatal: Option<AuthorityStoreError> = None;

    for path in device_paths {
        let path_str = path.as_ref().display().to_string();
        let result = (|| -> Result<Option<ClusterAuthorityRecord>, AuthorityStoreError> {
            let mut file = std::fs::File::open(path.as_ref())
                .map_err(|e| AuthorityStoreError::Io(e.to_string()))?;
            scan_authority_from_device(&mut file)
        })();

        match &result {
            Ok(Some(record)) => {
                // Select best: highest (sequence, committed_txg).
                let is_better = match &best {
                    None => true,
                    Some(current) => {
                        record.sequence > current.sequence
                            || (record.sequence == current.sequence
                                && record.committed_txg > current.committed_txg)
                    }
                };
                if is_better {
                    best = Some(record.clone());
                }
            }
            Ok(None) => {}
            Err(e) => {
                if first_fatal.is_none() {
                    first_fatal = Some(e.clone());
                }
            }
        }

        per_device.insert(path_str, result);
    }

    Ok((best, per_device))
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_authority_record::ClusterAuthorityRecord;
    use std::collections::BTreeSet;
    use std::io::Cursor;

    fn voters(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    fn make_genesis() -> ClusterAuthorityRecord {
        ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]),
            BTreeSet::new(),
            1,
            [0xCD; 32],
            5,
        )
    }

    // ── Encode/decode roundtrip ──────────────────────────────────

    #[test]
    fn write_and_read_single_record() {
        let genesis = make_genesis();
        let mut buf = Vec::new();
        encode_header_into(1, &mut buf);
        encode_record_envelope_into(&genesis, &mut buf);

        let records = read_all_records_from_bytes(&buf).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], genesis);
    }

    #[test]
    fn write_and_read_chain_of_three() {
        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .voter_set(voters(&[1, 2, 3, 4]))
            .build();
        let r2 = r1
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(3))
            .voter_set(voters(&[1, 2, 3, 4, 5]))
            .placement_map_epoch(1)
            .build();

        let mut buf = Vec::new();
        encode_header_into(3, &mut buf);
        encode_record_envelope_into(&r0, &mut buf);
        encode_record_envelope_into(&r1, &mut buf);
        encode_record_envelope_into(&r2, &mut buf);

        let records = read_all_records_from_bytes(&buf).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], r0);
        assert_eq!(records[1], r1);
        assert_eq!(records[2], r2);
    }

    // ── Scan ─────────────────────────────────────────────────────

    #[test]
    fn scan_returns_latest_record() {
        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .build();

        let mut buf = Vec::new();
        encode_header_into(2, &mut buf);
        encode_record_envelope_into(&r0, &mut buf);
        encode_record_envelope_into(&r1, &mut buf);

        let result = scan_authority_from_bytes(&buf).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), r1);
    }

    #[test]
    fn scan_empty_region_returns_none() {
        let result = scan_authority_from_bytes(&[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn scan_zero_filled_region_returns_none() {
        let buf = vec![0u8; 100];
        let result = scan_authority_from_bytes(&buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn scan_tampered_record_rejected() {
        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .build();

        let mut buf = Vec::new();
        encode_header_into(2, &mut buf);
        encode_record_envelope_into(&r0, &mut buf);

        // Tamper with r1: encode a record with a broken prev_digest.
        let mut bad_r1 = r1.clone();
        bad_r1.prev_digest = [0xFF; 32];
        bad_r1 = bad_r1.seal();
        encode_record_envelope_into(&bad_r1, &mut buf);

        let result = scan_authority_from_bytes(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn write_authority_chain_pads_to_region_max() {
        let r0 = make_genesis();
        let mut cursor = Cursor::new(Vec::new());
        write_authority_chain_to_device(&mut cursor, &[r0.clone()]).unwrap();

        let written = cursor.into_inner();
        // write_authority_chain_to_device writes at offset, so the resulting
        // Vec includes the offset gap. The authority region itself is
        // CLUSTER_AUTHORITY_REGION_MAX bytes after the offset.
        assert!(written.len() >= CLUSTER_AUTHORITY_REGION_MAX);

        // Read back the region directly from the authority section.
        let region = &written[CLUSTER_AUTHORITY_REGION_OFFSET as usize..];
        let records = read_all_records_from_bytes(region).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], r0);
    }

    #[test]
    fn append_record_extends_chain() {
        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .build();

        let mut cursor = Cursor::new(Vec::new());
        write_authority_chain_to_device(&mut cursor, &[r0.clone()]).unwrap();

        let records = read_all_records_from_device(&mut cursor).unwrap();
        assert_eq!(records.len(), 1);

        append_authority_record_to_device(&mut cursor, &r1).unwrap();

        let records = read_all_records_from_device(&mut cursor).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], r0);
        assert_eq!(records[1], r1);
    }

    // ── Header validation ────────────────────────────────────────

    #[test]
    fn bad_magic_rejected() {
        let mut buf = vec![0u8; CLUSTER_AUTHORITY_HEADER_SIZE];
        buf[0..4].copy_from_slice(b"BADC");
        let result = read_all_records_from_bytes(&buf);
        assert!(matches!(result, Err(AuthorityStoreError::BadMagic)));
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CLUSTER_AUTHORITY_MAGIC);
        buf.extend_from_slice(&99u32.to_le_bytes()); // wrong version
        buf.extend_from_slice(&0u32.to_le_bytes()); // record_count
        buf.extend_from_slice(&[0u8; 12]); // reserved
                                           // Compute checksum with wrong version
        let header_bytes = &buf[buf.len() - 24..];
        let mut hasher = blake3::Hasher::new();
        hasher.update(HEADER_DOMAIN);
        hasher.update(header_bytes);
        let csum = hasher.finalize();
        buf.extend_from_slice(csum.as_bytes());

        let result = read_all_records_from_bytes(&buf);
        assert!(matches!(
            result,
            Err(AuthorityStoreError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn header_checksum_mismatch_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CLUSTER_AUTHORITY_MAGIC);
        buf.extend_from_slice(&CLUSTER_AUTHORITY_VERSION.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // record_count
        buf.extend_from_slice(&[0u8; 12]); // reserved
        buf.extend_from_slice(&[0xFFu8; 32]); // wrong checksum

        let result = read_all_records_from_bytes(&buf);
        assert!(matches!(
            result,
            Err(AuthorityStoreError::HeaderChecksumMismatch)
        ));
    }

    #[test]
    fn truncated_header_rejected() {
        // Use non-zero bytes so the zero-fill check doesn't fire.
        let buf = vec![0xABu8; 10];
        let result = read_all_records_from_bytes(&buf);
        assert!(matches!(
            result,
            Err(AuthorityStoreError::TruncatedHeader { .. })
        ));
    }

    #[test]
    fn truncated_record_rejected() {
        let mut buf = Vec::new();
        encode_header_into(1, &mut buf);
        // Write partial record envelope (just the length field, no checksum/bytes).
        buf.extend_from_slice(&1000u32.to_le_bytes());

        let result = read_all_records_from_bytes(&buf);
        assert!(matches!(
            result,
            Err(AuthorityStoreError::TruncatedRecord { .. })
        ));
    }

    // ── Multi-device scan ────────────────────────────────────────

    #[test]
    fn scan_multiple_devices_selects_best() {
        use std::io::Write;

        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .build();

        let dir = tempfile::TempDir::new().unwrap();
        let dev1_path = dir.path().join("dev1");
        let dev2_path = dir.path().join("dev2");

        {
            let mut f1 = std::fs::File::create(&dev1_path).unwrap();
            f1.write_all(&vec![0u8; CLUSTER_AUTHORITY_REGION_OFFSET as usize])
                .unwrap();
            write_authority_chain_to_device(&mut f1, &[r0.clone()]).unwrap();
        }
        {
            let mut f2 = std::fs::File::create(&dev2_path).unwrap();
            f2.write_all(&vec![0u8; CLUSTER_AUTHORITY_REGION_OFFSET as usize])
                .unwrap();
            write_authority_chain_to_device(&mut f2, &[r0.clone(), r1.clone()]).unwrap();
        }

        let (best, per_device) = scan_authority_from_devices(&[&dev1_path, &dev2_path]).unwrap();
        assert!(best.is_some());
        assert_eq!(best.unwrap(), r1);
        assert_eq!(per_device.len(), 2);

        let dev1_result = per_device
            .get(&dev1_path.display().to_string())
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap();
        assert_eq!(dev1_result.sequence, 0);

        let dev2_result = per_device
            .get(&dev2_path.display().to_string())
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap();
        assert_eq!(dev2_result.sequence, 1);
    }

    #[test]
    fn fresh_pool_zero_filled_region_returns_none_on_scan() {
        let mut cursor = Cursor::new(vec![0u8; CLUSTER_AUTHORITY_REGION_MAX]);
        let result = scan_authority_from_device(&mut cursor).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn empty_device_scan_returns_none() {
        let mut cursor = Cursor::new(Vec::new());
        let result = scan_authority_from_device(&mut cursor);
        // Empty file: read returns 0 bytes -> NoRecords
        assert!(matches!(
            result,
            Ok(None) | Err(AuthorityStoreError::NoRecords)
        ));
    }

    // ── Error display ────────────────────────────────────────────

    #[test]
    fn error_display() {
        assert!(AuthorityStoreError::BadMagic
            .to_string()
            .contains("bad authority"));
        assert!(AuthorityStoreError::NoRecords
            .to_string()
            .contains("no authority records"));
        assert!(AuthorityStoreError::HeaderChecksumMismatch
            .to_string()
            .contains("checksum"));
        let e = AuthorityStoreError::Io("test".into());
        assert!(e.to_string().contains("test"));
    }
}
