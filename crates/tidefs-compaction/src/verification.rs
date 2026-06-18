//! Compaction verification utilities.
//!
//! BLAKE3 domain-separated hashing ("TideFS compaction v1"), sealed-blob
//! encoding with integrity footer, and byte-for-byte equivalence checking
//! for post-rewrite verification.
//!
//! ## Sealed-blob format
//!
//! ```text
//! [payload_len: u32 LE][payload bytes][blake3_hash: 32 bytes]
//! ```
//!
//! The hash covers `domain ++ payload`, where domain is
//! `"TideFS compaction v1"`.

use blake3::Hasher;

/// Domain string for BLAKE3 domain separation across the compaction crate.
pub const COMPACTION_DOMAIN: &[u8] = b"TideFS compaction v1";

// ---------------------------------------------------------------------------
// CompactionHasher — domain-separated BLAKE3 hasher
// ---------------------------------------------------------------------------

/// A BLAKE3 hasher pre-keyed with the compaction domain for
/// domain-separated integrity digests.
#[derive(Clone)]
pub struct CompactionHasher {
    hasher: Hasher,
}

impl CompactionHasher {
    /// Create a new hasher pre-keyed with the compaction domain.
    #[must_use]
    pub fn new() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(COMPACTION_DOMAIN);
        Self { hasher }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the BLAKE3-256 digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Default for CompactionHasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Domain-separated hash functions
// ---------------------------------------------------------------------------

/// Compute a BLAKE3-256 hash over `data` with the compaction domain prefix.
#[must_use]
pub fn compaction_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = CompactionHasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute a BLAKE3-256 hash over multiple byte slices with domain separation.
#[must_use]
pub fn compaction_hash_multi(slices: &[&[u8]]) -> [u8; 32] {
    let mut hasher = CompactionHasher::new();
    for slice in slices {
        hasher.update(slice);
    }
    hasher.finalize()
}

// ---------------------------------------------------------------------------
// SealedBlob — payload with BLAKE3 integrity footer
// ---------------------------------------------------------------------------

/// A sealed blob: arbitrary payload followed by a BLAKE3-256 integrity
/// footer computed over `COMPACTION_DOMAIN ++ payload`.
///
/// # Wire format
///
/// ```text
/// [payload_len: u32 LE][payload bytes][blake3_hash: 32 bytes]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    /// The wrapped payload bytes.
    pub payload: Vec<u8>,
}

/// Errors that can occur when decoding a [`SealedBlob`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedBlobError {
    /// Input is shorter than the minimum size (4 byte header + 32 byte footer).
    Truncated,
    /// The declared payload length exceeds available data.
    PayloadLengthOverflow,
    /// The integrity footer does not match the computed digest.
    IntegrityFooterMismatch,
}

impl core::fmt::Display for SealedBlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "sealed blob too short (need >= 36 bytes)"),
            Self::PayloadLengthOverflow => {
                write!(f, "declared payload length exceeds available data")
            }
            Self::IntegrityFooterMismatch => {
                write!(f, "BLAKE3 integrity footer mismatch")
            }
        }
    }
}

impl SealedBlob {
    /// Create a new sealed blob from a payload.
    ///
    /// The payload is prefixed with its length (u32 LE) and suffixed
    /// with a BLAKE3-256 integrity footer computed over
    /// `COMPACTION_DOMAIN ++ payload`.
    #[must_use]
    pub fn seal(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    /// Encode the sealed blob to bytes.
    ///
    /// Returns `[payload_len: u32 LE][payload][hash: 32]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let hash = compaction_hash(&self.payload);
        let mut buf = Vec::with_capacity(4 + self.payload.len() + 32);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&hash);
        buf
    }

    /// Decode a sealed blob from bytes, verifying the integrity footer.
    ///
    /// # Errors
    ///
    /// Returns [`SealedBlobError`] if the input is truncated, the
    /// payload length overflows, or the integrity footer mismatches.
    pub fn decode(data: &[u8]) -> Result<Self, SealedBlobError> {
        if data.len() < 36 {
            return Err(SealedBlobError::Truncated);
        }

        let payload_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let total_needed = 4usize.saturating_add(payload_len).saturating_add(32);

        if data.len() < total_needed {
            return Err(SealedBlobError::PayloadLengthOverflow);
        }

        let payload = data[4..4 + payload_len].to_vec();
        let expected_hash = &data[4 + payload_len..4 + payload_len + 32];

        let computed_hash = compaction_hash(&payload);
        if computed_hash != expected_hash {
            return Err(SealedBlobError::IntegrityFooterMismatch);
        }

        Ok(Self { payload })
    }

    /// Returns the total encoded size (header + payload + footer).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        4usize.saturating_add(self.payload.len()).saturating_add(32)
    }

    /// Returns true if the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Byte-for-byte equivalence checking
// ---------------------------------------------------------------------------

/// Result of a byte-for-byte equivalence check between a set of
/// source extents and their rewritten target segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivalenceReport {
    /// Whether all source data matches the rewritten target.
    pub verified: bool,
    /// Total bytes compared.
    pub bytes_compared: u64,
    /// Number of source extents compared.
    pub extents_compared: usize,
    /// If verification failed, the first mismatch offset (0-based).
    pub first_mismatch_offset: Option<u64>,
}

impl EquivalenceReport {
    /// Create a successful empty report.
    #[must_use]
    fn empty_ok() -> Self {
        Self {
            verified: true,
            bytes_compared: 0,
            extents_compared: 0,
            first_mismatch_offset: None,
        }
    }
}

/// Check that each source extent's data matches the corresponding
/// slice in the rewritten target segment.
///
/// `source_data` is an iterator of `(key, data)` tuples from the
/// source segments. `target_segment_data` is the complete contiguous
/// buffer of the rewritten target segment. The check uses the known
/// byte offsets of each object in the target segment to slice out
/// the expected region and compare byte-for-byte.
///
/// Returns an [`EquivalenceReport`] describing the outcome.
#[must_use]
pub fn verify_byte_equivalence(
    source_extents: &[(&[u8], &[u8])], // (key, data)
    target_segment_data: &[u8],
    target_offsets: &[u64], // byte offset in target for each extent
) -> EquivalenceReport {
    if source_extents.is_empty() {
        return EquivalenceReport::empty_ok();
    }

    if source_extents.len() != target_offsets.len() {
        return EquivalenceReport {
            verified: false,
            bytes_compared: 0,
            extents_compared: 0,
            first_mismatch_offset: Some(0),
        };
    }

    let mut bytes_compared: u64 = 0;

    for (i, ((_key, data), &offset)) in source_extents.iter().zip(target_offsets.iter()).enumerate()
    {
        let end = offset.saturating_add(data.len() as u64);
        let end_usize = end as usize;

        if end_usize > target_segment_data.len() {
            return EquivalenceReport {
                verified: false,
                bytes_compared,
                extents_compared: i,
                first_mismatch_offset: Some(offset),
            };
        }

        let target_slice = &target_segment_data[offset as usize..end_usize];
        if target_slice != *data {
            // Find the exact mismatch offset.
            let mismatch_pos = target_slice
                .iter()
                .zip(data.iter())
                .position(|(t, s)| t != s)
                .unwrap_or(0);
            return EquivalenceReport {
                verified: false,
                bytes_compared: bytes_compared.saturating_add(mismatch_pos as u64),
                extents_compared: i,
                first_mismatch_offset: Some(offset.saturating_add(mismatch_pos as u64)),
            };
        }

        bytes_compared = bytes_compared.saturating_add(data.len() as u64);
    }

    EquivalenceReport {
        verified: true,
        bytes_compared,
        extents_compared: source_extents.len(),
        first_mismatch_offset: None,
    }
}

/// Verify that two byte slices are equal, returning a simple boolean
/// result. Uses constant-time comparison to avoid timing side-channels.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // constant_time_eq crate is a dependency via blake3.
    a.len() == b.len() && constant_time_eq::constant_time_eq(a, b)
}

// ---------------------------------------------------------------------------
// Swap manifest domain
// ---------------------------------------------------------------------------

/// Domain string for BLAKE3 domain-separated swap-manifest hashing.
pub const SWAP_MANIFEST_DOMAIN: &[u8] = b"TideFS compaction v1 swap-manifest";

// ---------------------------------------------------------------------------
// SwapVerificationError -- reasons a swap manifest fails verification
// ---------------------------------------------------------------------------

/// Reasons a swap manifest fails post-rewrite verification against
/// the stored target data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapVerificationError {
    /// The manifest itself is missing required fields.
    MissingManifestData { detail: String },
    /// Reading back an object from the target store failed.
    TargetReadFailed { key: [u8; 32], reason: String },
    /// The BLAKE3 digest of the stored object does not match the
    /// digest recorded in the relocation entry.
    DigestMismatch {
        key: [u8; 32],
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The manifest's release shape does not match the relocation
    /// entries present for the claimed source segments.
    EntryCountMismatch {
        manifest_count: usize,
        actual_count: usize,
    },
    /// A source or target segment reference is inconsistent.
    SourceTargetMismatch { detail: String },
    /// The manifest is explicitly empty and cannot release segments.
    EmptyManifest,
}

impl core::fmt::Display for SwapVerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingManifestData { detail } => {
                write!(f, "missing manifest data: {detail}")
            }
            Self::TargetReadFailed { key, reason } => {
                write!(f, "target read failed for {key:02x?}: {reason}")
            }
            Self::DigestMismatch {
                key,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "BLAKE3 digest mismatch for {key:02x?}: expected {expected:02x?}, got {actual:02x?}"
                )
            }
            Self::EntryCountMismatch {
                manifest_count,
                actual_count,
            } => {
                write!(
                    f,
                    "entry count mismatch: manifest={manifest_count}, actual={actual_count}"
                )
            }
            Self::SourceTargetMismatch { detail } => {
                write!(f, "source/target mismatch: {detail}")
            }
            Self::EmptyManifest => {
                write!(f, "empty manifest cannot release source segments")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SwapVerification -- outcome of verifying a swap manifest
// ---------------------------------------------------------------------------

/// Result of verifying a swap manifest against stored target data.
///
/// Source segments become eligible for release only when `verified`
/// is `true` and `errors` is empty.
#[derive(Clone, Debug)]
pub struct SwapVerification {
    /// Whether all relocation entries passed verification.
    pub verified: bool,
    /// Number of relocation entries that matched.
    pub entries_verified: usize,
    /// Total relocation entries checked.
    pub entries_total: usize,
    /// Total bytes compared.
    pub bytes_compared: u64,
    /// Errors encountered during verification.
    pub errors: Vec<SwapVerificationError>,
}

impl SwapVerification {
    /// Construct a failed verification with a single error.
    #[must_use]
    pub fn failed(error: SwapVerificationError) -> Self {
        Self {
            verified: false,
            entries_verified: 0,
            entries_total: 0,
            bytes_compared: 0,
            errors: vec![error],
        }
    }

    /// Construct a successful verification.
    #[must_use]
    fn success(entries_verified: usize, bytes_compared: u64) -> Self {
        Self {
            verified: true,
            entries_verified,
            entries_total: entries_verified,
            bytes_compared,
            errors: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// verify_swap_manifest -- post-rewrite integrity check
// ---------------------------------------------------------------------------

/// Verify a swap manifest against the data stored in `store`.
///
/// Every relocation entry in the manifest is checked:
///
/// 1. The manifest must not be empty if it claims to release segments.
/// 2. Each object key is read back from the store.
/// 3. The BLAKE3 digest of the stored data is compared against the
///    digest recorded in the relocation entry.
/// 4. Entry counts and source/target consistency are checked.
///
/// Source segments become eligible for release only when this function
/// returns [`SwapVerification::verified`] == `true`.
pub fn verify_swap_manifest<S: crate::CompactionStore>(
    manifest: &crate::rewrite_engine::SwapManifest,
    store: &S,
) -> SwapVerification {
    // Empty manifests cannot release segments.
    if manifest.is_empty() {
        return SwapVerification::failed(SwapVerificationError::EmptyManifest);
    }

    // Manifest must carry relocation entries to be meaningful.
    if manifest.relocation_entries.is_empty() && !manifest.source_segments.is_empty() {
        return SwapVerification::failed(SwapVerificationError::MissingManifestData {
            detail: "manifest declares source segments but has no relocation entries".into(),
        });
    }

    // Verify the manifest's own hash is internally consistent.
    if !manifest.verify_self() {
        return SwapVerification::failed(SwapVerificationError::MissingManifestData {
            detail: "manifest hash mismatch; data may be corrupted".into(),
        });
    }

    let mut entries_verified: usize = 0;
    let mut bytes_compared: u64 = 0;
    let mut errors: Vec<SwapVerificationError> = Vec::new();
    let mut sources_with_entries: Vec<u64> = Vec::new();
    let mut entries_by_source: std::collections::BTreeMap<
        u64,
        std::collections::BTreeSet<[u8; 32]>,
    > = std::collections::BTreeMap::new();

    if manifest.target_segment == 0 {
        errors.push(SwapVerificationError::SourceTargetMismatch {
            detail: "manifest declares source release without a target segment".into(),
        });
    }

    if manifest.source_segments.contains(&manifest.target_segment) {
        errors.push(SwapVerificationError::SourceTargetMismatch {
            detail: format!(
                "target segment {} is also listed as a source segment",
                manifest.target_segment
            ),
        });
    }

    for entry in &manifest.relocation_entries {
        // Verify source segment membership.
        if !manifest.source_segments.contains(&entry.source_segment) {
            errors.push(SwapVerificationError::SourceTargetMismatch {
                detail: format!(
                    "relocation entry references source segment {} not in manifest",
                    entry.source_segment
                ),
            });
            continue;
        }
        if !sources_with_entries.contains(&entry.source_segment) {
            sources_with_entries.push(entry.source_segment);
        }
        if !entries_by_source
            .entry(entry.source_segment)
            .or_default()
            .insert(entry.object_key)
        {
            errors.push(SwapVerificationError::SourceTargetMismatch {
                detail: format!(
                    "duplicate relocation entry for source segment {} object {:02x?}",
                    entry.source_segment, entry.object_key
                ),
            });
            continue;
        }

        // Read the object back from the store and verify its digest.
        match store.read_object(&entry.object_key) {
            Ok(data) => {
                let actual_hash: [u8; 32] = blake3::hash(&data).into();

                if actual_hash != entry.blake3_hash {
                    errors.push(SwapVerificationError::DigestMismatch {
                        key: entry.object_key,
                        expected: entry.blake3_hash,
                        actual: actual_hash,
                    });
                    continue;
                }

                if entry.target_offset != bytes_compared {
                    errors.push(SwapVerificationError::SourceTargetMismatch {
                        detail: format!(
                            "entry target offset {} does not match expected contiguous offset {}",
                            entry.target_offset, bytes_compared
                        ),
                    });
                    continue;
                }

                entries_verified = entries_verified.saturating_add(1);
                bytes_compared = bytes_compared.saturating_add(data.len() as u64);
            }
            Err(e) => {
                errors.push(SwapVerificationError::TargetReadFailed {
                    key: entry.object_key,
                    reason: format!("{e}"),
                });
                continue;
            }
        }
    }

    if sources_with_entries.len() != manifest.source_segments.len() {
        errors.push(SwapVerificationError::EntryCountMismatch {
            manifest_count: manifest.source_segments.len(),
            actual_count: sources_with_entries.len(),
        });
    }

    for source_segment in &manifest.source_segments {
        match store.live_object_keys(*source_segment) {
            Ok(expected_keys) => {
                let expected: std::collections::BTreeSet<[u8; 32]> =
                    expected_keys.into_iter().collect();
                let actual = entries_by_source
                    .get(source_segment)
                    .cloned()
                    .unwrap_or_default();

                if expected.len() != actual.len() {
                    errors.push(SwapVerificationError::EntryCountMismatch {
                        manifest_count: expected.len(),
                        actual_count: actual.len(),
                    });
                }

                for missing in expected.difference(&actual) {
                    errors.push(SwapVerificationError::MissingManifestData {
                        detail: format!(
                            "source segment {} live object {:02x?} has no relocation entry",
                            source_segment, missing
                        ),
                    });
                }

                for unexpected in actual.difference(&expected) {
                    errors.push(SwapVerificationError::SourceTargetMismatch {
                        detail: format!(
                            "relocation entry for object {:02x?} is not live in source segment {}",
                            unexpected, source_segment
                        ),
                    });
                }
            }
            Err(e) => errors.push(SwapVerificationError::MissingManifestData {
                detail: format!(
                    "source segment {} live-key enumeration failed: {e}",
                    source_segment
                ),
            }),
        }
    }

    if bytes_compared != manifest.total_bytes && errors.is_empty() {
        errors.push(SwapVerificationError::MissingManifestData {
            detail: format!(
                "manifest byte count {} does not match verified target bytes {}",
                manifest.total_bytes, bytes_compared
            ),
        });
    }

    if errors.is_empty() {
        SwapVerification::success(entries_verified, bytes_compared)
    } else {
        SwapVerification {
            verified: false,
            entries_verified,
            entries_total: manifest.relocation_entries.len(),
            bytes_compared,
            errors,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // CompactionHasher tests
    // ------------------------------------------------------------------

    #[test]
    fn hasher_domain_separated() {
        let mut h1 = CompactionHasher::new();
        h1.update(b"hello");
        let d1 = h1.finalize();

        let mut h2 = CompactionHasher::new();
        h2.update(b"hello");
        let d2 = h2.finalize();

        assert_eq!(d1, d2);

        // Domain separation: same data without domain should differ.
        let mut raw = Hasher::new();
        raw.update(b"hello");
        let raw_hash: [u8; 32] = raw.finalize().into();
        assert_ne!(d1, raw_hash);
    }

    #[test]
    fn hasher_deterministic() {
        let mut h1 = CompactionHasher::new();
        h1.update(b"abc");
        h1.update(b"def");
        let d1 = h1.finalize();

        let mut h2 = CompactionHasher::new();
        h2.update(b"abcdef");
        let d2 = h2.finalize();

        // BLAKE3 is incremental, so these should be equal.
        assert_eq!(d1, d2);
    }

    #[test]
    fn hasher_default_is_new() {
        let h1 = CompactionHasher::new();
        let h2 = CompactionHasher::default();
        // Both are fresh hashers pre-keyed with domain.
        let d1 = h1.finalize();
        let d2 = h2.finalize();
        // Empty hashes with same domain should be equal.
        assert_eq!(d1, d2);
    }

    // ------------------------------------------------------------------
    // compaction_hash tests
    // ------------------------------------------------------------------

    #[test]
    fn compaction_hash_deterministic() {
        let h1 = compaction_hash(b"test");
        let h2 = compaction_hash(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compaction_hash_differs_by_input() {
        let h1 = compaction_hash(b"alpha");
        let h2 = compaction_hash(b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compaction_hash_multi_equivalent_to_concatenated() {
        let a: &[u8] = b"one";
        let b: &[u8] = b"two";
        let h_multi = compaction_hash_multi(&[a, b]);
        let concat: Vec<u8> = [a, b].concat();
        let h_concat = compaction_hash(&concat);
        assert_eq!(h_multi, h_concat);
    }

    // ------------------------------------------------------------------
    // SealedBlob tests
    // ------------------------------------------------------------------

    #[test]
    fn sealed_blob_roundtrip() {
        let payload = b"compaction outcome payload".to_vec();
        let blob = SealedBlob::seal(payload.clone());
        let encoded = blob.encode();

        assert_eq!(blob.encoded_len(), 4 + payload.len() + 32);
        assert_eq!(encoded.len(), blob.encoded_len());

        let decoded = SealedBlob::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn sealed_blob_empty_payload() {
        let blob = SealedBlob::seal(vec![]);
        assert!(blob.is_empty());
        let encoded = blob.encode();
        assert_eq!(encoded.len(), 36);
        let decoded = SealedBlob::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn sealed_blob_detects_truncated() {
        let result = SealedBlob::decode(&[0u8; 10]);
        assert_eq!(result, Err(SealedBlobError::Truncated));
    }

    #[test]
    fn sealed_blob_detects_truncated_at_35_bytes() {
        let result = SealedBlob::decode(&[0u8; 35]);
        assert_eq!(result, Err(SealedBlobError::Truncated));
    }

    #[test]
    fn sealed_blob_detects_payload_overflow() {
        // Header says 100 bytes but data is only 40 bytes total.
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&100u32.to_le_bytes());
        let result = SealedBlob::decode(&data);
        assert_eq!(result, Err(SealedBlobError::PayloadLengthOverflow));
    }

    #[test]
    fn sealed_blob_detects_integrity_footer_mismatch() {
        let blob = SealedBlob::seal(b"data".to_vec());
        let mut encoded = blob.encode();
        // Flip a byte in the footer.
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        let result = SealedBlob::decode(&encoded);
        assert_eq!(result, Err(SealedBlobError::IntegrityFooterMismatch));
    }

    #[test]
    fn sealed_blob_detects_payload_corruption() {
        let blob = SealedBlob::seal(b"data".to_vec());
        let mut encoded = blob.encode();
        // Corrupt payload byte.
        encoded[5] ^= 0xFF;
        let result = SealedBlob::decode(&encoded);
        assert_eq!(result, Err(SealedBlobError::IntegrityFooterMismatch));
    }

    #[test]
    fn sealed_blob_encoded_len_matches_encode() {
        let blob = SealedBlob::seal(vec![0u8; 1024]);
        assert_eq!(blob.encode().len(), blob.encoded_len());
        assert_eq!(blob.encoded_len(), 4 + 1024 + 32);
    }

    // ------------------------------------------------------------------
    // Byte equivalence tests
    // ------------------------------------------------------------------

    #[test]
    fn byte_equivalence_empty() {
        let report = verify_byte_equivalence(&[], b"anything", &[]);
        assert!(report.verified);
        assert_eq!(report.bytes_compared, 0);
        assert_eq!(report.extents_compared, 0);
        assert_eq!(report.first_mismatch_offset, None);
    }

    #[test]
    fn byte_equivalence_mismatched_lengths() {
        let key1 = b"key1";
        let data1 = b"hello";
        let report = verify_byte_equivalence(
            &[(key1, data1)],
            b"hello",
            &[], // missing offset
        );
        assert!(!report.verified);
    }

    #[test]
    fn byte_equivalence_single_extent_match() {
        let key1 = b"key1";
        let data1 = b"hello world";
        let target = b"hello world";
        let offsets = vec![0u64];
        let report = verify_byte_equivalence(&[(key1, data1)], target, &offsets);
        assert!(report.verified);
        assert_eq!(report.bytes_compared, 11);
        assert_eq!(report.extents_compared, 1);
        assert_eq!(report.first_mismatch_offset, None);
    }

    #[test]
    fn byte_equivalence_single_extent_mismatch() {
        let key1 = b"key1";
        let data1 = b"hello";
        let target = b"hxllo"; // mismatch at byte 1
        let offsets = vec![0u64];
        let report = verify_byte_equivalence(&[(key1, data1)], target, &offsets);
        assert!(!report.verified);
        assert_eq!(report.bytes_compared, 1);
        assert_eq!(report.extents_compared, 0);
        assert_eq!(report.first_mismatch_offset, Some(1));
    }

    #[test]
    fn byte_equivalence_multi_extent_contiguous() {
        let d1 = b"AAA";
        let d2 = b"BBB";
        let d3 = b"CCC";
        let target = b"AAABBBCCC";
        let offsets = vec![0u64, 3, 6];
        let report =
            verify_byte_equivalence(&[(b"k1", d1), (b"k2", d2), (b"k3", d3)], target, &offsets);
        assert!(report.verified);
        assert_eq!(report.bytes_compared, 9);
        assert_eq!(report.extents_compared, 3);
    }

    #[test]
    fn byte_equivalence_multi_extent_mismatch_in_second() {
        let d1 = b"AAA";
        let d2 = b"BBB"; // source data
        let d3 = b"CCC";
        let target = b"AAABxBCxCC"; // target corrupted at positions 4 and 8
        let offsets = vec![0u64, 3, 6];
        let report =
            verify_byte_equivalence(&[(b"k1", d1), (b"k2", d2), (b"k3", d3)], target, &offsets);
        assert!(!report.verified);
        assert_eq!(report.extents_compared, 1); // stopped at extent index 1
        assert_eq!(report.first_mismatch_offset, Some(4)); // offset 3 + 1
    }

    #[test]
    fn byte_equivalence_target_too_short() {
        let d1 = b"AAAAAA";
        let target = b"AAA"; // too short
        let offsets = vec![0u64];
        let report = verify_byte_equivalence(&[(b"k1", d1)], target, &offsets);
        assert!(!report.verified);
        assert_eq!(report.first_mismatch_offset, Some(0));
    }

    #[test]
    fn byte_equivalence_non_zero_offsets() {
        let d1 = b"hello";
        let d2 = b"world";
        // Target: [padding 10][hello][padding 5][world]
        let target = b"xxxxxxxxxxhelloxxxxxworld";
        let offsets = vec![10u64, 20];
        let report = verify_byte_equivalence(&[(b"k1", d1), (b"k2", d2)], target, &offsets);
        assert!(report.verified);
        assert_eq!(report.bytes_compared, 10);
        assert_eq!(report.extents_compared, 2);
    }

    // ------------------------------------------------------------------
    // constant_time_eq tests
    // ------------------------------------------------------------------

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // ------------------------------------------------------------------
    // Error display tests
    // ------------------------------------------------------------------

    #[test]
    fn sealed_blob_error_display_non_empty() {
        let variants = [
            SealedBlobError::Truncated,
            SealedBlobError::PayloadLengthOverflow,
            SealedBlobError::IntegrityFooterMismatch,
        ];
        for err in &variants {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }
}
